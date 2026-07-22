use mpc_chain_integration_core::utils::stream::chain_event_channel;
use mpc_chain_integration_core::NoopPublisherTelemetry;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_sol_types::SolValue;
use anchor_client::anchor_lang::AnchorDeserialize;
use anchor_lang::solana_program::keccak;
use anchor_lang::Discriminator;
use anyhow::Context;
use async_trait::async_trait;
use futures_util::stream::StreamExt;
use futures_util::Stream;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, Scalar};
use mpc_chain_integration_core::{
    utils::{
        hashing::{compute_request_id, hash_payload},
        task::AbortOnDrop,
    },
    ChainIndexer, ChainTelemetry, StateManager,
};
use mpc_crypto::kdf::derive_epsilon_sol;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, SignArgs, SignId, LATEST_MPC_KEY_VERSION,
    MAX_SECP256K1_SCALAR,
};
use signet_program::{
    RespondBidirectionalEvent, SignBidirectionalEvent, SignatureRequestedEvent,
    SignatureRespondedEvent,
};
use solana_client::{
    nonblocking::pubsub_client::PubsubClient,
    rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter},
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{
    EncodedTransaction, EncodedTransactionWithStatusMeta, UiConfirmedBlock, UiInstruction,
    UiParsedInstruction,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::client::{SolanaCatchupBlock, MAX_CONCURRENT_CHUNK_SIZE};
use crate::utils::current_unix_timestamp;
use crate::{SolConfig, SolanaClient};

const CPI_EVENT_HINTS: &[&str] = &[
    "Program log: Instruction: Sign",
    "Program log: Instruction: SignBidirectional",
];

const CPI_RESPOND_EVENT_HINTS: &[&str] = &[
    "Program log: Instruction: Respond",
    "Program log: Instruction: RespondBidirectional",
];

pub struct SolanaIndexer<S: StateManager, T: ChainTelemetry> {
    program_id: Pubkey,
    client: SolanaClient,
    state_manager: S,
    telemetry: T,
}

impl<S: StateManager, T: ChainTelemetry> SolanaIndexer<S, T> {
    pub fn new(sol: SolConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        let program_id = Pubkey::from_str(&sol.program_address).with_context(|| {
            format!(
                "failed to parse solana program address: {}",
                sol.program_address
            )
        })?;

        let client = SolanaClient::for_indexer(
            sol.rpc_http_url.clone(),
            sol.rpc_ws_url.clone(),
            program_id,
            Arc::new(NoopPublisherTelemetry), // Indexer does not publish
        );

        Ok(Self {
            program_id,
            client,
            state_manager,
            telemetry,
        })
    }

    /// Catchup items in `[processed + 1, anchor)` fetched in chunks.
    /// `fetch_slots` failures are propagated so the supervisor can restart.
    async fn catchup_blocks(
        &self,
        anchor_height: u64,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = (u64, SolanaCatchupBlock)> + Send + 'static>>>
    {
        // Get the last persisted processed block height from backlog
        // TODO: https://github.com/sig-net/mpc/issues/777
        let start_slot = self
            .state_manager
            .get_processed_block(Chain::Solana)
            .await
            .map(|n| n.saturating_add(1))
            .unwrap_or(anchor_height);
        let end_slot = anchor_height.saturating_sub(1); // We want to catch up to just before the anchor
        if start_slot > end_slot {
            return Ok(Box::pin(futures_util::stream::empty()));
        }

        // The error should be propagated, to let supervisor restart on error, otherwise
        // an empty stream is returned and catchup finishes without processing missing blocks.
        let slots = self.client.fetch_slots(start_slot, end_slot).await?;
        let remaining_slots: VecDeque<u64> = slots.into_iter().collect();

        let client = self.client.clone();
        let stream = futures_util::stream::unfold(
            (remaining_slots, client, VecDeque::new()),
            |state| async move {
                let (mut remaining_slots, client, mut current_chunk) = state;
                loop {
                    if let Some(block) = current_chunk.pop_front() {
                        return Some((block, (remaining_slots, client, current_chunk)));
                    }
                    if remaining_slots.is_empty() {
                        return None;
                    }

                    let chunk_slots: BTreeSet<u64> = remaining_slots
                        .drain(..std::cmp::min(MAX_CONCURRENT_CHUNK_SIZE, remaining_slots.len()))
                        .collect();

                    let blocks = client.fetch_blocks_for_slots(chunk_slots).await;
                    current_chunk = blocks.into_iter().collect();
                }
            },
        );

        Ok(Box::pin(stream))
    }

    async fn process_catchup_item(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        slot: u64,
        block: &SolanaCatchupBlock,
    ) -> anyhow::Result<()> {
        match block {
            SolanaCatchupBlock::Block(block) => self.process_block(events_tx, slot, block).await,
            SolanaCatchupBlock::Missing => {
                let block = self.client.get_block(slot).await?;
                self.process_block(events_tx, slot, &block).await
            }
        }
    }

    /// Retries `process_catchup_item` with `RETRY_DELAY` backoff until it
    /// succeeds or `cancel` fires.
    async fn process_catchup_retrying(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        slot: u64,
        block: &SolanaCatchupBlock,
        cancel: &CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                result = self.process_catchup_item(events_tx, slot, block) => {
                    match result {
                        Ok(()) => return,
                        Err(err) => {
                            tracing::warn!(?err, slot, "solana catchup block processing failed; retrying");
                        }
                    }
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(Self::RETRY_DELAY) => {}
            }
        }
    }

    /// Live phase: forward events produced by the live subscription until
    /// `cancel` fires or the producer terminates.
    async fn forward_live_events(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        live_rx: &mut mpsc::Receiver<ChainEvent>,
        cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                event = live_rx.recv() => event,
            };
            let Some(event) = event else {
                anyhow::bail!("solana live event producer terminated");
            };
            events_tx
                .send(event)
                .await
                .context("failed to forward live solana event")?;
        }
    }

    async fn process_block(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        height: u64,
        block: &UiConfirmedBlock,
    ) -> anyhow::Result<()> {
        // Update indexed block metrics
        self.telemetry.block_indexed(height);

        let Some(transactions) = &block.transactions else {
            events_tx.send(ChainEvent::Block(height)).await?;
            return Ok(());
        };

        for tx in transactions {
            let Some(logs) = tx
                .meta
                .as_ref()
                .and_then(|meta| match meta.log_messages.as_ref() {
                    OptionSerializer::Some(logs) => Some(logs),
                    _ => None,
                })
            else {
                continue;
            };

            let signature = extract_tx_signature(&tx.transaction)?;
            emit_events(events_tx, &self.program_id, signature, tx, logs).await?;
        }

        events_tx.send(ChainEvent::Block(height)).await?;
        Ok(())
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for SolanaIndexer<S, T> {
    const CHAIN: Chain = Chain::Solana;
    type Block = (u64, SolanaCatchupBlock);
    type Iter = Pin<Box<dyn Stream<Item = Self::Block> + Send + 'static>>;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Start the live subscription first: it buffers events while catchup
        // runs, and resolves the anchor slot once the WS is live so catchup
        // covers `[persisted_block, anchor)` with no gaps. The abort-on-drop
        // guard ties the task's lifetime to this `run()`.

        // TODO: live channel is bounded, if catchup takes too long live
        // channel will fill up and block subscription task, websocket connection will be closed.
        // Consider better solution.
        let (live_tx, mut live_rx) = chain_event_channel();
        let (anchor_tx, anchor_rx) = oneshot::channel::<u64>();
        let _live_task = AbortOnDrop(tokio::spawn(subscribe_and_buffer_live_events(
            self.program_id,
            self.client.clone(),
            live_tx,
            anchor_tx,
            self.telemetry.clone(),
        )));

        let anchor = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            anchor = anchor_rx => anchor.context("solana live subscription ended before resolving anchor slot")?,
        };

        let mut catchup_iter = self.catchup_blocks(anchor).await?;
        loop {
            let item = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                item = catchup_iter.next() => item,
            };
            let Some((slot, block)) = item else { break };
            self.process_catchup_retrying(&events_tx, slot, &block, &cancel)
                .await;
        }

        events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send catchup completed event")?;

        self.forward_live_events(&events_tx, &mut live_rx, &cancel)
            .await
    }
}

pub enum SolanaSignEvent {
    SignatureRequested(SignatureRequestedEvent),
    SignBidirectional(SignBidirectionalEvent),
}

impl SolanaSignEvent {
    fn is_valid(&self, sign_id: SignId) -> bool {
        let (deposit, key_version) = match self {
            SolanaSignEvent::SignatureRequested(ev) => (ev.deposit, ev.key_version),
            SolanaSignEvent::SignBidirectional(ev) => (ev.deposit, ev.key_version),
        };

        if deposit == 0 {
            tracing::warn!(?sign_id, "deposit is 0, skipping sign request");
            return false;
        }

        if key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!(?sign_id, "unsupported key version: {}", key_version);
            return false;
        }

        true
    }

    pub fn generate_request_id(&self) -> [u8; 32] {
        match self {
            SolanaSignEvent::SignatureRequested(ev) => compute_request_id(
                &ev.sender.to_string(),
                &ev.payload,
                &ev.path,
                ev.key_version,
                &ev.chain_id,
                &ev.algo,
                &ev.dest,
                &ev.params,
            ),
            SolanaSignEvent::SignBidirectional(ev) => {
                let encoded = (
                    ev.sender.to_string(),
                    ev.serialized_transaction.clone(),
                    ev.caip2_id.clone(),
                    ev.key_version,
                    ev.path.clone(),
                    ev.algo.clone(),
                    ev.dest.clone(),
                    ev.params.clone(),
                )
                    .abi_encode_packed();

                keccak::hash(&encoded).to_bytes()
            }
        }
    }

    pub fn generate_sign_request(&self, entropy: [u8; 32]) -> Option<IndexedSignRequest> {
        let sign_id = SignId::new(self.generate_request_id());
        if !self.is_valid(sign_id) {
            return None;
        }

        match self {
            SolanaSignEvent::SignatureRequested(ev) => {
                let payload = Scalar::from_bytes(ev.payload).or_else(|| {
                    tracing::warn!(
                        ?sign_id,
                        "solana `sign` did not produce payload hash correctly: {:?}",
                        ev.payload,
                    );
                    None
                })?;

                if payload > *MAX_SECP256K1_SCALAR {
                    tracing::warn!(?sign_id, ?payload, "payload exceeds secp256k1 curve order");
                    return None;
                }

                tracing::info!(?sign_id, "solana signature requested");
                let epsilon = derive_epsilon_sol(ev.key_version, &ev.sender.to_string(), &ev.path);
                Some(IndexedSignRequest::sign(
                    sign_id,
                    SignArgs {
                        entropy,
                        epsilon,
                        payload,
                        path: ev.path.clone(),
                        key_version: ev.key_version,
                    },
                    Chain::Solana,
                    current_unix_timestamp(),
                ))
            }
            SolanaSignEvent::SignBidirectional(ev) => {
                let epsilon = derive_epsilon_sol(ev.key_version, &ev.sender.to_string(), &ev.path);
                tracing::info!(?sign_id, "solana bidirectional signature requested");
                let unsigned_tx_hash = hash_payload(&ev.serialized_transaction);
                let payload = Scalar::from_bytes(unsigned_tx_hash)?;

                if payload > *MAX_SECP256K1_SCALAR {
                    tracing::warn!(?payload, "payload exceeds secp256k1 curve order");
                    return None;
                }

                Some(IndexedSignRequest::sign_bidirectional(
                    sign_id,
                    SignArgs {
                        entropy,
                        epsilon,
                        payload,
                        path: ev.path.clone(),
                        key_version: ev.key_version,
                    },
                    Chain::Solana,
                    current_unix_timestamp(),
                    mpc_primitives::SignBidirectionalEvent {
                        sender: ev.sender.to_bytes(),
                        serialized_transaction: ev.serialized_transaction.clone(),
                        caip2_id: ev.caip2_id.clone(),
                        key_version: ev.key_version,
                        deposit: ev.deposit,
                        path: ev.path.clone(),
                        algo: ev.algo.clone(),
                        dest: ev.dest.clone(),
                        params: ev.params.clone(),
                        output_deserialization_schema: ev.output_deserialization_schema.clone(),
                        respond_serialization_schema: ev.respond_serialization_schema.clone(),
                        chain: Chain::Solana,
                        chain_ctx: None,
                    },
                ))
            }
        }
    }

    fn build_sign_request(self, tx_sig: &[u8]) -> Option<IndexedSignRequest> {
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&tx_sig[..32]);
        self.generate_sign_request(entropy)
    }
}

/// Subscribe to the live WS feed, preprocess events into `ChainEvent`s, and buffer them
/// in `live_tx`. The anchor slot (current confirmed slot at subscription time) is sent
/// via `anchor_tx` so that `run()` can bound catchup with it.
///
/// The anchor is resolved inside `subscribe_to_program_events` immediately after the WS
/// subscription is established — ensuring the subscription is live before we anchor, so
/// catchup covers `[persisted_block, anchor)` with no gaps.
async fn subscribe_and_buffer_live_events<T: ChainTelemetry>(
    program_id: Pubkey,
    client: SolanaClient,
    live_tx: mpsc::Sender<ChainEvent>,
    anchor_tx: oneshot::Sender<u64>,
    telemetry: T,
) {
    let mut anchor_tx = Some(anchor_tx);
    loop {
        // TODO: if solana ever fails and needs to retry, we actually need to do catchup
        // again. This requires potentially complicating the coordination we have on the
        // high level of run_stream. Issue: https://github.com/sig-net/mpc/issues/811
        let result = subscribe_to_program_events(
            program_id,
            &client,
            live_tx.clone(),
            &mut anchor_tx,
            telemetry.clone(),
        )
        .await;

        if let Err(err) = result {
            tracing::warn!("Live solana subscription failed: {:?}", err);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

// TODO: move this to an events.rs file
// TODO: enhance to handle malformed events and prevent panic
fn parse_cpi_events(
    tx: &EncodedTransactionWithStatusMeta,
    target_program_id: &Pubkey,
) -> anyhow::Result<Vec<SolanaSignEvent>> {
    let Some(meta) = &tx.meta else {
        return Ok(Vec::new());
    };

    let target_program_str = target_program_id.to_string();
    let mut out = Vec::<SolanaSignEvent>::new();

    // Small helper closure to try decoding both event types from raw data
    let try_parse_events = |data: &str| -> anyhow::Result<Vec<SolanaSignEvent>> {
        let Ok(ix_data) = solana_sdk::bs58::decode(data).into_vec() else {
            tracing::warn!("Failed to decode instruction data for target program");
            return Ok(Vec::new());
        };

        // Ensure this is an Anchor emit_cpi! instruction
        if !ix_data.starts_with(anchor_lang::event::EVENT_IX_TAG_LE) {
            return Ok(Vec::new());
        }

        let event_discriminator = &ix_data[8..16];
        let event_data = &ix_data[16..];

        let mut acc = Vec::new();

        // handle both event types
        if event_discriminator == SignatureRequestedEvent::DISCRIMINATOR {
            match SignatureRequestedEvent::deserialize(&mut &event_data[..]) {
                Ok(ev) => acc.push(SolanaSignEvent::SignatureRequested(ev)),
                Err(e) => tracing::warn!("Failed to deserialize SignatureRequestedEvent: {e}"),
            }
        } else if event_discriminator == SignBidirectionalEvent::DISCRIMINATOR {
            match <SignBidirectionalEvent as AnchorDeserialize>::deserialize(&mut &event_data[..]) {
                Ok(ev) => {
                    // caip2_id represents the mainnet CAIP-2 chain ID of the target chain
                    // we won't process the event if the caip2_id is invalid, since it won't be able to be handled correctly downstream anyway
                    if let Err(e) = Chain::from_caip2_chain_id(&ev.caip2_id) {
                        tracing::warn!("invalid caip2 chain id in sign bidirectional event: {e:?}")
                    } else {
                        acc.push(SolanaSignEvent::SignBidirectional(ev))
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to deserialize SignBidirectionalEvent: {e}")
                }
            }
        }

        Ok(acc)
    };

    // Look into inner instructions for CPI calls
    let inner_ixs = match &meta.inner_instructions {
        OptionSerializer::Some(ixs) => ixs,
        _ => return Ok(Vec::new()),
    };

    for (set_idx, inner_ix_set) in inner_ixs.iter().enumerate() {
        for (ix_idx, instruction) in inner_ix_set.instructions.iter().enumerate() {
            if let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ui)) = instruction {
                if ui.program_id == target_program_str {
                    match try_parse_events(&ui.data) {
                        Ok(mut v) => {
                            if !v.is_empty() {
                                tracing::info!(
                                    "parsed {} event(s) from {}.{}",
                                    v.len(),
                                    set_idx,
                                    ix_idx
                                );
                            }
                            out.append(&mut v);
                        }
                        Err(e) => tracing::warn!(
                            "Error processing inner instruction {}.{}: {}",
                            set_idx,
                            ix_idx,
                            e
                        ),
                    }
                }
            }
        }
    }

    Ok(out)
}

async fn subscribe_to_program_events<T: ChainTelemetry>(
    program_id: Pubkey,
    client: &SolanaClient,
    events_tx: mpsc::Sender<ChainEvent>,
    anchor_tx: &mut Option<oneshot::Sender<u64>>,
    telemetry: T,
) -> anyhow::Result<()> {
    let pubsub_client = PubsubClient::new(&client.rpc_ws_url).await?;

    let filter = RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]);
    let config = RpcTransactionLogsConfig {
        commitment: Some(CommitmentConfig::confirmed()),
    };

    let (mut stream, _unsubscriber) = pubsub_client.logs_subscribe(filter, config).await?;

    // The WS subscription is now live. Fetch the current confirmed slot via RPC as the
    // anchor: this is the correct boundary because the subscription is already buffering
    // all new events, so catchup can safely cover [persisted_block, anchor) via RPC history
    // with no gaps. We do not wait for the first WS event because that could deadlock if
    // no program-mentioning transactions arrive (e.g. in tests after a single sign call).
    if let Some(anchor_tx) = anchor_tx.take() {
        // TODO: this should probably use client.get_slot with retry strategy,
        // otherwise if RPC fails the anchor will not be sent and catchup will not run
        match client
            .rpc_client
            .get_slot_with_commitment(CommitmentConfig::confirmed())
            .await
        {
            Ok(slot) => {
                let _ = anchor_tx.send(slot);
            }
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to fetch anchor slot after WS subscribe; retry on reconnect"
                );
                // Drop anchor_tx — livestream() will receive a RecvError and propagate the failure.
            }
        }
    }

    // stall watchdog
    let stall_timeout = Duration::from_secs(60);
    let mut last_ws_msg = Instant::now();
    let mut watchdog = tokio::time::interval(Duration::from_secs(5));

    // Mirrors `wait_for_finalized_block`'s staleness warn in the Ethereum indexer
    const SLOT_STALL_WARN_SECS: u64 = 60;
    let mut last_slot: Option<u64> = None;
    let mut last_slot_advanced_at = Instant::now();
    let mut last_slot_stall_warn_at = Instant::now();

    // Simple TTL cache to avoid multiple getTransaction calls for the same signature
    let mut seen: HashMap<Signature, Instant> = HashMap::new();
    let ttl = Duration::from_secs(30);

    let program_invoke_log = format!("Program {program_id} invoke [");

    loop {
        // TODO: this might introduce CPU overhead if the WS is busy, consider a more efficient alternative
        cleanup_seen_cache(&mut seen, ttl);
        tokio::select! {
            // Receive WS logs
            maybe = stream.next() => {
                match maybe {
                    Some(response) => {
                        last_ws_msg = Instant::now();

                        let slot = response.context.slot;

                        // Update last observed slot and reset the stall timer if it advanced
                        if last_slot.is_none_or(|s| slot > s) {
                            last_slot = Some(slot);
                            last_slot_advanced_at = Instant::now();
                        }

                        // Update indexed block metrics
                        telemetry.block_indexed(slot);

                        let logs = &response.value.logs;
                        if response.value.err.is_some() || !has_log_starts_with(logs, &program_invoke_log) {
                            // block is not relevant to our program, skip but still
                            // emit block event for progress tracking
                            if let Err(err) = events_tx.send(ChainEvent::Block(slot)).await {
                                tracing::warn!(?err, "failed to send block event");
                            }
                            continue;
                        }

                        let Ok(signature) = Signature::from_str(&response.value.signature) else {
                            tracing::warn!("Invalid signature format");
                            continue;
                        };

                        if seen.contains_key(&signature) {
                            continue;
                        }

                        let tx_res = match client.get_tx(&signature).await {
                            Ok(tx) => tx,
                            Err(e) => {
                                tracing::warn!("Failed to fetch transaction {}: {}", signature, e);
                                continue;
                            }
                        };

                        let now = Instant::now();
                        seen.insert(signature, now);

                        if let Err(err) = emit_events(
                            &events_tx,
                            &program_id,
                            signature,
                            &tx_res.transaction,
                            logs,
                        )
                        .await
                        {
                            tracing::warn!(?err, sig = %signature, "failed to parse solana tx events");
                            continue;
                        }

                        // Emit block event for every observed slot
                        if let Err(err) = events_tx.send(ChainEvent::Block(slot)).await {
                            tracing::warn!(?err, "failed to send block event");
                        }
                    }
                    None => {
                        // stream ended => force reconnect
                        anyhow::bail!("solana logs stream ended (None), reconnecting");
                    }
                }
            }

            // Watchdog tick
            _ = watchdog.tick() => {
                if last_ws_msg.elapsed() > stall_timeout {
                    anyhow::bail!(
                        "solana logs subscription stalled: no ws message for {:?}",
                        stall_timeout
                    );
                }

                // Warn if the last observed slot has not advanced for a while
                let now = Instant::now();
                let secs_since_advance = now.duration_since(last_slot_advanced_at).as_secs();
                if secs_since_advance >= SLOT_STALL_WARN_SECS
                    && now.duration_since(last_slot_stall_warn_at).as_secs() >= SLOT_STALL_WARN_SECS
                {
                    tracing::warn!(
                        last_slot,
                        secs_since_advance,
                        "solana observed slot has not advanced; \
                         live feed may be stuck delivering stale slots. \
                         If this persists the stream watchdog will restart the pipeline"
                    );
                    last_slot_stall_warn_at = now;
                }
            }
        }
    }
}

fn looks_like_cpi_sign_event(logs: &[String]) -> bool {
    logs.iter()
        .any(|l| CPI_EVENT_HINTS.iter().any(|h| l.contains(h)))
}

fn looks_like_respond_event(logs: &[String]) -> bool {
    logs.iter()
        .any(|l| CPI_RESPOND_EVENT_HINTS.iter().any(|h| l.contains(h)))
}

fn has_log_starts_with(logs: &[String], start_with: &str) -> bool {
    logs.iter().any(|l| l.starts_with(start_with))
}

// TODO: move this to an events.rs file
// TODO: enhance to handle malformed events and prevent panic
fn parse_cpi_respond_events(
    tx: &EncodedTransactionWithStatusMeta,
    target_program_id: &Pubkey,
) -> anyhow::Result<(Vec<RespondBidirectionalEvent>, Vec<SignatureRespondedEvent>)> {
    use solana_transaction_status::{UiInstruction, UiParsedInstruction};

    let Some(meta) = &tx.meta else {
        return Ok((Vec::new(), Vec::new()));
    };

    let target_program_str = target_program_id.to_string();
    let mut respond_bidirectional_events = Vec::<RespondBidirectionalEvent>::new();
    let mut signature_responded_events = Vec::<SignatureRespondedEvent>::new();

    // Helper closure to try decoding RespondBidirectionalEvent and SignatureRespondedEvent from raw data
    let try_parse_respond_event = |data: &str| -> anyhow::Result<(
        Vec<RespondBidirectionalEvent>,
        Vec<SignatureRespondedEvent>,
    )> {
        let Ok(ix_data) = solana_sdk::bs58::decode(data).into_vec() else {
            tracing::warn!("Failed to decode instruction data for target program");
            return Ok((Vec::new(), Vec::new()));
        };

        // Ensure this is an Anchor event instruction
        if !ix_data.starts_with(anchor_lang::event::EVENT_IX_TAG_LE) {
            return Ok((Vec::new(), Vec::new()));
        }

        let event_discriminator = &ix_data[8..16];
        let event_data = &ix_data[16..];

        let mut respond_bdx = Vec::new();
        let mut sig_resp = Vec::new();

        // Handle RespondBidirectionalEvent
        if event_discriminator == RespondBidirectionalEvent::DISCRIMINATOR {
            match RespondBidirectionalEvent::deserialize(&mut &event_data[..]) {
                Ok(ev) => respond_bdx.push(ev),
                Err(e) => {
                    tracing::warn!("Failed to deserialize RespondBidirectionalEvent: {e}")
                }
            }
        }

        // Handle SignatureRespondedEvent
        if event_discriminator == SignatureRespondedEvent::DISCRIMINATOR {
            match SignatureRespondedEvent::deserialize(&mut &event_data[..]) {
                Ok(ev) => sig_resp.push(ev),
                Err(e) => {
                    tracing::warn!("Failed to deserialize SignatureRespondedEvent: {e}")
                }
            }
        }

        Ok((respond_bdx, sig_resp))
    };

    // Look into inner instructions for CPI calls
    let inner_ixs = match &meta.inner_instructions {
        OptionSerializer::Some(ixs) => ixs,
        _ => return Ok((Vec::new(), Vec::new())),
    };

    for (set_idx, inner_ix_set) in inner_ixs.iter().enumerate() {
        for (ix_idx, instruction) in inner_ix_set.instructions.iter().enumerate() {
            if let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ui)) = instruction {
                if ui.program_id == target_program_str {
                    match try_parse_respond_event(&ui.data) {
                        Ok((mut r_bdx, mut s_resp)) => {
                            if !r_bdx.is_empty() {
                                tracing::info!(
                                    "parsed {} RespondBidirectionalEvent(s) from {}.{}",
                                    r_bdx.len(),
                                    set_idx,
                                    ix_idx
                                );
                            }
                            if !s_resp.is_empty() {
                                tracing::info!(
                                    "parsed {} SignatureRespondedEvent(s) from {}.{}",
                                    s_resp.len(),
                                    set_idx,
                                    ix_idx
                                );
                            }
                            respond_bidirectional_events.append(&mut r_bdx);
                            signature_responded_events.append(&mut s_resp);
                        }
                        Err(e) => tracing::warn!(
                            "Error processing inner instruction {}.{}: {}",
                            set_idx,
                            ix_idx,
                            e
                        ),
                    }
                }
            }
        }
    }

    Ok((respond_bidirectional_events, signature_responded_events))
}

// TODO: move this to an events.rs file
enum SolanaEvents {
    Sign(Vec<SolanaSignEvent>),
    Respond {
        bidirectional: Vec<RespondBidirectionalEvent>,
        responded: Vec<SignatureRespondedEvent>,
    },
    None,
}

impl SolanaEvents {
    fn parse(
        tx: &EncodedTransactionWithStatusMeta,
        target_program_id: &Pubkey,
        logs: &[String],
    ) -> anyhow::Result<Self> {
        if looks_like_cpi_sign_event(logs) {
            Ok(SolanaEvents::Sign(parse_cpi_events(tx, target_program_id)?))
        } else if looks_like_respond_event(logs) {
            let (bidirectional, responded) = parse_cpi_respond_events(tx, target_program_id)?;
            Ok(SolanaEvents::Respond {
                bidirectional,
                responded,
            })
        } else {
            Ok(SolanaEvents::None)
        }
    }
}

async fn emit_events(
    events_tx: &mpsc::Sender<ChainEvent>,
    program_id: &Pubkey,
    signature: Signature,
    tx: &EncodedTransactionWithStatusMeta,
    logs: &[String],
) -> anyhow::Result<()> {
    match SolanaEvents::parse(tx, program_id, logs)? {
        SolanaEvents::Sign(events) => {
            let sig_bytes = signature.as_ref().to_vec();
            for ev in events {
                if let Some(request) = ev.build_sign_request(&sig_bytes) {
                    // `signature` is the Solana transaction signature, i.e. the tx hash
                    // shown in explorers and used as the getTransaction lookup key. Log it
                    // next to the sign_id so a given tx can be matched to its request.
                    tracing::info!(
                        tx_hash = %signature,
                        sign_id = ?request.id,
                        "solana sign request parsed",
                    );
                    events_tx
                        .send(ChainEvent::SignRequest {
                            request,
                            block_timestamp: None,
                        })
                        .await?;
                }
            }
        }
        SolanaEvents::Respond {
            bidirectional,
            responded,
        } => {
            for ev in bidirectional {
                let signature =
                    to_mpc_signature(&ev.signature).context("failed to parse Solana signature")?;
                let _ = events_tx
                    .send(ChainEvent::RespondBidirectional(
                        mpc_primitives::RespondBidirectionalEvent {
                            request_id: ev.request_id,
                            signature,
                            chain: Chain::Solana,
                        },
                    ))
                    .await;
            }

            for ev in responded {
                let signature =
                    to_mpc_signature(&ev.signature).context("failed to parse Solana signature")?;
                let _ = events_tx
                    .send(ChainEvent::Respond(
                        mpc_primitives::SignatureRespondedEvent {
                            request_id: ev.request_id,
                            signature,
                            chain: Chain::Solana,
                        },
                    ))
                    .await;
            }
        }
        SolanaEvents::None => {}
    }
    Ok(())
}

fn extract_tx_signature(tx: &EncodedTransaction) -> anyhow::Result<Signature> {
    match tx {
        EncodedTransaction::Json(ui_tx) => {
            let signature = ui_tx
                .signatures
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing signature in block transaction"))?;
            Signature::from_str(signature)
                .map_err(|err| anyhow::anyhow!(err).context("failed to parse block signature"))
        }
        other => {
            anyhow::bail!("unsupported encoded transaction variant in block catchup: {other:?}")
        }
    }
}

// Clean up seen cache based on TTL
fn cleanup_seen_cache(seen: &mut HashMap<Signature, Instant>, ttl: Duration) {
    let now = Instant::now();
    seen.retain(|_, &mut t| now.duration_since(t) < ttl);
}

pub fn to_mpc_signature(
    sig: &signet_program::Signature,
) -> anyhow::Result<mpc_primitives::Signature> {
    // Create a 65-byte uncompressed point representation (0x04 || x || y)
    let mut big_r = [0u8; 65];
    big_r[0] = 0x04;
    big_r[1..33].copy_from_slice(&sig.big_r.x);
    big_r[33..65].copy_from_slice(&sig.big_r.y);

    let big_r = k256::EncodedPoint::from_bytes(big_r)
        .map_err(|err| anyhow::anyhow!("unable to parse big_r for encoded point: {err}"))?;
    let big_r_ct_opt = AffinePoint::from_encoded_point(&big_r);
    let big_r = big_r_ct_opt
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("failed to create AffinePoint from encoded point"))?;

    let s = Scalar::from_bytes(sig.s)
        .ok_or_else(|| anyhow::anyhow!("failed to create Scalar from s bytes"))?;

    Ok(mpc_primitives::Signature {
        big_r,
        s,
        recovery_id: sig.recovery_id,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
    use solana_sdk::commitment_config::CommitmentLevel;
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status::{
        TransactionDetails, UiTransactionEncoding, UiTransactionStatusMeta,
    };

    /// Create a test indexer with a mock state manager and a given RPC URL.
    fn test_indexer(
        url: &str,
        state_manager: MockStateManager,
    ) -> SolanaIndexer<MockStateManager, NoopChainTelemetry> {
        let program_id = Pubkey::new_unique();
        let client = SolanaClient::for_indexer(
            url.to_string(),
            url.replace("http", "ws"),
            program_id,
            Arc::new(NoopPublisherTelemetry),
        )
        .with_fast_retry();
        SolanaIndexer {
            program_id,
            client,
            state_manager,
            telemetry: NoopChainTelemetry,
        }
    }

    /// Create a mock signature entry for testing, with a given slot.
    fn signature_entry(slot: u64) -> serde_json::Value {
        serde_json::json!({
            "signature": Signature::new_unique().to_string(),
            "slot": slot,
            "err": null,
            "memo": null,
            "blockTime": null,
            "confirmationStatus": "confirmed"
        })
    }

    /// Create a mock JSON-RPC response for a list of signature entries.
    fn signatures_response(entries: &[serde_json::Value]) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": entries
        })
        .to_string()
    }

    /// Create a mock JSON-RPC response for a block at a given slot.
    fn block_response(id: usize, slot: u64) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "result": {
                "blockHeight": slot,
                "blockTime": null,
                "blockhash": "11111111111111111111111111111111",
                "parentSlot": slot.saturating_sub(1),
                "previousBlockhash": "11111111111111111111111111111111",
                "transactions": [],
                "rewards": []
            }
        })
    }

    #[test]
    fn request_id_matches_ethabi() {
        let event = SignatureRequestedEvent {
            sender: Pubkey::new_from_array([0x11; 32]),
            payload: [0x22; 32],
            key_version: 7,
            deposit: 12345,
            chain_id: "solana-test-chain".to_string(),
            path: "m/44'/501'/0'/0'".to_string(),
            algo: "secp256k1".to_string(),
            dest: "destination-address".to_string(),
            params: "params-json".to_string(),
            fee_payer: None,
        };

        assert_eq!(
            hex::encode(SolanaSignEvent::SignatureRequested(event).generate_request_id()),
            "7f7aee49c2a994cc17f85058f7e0b19a44603d619a7e738522f9aa329e457879"
        );
    }

    #[test]
    fn block_fetch_config_sets_max_supported_transaction_version() {
        let config = SolanaClient::block_fetch_config();

        assert_eq!(config.max_supported_transaction_version, Some(0));
        assert_eq!(config.transaction_details, Some(TransactionDetails::Full));
        assert_eq!(config.encoding, Some(UiTransactionEncoding::Json));
        assert_eq!(config.rewards, Some(false));
        assert_eq!(
            config.commitment.map(|commitment| commitment.commitment),
            Some(CommitmentLevel::Confirmed)
        );
    }

    #[test]
    fn btree_extend_preserves_slot_order_for_catchup() {
        let mut from_signatures = BTreeMap::new();
        from_signatures.insert(10_u64, SolanaCatchupBlock::Missing);
        from_signatures.insert(12_u64, SolanaCatchupBlock::Missing);

        let mut from_sparse = BTreeMap::new();
        from_sparse.insert(8_u64, SolanaCatchupBlock::Missing);
        from_sparse.insert(9_u64, SolanaCatchupBlock::Missing);

        from_signatures.extend(from_sparse);

        let slots: Vec<_> = from_signatures.into_keys().collect();
        assert_eq!(slots, vec![8, 9, 10, 12]);
    }

    /// Check we can still parse the old format for failed transactions.
    ///
    /// Note that there are some SDK versions that can parse the new format but
    /// not the new, and other versions that have the opposite problem.
    /// See: https://github.com/anza-xyz/solana-sdk/pull/410
    /// and https://github.com/anza-xyz/solana-sdk/issues/394
    ///
    /// We want a version that can parse both.
    #[test]
    fn transaction_error_borsh_io_error_object_deserialization() {
        // Exact error shape returned _before_ Solana 4.0 RPC for a failed transaction.
        let json = r#"{"InstructionError": [0, { "BorshIoError": "Reason for the error" }]}"#;
        let result: std::result::Result<solana_sdk::transaction::TransactionError, _> =
            serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "BorshIoError unit-variant deserialization failed: {:?}",
            result.err()
        );
    }

    /// Check we can parse the new format for failed transactions.
    ///
    /// Note that there are some SDK versions that can parse the new format but
    /// not the new, and other versions that have the opposite problem.
    /// See: https://github.com/anza-xyz/solana-sdk/pull/410
    /// and https://github.com/anza-xyz/solana-sdk/issues/394
    ///
    /// We want a version that can parse both.
    #[test]
    fn transaction_error_borsh_io_error_unit_variant_deserialization() {
        // Exact error shape returned by Solana 4.0 RPC for a failed transaction.
        let json = r#"{"InstructionError": [0, "BorshIoError"]}"#;
        let result: std::result::Result<solana_sdk::transaction::TransactionError, _> =
            serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "BorshIoError unit-variant deserialization failed: {:?}",
            result.err()
        );
    }

    /// Regression test for being able to deserialize devnet slot 466737912 (TX
    /// index 32).
    ///
    /// This is the exact UiTransactionStatusMeta captured from the devnet slot.
    /// It got the SOL indexer stuck as reported in
    /// https://github.com/sig-net/mpc/issues/844.
    #[test]
    fn ui_transaction_meta_with_borsh_io_error_deserializes() {
        let meta_json = r#"{
            "err": {"InstructionError": [0, "BorshIoError"]},
            "status": {"Err": {"InstructionError": [0, "BorshIoError"]}},
            "fee": 5000,
            "preBalances":  [1130764920,0,0,1,1461600,1003361680,1141440,0,1009200,12051573357],
            "postBalances": [1130759920,0,0,1,1461600,1003361680,1141440,0,1009200,12051573357],
            "innerInstructions": [],
            "logMessages": [
                "Program 3kjK4HA6A4K86NgNB93gGhSt257wtN4QAqXMNPQ4fVTm invoke [1]",
                "Program log: Instruction 12: WithdrawFromFeeAccount",
                "Program 3kjK4HA6A4K86NgNB93gGhSt257wtN4QAqXMNPQ4fVTm consumed 5299 of 200000 compute units",
                "Program 3kjK4HA6A4K86NgNB93gGhSt257wtN4QAqXMNPQ4fVTm failed: Failed to serialize or deserialize account data"
            ],
            "preTokenBalances": [],
            "postTokenBalances": [],
            "rewards": null,
            "loadedAddresses": {"readonly": [], "writable": []},
            "computeUnitsConsumed": 5299
        }"#;

        let result: std::result::Result<UiTransactionStatusMeta, _> =
            serde_json::from_str(meta_json);
        assert!(
            result.is_ok(),
            "UiTransactionStatusMeta with BorshIoError failed to deserialize: {:?}",
            result.err()
        );
        let meta = result.unwrap();
        assert!(meta.err.is_some(), "expected err to be set");
    }

    #[tokio::test]
    async fn catchup_blocks_empty_when_up_to_date() {
        let server = mockito::Server::new_async().await;
        let indexer = test_indexer(&server.url(), MockStateManager::new());
        const ANCHOR_SLOT: u64 = 10;

        // No processed block persisted: start == anchor, so no catchup and no RPC calls.
        let mut stream = indexer.catchup_blocks(ANCHOR_SLOT).await.unwrap();
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn catchup_blocks_propagates_fetch_slots_error() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .expect(3) // 1 attempt + 2 retries (fast retry config)
            .create_async()
            .await;

        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 5).await;
        let indexer = test_indexer(&server.url(), state_manager);

        let result = indexer.catchup_blocks(10).await;
        assert!(result.is_err(), "fetch_slots error should propagate");
    }

    #[tokio::test]
    async fn catchup_processes_slots_in_order() {
        let mut server = mockito::Server::new_async().await;

        // Signatures walk back from the anchor: slots 9..=6 are in range,
        // slot 5 (< start_slot 6) terminates the walk.
        let entries: Vec<_> = [9, 8, 7, 6, 5].into_iter().map(signature_entry).collect();
        let _signatures = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                "getSignaturesForAddress".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&entries))
            .create_async()
            .await;

        let blocks = serde_json::json!([
            block_response(0, 6),
            block_response(1, 7),
            block_response(2, 8),
            block_response(3, 9),
        ])
        .to_string();
        let _blocks = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("getBlock".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(blocks)
            .create_async()
            .await;

        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 5).await;
        let indexer = test_indexer(&server.url(), state_manager);

        let (events_tx, mut events_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        let mut stream = indexer.catchup_blocks(10).await.unwrap();
        while let Some((slot, block)) = stream.next().await {
            indexer
                .process_catchup_retrying(&events_tx, slot, &block, &cancel)
                .await;
        }

        // Verify that the events were emitted in order
        for expected in 6..=9 {
            let event = events_rx.recv().await.unwrap();
            assert!(
                matches!(event, ChainEvent::Block(slot) if slot == expected),
                "expected Block({expected}), got {event:?}"
            );
        }
    }

    // TODO: do we need live event channel?
    #[tokio::test]
    async fn forward_live_events_forwards_until_cancel() {
        let indexer = test_indexer("http://localhost:1", MockStateManager::new());
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (live_tx, mut live_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        live_tx.send(ChainEvent::Block(42)).await.unwrap();

        let mut forward = Box::pin(indexer.forward_live_events(&events_tx, &mut live_rx, &cancel));
        tokio::select! {
            result = &mut forward => panic!("forwarding ended early: {result:?}"),
            event = events_rx.recv() => {
                assert!(matches!(event, Some(ChainEvent::Block(42))));
            }
        }

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), &mut forward)
            .await
            .expect("forwarding should stop promptly on cancel")
            .unwrap();
    }

    #[tokio::test]
    async fn forward_live_events_bails_when_producer_drops() {
        let indexer = test_indexer("http://localhost:1", MockStateManager::new());
        let (events_tx, _events_rx) = mpsc::channel(16);
        let (live_tx, mut live_rx) = mpsc::channel::<ChainEvent>(16);
        drop(live_tx);

        let result = indexer
            .forward_live_events(&events_tx, &mut live_rx, &CancellationToken::new())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn process_catchup_retrying_stops_on_cancel() {
        // No mock: any RPC attempt fails after fast retries; cancel must
        // interrupt the retry loop without waiting for it.
        let indexer = test_indexer("http://localhost:1", MockStateManager::new());
        let (events_tx, _events_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();
        cancel.cancel();

        tokio::time::timeout(
            Duration::from_secs(5),
            indexer.process_catchup_retrying(&events_tx, 7, &SolanaCatchupBlock::Missing, &cancel),
        )
        .await
        .expect("process_catchup_retrying should stop promptly on cancel");
    }

    // Very expensive test in terms of RPC usage.
    #[tokio::test]
    #[ignore]
    async fn test_solana_pipeline_devnet() {
        let _ = tracing_subscriber::fmt::try_init();

        let api_key = match std::env::var("MPC_TEST_API_KEY") {
            Ok(key) if !key.is_empty() => key,
            _ => {
                tracing::debug!("Skipping devnet test: MPC_TEST_API_KEY not set");
                return;
            }
        };

        let sol_addr = std::env::var("MPC_TEST_SOL_ADDR")
            .unwrap_or_else(|_| "SigDuEPNeDjh3oJv7MUraPN7zaTFomS6ZWfpXwjUg4B".to_string());

        let http_url = format!("https://solana-devnet.g.alchemy.com/v2/{api_key}");
        let ws_url = format!("wss://solana-devnet.g.alchemy.com/v2/{api_key}");

        let state_manager = MockStateManager::new();
        let (events_tx, mut events_rx) = mpsc::channel(1_000_000);

        let client = SolanaClient::for_indexer(
            http_url.clone(),
            ws_url.clone(),
            Pubkey::from_str(&sol_addr).unwrap(),
            Arc::new(NoopPublisherTelemetry),
        );

        let indexer = SolanaIndexer {
            program_id: Pubkey::from_str(&sol_addr).unwrap(),
            client,
            state_manager,
            telemetry: NoopChainTelemetry,
        };

        // Resolve anchor slot
        let anchor_height = indexer
            .client
            .get_slot()
            .await
            .expect("Failed to fetch current slot");

        tracing::debug!("Resolved anchor slot: {anchor_height}");

        // Start from a checkpoint ~1 week behind (assuming ~2.5 slots per second => 1,512,000 slots per week)
        let start_slot = anchor_height.saturating_sub(1_512_000);
        tracing::debug!("Starting catchup from slot: {start_slot} (~1 week behind)");

        indexer
            .state_manager
            .set_processed_block(Chain::Solana, start_slot.saturating_sub(1))
            .await;

        // Start the indexer in a separate task
        let cancel = CancellationToken::new();
        let run_handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { indexer.run(events_tx, cancel).await }
        });

        // Drain events until catchup completes
        loop {
            match events_rx.recv().await {
                Some(ChainEvent::CatchupCompleted) => {
                    tracing::debug!("Solana catchup complete");
                    break;
                }
                Some(event) => tracing::debug!("Received event: {:?}", event),
                None => break,
            }
        }

        cancel.cancel();
        run_handle.abort();
    }
}
