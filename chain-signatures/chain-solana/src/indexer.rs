use std::collections::BTreeSet;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::sol_types::SolValue;
use anchor_client::anchor_lang::AnchorDeserialize;
use anchor_lang::solana_program::keccak;
use anchor_lang::Discriminator;
use anyhow::Context;
use async_trait::async_trait;
use futures_util::stream::{self, StreamExt};
use futures_util::Stream;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, Scalar};
use mpc_chain_integration_core::{
    utils::hashing::{compute_request_id, hash_payload},
    ChainIndexer, ChainTelemetry, NoopPublisherTelemetry, StateManager,
};
use mpc_crypto::kdf::derive_epsilon_sol;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, SignArgs, SignId, LATEST_MPC_KEY_VERSION,
    MAX_SECP256K1_SCALAR,
};
use mpc_utils::{task::retry_until_ok, time::current_unix_timestamp};
use signet_program::{
    RespondBidirectionalEvent, SignBidirectionalEvent, SignatureRequestedEvent,
    SignatureRespondedEvent,
};
use solana_sdk::{pubkey::Pubkey, signature::Signature};
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{
    EncodedTransaction, EncodedTransactionWithStatusMeta, UiConfirmedBlock, UiInstruction,
    UiParsedInstruction,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::client::{SolanaCatchupBlock, CATCHUP_PAGE_SIZE};
use crate::{SolConfig, SolanaClient};

const CPI_EVENT_HINTS: &[&str] = &[
    "Program log: Instruction: Sign",
    "Program log: Instruction: SignBidirectional",
];

const CPI_RESPOND_EVENT_HINTS: &[&str] = &[
    "Program log: Instruction: Respond",
    "Program log: Instruction: RespondBidirectional",
];

/// Live polling configuration.
#[derive(Clone, Copy, Debug)]
struct PollingConfig {
    /// Delay between polling iterations once caught up.
    // TODO: make configurable (e.g. via `SolConfig`) so it can be tuned to RPC budget / latency needs.
    poll_interval: Duration,
    /// Maximum time to wait for the anchor slot to advance before bailing. This is a safety check against frozen RPC nodes.
    /// Supervisor watchdog is not enough because it only sees the last block event, which can be a heartbeat from a lagging replica.
    slot_stall_timeout: Duration,
}

impl Default for PollingConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(500),
            slot_stall_timeout: Duration::from_secs(60),
        }
    }
}

/// Per-run state for the indexer poll loop. 
/// Seeded once from persisted state (resume point), then advanced by drained ticks.
#[derive(Clone, Copy)]
struct PollState {
    /// Slot the next tick starts draining from
    // TODO: https://github.com/sig-net/mpc/issues/777
    next_start: u64,
    /// Highest anchor slot observed this run; `None` until the first tick.
    last_observed_slot: Option<u64>,
    /// When `last_observed_slot` last advanced.
    slot_last_advanced_at: Instant,
    /// Lowest slot that has been fully drained and emitted as a heartbeat. 
    heartbeat_floor: u64,
    /// Whether [`ChainEvent::CatchupCompleted`] has been emitted
    caught_up: bool,
}

impl PollState {
    /// Initialize from persisted state (resume point) or the current anchor slot if none exists.
    async fn resumed<S: StateManager>(state_manager: &S, seed_anchor: u64) -> Self {
        // The persisted watermark is the last fully drained slot, so the next tick starts at the next slot.
        let next_start = state_manager
            .get_processed_block(Chain::Solana)
            .await
            .map(|n| n.saturating_add(1))
            .unwrap_or(seed_anchor);

        Self {
            next_start,
            last_observed_slot: None,
            slot_last_advanced_at: Instant::now(),
            heartbeat_floor: 0,
            caught_up: false,
        }
    }

    /// Slot-stall watchdog: only a strictly greater anchor counts as progress
    /// Warns at half the budget, bails at the full budget so the supervisor
    /// restarts and surfaces the frozen node (The heartbeat keeps `Block`
    /// events flowing even on a frozen node, so the supervisor cannot detect
    /// this on its own)
    fn observe_anchor(self, anchor: u64, timeout: Duration) -> anyhow::Result<Self> {
        // Only a strictly greater anchor counts as progress
        match self.last_observed_slot {
            Some(prev) if anchor > prev => Ok(Self {
                last_observed_slot: Some(anchor),
                slot_last_advanced_at: Instant::now(),
                ..self
            }),
            // If the anchor has not advanced, check how long it has been stalled for
            Some(prev) => {
                let stalled_for = self.slot_last_advanced_at.elapsed();
                if stalled_for >= timeout {
                    anyhow::bail!(
                        "solana observed slot frozen at {prev} for {stalled_for:?}; \
                         bailing so the supervisor restarts and surfaces it"
                    );
                }
                if stalled_for >= timeout / 2 {
                    tracing::warn!(
                        last_slot = prev,
                        ?stalled_for,
                        "solana observed slot has not advanced; RPC node may be frozen"
                    );
                }
                Ok(self)
            }
            // If this is the first tick, seed the last observed slot so the watchdog has a baseline
            None => Ok(Self {
                last_observed_slot: Some(anchor),
                slot_last_advanced_at: Instant::now(),
                ..self
            }),
        }
    }

    /// Update the heartbeat floor and next start slot after a tick has drained to the anchor.
    fn drained(self, anchor: u64) -> (Self, Option<u64>) {
        // The heartbeat is the highest slot that has been fully drained and emitted as a `Block` event.
        let heartbeat = anchor.saturating_sub(1).max(self.heartbeat_floor);
        (
            Self {
                next_start: anchor,
                heartbeat_floor: heartbeat,
                caught_up: true,
                ..self
            },
            (heartbeat > 0).then_some(heartbeat),
        )
    }
}

pub struct SolanaIndexer<S: StateManager, T: ChainTelemetry> {
    program_id: Pubkey,
    client: SolanaClient,
    polling: PollingConfig,
    state_manager: S,
    telemetry: T,
}

type CatchupBlockItem = (u64, SolanaCatchupBlock);

impl<S: StateManager, T: ChainTelemetry> SolanaIndexer<S, T> {
    /// Delay between retries of transient RPC failures
    const RETRY_DELAY: Duration = Duration::from_millis(500);

    /// Current confirmed anchor slot, or `None` on cancellation.
    async fn next_anchor(&self, cancel: &CancellationToken) -> Option<anyhow::Result<u64>> {
        tokio::select! {
            _ = cancel.cancelled() => None,
            slot = self.client.get_slot_confirmed() => Some(
                slot.context("solana failed to fetch anchor slot")
            ),
        }
    }

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
            polling: PollingConfig::default(),
            state_manager,
            telemetry,
        })
    }

    /// Catchup items in `[start_slot, anchor)` fetched in chunks.
    /// `fetch_slots` failures are propagated so the supervisor can restart.
    async fn catchup_blocks(
        &self,
        anchor_height: u64,
        start_slot: u64,
    ) -> anyhow::Result<
        Pin<Box<dyn Stream<Item = anyhow::Result<CatchupBlockItem>> + Send + 'static>>,
    > {
        let end_slot = anchor_height.saturating_sub(1);
        if start_slot > end_slot {
            tracing::info!(anchor_slot = anchor_height, "solana catchup not required");
            return Ok(Box::pin(stream::empty()));
        }

        tracing::info!(
            anchor_slot = anchor_height,
            start_slot,
            end_slot,
            "solana catchup started"
        );

        let newest_first_pages =
            Self::paginate_slots(self.client.clone(), self.program_id, start_slot, end_slot);
        let ordered_pages = Self::order_and_chunk_pages(
            newest_first_pages,
            start_slot,
            end_slot,
            CATCHUP_PAGE_SIZE,
        );

        Ok(Self::fetch_blocks_for_pages(
            self.client.clone(),
            ordered_pages,
        ))
    }

    /// Collect newest-first signature pages and emit globally ascending,
    /// deduplicated slot chunks. Keeping this as a lazy stream lets the caller
    /// cancel catchup while signature pagination is still in progress.
    fn order_and_chunk_pages(
        pages: impl Stream<Item = anyhow::Result<BTreeSet<u64>>> + Send + 'static,
        start_slot: u64,
        end_slot: u64,
        chunk_size: usize,
    ) -> impl Stream<Item = anyhow::Result<BTreeSet<u64>>> + Send + 'static {
        stream::once(async move {
            futures_util::pin_mut!(pages);

            let started_at = Instant::now();
            let mut signature_pages = 0usize;
            let mut ordered_slots = BTreeSet::new();
            while let Some(page) = pages.next().await {
                signature_pages += 1;
                ordered_slots.extend(page?);
            }

            tracing::info!(
                start_slot,
                end_slot,
                signature_pages,
                unique_slots = ordered_slots.len(),
                elapsed = ?started_at.elapsed(),
                "solana catchup signature pagination complete"
            );

            Ok::<_, anyhow::Error>(Self::chunk_slots(ordered_slots, chunk_size))
        })
        .flat_map(|result| {
            let chunks: Vec<anyhow::Result<BTreeSet<u64>>> = match result {
                Ok(chunks) => chunks.into_iter().map(Ok).collect(),
                Err(err) => vec![Err(err)],
            };
            stream::iter(chunks)
        })
    }

    /// Split globally ordered slots into bounded, ascending chunks. Collecting
    /// all slot numbers first is necessary because Solana signature pages are
    /// returned newest-to-oldest, while request lifecycle events must be
    /// replayed oldest-to-newest.
    fn chunk_slots(slots: BTreeSet<u64>, chunk_size: usize) -> Vec<BTreeSet<u64>> {
        debug_assert!(chunk_size > 0, "catchup slot chunk size must be positive");

        slots.into_iter().fold(Vec::new(), |mut chunks, slot| {
            match chunks.last_mut() {
                Some(chunk) if chunk.len() < chunk_size => {
                    chunk.insert(slot);
                }
                _ => chunks.push(BTreeSet::from([slot])),
            }
            chunks
        })
    }

    /// Paginate `getSignaturesForAddress` backwards from the anchor, yielding
    /// pages of slots within `[start_slot, end_slot]`. Stops once the cursor
    /// walks past `start_slot` or the RPC runs dry.
    fn paginate_slots(
        client: SolanaClient,
        program_id: Pubkey,
        start_slot: u64,
        end_slot: u64,
    ) -> impl Stream<Item = anyhow::Result<BTreeSet<u64>>> {
        struct PageState {
            client: SolanaClient,
            program_id: Pubkey,
            start_slot: u64,
            end_slot: u64,
            cursor: Option<Signature>,
            finished: bool,
        }

        stream::unfold(
            PageState {
                client,
                program_id,
                start_slot,
                end_slot,
                cursor: None,
                finished: false,
            },
            |mut state| async move {
                if state.finished {
                    return None;
                }

                let batch = match state
                    .client
                    .fetch_signatures_from_latest(&state.program_id, state.cursor)
                    .await
                {
                    Ok(b) if b.is_empty() => return None,
                    Ok(b) => b,
                    Err(e) => {
                        state.finished = true;
                        return Some((Err(e), state));
                    }
                };

                state.cursor = batch
                    .last()
                    .and_then(|s| Signature::from_str(&s.signature).ok());
                if state.cursor.is_none() {
                    state.finished = true;
                }

                let mut slots = BTreeSet::new();
                for sig in batch {
                    if sig.slot < state.start_slot {
                        state.finished = true;
                    } else if sig.slot <= state.end_slot {
                        slots.insert(sig.slot);
                    }
                }

                Some((Ok(slots), state))
            },
        )
    }

    /// Fetch blocks for each page of slots and flatten into a stream of `(slot, block)` items.
    fn fetch_blocks_for_pages(
        client: SolanaClient,
        pages: impl Stream<Item = anyhow::Result<BTreeSet<u64>>> + Send + 'static,
    ) -> Pin<Box<dyn Stream<Item = anyhow::Result<CatchupBlockItem>> + Send + 'static>> {
        let stream = pages
            .filter_map(|res| async move {
                match res {
                    Ok(slots) if slots.is_empty() => None,
                    Ok(slots) => Some(Ok(slots)),
                    Err(e) => Some(Err(e)),
                }
            })
            // This must remain sequential and order-preserving: lifecycle
            // events in older slots must reach the backlog before newer ones.
            // Using buffer_unordered here would undo global slot ordering.
            .then(move |res| {
                let client = client.clone();
                async move {
                    let slots = res?;
                    let mut blocks = client.fetch_blocks_for_slots(slots.clone()).await;
                    let items: Vec<CatchupBlockItem> = slots
                        .into_iter()
                        .map(|s| {
                            let block = blocks.remove(&s).unwrap_or(SolanaCatchupBlock::Missing);
                            (s, block)
                        })
                        .collect();
                    Ok::<_, anyhow::Error>(items)
                }
            })
            .map(|res| match res {
                Ok(items) => {
                    let stream_items: Vec<anyhow::Result<CatchupBlockItem>> =
                        items.into_iter().map(Ok).collect();
                    stream::iter(stream_items)
                }
                Err(e) => stream::iter(vec![Err(e)]),
            })
            .flatten();

        Box::pin(stream)
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
        retry_until_ok(
            cancel,
            Self::RETRY_DELAY,
            &format!("solana catchup block processing (slot {slot})"),
            || async { self.process_catchup_item(events_tx, slot, block).await },
        )
        .await;
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

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Seed the resume point before entering the loop
        let Some(seed) = self.next_anchor(&cancel).await else {
            return Ok(());
        };
        let mut state = PollState::resumed(&self.state_manager, seed?).await;

        loop {
            let Some(res) = self.next_anchor(&cancel).await else {
                return Ok(());
            };
            let anchor = res?;
            state = state.observe_anchor(anchor, self.polling.slot_stall_timeout)?;

            let tick_started_at = Instant::now();
            let mut catchup_iter = self
                .catchup_blocks(anchor, state.next_start)
                .await?;
            loop {
                let item = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    item = catchup_iter.next() => item,
                };
                let Some(res) = item else { break };
                // Propagate RPC page errors so supervisor restarts cleanly
                let (slot, block) = res?;
                self.process_catchup_retrying(&events_tx, slot, &block, &cancel)
                    .await;
            }

            let was_caught_up = state.caught_up;
            let (next_state, heartbeat) = state.drained(anchor);
            state = next_state;

            if let Some(height) = heartbeat {
                events_tx
                    .send(ChainEvent::Block(height))
                    .await
                    .context("failed to send heartbeat block event")?;
            }

            if !was_caught_up {
                tracing::info!(
                    anchor_slot = anchor,
                    elapsed = ?tick_started_at.elapsed(),
                    "solana catchup complete"
                );
                events_tx
                    .send(ChainEvent::CatchupCompleted)
                    .await
                    .context("failed to send catchup completed event")?;
            } else {
                tracing::debug!(
                    anchor_slot = anchor,
                    elapsed = ?tick_started_at.elapsed(),
                    "solana poll iteration complete"
                );
            }

            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep(self.polling.poll_interval) => {}
            }
        }
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

/// Split an Anchor `emit_cpi!` event instruction payload into its 8-byte event
/// discriminator and the trailing borsh-encoded event bytes.
///
/// Returns `None` when the data should not be parsed as an event: either it
/// lacks the 8-byte Anchor event tag, or it is too short to also contain the
/// discriminator. The length guard is what prevents an out-of-bounds panic on
/// malformed (e.g. attacker-crafted) instruction data — `starts_with` only
/// guarantees the first 8 bytes, but the split needs at least 16.
fn split_cpi_event(ix_data: &[u8]) -> Option<(&[u8], &[u8])> {
    if !ix_data.starts_with(anchor_lang::event::EVENT_IX_TAG_LE) {
        return None;
    }
    if ix_data.len() < 16 {
        tracing::warn!(
            len = ix_data.len(),
            "CPI event instruction data too short; skipping"
        );
        return None;
    }
    Some((&ix_data[8..16], &ix_data[16..]))
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

        // Split into the 8-byte event discriminator and trailing event bytes,
        // skipping anything that isn't a well-formed Anchor event instruction.
        let Some((event_discriminator, event_data)) = split_cpi_event(&ix_data) else {
            return Ok(Vec::new());
        };

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

fn looks_like_cpi_sign_event(logs: &[String]) -> bool {
    logs.iter()
        .any(|l| CPI_EVENT_HINTS.iter().any(|h| l.contains(h)))
}

fn looks_like_respond_event(logs: &[String]) -> bool {
    logs.iter()
        .any(|l| CPI_RESPOND_EVENT_HINTS.iter().any(|h| l.contains(h)))
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

        // Split into the 8-byte event discriminator and trailing event bytes,
        // skipping anything that isn't a well-formed Anchor event instruction.
        let Some((event_discriminator, event_data)) = split_cpi_event(&ix_data) else {
            return Ok((Vec::new(), Vec::new()));
        };

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
                            request: Arc::new(request),
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
    use anchor_lang::AnchorSerialize;
    use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
    use solana_sdk::commitment_config::CommitmentLevel;
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status::{
        TransactionDetails, UiTransactionEncoding, UiTransactionStatusMeta,
    };

    #[test]
    fn split_cpi_event_handles_short_and_valid_data() {
        let tag = anchor_lang::event::EVENT_IX_TAG_LE;

        // No event tag -> not an event instruction.
        assert!(split_cpi_event(b"not-an-event").is_none());

        // Tag present but too short for the 8-byte discriminator. This is the
        // regression case: previously `&ix_data[8..16]` panicked here.
        for extra in 0..8usize {
            let mut data = tag.to_vec();
            data.extend(std::iter::repeat_n(0u8, extra));
            assert!(
                split_cpi_event(&data).is_none(),
                "tag + {extra} bytes ({} total) should be skipped, not panic",
                data.len()
            );
        }

        // Tag + 8-byte discriminator + payload -> split correctly.
        let mut data = tag.to_vec();
        data.extend_from_slice(&[9u8; 8]); // discriminator
        data.extend_from_slice(&[1, 2, 3]); // event payload
        let (disc, payload) = split_cpi_event(&data).expect("well-formed event should split");
        assert_eq!(disc, [9u8; 8]);
        assert_eq!(payload, [1, 2, 3]);
    }

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
            polling: PollingConfig::default(),
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

    fn cpi_event_instruction<T: AnchorSerialize + Discriminator>(event: &T) -> String {
        let mut data = anchor_lang::event::EVENT_IX_TAG_LE.to_vec();
        data.extend_from_slice(T::DISCRIMINATOR);
        event.serialize(&mut data).unwrap();
        solana_sdk::bs58::encode(data).into_string()
    }

    fn event_transaction(
        program_id: Pubkey,
        signature: Signature,
        instruction: &str,
        event_data: String,
    ) -> serde_json::Value {
        serde_json::json!({
            "meta": {
                "err": null,
                "status": { "Ok": null },
                "fee": 5_000,
                "preBalances": [],
                "postBalances": [],
                "innerInstructions": [{
                    "index": 0,
                    "instructions": [{
                        "accounts": [],
                        "data": event_data,
                        "programId": program_id.to_string(),
                        "stackHeight": 2
                    }]
                }],
                "logMessages": [
                    format!("Program {program_id} invoke [1]"),
                    format!("Program log: Instruction: {instruction}"),
                    format!("Program {program_id} success")
                ],
                "preTokenBalances": [],
                "postTokenBalances": [],
                "rewards": null,
                "loadedAddresses": { "readonly": [], "writable": [] },
                "computeUnitsConsumed": 0
            },
            "transaction": {
                "message": {
                    "accountKeys": [{
                        "pubkey": program_id.to_string(),
                        "signer": false,
                        "source": "transaction",
                        "writable": false
                    }],
                    "instructions": [],
                    "recentBlockhash": "11111111111111111111111111111111"
                },
                "signatures": [signature.to_string()]
            },
            "version": "legacy"
        })
    }

    fn event_block_response(
        id: usize,
        slot: u64,
        transaction: serde_json::Value,
    ) -> serde_json::Value {
        let mut response = block_response(id, slot);
        response["result"]["transactions"] = serde_json::json!([transaction]);
        response
    }

    /// Match a JSON-RPC block batch whose first `getBlock` request is for `slot`.
    fn block_batch_starting_at(slot: u64) -> mockito::Matcher {
        mockito::Matcher::Regex(format!(r#""params"\s*:\s*\[\s*{slot}\s*,"#))
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
        assert_eq!(config.encoding, Some(UiTransactionEncoding::JsonParsed));
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

    #[test]
    fn globally_ordered_slots_are_split_into_bounded_chunks() {
        let chunks = SolanaIndexer::<MockStateManager, NoopChainTelemetry>::chunk_slots(
            BTreeSet::from([5, 1, 4, 2, 3]),
            2,
        );

        assert_eq!(
            chunks,
            vec![
                BTreeSet::from([1, 2]),
                BTreeSet::from([3, 4]),
                BTreeSet::from([5]),
            ]
        );
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
        let mut stream = indexer.catchup_blocks(ANCHOR_SLOT, ANCHOR_SLOT).await.unwrap();
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
        const ANCHOR_SLOT: u64 = 10;

        let mut stream = indexer.catchup_blocks(ANCHOR_SLOT, 6).await.unwrap();
        let first = stream.next().await;
        assert!(first.is_some() && first.unwrap().is_err());
    }

    #[tokio::test]
    async fn single_page_catchup_processes_slots_in_order() {
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
        const ANCHOR_SLOT: u64 = 10;

        let mut stream = indexer.catchup_blocks(ANCHOR_SLOT, 6).await.unwrap();

        while let Some(res) = stream.next().await {
            let (slot, block) = res.unwrap();
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

    #[tokio::test]
    async fn catchup_parses_request_and_response_cpi_events() {
        let mut server = mockito::Server::new_async().await;
        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 5).await;
        let indexer = test_indexer(&server.url(), state_manager);

        let request = SignatureRequestedEvent {
            sender: Pubkey::new_unique(),
            payload: [1; 32],
            key_version: 0,
            deposit: 1,
            chain_id: "solana".to_string(),
            path: "test".to_string(),
            algo: "secp256k1".to_string(),
            dest: "test".to_string(),
            params: String::new(),
            fee_payer: None,
        };
        let request_id = SolanaSignEvent::SignatureRequested(request.clone()).generate_request_id();
        let response = SignatureRespondedEvent {
            request_id,
            responder: Pubkey::new_unique(),
            signature: signet_program::Signature {
                big_r: signet_program::AffinePoint {
                    x: hex::decode(
                        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    )
                    .unwrap()
                    .try_into()
                    .unwrap(),
                    y: hex::decode(
                        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
                    )
                    .unwrap()
                    .try_into()
                    .unwrap(),
                },
                s: [1; 32],
                recovery_id: 0,
            },
        };

        let entries: Vec<_> = [8, 7, 5].into_iter().map(signature_entry).collect();
        let _signatures = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                "getSignaturesForAddress".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&entries))
            .expect(1)
            .create_async()
            .await;

        let blocks = serde_json::json!([
            event_block_response(
                0,
                7,
                event_transaction(
                    indexer.program_id,
                    Signature::new_unique(),
                    "Sign",
                    cpi_event_instruction(&request),
                ),
            ),
            event_block_response(
                1,
                8,
                event_transaction(
                    indexer.program_id,
                    Signature::new_unique(),
                    "Respond",
                    cpi_event_instruction(&response),
                ),
            ),
        ]);
        let _blocks = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                r#""method":"getBlock".*"encoding":"jsonParsed""#.to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(blocks.to_string())
            .expect(1)
            .create_async()
            .await;

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let mut catchup = indexer.catchup_blocks(9, 6).await.unwrap();
        while let Some(item) = catchup.next().await {
            let (slot, block) = item.unwrap();
            indexer
                .process_catchup_item(&events_tx, slot, &block)
                .await
                .unwrap();
        }

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::SignRequest { request, .. }) if request.id == SignId::new(request_id)
        ));
        assert!(matches!(events_rx.recv().await, Some(ChainEvent::Block(7))));
        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Respond(event)) if event.request_id == request_id
        ));
        assert!(matches!(events_rx.recv().await, Some(ChainEvent::Block(8))));
    }

    #[tokio::test]
    async fn block_fetch_pages_preserve_slot_order() {
        let mut server = mockito::Server::new_async().await;

        // Delay the older page. Sequential fetching must still emit it before
        // the immediately available newer page.
        let _older_blocks = server
            .mock("POST", "/")
            .match_body(block_batch_starting_at(1))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_chunked_body(|writer| {
                std::thread::sleep(Duration::from_millis(100));
                writer.write_all(b"[]")
            })
            .expect(1)
            .create_async()
            .await;
        let _newer_blocks = server
            .mock("POST", "/")
            .match_body(block_batch_starting_at(3))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .expect(1)
            .create_async()
            .await;

        let indexer = test_indexer(&server.url(), MockStateManager::new());
        let pages = stream::iter([Ok(BTreeSet::from([1, 2])), Ok(BTreeSet::from([3, 4]))]);
        let mut blocks =
            SolanaIndexer::<MockStateManager, NoopChainTelemetry>::fetch_blocks_for_pages(
                indexer.client,
                pages,
            );

        let mut slots = Vec::new();
        while let Some(item) = blocks.next().await {
            slots.push(item.unwrap().0);
        }

        assert_eq!(slots, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn multipage_catchup_does_not_lose_response_before_older_request() {
        let mut server = mockito::Server::new_async().await;
        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 5).await;
        let indexer = test_indexer(&server.url(), state_manager);

        // getSignaturesForAddress paginates newest-to-oldest. The response is
        // in the first (newer) page, while its request is in the second (older)
        // page. Slot 5 is below the catchup start and terminates pagination.
        let newest_page: Vec<_> = [9, 8].into_iter().map(signature_entry).collect();
        // Slot 8 appears on both pages to verify global deduplication at a page
        // boundary. Fetching its block once still discovers every transaction
        // in that slot.
        let older_page: Vec<_> = [8, 7, 6, 5].into_iter().map(signature_entry).collect();
        let before_cursor = newest_page
            .last()
            .and_then(|entry| entry["signature"].as_str())
            .expect("newest page should have a cursor signature");

        let _newest_page = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "method": "getSignaturesForAddress",
                "params": [indexer.program_id.to_string(), { "before": null }],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&newest_page))
            .expect(1)
            .create_async()
            .await;
        let _older_page = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "method": "getSignaturesForAddress",
                "params": [indexer.program_id.to_string(), { "before": before_cursor }],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&older_page))
            .expect(1)
            .create_async()
            .await;

        let ordered_blocks = serde_json::json!([
            block_response(0, 6),
            block_response(1, 7),
            block_response(2, 8),
            block_response(3, 9),
        ])
        .to_string();

        let _ordered_blocks = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("getBlock".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ordered_blocks)
            .expect(1)
            .create_async()
            .await;

        let mut catchup = indexer.catchup_blocks(10, 6).await.unwrap();

        let mut replayed_slots = Vec::new();
        let mut request_pending = false;
        let mut response_applied = false;

        while let Some(item) = catchup.next().await {
            let (slot, _block) = item.unwrap();
            replayed_slots.push(slot);
            match slot {
                // The request is created in the older block.
                7 => request_pending = true,
                // This mirrors process_respond_event: if the request is not
                // in the backlog yet, the response is skipped permanently.
                8 if request_pending => {
                    request_pending = false;
                    response_applied = true;
                }
                _ => {}
            }
        }

        assert_eq!(replayed_slots, vec![6, 7, 8, 9]);
        assert!(
            response_applied && !request_pending,
            "catchup replayed slots as {replayed_slots:?}; the response was processed before its request and lost"
        );
    }

    #[tokio::test]
    async fn run_emits_heartbeat_and_single_catchup_completed_when_idle() {
        let mut server = mockito::Server::new_async().await;

        // Frozen anchor: an idle chain whose tip never moves.
        // The indexer must still emit a heartbeat for the covered tip and a
        // single CatchupCompleted event.
        let _slot = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("getSlot".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":10}"#)
            .create_async()
            .await;

        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 9).await;
        let mut indexer = test_indexer(&server.url(), state_manager);
        indexer.polling = PollingConfig {
            poll_interval: Duration::from_millis(5),
            slot_stall_timeout: Duration::from_secs(30),
        };

        let (events_tx, mut events_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let run = {
            let cancel = cancel.clone();
            tokio::spawn(async move { indexer.run(events_tx, cancel).await })
        };

        // First tick: heartbeat for the covered tip, then exactly one
        // CatchupCompleted.
        // Second tick (after POLL_INTERVAL): heartbeat again — same height
        assert!(matches!(events_rx.recv().await, Some(ChainEvent::Block(9))));
        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::CatchupCompleted)
        ));
        assert!(matches!(events_rx.recv().await, Some(ChainEvent::Block(9))));

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run should stop promptly on cancel")
            .expect("run task should not panic")
            .expect("run should return Ok on cancel");
    }

    #[tokio::test]
    async fn run_bails_when_observed_slot_frozen() {
        let mut server = mockito::Server::new_async().await;

        // A frozen RPC node: getSlot keeps returning the same slot forever.
        // The heartbeat keeps Block events flowing, so only the indexer-side
        // slot-stall watchdog can catch this.
        let _slot = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("getSlot".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":10}"#)
            .create_async()
            .await;

        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 9).await;
        let mut indexer = test_indexer(&server.url(), state_manager);
        indexer.polling = PollingConfig {
            poll_interval: Duration::from_millis(5),
            slot_stall_timeout: Duration::from_millis(100),
        };

        let (events_tx, _events_rx) = mpsc::channel(64);
        let result = indexer
            .run(events_tx, CancellationToken::new())
            .await;

        let err = result.expect_err("run should bail on a frozen observed slot");
        assert!(err.to_string().contains("frozen"));
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
            polling: PollingConfig::default(),
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
