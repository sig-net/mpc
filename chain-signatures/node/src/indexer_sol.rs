use crate::backlog::Backlog;
use crate::protocol::Chain;
use crate::sign_bidirectional::hash_rlp_data;
use crate::solana_client::{SolanaCatchupBlock, SolanaClient, MAX_CONCURRENT_CHUNK_SIZE};
use crate::stream::{ChainIndexer, ChainStream};
use crate::util::ethabi_request_id;
use crate::util::retry::{retry_async, RetryConfig, RetryError, RetryReason};

pub use crate::solana_client::SolConfig;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::pin::Pin;
use std::str::FromStr;
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
use mpc_crypto::kdf::derive_epsilon_sol;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{
    ChainEvent, IndexedSignRequest, SignArgs, SignId, LATEST_MPC_KEY_VERSION, MAX_SECP256K1_SCALAR,
};
use serde::{Deserialize, Serialize};
use signet_program::{
    RespondBidirectionalEvent, SignBidirectionalEvent, SignatureRequestedEvent,
    SignatureRespondedEvent,
};
use solana_client::{
    nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient},
    rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter},
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction,
    EncodedTransactionWithStatusMeta, UiConfirmedBlock, UiInstruction, UiParsedInstruction,
    UiTransactionEncoding,
};
use tokio::sync::{mpsc, oneshot};

const CPI_EVENT_HINTS: &[&str] = &[
    "Program log: Instruction: Sign",
    "Program log: Instruction: SignBidirectional",
];

const CPI_RESPOND_EVENT_HINTS: &[&str] = &[
    "Program log: Instruction: Respond",
    "Program log: Instruction: RespondBidirectional",
];

/// Configures Solana indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_sol_options")]
pub struct SolArgs {
    /// The solana account secret key used to sign solana respond txn.
    #[arg(long, env("MPC_SOL_ACCOUNT_SK"))]
    pub sol_account_sk: Option<String>,
    /// Solana RPC HTTP URL
    #[clap(long, env("MPC_SOL_RPC_HTTP_URL"), requires = "sol_account_sk")]
    pub sol_rpc_http_url: Option<String>,
    /// Solana RPC WS URL
    #[clap(long, env("MPC_SOL_RPC_WS_URL"), requires = "sol_account_sk")]
    pub sol_rpc_ws_url: Option<String>,
    /// The program address to watch
    #[clap(long, env("MPC_SOL_PROGRAM_ADDRESS"), requires = "sol_account_sk")]
    pub sol_program_address: Option<String>,
}

impl SolArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(6);
        if let Some(sol_account_sk) = self.sol_account_sk {
            args.extend(["--sol-account-sk".to_string(), sol_account_sk]);
        }
        if let Some(sol_rpc_http_url) = self.sol_rpc_http_url {
            args.extend(["--sol-rpc-http-url".to_string(), sol_rpc_http_url]);
        }
        if let Some(sol_rpc_ws_url) = self.sol_rpc_ws_url {
            args.extend(["--sol-rpc-ws-url".to_string(), sol_rpc_ws_url]);
        }
        if let Some(sol_program_address) = self.sol_program_address {
            args.extend(["--sol-program-address".to_string(), sol_program_address]);
        }
        args
    }

    pub fn into_config(self) -> Option<SolConfig> {
        Some(SolConfig {
            account_sk: self.sol_account_sk?,
            rpc_http_url: self.sol_rpc_http_url?,
            rpc_ws_url: self.sol_rpc_ws_url?,
            program_address: self.sol_program_address?,
        })
    }

    pub fn from_config(config: Option<SolConfig>) -> Self {
        match config {
            Some(config) => SolArgs {
                sol_account_sk: Some(config.account_sk),
                sol_rpc_http_url: Some(config.rpc_http_url),
                sol_rpc_ws_url: Some(config.rpc_ws_url),
                sol_program_address: Some(config.program_address),
            },
            None => SolArgs {
                sol_account_sk: None,
                sol_rpc_http_url: None,
                sol_rpc_ws_url: None,
                sol_program_address: None,
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SolSignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

/// Solana stream that implements the new ChainStream abstraction
pub struct SolanaStream {
    rx: Option<mpsc::Receiver<ChainEvent>>,
    start_state: Option<SolanaStreamStartState>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

pub struct SolanaIndexer {
    pub program_id: Pubkey,
    pub client: SolanaClient,
    pub events_tx: mpsc::Sender<ChainEvent>,
    pub backlog: Backlog,
    pub live_rx: Option<mpsc::Receiver<ChainEvent>>,
}

struct SolanaStreamStartState {
    program_id: Pubkey,
    rpc_http_url: String,
    rpc_ws_url: String,
    backlog: Backlog,
    tx: mpsc::Sender<ChainEvent>,
}

impl Drop for SolanaStream {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl SolanaStream {
    pub fn new(sol: Option<SolConfig>, backlog: Backlog) -> Option<Self> {
        let Some(sol) = sol else {
            tracing::warn!("solana indexer is disabled");
            return None;
        };

        let Ok(program_id) = Pubkey::from_str(&sol.program_address) else {
            tracing::error!("Failed to parse program address: {}", sol.program_address);
            return None;
        };

        let (tx, rx) = crate::stream::channel();

        Some(SolanaStream {
            rx: Some(rx),
            start_state: Some(SolanaStreamStartState {
                program_id,
                rpc_http_url: sol.rpc_http_url.clone(),
                rpc_ws_url: sol.rpc_ws_url.clone(),
                backlog,
                tx,
            }),
            tasks: Vec::new(),
        })
    }
}

#[async_trait]
impl ChainStream for SolanaStream {
    type Indexer = SolanaIndexer;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
        let Some(start_state) = self.start_state.take() else {
            anyhow::bail!("solana stream already started");
        };

        let client = SolanaClient::for_indexer(
            start_state.rpc_http_url.clone(),
            start_state.rpc_ws_url.clone(),
            start_state.program_id,
        );

        let indexer = SolanaIndexer {
            program_id: start_state.program_id,
            client,
            events_tx: start_state.tx.clone(),
            backlog: start_state.backlog.clone(),
            live_rx: None,
        };

        Ok(indexer)
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        match self.rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }
}

#[async_trait]
impl ChainIndexer for SolanaIndexer {
    const CHAIN: Chain = Chain::Solana;
    type Block = (u64, SolanaCatchupBlock);
    type Iter = Pin<Box<dyn Stream<Item = Self::Block> + Send + 'static>>;

    async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
        let (live_tx, live_rx) = crate::stream::channel();
        self.live_rx = Some(live_rx);

        let program_id = self.program_id;
        let rpc_http_url = self.client.rpc_http_url.clone();
        let rpc_ws_url = self.client.rpc_ws_url.clone();

        // Oneshot to receive the first observed slot from the live subscription.
        let (anchor_tx, anchor_rx) = oneshot::channel::<u64>();

        tokio::spawn(subscribe_and_buffer_live_events(
            program_id,
            rpc_http_url,
            rpc_ws_url,
            live_tx,
            anchor_tx,
        ));

        // Wait for the first slot observed on the live feed to use as anchor.
        Ok(Some(anchor_rx.await?))
    }

    async fn catchup_range(&self, anchor_height: u64) -> Self::Iter {
        // Get the last persisted processed block height from backlog
        // TODO: https://github.com/sig-net/mpc/issues/777
        let start_slot = self
            .backlog
            .processed_block(Chain::Solana)
            .await
            .map(|n| n.saturating_add(1))
            .unwrap_or(anchor_height);
        let end_slot = anchor_height.saturating_sub(1); // We want to catch up to just before the anchor
        if start_slot > end_slot {
            return Box::pin(futures_util::stream::empty());
        }

        let slots = self.client.fetch_slots(start_slot, end_slot).await;
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

        Box::pin(stream)
    }

    async fn process_catchup(&mut self, (slot, block): &Self::Block) -> anyhow::Result<()> {
        match block {
            SolanaCatchupBlock::Block(block) => self.process_block(*slot, block).await,
            SolanaCatchupBlock::Missing => {
                let block = self.client.get_block(*slot).await;
                self.process_block(*slot, &block).await
            }
        }
    }

    async fn process_next_block(&mut self) -> bool {
        let Some(rx) = self.live_rx.as_mut() else {
            return false;
        };
        let Some(event) = rx.recv().await else {
            return false;
        };
        if let Err(err) = self.events_tx.send(event).await {
            tracing::warn!(?err, "failed to forward live solana event");
            return false;
        }
        true
    }

    async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
        self.events_tx.send(ChainEvent::CatchupCompleted).await?;
        Ok(())
    }
}

impl SolanaIndexer {
    async fn process_block(&mut self, height: u64, block: &UiConfirmedBlock) -> anyhow::Result<()> {
        let Some(transactions) = &block.transactions else {
            self.events_tx.send(ChainEvent::Block(height)).await?;
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
            emit_events(&self.events_tx, &self.program_id, signature, tx, logs).await?;
        }

        self.events_tx.send(ChainEvent::Block(height)).await?;
        Ok(())
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
            SolanaSignEvent::SignatureRequested(ev) => ethabi_request_id(
                &ev.sender.to_string(),
                ev.payload,
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
                    crate::util::current_unix_timestamp(),
                ))
            }
            SolanaSignEvent::SignBidirectional(ev) => {
                let epsilon = derive_epsilon_sol(ev.key_version, &ev.sender.to_string(), &ev.path);
                tracing::info!(?sign_id, "solana bidirectional signature requested");
                let unsigned_tx_hash = hash_rlp_data(&ev.serialized_transaction);
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
                    crate::util::current_unix_timestamp(),
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
/// via `anchor_tx` so that `livestream()` can return it to the catchup logic.
///
/// Events accumulate in the channel while catchup runs; `process_next_block` drains them
/// only after catchup completes (enforced by `catchup_then_livestream`).
async fn subscribe_and_buffer_live_events(
    program_id: Pubkey,
    rpc_url: String,
    ws_url: String,
    live_tx: mpsc::Sender<ChainEvent>,
    anchor_tx: oneshot::Sender<u64>,
) {
    // Get anchor slot immediately so livestream() can return without waiting for an event.
    let rpc = RpcClient::new(rpc_url);
    let mut anchor_tx = Some(anchor_tx);
    loop {
        // TODO: if solana ever fails and needs to retry, we actually need to do catchup
        // again. This requires potentially complicating the coordination we have on the
        // high level of run_stream. Issue: https://github.com/sig-net/mpc/issues/811
        let result =
            subscribe_to_program_events(program_id, &rpc, &ws_url, live_tx.clone(), &mut anchor_tx)
                .await;

        if let Err(err) = result {
            tracing::warn!("Live solana subscription failed: {:?}", err);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

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

async fn subscribe_to_program_events(
    program_id: Pubkey,
    rpc_client: &RpcClient,
    ws_url: &str,
    events_tx: mpsc::Sender<ChainEvent>,
    anchor_tx: &mut Option<oneshot::Sender<u64>>,
) -> anyhow::Result<()> {
    let pubsub_client = PubsubClient::new(ws_url).await?;

    let filter = RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]);
    let config = RpcTransactionLogsConfig {
        commitment: Some(CommitmentConfig::confirmed()),
    };

    let (mut stream, _unsubscriber) = pubsub_client.logs_subscribe(filter, config).await?;

    // Resolve the anchor slot immediately after successfully subscribing, avoiding gaps.
    // We cannot wait for the websocket stream to get the first signature on our program
    // since our program can potentially not generate any transactions for a while.
    if let Some(tx) = anchor_tx.take() {
        let slot = rpc_client.get_slot().await?;
        let _ = tx.send(slot);
    }

    // stall watchdog
    let stall_timeout = Duration::from_secs(60);
    let mut last_ws_msg = Instant::now();
    let mut watchdog = tokio::time::interval(Duration::from_secs(5));

    // Simple TTL cache to avoid multiple getTransaction calls for the same signature
    let mut seen: HashMap<Signature, Instant> = HashMap::new();
    let ttl = Duration::from_secs(30);

    let program_invoke_log = format!("Program {program_id} invoke [");

    loop {
        cleanup_seen_cache(&mut seen, ttl);
        tokio::select! {
            // Receive WS logs
            maybe = stream.next() => {
                match maybe {
                    Some(response) => {
                        last_ws_msg = Instant::now();

                        let slot = response.context.slot;
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

                        let tx_res = match get_tx(rpc_client, &signature, RetryConfig::default()).await {
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
            let signature = signature.as_ref().to_vec();
            for ev in events {
                if let Some(req) = ev.build_sign_request(&signature) {
                    events_tx.send(ChainEvent::SignRequest(req)).await?;
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
                            chain: crate::protocol::Chain::Solana,
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

/// Fetch transaction with timeout + retry.
/// Returns the same type as `RpcClient::get_transaction_with_config`.
async fn get_tx(
    rpc_client: &RpcClient,
    signature: &Signature,
    retry_cfg: RetryConfig,
) -> anyhow::Result<EncodedConfirmedTransactionWithStatusMeta> {
    let max_attempts = retry_cfg.max_attempts;

    let res = retry_async(
        retry_cfg,
        |attempt| async move {
            rpc_client
                .get_transaction_with_config(
                    signature,
                    solana_client::rpc_config::RpcTransactionConfig {
                        encoding: Some(UiTransactionEncoding::JsonParsed),
                        commitment: Some(CommitmentConfig::confirmed()),
                        max_supported_transaction_version: Some(0),
                    },
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(e).context(format!(
                        "getTransaction failed (attempt {attempt}/{}) for {}",
                        max_attempts, signature
                    ))
                })
        },
        |_attempt, _reason| true,
        |attempt, reason, sleep| match reason {
            RetryReason::Error(e) => {
                tracing::warn!(
                    "getTransaction failed (attempt {attempt}/{}) for {}: {e:#}; retrying in {sleep:?}",
                    max_attempts,
                    signature
                );
            }
            RetryReason::Timeout(t) => {
                tracing::warn!(
                    "getTransaction timed out after {t:?} (attempt {attempt}/{}) for {}; retrying in {sleep:?}",
                    max_attempts,
                    signature
                );
            }
        },
    )
    .await;

    match res {
        Ok(tx) => Ok(tx),
        Err(RetryError::Exhausted { last_error, .. }) => Err(last_error),
        Err(RetryError::TimeoutExhausted {
            attempts,
            last_timeout,
        }) => Err(anyhow::anyhow!(
            "getTransaction timed out after {:?} (attempt {attempts}/{}) for {}",
            last_timeout,
            max_attempts,
            signature
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use solana_sdk::commitment_config::CommitmentLevel;
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status::{TransactionDetails, UiTransactionStatusMeta};

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

        let backlog = Backlog::new();
        let (events_tx, mut events_rx) = mpsc::channel(1_000_000);

        let client = SolanaClient::for_indexer(
            http_url.clone(),
            ws_url.clone(),
            Pubkey::from_str(&sol_addr).unwrap(),
        );

        let mut indexer = SolanaIndexer {
            program_id: Pubkey::from_str(&sol_addr).unwrap(),
            client,
            events_tx,
            backlog,
            live_rx: None,
        };

        // Initialize livestream (resolves anchor slot via get_slot and starts WS)
        let anchor_height = indexer
            .livestream()
            .await
            .expect("Failed to initialize livestream")
            .expect("Anchor height missing");

        tracing::debug!("Resolved anchor slot: {anchor_height}");

        // Start from a checkpoint ~1 week behind (assuming ~2.5 slots per second => 1,512,000 slots per week)
        let start_slot = anchor_height.saturating_sub(1_512_000);
        tracing::debug!("Starting catchup from slot: {start_slot} (~1 week behind)");

        indexer
            .backlog
            .set_processed_block_interval(Chain::Solana, start_slot.saturating_sub(1), 1)
            .await;

        // Run catchup range
        let catchup_stream = indexer.catchup_range(anchor_height).await;
        tokio::pin!(catchup_stream);
        let mut processed_any = false;
        while let Some(item) = catchup_stream.next().await {
            indexer
                .process_catchup(&item)
                .await
                .expect("Failed to process catchup block");
            processed_any = true;
        }

        tracing::debug!("Solana catchup complete. Processed blocks: {processed_any}");

        // Check if any events were received in the channel
        while let Ok(event) = events_rx.try_recv() {
            tracing::debug!("Received event: {:?}", event);
        }
    }
}
