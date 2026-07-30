use crate::abi::ChainSignatures;
use crate::client::{
    block_may_contain_logs, BlockNumber, CatchupItem, CatchupIter, EthereumClient, MaybeBlock,
};
use crate::event_parsing::{emit_respond_events, is_contract_call, parse_filtered_logs};
use crate::EthConfig;
use alloy::consensus::Transaction;
use alloy::eips::BlockNumberOrTag;
use alloy::network::TransactionResponse;
use alloy::primitives::{Address, B256};
use alloy::rpc::types::{Block, BlockId, BlockTransactions, Log};
use alloy::sol_types::SolEvent;
use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::{stream, Stream, StreamExt};
use mpc_chain_integration_core::utils::task::AbortOnDrop;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainConfig as _, ChainEvent, ExecutionOutcome,
    IndexedSignRequest, SignId,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Duration, Instant};
use tokio_util::sync::CancellationToken;

pub struct BlockAndRequests {
    block_number: u64,
    block_hash: alloy::primitives::B256,
    /// Block timestamp captured from the block we already fetched, so
    /// `emit_processed_block` doesn't need to re-fetch the block just to read
    /// it back. Used for `ChainEvent::SignRequest`'s `block_timestamp` field.
    block_timestamp: u64,
    indexed_requests: Vec<IndexedSignRequest>,
    respond_logs: Vec<Log>,
    execution_events: Vec<ChainEvent>,
}

impl BlockAndRequests {
    fn new(
        block_number: u64,
        block_hash: alloy::primitives::B256,
        block_timestamp: u64,
        indexed_requests: Vec<IndexedSignRequest>,
        respond_logs: Vec<Log>,
        execution_events: Vec<ChainEvent>,
    ) -> Self {
        Self {
            block_number,
            block_hash,
            block_timestamp,
            indexed_requests,
            respond_logs,
            execution_events,
        }
    }
}

pub struct EthereumIndexer<S: StateManager, T: ChainTelemetry> {
    eth: EthConfig,
    state_manager: S,
    telemetry: T,
    client: Arc<EthereumClient>,
    contract_address: Address,
    /// Cached finalized head maintained by `watch_finalized_head`, consulted by
    /// `emit_processed_block` so each block need not poll finality independently.
    finalized_head: watch::Sender<u64>,
    /// Watcher nonce-gate scheduling state (first-appearance checks + retries).
    watcher_gate: Mutex<WatcherGateState>,
}

/// Scheduling state for the watcher nonce gate
#[derive(Default)]
struct WatcherGateState {
    /// Watchers present at the previous block, for first-appearance detection.
    prev: HashSet<BidirectionalTxId>,
    /// Watchers whose last RPC resolution attempt failed; retried every block.
    retry: HashSet<BidirectionalTxId>,
}

/// A pending execution watcher entry from the state manager.
type WatcherEntry = (BidirectionalTxId, (SignId, BidirectionalTx));

/// Per-watcher receipt resolution result.
type WatcherReceipt = (
    BidirectionalTxId,
    SignId,
    BidirectionalTx,
    anyhow::Result<BackfillOutcome>,
);

/// Result of a `backfill_execution_confirmation`. `Observed` carries an
/// optional event; the staleness check skips observed watchers so a mined tx
/// with a failed extraction can stay pending for retry. `NotObserved` covers
/// "no receipt yet" (pending or replaced).
#[allow(clippy::large_enum_variant)] // value is consumed in one match arm; never stored.
enum BackfillOutcome {
    NotObserved,
    Observed { event: Option<ChainEvent> },
}

// TODO: Probably can be reused elsewhere, double check and put in a common place
/// Sleeps for `dur`, returning early if `cancel` fires first. Returns `true`
/// if the sleep was interrupted by cancellation.
async fn sleep_or_cancel(cancel: &CancellationToken, dur: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = sleep(dur) => false,
    }
}

/// Tracks finalized-head advancement for stall detection, emitting the
/// advance / backwards / stalled warnings.
struct FinalizedHeadStall {
    last_final: Option<u64>,
    last_advanced_at: Instant,
    last_stall_warn_at: Instant,
    warn_after_secs: u64,
    rewarn_every_secs: u64,
}

impl FinalizedHeadStall {
    fn new(warn_after_secs: u64, rewarn_every_secs: u64) -> Self {
        let now = Instant::now();
        Self {
            last_final: None,
            last_advanced_at: now,
            last_stall_warn_at: now,
            warn_after_secs,
            rewarn_every_secs,
        }
    }

    /// Record a finalized-head sample, emitting advance/stall warnings as needed.
    fn observe(&mut self, new_final: u64) {
        if self.last_final.is_none_or(|n| new_final > n) {
            self.last_advanced_at = Instant::now();
            tracing::debug!(new_final, prev = self.last_final, "finalized head advanced");
        }

        match self.last_final.replace(new_final) {
            Some(prev) if new_final < prev => {
                tracing::warn!(new_final, prev, "finalized block number went backwards");
            }
            Some(prev) if prev == new_final => self.warn_if_stalled(new_final),
            _ => {}
        }
    }

    fn warn_if_stalled(&mut self, new_final: u64) {
        let now = Instant::now();
        let stalled_for = now.duration_since(self.last_advanced_at).as_secs();
        if stalled_for < self.warn_after_secs {
            return;
        }
        if now.duration_since(self.last_stall_warn_at).as_secs() < self.rewarn_every_secs {
            return;
        }
        tracing::warn!(
            new_final,
            stalled_for,
            warn_after_secs = self.warn_after_secs,
            "ethereum finalized head has not advanced; \
             blocks above it will not be emitted until finality catches up. \
             If this persists the stream watchdog will restart the pipeline"
        );
        self.last_stall_warn_at = now;
    }
}

impl<S: StateManager, T: ChainTelemetry> EthereumIndexer<S, T> {
    /// Delay between retries of transient RPC failures
    const RETRY_DELAY: Duration = Duration::from_millis(500);

    pub async fn new(eth: EthConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        let client = Arc::new(EthereumClient::new(eth.clone()).await?);
        let contract_address = eth.contract_address;

        Ok(Self {
            eth,
            state_manager,
            telemetry,
            client,
            contract_address,
            finalized_head: watch::channel(0).0,
            watcher_gate: Mutex::new(WatcherGateState::default()),
        })
    }

    /// Construct an `EthereumIndexer` for tests with a pre-built `EthereumClient`
    /// (so a mockito URL can be injected) and a parsed `contract_address`.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        eth: EthConfig,
        state_manager: S,
        telemetry: T,
        client: Arc<EthereumClient>,
        contract_address: Address,
    ) -> Self {
        Self {
            eth,
            state_manager,
            telemetry,
            client,
            contract_address,
            finalized_head: watch::channel(0).0,
            watcher_gate: Mutex::new(WatcherGateState::default()),
        }
    }

    async fn index_live_blocks(
        client: Arc<EthereumClient>,
        start_block_number: u64,
        live_blocks: mpsc::Sender<MaybeBlock>,
    ) {
        tracing::info!("indexing ethereum live blocks");

        let mut current_block_number = start_block_number;

        // Missing ticks is what we want due to retrying on transient errors
        let mut interval = tokio::time::interval(Self::RETRY_DELAY);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            interval.tick().await;

            // Fetch the latest block number
            let latest_block_number = match client.get_latest_block_number().await {
                Ok(Some(number)) => number,
                Ok(None) => continue,
                Err(err) => {
                    tracing::warn!(?err, "ethereum latest block fetch failed");
                    continue;
                }
            };

            // Fetch blocks in order until we reach the latest block number
            while current_block_number <= latest_block_number {
                let block = match client
                    .get_block(BlockId::Number(BlockNumberOrTag::Number(
                        current_block_number,
                    )))
                    .await
                {
                    Ok(Some(block)) => block,
                    Ok(None) => {
                        tracing::warn!(
                            current_block_number,
                            "ethereum live block not yet available"
                        );
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            current_block_number,
                            "ethereum live block fetch failed"
                        );
                        break;
                    }
                };

                if let Err(err) = live_blocks.send(MaybeBlock::Block(block)).await {
                    tracing::warn!(
                        ?err,
                        current_block_number,
                        "failed to add ethereum live block"
                    );
                    return;
                }

                current_block_number = current_block_number.saturating_add(1);
            }
        }
    }

    /// Fetch the contract-relevant logs for a single `block`, gated by its
    /// bloom filter.
    async fn fetch_block_logs(&self, block: &Block) -> anyhow::Result<Vec<Log>> {
        if !block_may_contain_logs(block, self.contract_address) {
            return Ok(Vec::new());
        }
        self.client
            .get_logs(self.contract_address, block.header.number.into())
            .await
    }

    /// Process the block and emit relevant ChainEvents from the block.
    async fn process_block(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        block: &Block,
        relevant_logs: &[Log],
    ) -> anyhow::Result<()> {
        // Emit telemetry for the indexed block number
        self.telemetry.block_indexed(block.header.number);

        let processed = self.parse_block(block, relevant_logs).await?;
        self.emit_processed_block(events_tx, processed).await?;

        Ok(())
    }

    /// Parse the block and its relevant logs into a `BlockAndRequests` payload.
    async fn parse_block(
        &self,
        block: &Block,
        relevant_logs: &[Log],
    ) -> anyhow::Result<BlockAndRequests> {
        let block_number = block.header.number;
        let block_hash = block.header.hash;

        tracing::info!(
            "Processing block number {} with hash {:?}",
            block_number,
            block_hash
        );

        let mut sign_requests = Vec::new();

        let (respond_logs, potential_request_logs): (Vec<Log>, Vec<Log>) =
            relevant_logs.iter().cloned().partition(|log| {
                log.topic0().is_some_and(|topic| {
                    *topic == ChainSignatures::SignatureResponded::SIGNATURE_HASH
                })
            });

        let request_logs: Vec<Log> = potential_request_logs
            .into_iter()
            .filter(|log| {
                log.topic0().is_some_and(|topic| {
                    *topic == ChainSignatures::SignatureRequested::SIGNATURE_HASH
                })
            })
            .collect();

        if !request_logs.is_empty() {
            sign_requests.extend(parse_filtered_logs(request_logs));
        }

        // Collect execution confirmations (if any) and emit ExecutionConfirmed events
        let exec_events = self.collect_execution_confirmations(block).await?;

        // Always forward the processed block to the "finalization" stage so it can emit
        // `ChainEvent::Block` even when there are no relevant contract logs.
        Ok(BlockAndRequests::new(
            block_number,
            block_hash,
            block.header.timestamp,
            sign_requests,
            respond_logs,
            exec_events,
        ))
    }

    /// Extract the output of a successful transaction, either from the trace or from the receipt.
    async fn extract_success_tx_output(
        &self,
        tx_id: alloy::primitives::B256,
        tx: &BidirectionalTx,
    ) -> anyhow::Result<Vec<u8>> {
        let Some(tx_info) = self.client.get_transaction_by_hash(tx_id).await? else {
            anyhow::bail!("Failed to fetch transaction {tx_id:?}");
        };

        if tx_info.inner.to().is_none() {
            anyhow::bail!("unsupported contract deployment (CREATE): {tx_id:?}");
        }

        let data = tx_info.inner.input().clone();
        let is_contract_call = is_contract_call(&data);

        let trace_output = if is_contract_call {
            tracing::info!(
                ?tx_id,
                "Extracting transaction output via debug_traceTransaction"
            );
            Some(self.client.trace_transaction_output(tx_id).await?)
        } else {
            None
        };

        crate::respond_bidirectional::build_serialized_output(
            is_contract_call,
            &tx.output_deserialization_schema,
            trace_output.as_ref(),
            tx.source_chain.respond_serialization_format(),
            &tx.respond_serialization_schema,
        )
    }

    /// Construct a `ChainEvent::ExecutionConfirmed` for a mined transaction, if possible.
    async fn execution_confirmed_event(
        &self,
        tx_id: BidirectionalTxId,
        sign_id: SignId,
        pending_tx: &BidirectionalTx,
        block_number: u64,
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> Option<ChainEvent> {
        let receipt_succeeded = receipt.status();

        tracing::info!(
            ?tx_id,
            ?sign_id,
            block_number,
            "bidirectional execution observed via rpc"
        );

        let result = if receipt_succeeded {
            match self
                .extract_success_tx_output(tx_id.0.into(), pending_tx)
                .await
            {
                Ok(serialized_output) => {
                    tracing::info!(
                        ?tx_id,
                        ?sign_id,
                        "extracted transaction output for bidirectional tx"
                    );
                    ExecutionOutcome::Success {
                        output: serialized_output,
                    }
                }
                Err(err) => {
                    tracing::error!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "Failed to extract transaction output"
                    );
                    return None;
                }
            }
        } else {
            ExecutionOutcome::Failed
        };

        Some(ChainEvent::ExecutionConfirmed {
            tx_id,
            sign_id,
            source_chain: pending_tx.source_chain,
            block_height: block_number,
            result,
        })
    }

    async fn backfill_execution_confirmation(
        &self,
        tx_id: BidirectionalTxId,
        sign_id: SignId,
        pending_tx: &BidirectionalTx,
        current_block_number: u64,
    ) -> anyhow::Result<BackfillOutcome> {
        // Fetch this single watcher tx's receipt
        let Some(receipt) = self.client.get_transaction_receipt(tx_id.0.into()).await? else {
            return Ok(BackfillOutcome::NotObserved);
        };

        let Some(mined_block_number) = receipt.block_number else {
            tracing::debug!(
                ?tx_id,
                ?sign_id,
                "late watcher backfill: transaction receipt has no block number"
            );
            return Ok(BackfillOutcome::NotObserved);
        };

        if mined_block_number > current_block_number {
            tracing::debug!(
                ?tx_id,
                ?sign_id,
                mined_block_number,
                current_block_number,
                "skipping late watcher backfill for future ethereum block"
            );

            return Ok(BackfillOutcome::NotObserved);
        }

        tracing::info!(
            ?tx_id,
            ?sign_id,
            mined_block_number,
            current_block_number,
            "backfilled execution confirmation for late ethereum watcher"
        );

        let event = self
            .execution_confirmed_event(tx_id, sign_id, pending_tx, mined_block_number, &receipt)
            .await;
        Ok(BackfillOutcome::Observed { event })
    }

    /// Collects execution confirmations for all watchers at the given block
    async fn collect_execution_confirmations(
        &self,
        block: &Block,
    ) -> anyhow::Result<Vec<ChainEvent>> {
        let watchers = self
            .state_manager
            .get_execution_watchers(Chain::Ethereum)
            .await;

        if watchers.is_empty() {
            return Ok(Vec::new());
        }

        let block_number = block.header.number;
        tracing::info!(
            watchers_count = watchers.len(),
            block_number,
            "collect_execution_confirmations checking watchers"
        );

        let (new_watchers, retry) = self.schedule_watcher_gates(&watchers);

        // Extract hashes from the block
        let block_tx_hashes: HashSet<_> = match &block.transactions {
            BlockTransactions::Hashes(hashes) => hashes.iter().copied().collect(),
            BlockTransactions::Full(txs) => txs.iter().map(|tx| tx.tx_hash()).collect(),
            _ => HashSet::new(),
        };

        // Partition watchers into those that mined in this block and those that did not
        let (mined_in_block, unmined_watchers): (Vec<_>, Vec<_>) = watchers
            .into_iter()
            .partition(|(tx_id, _)| block_tx_hashes.contains(&B256::from(tx_id.0)));

        // Receipts for watched txs mined in this block
        let (mut events, consumed_slots, mut failed) = self
            .resolve_mined_watchers(mined_in_block, block_number)
            .await;

        // Fail pending watchers replaced by a sibling tx mined in this block
        let (sibling_events, unmined_watchers) =
            Self::resolve_replaced_siblings(unmined_watchers, &consumed_slots, block_number);

        events.extend(sibling_events);

        // Nonce gate: one-shot for new watchers, every block for retries,
        // every WATCHER_SLOW_SWEEP_INTERVAL blocks for edge-case consumption by a tx with no local watcher.
        let sweep_all = block_number % self.eth.indexer.watcher_slow_sweep_interval == 0;
        let gated: Vec<_> = unmined_watchers
            .into_iter()
            .filter(|(tx_id, _)| sweep_all || new_watchers.contains(tx_id) || retry.contains(tx_id))
            .collect();

        let (gated_events, gated_failed) = self.resolve_gated_watchers(gated, block_number).await;
        events.extend(gated_events);
        failed.extend(gated_failed);

        // Failed watchers are retried on the next block.
        self.lock_watcher_gate().retry = failed;

        Ok(events)
    }

    /// Locks the watcher gate Mutex, recovering the guard if poisoned.
    fn lock_watcher_gate(&self) -> MutexGuard<'_, WatcherGateState> {
        self.watcher_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Updates gate scheduling state, returning the watchers to nonce-check
    /// this block: newly appeared ones (one-shot) and previously failed ones
    /// (retried every block).
    fn schedule_watcher_gates(
        &self,
        watchers: &HashMap<BidirectionalTxId, (SignId, BidirectionalTx)>,
    ) -> (HashSet<BidirectionalTxId>, HashSet<BidirectionalTxId>) {
        let mut gate = self.lock_watcher_gate();
        gate.retry.retain(|id| watchers.contains_key(id));
        let new_watchers = watchers
            .keys()
            .filter(|id| !gate.prev.contains(*id))
            .copied()
            .collect();
        gate.prev = watchers.keys().copied().collect();
        (new_watchers, gate.retry.clone())
    }

    /// Fetches receipts for a batch of watchers with bounded concurrency,
    /// keeping per-watcher results so one failure doesn't abort the batch.
    async fn fetch_watcher_receipts(
        &self,
        watchers: Vec<WatcherEntry>,
        block_number: u64,
    ) -> Vec<WatcherReceipt> {
        stream::iter(
            watchers
                .into_iter()
                .map(|(tx_id, (sign_id, pending_tx))| async move {
                    let result = self
                        .backfill_execution_confirmation(tx_id, sign_id, &pending_tx, block_number)
                        .await;
                    (tx_id, sign_id, pending_tx, result)
                }),
        )
        .buffer_unordered(self.eth.indexer.max_concurrent_watcher_rpcs)
        .collect()
        .await
    }

    /// Fetches nonces for the given senders with bounded concurrency.
    async fn fetch_sender_nonces(
        &self,
        senders: HashSet<Address>,
        block_number: u64,
    ) -> Vec<(Address, anyhow::Result<u64>)> {
        stream::iter(senders.into_iter().map(|sender| async move {
            let result = self
                .client
                .get_nonce(
                    sender,
                    BlockId::Number(BlockNumberOrTag::Number(block_number)),
                )
                .await;
            (sender, result)
        }))
        .buffer_unordered(self.eth.indexer.max_concurrent_watcher_rpcs)
        .collect()
        .await
    }

    /// Resolves watched txs whose hash appears in this block. Returns emitted
    /// events, the (sender, nonce) slots consumed by observed txs (input to
    /// sibling correlation), and watchers whose RPC attempt failed.
    async fn resolve_mined_watchers(
        &self,
        mined: Vec<WatcherEntry>,
        block_number: u64,
    ) -> (
        Vec<ChainEvent>,
        HashSet<(Address, u64)>,
        HashSet<BidirectionalTxId>,
    ) {
        let mut events = Vec::new();
        let mut consumed_slots = HashSet::new();
        let mut failed = HashSet::new();

        for (tx_id, sign_id, pending_tx, result) in
            self.fetch_watcher_receipts(mined, block_number).await
        {
            match result {
                Ok(BackfillOutcome::Observed { event }) => {
                    consumed_slots
                        .insert((Address::from(pending_tx.from_address), pending_tx.nonce));
                    if let Some(event) = event {
                        events.push(event);
                    }
                }
                Ok(BackfillOutcome::NotObserved) => {}
                Err(err) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "failed to fetch receipt for bidirectional tx mined in block"
                    );
                    failed.insert(tx_id);
                }
            }
        }

        (events, consumed_slots, failed)
    }

    /// Fails pending watchers whose (sender, nonce) slot was consumed by a
    /// different tx mined in this block: since only the network can sign for
    /// these sender addresses, the consuming tx is necessarily another
    /// watcher, making replacement a pure function of block content + local
    /// watcher state (no RPC, deterministic `block_height` across nodes).
    /// Returns the events and the remaining unmined watchers.
    fn resolve_replaced_siblings(
        unmined: Vec<WatcherEntry>,
        consumed_slots: &HashSet<(Address, u64)>,
        block_number: u64,
    ) -> (Vec<ChainEvent>, Vec<WatcherEntry>) {
        let (replaced, remaining): (Vec<_>, Vec<_>) =
            unmined.into_iter().partition(|(_, (_, tx))| {
                consumed_slots.contains(&(Address::from(tx.from_address), tx.nonce))
            });

        let events = replaced
            .into_iter()
            .map(|(tx_id, (sign_id, tx))| {
                tracing::warn!(
                    ?tx_id,
                    ?sign_id,
                    nonce = tx.nonce,
                    "transaction replaced by sibling tx mined in this block"
                );
                ChainEvent::ExecutionConfirmed {
                    tx_id,
                    sign_id,
                    source_chain: tx.source_chain,
                    block_height: block_number,
                    result: ExecutionOutcome::Failed,
                }
            })
            .collect();

        (events, remaining)
    }

    /// Nonce-gates unmined watchers: fetches deduped sender nonces, then
    /// resolves watchers whose nonce was consumed. Returns emitted events and
    /// watchers whose RPC attempt failed.
    async fn resolve_gated_watchers(
        &self,
        gated: Vec<WatcherEntry>,
        block_number: u64,
    ) -> (Vec<ChainEvent>, HashSet<BidirectionalTxId>) {
        let unique_senders: HashSet<_> = gated
            .iter()
            .map(|(_, (_, tx))| Address::from(tx.from_address))
            .collect();

        // Failed senders are skipped: their watchers stay pending and are
        // retried on the next block.
        let mut nonces = HashMap::new();
        let mut failed = HashSet::new();
        for (sender, result) in self.fetch_sender_nonces(unique_senders, block_number).await {
            match result {
                Ok(nonce) => {
                    nonces.insert(sender, nonce);
                }
                Err(err) => {
                    tracing::warn!(?sender, ?err, "failed to fetch nonce for bidirectional tx");
                    failed.extend(
                        gated
                            .iter()
                            .filter(|(_, (_, tx))| Address::from(tx.from_address) == sender)
                            .map(|(tx_id, _)| *tx_id),
                    );
                }
            }
        }

        // Keep ONLY watchers whose nonces were consumed
        let consumed_txs: Vec<_> = gated
            .into_iter()
            .filter(|(_, (_, tx))| {
                nonces
                    .get(&Address::from(tx.from_address))
                    .is_some_and(|&current_nonce| tx.nonce < current_nonce)
            })
            .collect();

        let mut events = Vec::new();
        for (tx_id, sign_id, pending_tx, result) in self
            .fetch_watcher_receipts(consumed_txs, block_number)
            .await
        {
            match result {
                Ok(BackfillOutcome::Observed { event }) => {
                    if let Some(event) = event {
                        events.push(event); // Late watcher pickup
                    }
                }
                Ok(BackfillOutcome::NotObserved) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        expected_nonce = pending_tx.nonce,
                        "transaction replaced or dropped (nonce consumed by another tx)"
                    );
                    events.push(ChainEvent::ExecutionConfirmed {
                        tx_id,
                        sign_id,
                        source_chain: pending_tx.source_chain,
                        block_height: block_number,
                        result: ExecutionOutcome::Failed,
                    });
                }
                Err(err) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "failed to fetch receipt for nonce-consumed bidirectional tx"
                    );
                    failed.insert(tx_id);
                }
            }
        }

        (events, failed)
    }

    /// Emits the processed block in-order once we reach finality for it.
    async fn emit_processed_block(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        BlockAndRequests {
            block_number,
            block_hash,
            block_timestamp,
            indexed_requests,
            respond_logs,
            execution_events,
        }: BlockAndRequests,
    ) -> anyhow::Result<()> {
        // Optimistic mode is for demos/integration tests only: dev chains
        // never report finality (so the wait would hang) and never reorg
        // (so skipping the wait cannot emit stale events there).
        if !self.eth.optimistic_requests {
            self.wait_for_finalized_block(block_number).await?;
        }

        // Reorg hash-check: only for blocks not covered by the finalized head.
        if *self.finalized_head.borrow() < block_number {
            let block = self
                .client
                .as_ref()
                .get_block(BlockId::Number(BlockNumberOrTag::Number(block_number)))
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("ethereum block {block_number} not found during emission")
                })?;

            if block.header.hash != block_hash {
                // The block was reorged after `process_block` produced this payload.
                // Do not emit stale events for a different canonical block, but also do
                // not return an error that would cause the catchup path to retry this
                // same stale payload forever.
                return Ok(());
            }
        }

        for event in execution_events {
            events_tx
                .send(event)
                .await
                .context("failed to emit ExecutionConfirmed event")?;
        }

        for request in indexed_requests {
            events_tx
                .send(ChainEvent::SignRequest {
                    request,
                    block_timestamp: Some(block_timestamp),
                })
                .await
                .context("failed to emit SignRequest event")?;
        }

        if !respond_logs.is_empty() {
            emit_respond_events(&respond_logs, events_tx.clone()).await;
        }

        events_tx
            .send(ChainEvent::Block(block_number))
            .await
            .context("failed to emit block event")?;

        Ok(())
    }

    /// Retries `process_catchup_item` with `RETRY_DELAY` backoff until it
    /// succeeds or `cancel` fires.
    async fn process_catchup_retrying(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        item: &CatchupItem,
        cancel: &CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                result = self.process_catchup_item(events_tx, item) => {
                    match result {
                        Ok(()) => return,
                        Err(err) => {
                            tracing::warn!(?err, "ethereum catchup block processing failed; retrying");
                        }
                    }
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = sleep(Self::RETRY_DELAY) => {}
            }
        }
    }

    /// Retries `process_live_item` with `RETRY_DELAY` backoff until it
    /// succeeds or `cancel` fires.
    async fn process_live_retrying(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        item: &CatchupItem,
        cancel: &CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                result = self.process_live_item(events_tx, item) => {
                    match result {
                        Ok(()) => return,
                        Err(err) => {
                            tracing::warn!(?err, "ethereum live block processing failed; retrying");
                        }
                    }
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = sleep(Self::RETRY_DELAY) => {}
            }
        }
    }

    /// Catchup blocks in `[processed + 1, anchor_height)` fetched in batches.
    /// Samples the finalized head once at catchup start, so blocks at or below
    /// it can skip the per-block re-fetch + reorg hash check.
    pub async fn catchup_blocks(
        &self,
        anchor_height: u64,
    ) -> std::pin::Pin<Box<dyn Stream<Item = CatchupItem> + Send + 'static>> {
        #[cfg(feature = "bench")]
        crate::bench::rpc_reset();

        // TODO: start from genesis block of contract deployment instead of
        // anchor_height so that we can start from the very beginning of
        // the history of the network in case where we do not have a checkpoint.
        // https://github.com/sig-net/mpc/issues/777
        let current_block = self
            .state_manager
            .get_processed_block(Chain::Ethereum)
            .await
            .map(|n| n.saturating_add(1))
            .unwrap_or(anchor_height);
        let catchup_start = self
            .client
            .clamp_oldest_supported(current_block, anchor_height);

        let catchup_iter = CatchupIter::new(
            self.client.clone(),
            catchup_start,
            anchor_height,
            self.contract_address,
            self.eth.indexer.catchup_block_batch_size,
        );

        // Convert the async state machine into a Stream
        let stream = stream::unfold(catchup_iter, |mut state| async move {
            let item = state.next().await;
            item.map(|block| (block, state))
        });

        Box::pin(stream)
    }

    /// Process a single catchup item (batch block, missing-block refetch, or
    /// live block) and emit its events.
    pub async fn process_catchup_item(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        item: &CatchupItem,
    ) -> anyhow::Result<()> {
        // NOTE: oh rust: needed otherwise the block gets dropped before we can use
        // it, since it `block` is of reference type. Maybe the language will let
        // us elide this in the future, but for now we need to introduce a new var.
        let _block;
        let _logs;

        let (block, logs) = match item {
            CatchupItem::BatchBlock { block, logs } => (block, logs.as_slice()),
            CatchupItem::Missing(block_id) => {
                tracing::warn!(
                    ?block_id,
                    "ethereum catchup block missing from batch; refetching"
                );

                #[cfg(feature = "bench")]
                let start = std::time::Instant::now();

                // Refetch the block, then bloom-gate a single-block `eth_getLogs`.
                let block = self.client.get_block(*block_id).await?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "ethereum catchup block {block_id:?} is still unavailable after refetch"
                    )
                })?;
                let l = self.fetch_block_logs(&block).await?;

                #[cfg(feature = "bench")]
                crate::bench::add_refetch_time(start.elapsed());

                _block = block;
                _logs = l;
                (&_block, _logs.as_slice())
            }
            CatchupItem::LiveBlock(block) => {
                _logs = self.fetch_block_logs(block).await?;
                (block, _logs.as_slice())
            }
        };

        let height = block.header.number;
        if height.is_multiple_of(10) {
            tracing::info!(height, "processed ethereum catchup block attempt");
        }

        #[cfg(feature = "bench")]
        let start_process = std::time::Instant::now();

        self.process_block(events_tx, block, logs).await?;

        #[cfg(feature = "bench")]
        {
            crate::bench::add_process_time(start_process.elapsed());
            if crate::bench::inc_block() % 100 == 0 {
                crate::bench::report_metrics("catchup_progress");
            }
        }

        Ok(())
    }

    /// Process a single live item and emit its events, keeping the reorg hash
    /// check (live blocks are not yet finalized).
    async fn process_live_item(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        item: &CatchupItem,
    ) -> anyhow::Result<()> {
        let _block;
        let _logs;

        let (block, logs) = match item {
            CatchupItem::LiveBlock(block) => {
                _logs = self.fetch_block_logs(block).await?;
                (block, _logs.as_slice())
            }
            CatchupItem::BatchBlock { block, logs } => (block, logs.as_slice()),
            CatchupItem::Missing(block_id) => {
                let block = self
                    .client
                    .get_block(*block_id)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "ethereum live stream yielded missing block {block_id:?} and refetch failed"
                        )
                    })?;
                _logs = self.fetch_block_logs(&block).await?;
                _block = block;
                (&_block, _logs.as_slice())
            }
        };

        self.process_block(events_tx, block, logs).await?;
        Ok(())
    }

    /// Blocks until the cached finalized head (`self.finalized_head`, maintained
    /// by `watch_finalized_head`) covers `block_number`.
    async fn wait_for_finalized_block(&self, block_number: BlockNumber) -> anyhow::Result<()> {
        // Fast path: the cached head already covers this block.
        if *self.finalized_head.borrow() >= block_number {
            return Ok(());
        }

        // Slow path: wait for the watcher to publish an advance
        let mut rx = self.finalized_head.subscribe();
        loop {
            if *rx.borrow_and_update() >= block_number {
                return Ok(());
            }
            if rx.changed().await.is_err() {
                anyhow::bail!(
                    "finalized-head watcher terminated before block {block_number} finalized"
                );
            }
        }
    }

    /// Spawn the background finalized-head watcher that maintains `finalized_head`.
    ///
    /// Returns a guard whose drop aborts the task, or `None` in optimistic mode
    /// (dev chains never report a finalized head).
    pub fn spawn_finalized_head_watcher(&self, cancel: CancellationToken) -> Option<AbortOnDrop> {
        (!self.eth.optimistic_requests).then(|| {
            AbortOnDrop(tokio::spawn(Self::watch_finalized_head(
                self.client.clone(),
                self.finalized_head.clone(),
                self.eth.refresh_finalized_interval,
                self.eth.indexer.max_finalized_failures,
                self.eth.indexer.stall_rewarn_secs,
                cancel,
            )))
        })
    }

    // TODO: Currently if this dies silently we have to wait 35 min for the stream supervisor to restart it. Implement faster failure detection and restart.
    /// Background task maintaining the cached finalized head (`self.finalized_head`).
    ///
    /// Polls `eth_getBlockByNumber(Finalized)` on `refresh_finalized_interval`
    /// and publishes advances over the `watch` channel.
    ///
    /// Retries forever, the stream supervisor watchdog remains the
    /// escape hatch.
    async fn watch_finalized_head(
        client: Arc<EthereumClient>,
        head: watch::Sender<u64>,
        refresh_interval_ms: u64,
        max_failures: u32,
        stall_rewarn_secs: u64,
        cancel: CancellationToken,
    ) {
        let interval = Duration::from_millis(refresh_interval_ms);
        let mut stall = FinalizedHeadStall::new(
            Chain::Ethereum.expected_finality_time_secs(),
            stall_rewarn_secs,
        );
        let mut failures = 0u32;

        tracing::info!("ethereum finalized-head watcher started");

        loop {
            match client
                .get_block(BlockId::Number(BlockNumberOrTag::Finalized))
                .await
            {
                Ok(Some(block)) => {
                    failures = 0;
                    let new_final = block.header.number;
                    stall.observe(new_final);
                    head.send_if_modified(|cur| {
                        if new_final > *cur {
                            *cur = new_final;
                            true
                        } else {
                            false
                        }
                    });
                }
                Ok(None) => {
                    tracing::warn!(
                        "ethereum get_block(Finalized) returned no block; watcher keeps retrying"
                    );
                }
                Err(err) => {
                    failures = failures.saturating_add(1);
                    tracing::warn!(
                        ?err,
                        failures,
                        max_failures,
                        "ethereum get_block(Finalized) failed; watcher keeps retrying"
                    );
                }
            }

            if sleep_or_cancel(&cancel, interval).await {
                return;
            }
        }
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for EthereumIndexer<S, T> {
    const CHAIN: Chain = Chain::Ethereum;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Anchor: the live task starts here once catchup reaches it.
        let anchor_height = loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            match self.client.get_latest_block_number().await {
                Ok(Some(latest)) => break latest.saturating_add(1),
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!(?err, "ethereum latest block fetch failed");
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = sleep(Self::RETRY_DELAY) => {}
            }
        };

        let _finalized_watcher = self.spawn_finalized_head_watcher(cancel.clone());

        let mut catchup_iter = self.catchup_blocks(anchor_height).await;
        loop {
            let item = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                item = catchup_iter.next() => item,
            };
            let Some(item) = item else { break };
            self.process_catchup_retrying(&events_tx, &item, &cancel)
                .await;
        }

        events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send catchup completed event")?;

        // Spawned only after catchup: no catchup/live coordination needed, and
        // the abort-on-drop guard ties the task's lifetime to this `run()`.
        let (live_blocks_tx, mut live_blocks_rx) =
            mpsc::channel(self.eth.indexer.live_block_buffer);
        let _live_task = AbortOnDrop(tokio::spawn(Self::index_live_blocks(
            self.client.clone(),
            anchor_height,
            live_blocks_tx,
        )));

        loop {
            let maybe = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                maybe = live_blocks_rx.recv() => maybe,
            };
            let Some(maybe) = maybe else {
                anyhow::bail!("ethereum live block producer terminated");
            };
            let item = match maybe {
                MaybeBlock::Block(block) => CatchupItem::LiveBlock(block),
                MaybeBlock::Missing(id) => CatchupItem::Missing(id),
            };
            self.process_live_retrying(&events_tx, &item, &cancel).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::client::CatchupItem;
    use crate::test_utils;
    use alloy::eips::BlockNumberOrTag;
    use alloy::primitives::{address, b256};
    use alloy::rpc::types::{Block, BlockId, BlockTransactions};
    use mockito::{Matcher, Server};
    use mpc_chain_integration_core::utils::stream::chain_event_channel;
    use mpc_chain_integration_core::{ChainIndexer, StateManager};
    use mpc_primitives::{
        BidirectionalTx, BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome, SignId,
        LATEST_MPC_KEY_VERSION,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn missing_catchup_block_is_refetched() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": ["0xc", false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(1, 12).to_string())
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getLogs".to_string()))
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();

        indexer
            .process_catchup_item(
                &events_tx,
                &CatchupItem::Missing(BlockId::Number(BlockNumberOrTag::Number(12))),
            )
            .await
            .expect("missing catchup block should be refetched successfully");

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(12))
        ));
    }

    #[tokio::test]
    async fn catchup_batch_logs_skipped_on_empty_bloom() {
        let mut server = Server::new_async().await;

        // 32-block catchup: blocks have empty blooms so the batch issues exactly
        // 1 eth_getBlockByNumber(batch) and ZERO eth_getLogs (bloom gate skips).
        let blocks: Vec<_> = (1..=32)
            .map(|n| test_utils::block_response(n as u64, n as u64))
            .collect();
        let blocks_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(blocks).to_string())
            .expect(1)
            .create_async()
            .await;

        let logs_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getLogs".to_string()))
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();
        // Ensure blocks are considered finalized to avoid reorg-check refetches in process_catchup
        indexer.finalized_head.send_replace(100);

        let mut iter = crate::client::CatchupIter::new(
            indexer.client.clone(),
            1,
            33,
            indexer.contract_address,
            indexer.eth.indexer.catchup_block_batch_size,
        );
        for n in 1..=32 {
            let item = iter.next().await.expect("expected item");
            indexer
                .process_catchup_item(&events_tx, &item)
                .await
                .expect("processing batch block should succeed");

            assert!(matches!(
                events_rx.recv().await,
                Some(ChainEvent::Block(b)) if b == n
            ));
        }

        blocks_mock.assert_async().await;
        logs_mock.assert_async().await;
    }

    #[tokio::test]
    async fn catchup_batch_receipts_preserves_order() {
        let mut server = Server::new_async().await;

        // Mock batch receipt responses deliberately out-of-order by id
        let blocks_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    test_utils::block_response(1, 10),
                    test_utils::block_response(2, 11)
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let logs_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getLogs".to_string()))
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();
        indexer.finalized_head.send_replace(100);

        let mut iter = crate::client::CatchupIter::new(
            indexer.client.clone(),
            10,
            12,
            indexer.contract_address,
            indexer.eth.indexer.catchup_block_batch_size,
        );

        let item1 = iter.next().await.unwrap();
        indexer
            .process_catchup_item(&events_tx, &item1)
            .await
            .unwrap();
        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(10))
        ));

        let item2 = iter.next().await.unwrap();
        indexer
            .process_catchup_item(&events_tx, &item2)
            .await
            .unwrap();
        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(11))
        ));

        blocks_mock.assert_async().await;
        logs_mock.assert_async().await;
    }

    #[tokio::test]
    async fn catchup_missing_block_falls_back_to_single_logs_fetch() {
        let mut server = Server::new_async().await;
        let block_number = 12;

        // One Missing in the batch;
        // assert process_catchup does 1 get_block + 1 single eth_getBlockReceipts for that block.
        let block_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": [format!("0x{block_number:x}"), false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(1, block_number).to_string())
            .expect(1) // Should only be fetched once because we consider it finalized
            .create_async()
            .await;

        let logs_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getLogs".to_string()))
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();

        // Ensure block is considered finalized to avoid the reorg-check refetch
        indexer.finalized_head.send_replace(100);

        let item = CatchupItem::Missing(BlockId::Number(BlockNumberOrTag::Number(block_number)));
        indexer
            .process_catchup_item(&events_tx, &item)
            .await
            .expect("processing missing block should succeed with refetch");

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(n)) if n == block_number
        ));

        block_mock.assert_async().await;
        logs_mock.assert_async().await;
    }

    #[tokio::test]
    async fn catchup_batch_receipts_null_treated_as_empty() {
        let mut server = Server::new_async().await;
        let block_number = 42;

        // A batch receipts response with null
        let blocks_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!([test_utils::block_response(1, block_number)]).to_string())
            .expect(1)
            .create_async()
            .await;

        let logs_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getLogs".to_string()))
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();
        // Ensure block is considered finalized to avoid the reorg-check refetch
        indexer.finalized_head.send_replace(100);

        let mut iter = crate::client::CatchupIter::new(
            indexer.client.clone(),
            42,
            43,
            indexer.contract_address,
            indexer.eth.indexer.catchup_block_batch_size,
        );
        let item = iter.next().await.unwrap();

        indexer
            .process_catchup_item(&events_tx, &item)
            .await
            .expect("processing batch block with null receipts (normalized) should succeed");

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(n)) if n == block_number
        ));

        blocks_mock.assert_async().await;
        logs_mock.assert_async().await;
    }

    #[tokio::test]
    async fn live_process_fetches_logs_singly() {
        let mut server = Server::new_async().await;
        let block_number = 42;
        let item = test_utils::live_block(block_number);
        let CatchupItem::LiveBlock(_) = &item else {
            unreachable!()
        };

        // Live path with an empty-bloom block: the bloom gate skips the
        // eth_getLogs fetch entirely.
        let logs_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getLogs".to_string()))
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        // Reorg check also happens for live blocks.
        let reorg_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(2, block_number).to_string())
            .expect(1)
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();

        indexer
            .process_live_item(&events_tx, &item)
            .await
            .expect("live process should succeed");

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(n)) if n == block_number
        ));

        logs_mock.assert_async().await;
        reorg_mock.assert_async().await;
    }

    #[tokio::test]
    async fn missing_catchup_block_returns_error_when_refetch_returns_null() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":null}"#)
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();

        let err = indexer
            .process_catchup_item(
                &events_tx,
                &CatchupItem::Missing(BlockId::Number(BlockNumberOrTag::Number(12))),
            )
            .await
            .expect_err("missing catchup block should fail when refetch returns no block");

        assert!(events_rx.try_recv().is_err());
        assert!(err.to_string().contains("still unavailable after refetch"));
    }

    #[tokio::test]
    async fn missing_catchup_block_propagates_error_when_refetch_rpc_fails() {
        let indexer = test_utils::TestIndexerBuilder::new("http://127.0.0.1:1")
            .client_url("http://127.0.0.1:1")
            .rpc_urls("", "http://127.0.0.1:1")
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();

        let err = indexer
            .process_catchup_item(
                &events_tx,
                &CatchupItem::Missing(BlockId::Number(BlockNumberOrTag::Number(12))),
            )
            .await
            .expect_err("missing catchup block should fail when refetch RPC fails");

        assert!(events_rx.try_recv().is_err());
        // The underlying RPC error propagates
        assert!(err.to_string().contains("error sending request"));
    }

    #[tokio::test]
    async fn catchup_finalized_block_does_not_refetch_for_emission() {
        let mut server = Server::new_async().await;

        let item = test_utils::batch_block(42, vec![]);
        let CatchupItem::BatchBlock { block, .. } = &item else {
            unreachable!("test_utils::batch_block returns CatchupItem::BatchBlock")
        };
        let block_number = block.header.number;

        // `eth_getBlockByNumber(Number)` for the same block — must NEVER be hit,
        // because this catchup block is at or below the finalized head sampled at
        // catchup start, so the reorg check is skipped.
        let block_by_number_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": [format!("0x{block_number:x}"), false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(3, block_number).to_string())
            .expect(0)
            .create_async()
            .await;

        // Optimistic mode (default) so `wait_for_finalized_block` is skipped.
        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();
        // Block 42 was finalized at fetch time (head sampled at 100), so the
        // re-fetch + reorg check is skipped.
        indexer.finalized_head.send_replace(100);

        indexer
            .process_catchup_item(&events_tx, &item)
            .await
            .expect("catchup over a present finalized block should succeed");

        block_by_number_mock.assert_async().await;

        // The block event must still be emitted.
        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(n)) if n == block_number
        ));
    }

    #[tokio::test]
    async fn catchup_unfinalized_block_keeps_reorg_check() {
        let mut server = Server::new_async().await;

        let item = test_utils::batch_block(42, vec![]);
        let CatchupItem::BatchBlock { block, .. } = &item else {
            unreachable!("test_utils::batch_block returns CatchupItem::BatchBlock")
        };
        let block_number = block.header.number;

        // `eth_getBlockByNumber(Number)` — expected once: block 42 is above the
        // sampled finalized head (10), so the check runs. Matching hash → emit.
        let block_by_number_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": [format!("0x{block_number:x}"), false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(3, block_number).to_string())
            .expect(1)
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();
        // Finalized head sampled at 10 → block 42 is unfinalized at fetch time.
        indexer.finalized_head.send_replace(10);

        indexer
            .process_catchup_item(&events_tx, &item)
            .await
            .expect("catchup over an unfinalized block should succeed");

        block_by_number_mock.assert_async().await;

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(n)) if n == block_number
        ));
    }

    #[tokio::test]
    async fn live_process_refetches_block_for_reorg_check() {
        let mut server = Server::new_async().await;

        let item = test_utils::live_block(42);
        let CatchupItem::LiveBlock(block) = &item else {
            unreachable!("test_utils::live_block returns CatchupItem::LiveBlock")
        };
        let block_number = block.header.number;

        let logs_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getLogs".to_string()))
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        // `eth_getBlockByNumber(Number)` — expected once for the reorg check.
        // Returns the same block (matching hash) so emission proceeds.
        let reorg_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": [format!("0x{block_number:x}"), false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(3, block_number).to_string())
            .expect(1)
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();

        indexer
            .process_live_item(&events_tx, &item)
            .await
            .expect("live process over a block should succeed");

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(n)) if n == block_number
        ));

        logs_mock.assert_async().await;
        reorg_mock.assert_async().await;
    }

    #[tokio::test]
    async fn live_process_skips_emission_when_block_reorged() {
        let mut server = Server::new_async().await;

        let item = test_utils::live_block(42);
        let CatchupItem::LiveBlock(block) = &item else {
            unreachable!("test_utils::live_block returns CatchupItem::LiveBlock")
        };
        let block_number = block.header.number;

        let logs_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getLogs".to_string()))
            .expect(0)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        // Re-fetch returns a block with a DIFFERENT number/hash (99), so the
        // hash comparison fails and emission is skipped.
        let reorg_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": [format!("0x{block_number:x}"), false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(3, 99).to_string())
            .expect(1)
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();

        indexer
            .process_live_item(&events_tx, &item)
            .await
            .expect("reorged live block should not error");

        // No events should be emitted for the reorged block.
        assert!(
            events_rx.try_recv().is_err(),
            "no events should be emitted for a reorged live block"
        );

        logs_mock.assert_async().await;
        reorg_mock.assert_async().await;
    }

    #[tokio::test]
    async fn wait_for_finalized_block_skips_rpc_when_head_covers_block() {
        let mut server = Server::new_async().await;

        // The cached head covers the block, so no eth_getBlockByNumber(Finalized)
        // should be issued at all.
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": ["finalized", false]
            })))
            .expect(0)
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .optimistic_requests(false)
            .build()
            .await;

        indexer.finalized_head.send_replace(100);

        indexer
            .wait_for_finalized_block(42)
            .await
            .expect("head covers block; should return without an RPC");
    }

    #[tokio::test]
    async fn wait_for_finalized_block_resolves_when_head_advances() {
        let server = Server::new_async().await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .optimistic_requests(false)
            .build()
            .await;

        // Head starts at 0; the wait must block until the head advances past 50.
        let head = indexer.finalized_head.clone();
        let advancer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            head.send_replace(100);
        });

        indexer
            .wait_for_finalized_block(50)
            .await
            .expect("should resolve once the head advances past the block");

        advancer.await.unwrap();
    }

    #[tokio::test]
    async fn watch_finalized_head_advances_head_and_unblocks_waiter() {
        let mut server = Server::new_async().await;

        // The watcher polls eth_getBlockByNumber(finalized); serve a head past 50.
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": ["finalized", false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(1, 100).to_string())
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .optimistic_requests(false)
            .build()
            .await;

        let cancel = CancellationToken::new();
        let _watcher = indexer.spawn_finalized_head_watcher(cancel.clone());

        indexer
            .wait_for_finalized_block(50)
            .await
            .expect("watcher should advance the head past 50 and unblock the wait");

        cancel.cancel();
    }

    #[tokio::test]
    async fn late_watcher_backfill_uses_tx_hash_and_mined_block() {
        let mut server = Server::new_async().await;

        let tx_hash = b256!("018b2331d461a4aeedf6a1f9cc37463377578244e6a35216057a8370714e798f");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let to_address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");

        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x2",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{to_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Mock Nonce Call: Block height 10 ("0xa"), returning current nonce 1
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0xa"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" }).to_string())
            .create_async()
            .await;

        // Mock Receipt Call
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": receipt_response,
                })
                .to_string(),
            )
            .create_async()
            .await;

        let sign_id = SignId::new([0x55; 32]);
        let tx = BidirectionalTx {
            id: BidirectionalTxId(tx_hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: sign_id.request_id,
            from_address: **from_address,
            nonce: 0,
        };

        let builder = test_utils::TestIndexerBuilder::new(server.url());
        builder
            .state_manager
            .watch_execution(Chain::Ethereum, sign_id, tx)
            .await;
        let indexer = builder.build().await;

        // Construct mock block at height 10 (triggers modulo 10 check)
        let mut block: Block = Block::default();
        block.header.number = 10;
        block.transactions = BlockTransactions::Hashes(Vec::new());

        let events = indexer
            .collect_execution_confirmations(&block)
            .await
            .expect("late watcher backfill should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id: event_tx_id,
                sign_id: event_sign_id,
                source_chain,
                block_height,
                result,
            } => {
                assert_eq!(*event_tx_id, BidirectionalTxId(tx_hash.0));
                assert_eq!(*event_sign_id, sign_id);
                assert_eq!(*source_chain, Chain::Solana);
                assert_eq!(*block_height, 2);
                assert!(matches!(result, ExecutionOutcome::Failed));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }
    }

    /// JSON-RPC response for a single `eth_getBlockByNumber` request, echoing
    /// the request id.
    fn block_reply(req: &mockito::Request, number: u64) -> Vec<u8> {
        let body: serde_json::Value =
            serde_json::from_slice(req.body().expect("request body")).expect("json body");
        let id = body["id"].as_u64().expect("request id");
        test_utils::block_response(id, number)
            .to_string()
            .into_bytes()
    }

    /// Fixture for running the indexer in a test with a mock JSON-RPC server.
    /// Holds the mock server, latest block, and other state for running the indexer in tests.
    struct RunFixture {
        _server: mockito::ServerGuard,
        latest: Arc<AtomicU64>,
        /// Highest block number fetched by number, used to detect producer
        /// activity after cancellation.
        max_requested_block: Arc<AtomicU64>,
        cancel: CancellationToken,
        run_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
        events_rx: mpsc::Receiver<ChainEvent>,
    }

    impl RunFixture {
        async fn spawn(processed: u64, latest: u64) -> Self {
            let mut server = Server::new_async().await;
            let latest = Arc::new(AtomicU64::new(latest));
            let max_requested_block = Arc::new(AtomicU64::new(0));

            // Anchor sampling + live head polling.
            server
                .mock("POST", "/")
                .match_body(Matcher::PartialJson(json!({
                    "method": "eth_getBlockByNumber",
                    "params": ["latest", false]
                })))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body_from_request({
                    let latest = latest.clone();
                    move |req| block_reply(req, latest.load(Ordering::Relaxed))
                })
                .create_async()
                .await;

            // Finalized head sampled once at catchup start; tracking `latest`
            // means catchup blocks skip the reorg refetch.
            server
                .mock("POST", "/")
                .match_body(Matcher::PartialJson(json!({
                    "method": "eth_getBlockByNumber",
                    "params": ["finalized", false]
                })))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body_from_request({
                    let latest = latest.clone();
                    move |req| block_reply(req, latest.load(Ordering::Relaxed))
                })
                .create_async()
                .await;

            // Catchup batches (JSON-RPC array body): derive ids and block
            // numbers from the request.
            server
                .mock("POST", "/")
                .match_body(Matcher::Regex(r"^\[".to_string()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body_from_request(|req| {
                    let body: serde_json::Value =
                        serde_json::from_slice(req.body().expect("request body"))
                            .expect("json body");
                    let items = body
                        .as_array()
                        .expect("batch body")
                        .iter()
                        .map(|r| {
                            let id = r["id"].as_u64().expect("request id");
                            let hex = r["params"][0].as_str().expect("block number param");
                            let number = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
                                .expect("hex block number");
                            test_utils::block_response(id, number)
                        })
                        .collect();
                    serde_json::Value::Array(items).to_string().into_bytes()
                })
                .create_async()
                .await;

            // Single-block fetches by number (live fetch + reorg refetch).
            server
                .mock("POST", "/")
                .match_body(Matcher::Regex(r#"^\{.*"params":\["0x"#.to_string()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body_from_request({
                    let max_requested_block = max_requested_block.clone();
                    move |req| {
                        let body: serde_json::Value =
                            serde_json::from_slice(req.body().expect("request body"))
                                .expect("json body");
                        let id = body["id"].as_u64().expect("request id");
                        let hex = body["params"][0].as_str().expect("block number param");
                        let number = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
                            .expect("hex block number");
                        max_requested_block.fetch_max(number, Ordering::Relaxed);
                        test_utils::block_response(id, number)
                            .to_string()
                            .into_bytes()
                    }
                })
                .create_async()
                .await;

            let builder = test_utils::TestIndexerBuilder::new(server.url());
            builder
                .state_manager
                .set_processed_block(Chain::Ethereum, processed)
                .await;
            let indexer = builder.build().await;

            let (events_tx, events_rx) = chain_event_channel();
            let cancel = CancellationToken::new();
            let run_handle = tokio::spawn({
                let cancel = cancel.clone();
                async move { indexer.run(events_tx, cancel).await }
            });

            Self {
                _server: server,
                latest,
                max_requested_block,
                cancel,
                run_handle,
                events_rx,
            }
        }

        async fn next_event(&mut self) -> ChainEvent {
            tokio::time::timeout(Duration::from_secs(5), self.events_rx.recv())
                .await
                .expect("timed out waiting for chain event")
                .expect("events channel closed")
        }

        async fn cancel_and_join(&mut self) {
            self.cancel.cancel();
            tokio::time::timeout(Duration::from_secs(5), &mut self.run_handle)
                .await
                .expect("run() should stop promptly after cancel")
                .expect("run task panicked")
                .expect("run() should exit Ok on cancel");
        }
    }

    #[tokio::test]
    async fn run_processes_catchup_range_in_order() {
        let mut f = RunFixture::spawn(5, 9).await;

        for n in 6..=9 {
            let event = f.next_event().await;
            assert!(
                matches!(event, ChainEvent::Block(b) if b == n),
                "expected Block({n}), got {event:?}"
            );
        }
        let event = f.next_event().await;
        assert!(
            matches!(event, ChainEvent::CatchupCompleted),
            "expected CatchupCompleted, got {event:?}"
        );

        f.cancel_and_join().await;
    }

    #[tokio::test]
    async fn run_emits_live_blocks_after_catchup_completed() {
        let mut f = RunFixture::spawn(9, 9).await;
        assert!(matches!(f.next_event().await, ChainEvent::CatchupCompleted));

        f.latest.store(10, Ordering::Relaxed);
        let event = f.next_event().await;
        assert!(
            matches!(event, ChainEvent::Block(10)),
            "expected Block(10), got {event:?}"
        );

        f.cancel_and_join().await;
    }

    #[tokio::test]
    async fn run_stops_promptly_on_cancel_while_live() {
        let mut f = RunFixture::spawn(9, 9).await;
        assert!(matches!(f.next_event().await, ChainEvent::CatchupCompleted));
        f.cancel_and_join().await;
    }

    #[tokio::test]
    async fn run_stops_promptly_on_cancel_during_catchup() {
        let mut f = RunFixture::spawn(0, 500).await;
        f.cancel_and_join().await;
    }

    #[tokio::test]
    async fn cancel_aborts_live_block_producer() {
        let mut f = RunFixture::spawn(9, 9).await;
        assert!(matches!(f.next_event().await, ChainEvent::CatchupCompleted));

        f.latest.store(10, Ordering::Relaxed);
        assert!(matches!(f.next_event().await, ChainEvent::Block(10)));

        f.cancel_and_join().await;

        // The live producer ticks every RETRY_DELAY (500ms); if it survived
        // run() it would fetch block 11 well within this window.
        let max_at_cancel = f.max_requested_block.load(Ordering::Relaxed);
        f.latest.store(11, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            f.max_requested_block.load(Ordering::Relaxed),
            max_at_cancel,
            "live block producer survived run() cancellation"
        );
    }

    #[tokio::test]
    async fn watcher_resolution_deduplicates_nonces_and_gates_receipts() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash_0 = b256!("0000000000000000000000000000000000000000000000000000000000000000");
        let tx_hash_1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let tx_hash_2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");

        // Mock Nonce Call: Expect exactly 1 call (deduplicated) for height 10 ("0xa"), returning nonce 2
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0xa"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x2" }).to_string())
            .expect(1)
            .create_async()
            .await;

        // Mock Receipts: Expect calls for tx_0 and tx_1. tx_2 should NOT be called.
        let receipt_mock_0 = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({ "method": "eth_getTransactionReceipt", "params": [format!("{tx_hash_0:#x}")] })))
            .with_status(200)
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string())
            .expect(1)
            .create_async().await;

        let receipt_mock_1 = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({ "method": "eth_getTransactionReceipt", "params": [format!("{tx_hash_1:#x}")] })))
            .with_status(200)
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string())
            .expect(1)
            .create_async().await;

        let receipt_mock_2 = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({ "method": "eth_getTransactionReceipt", "params": [format!("{tx_hash_2:#x}")] })))
            .with_status(200)
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string())
            .expect(0) // Nonce < current_nonce is false
            .create_async().await;

        // Setup Indexer & Watchers
        let builder = test_utils::TestIndexerBuilder::new(server.url());

        let create_tx = |hash: alloy::primitives::B256, nonce: u64| BidirectionalTx {
            id: BidirectionalTxId(hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: hash.0,
            from_address: **from_address,
            nonce,
        };

        builder
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([0; 32]),
                create_tx(tx_hash_0, 0),
            )
            .await;
        builder
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([1; 32]),
                create_tx(tx_hash_1, 1),
            )
            .await;
        builder
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([2; 32]),
                create_tx(tx_hash_2, 2),
            )
            .await;

        let indexer = builder.build().await;

        // Mock block at height 10
        let mut block: Block = Block::default();
        block.header.number = 10;
        block.transactions = BlockTransactions::Hashes(Vec::new());

        let events = indexer
            .collect_execution_confirmations(&block)
            .await
            .expect("should succeed");

        assert_eq!(
            events.len(),
            2,
            "Should emit 2 Failed events for consumed nonces"
        );

        nonce_mock.assert_async().await;
        receipt_mock_0.assert_async().await;
        receipt_mock_1.assert_async().await;
        receipt_mock_2.assert_async().await;
    }

    #[tokio::test]
    async fn watcher_resolution_uses_block_transactions_without_nonce_rpc() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("018b2331d461a4aeedf6a1f9cc37463377578244e6a35216057a8370714e798f");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");

        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x5",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Mock Receipt: EXPECT 1 call
        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        // Mock Nonce: EXPECT 0 calls (because the hash was found directly in the block!)
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getTransactionCount".to_string()))
            .expect(0)
            .create_async()
            .await;

        let sign_id = SignId::new([0x55; 32]);
        let tx = BidirectionalTx {
            id: BidirectionalTxId(tx_hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: sign_id.request_id,
            from_address: **from_address,
            nonce: 0,
        };

        let builder = test_utils::TestIndexerBuilder::new(server.url());
        builder
            .state_manager
            .watch_execution(Chain::Ethereum, sign_id, tx)
            .await;
        let indexer = builder.build().await;

        // Block height 5 (NOT a modulo 10 block), but contains tx_hash in block.transactions
        let mut block: Block = Block::default();
        block.header.number = 5;
        block.transactions = BlockTransactions::Hashes(vec![tx_hash]);

        let events = indexer
            .collect_execution_confirmations(&block)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1);
        receipt_mock.assert_async().await;
        nonce_mock.assert_async().await;
    }

    #[tokio::test]
    async fn watcher_resolution_tolerates_single_receipt_failure() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash_ok = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let tx_hash_err = b256!("2222222222222222222222222222222222222222222222222222222222222222");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");

        let receipt_response = json!({
            "transactionHash": format!("{tx_hash_ok:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x5",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        let receipt_ok_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash_ok:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        // Always fail; the test client retries, so assert it was hit at least once
        let receipt_err_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash_err:#x}")]
            })))
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let builder = test_utils::TestIndexerBuilder::new(server.url());

        let create_tx = |hash: alloy::primitives::B256| BidirectionalTx {
            id: BidirectionalTxId(hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: hash.0,
            from_address: **from_address,
            nonce: 0,
        };

        builder
            .state_manager
            .watch_execution(Chain::Ethereum, SignId::new([1; 32]), create_tx(tx_hash_ok))
            .await;
        builder
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([2; 32]),
                create_tx(tx_hash_err),
            )
            .await;

        let state_manager = builder.state_manager.clone();
        let indexer = builder.build().await;

        let mut block: Block = Block::default();
        block.header.number = 5;
        block.transactions = BlockTransactions::Hashes(vec![tx_hash_ok, tx_hash_err]);

        // One failing receipt must not fail the whole block
        let events = indexer
            .collect_execution_confirmations(&block)
            .await
            .expect("block processing should tolerate a single receipt failure");

        assert_eq!(
            events.len(),
            1,
            "only the successful receipt emits an event"
        );
        match &events[0] {
            ChainEvent::ExecutionConfirmed { tx_id, .. } => {
                assert_eq!(tx_id.0, tx_hash_ok.0);
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }

        // The failed watcher stays pending for a later retry
        let pending = state_manager.get_execution_watchers(Chain::Ethereum).await;
        assert!(
            pending.contains_key(&BidirectionalTxId(tx_hash_err.0)),
            "failed watcher should remain pending"
        );

        receipt_ok_mock.assert_async().await;
        receipt_err_mock.assert_async().await;
    }

    #[tokio::test]
    async fn watcher_resolution_tolerates_nonce_fetch_failure() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("3333333333333333333333333333333333333333333333333333333333333333");

        // Nonce fetch always fails; watcher must stay pending without events
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
            })))
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        // No receipt fetch should happen for an unmined tx whose nonce is unknown
        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getTransactionReceipt".to_string()))
            .expect(0)
            .create_async()
            .await;

        let tx = BidirectionalTx {
            id: BidirectionalTxId(tx_hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: tx_hash.0,
            from_address: **from_address,
            nonce: 0,
        };

        let builder = test_utils::TestIndexerBuilder::new(server.url());
        builder
            .state_manager
            .watch_execution(Chain::Ethereum, SignId::new([3; 32]), tx)
            .await;
        let state_manager = builder.state_manager.clone();
        let indexer = builder.build().await;

        // Block height 10 triggers the throttled nonce check
        let mut block: Block = Block::default();
        block.header.number = 10;
        block.transactions = BlockTransactions::Hashes(Vec::new());

        let events = indexer
            .collect_execution_confirmations(&block)
            .await
            .expect("nonce fetch failure should not fail block processing");

        assert!(events.is_empty());
        let pending = state_manager.get_execution_watchers(Chain::Ethereum).await;
        assert!(pending.contains_key(&BidirectionalTxId(tx_hash.0)));

        nonce_mock.assert_async().await;
        receipt_mock.assert_async().await;
    }

    #[tokio::test]
    async fn new_watcher_resolves_at_appearance_block() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("4444444444444444444444444444444444444444444444444444444444444444");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x3",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Nonce check pinned at block 5 (NOT a tick): one-shot
        // appearance gate fires immediately for newly seen watchers
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0x5"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" }).to_string())
            .expect(1)
            .create_async()
            .await;

        // Receipt shows the tx already mined at block 3 (before registration)
        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        let builder = test_utils::TestIndexerBuilder::new(server.url());
        builder
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([4; 32]),
                BidirectionalTx {
                    id: BidirectionalTxId(tx_hash.0),
                    sender: [0u8; 32],
                    serialized_transaction: vec![],
                    source_chain: Chain::Solana,
                    target_chain: Chain::Ethereum,
                    caip2_id: "eip155:31337".to_string(),
                    key_version: LATEST_MPC_KEY_VERSION,
                    deposit: 0,
                    path: "m/44'/60'/0'/0/0".to_string(),
                    algo: "secp256k1".to_string(),
                    dest: Chain::Ethereum.to_string(),
                    params: "{}".to_string(),
                    output_deserialization_schema: vec![],
                    respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
                    request_id: tx_hash.0,
                    from_address: **from_address,
                    nonce: 0,
                },
            )
            .await;
        let indexer = builder.build().await;

        let mut block: Block = Block::default();
        block.header.number = 5;
        block.transactions = BlockTransactions::Hashes(Vec::new());

        let events = indexer
            .collect_execution_confirmations(&block)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id,
                block_height,
                result,
                ..
            } => {
                assert_eq!(tx_id.0, tx_hash.0);
                assert_eq!(*block_height, 3, "event height is the mined block");
                assert!(matches!(result, ExecutionOutcome::Failed));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }

        nonce_mock.assert_async().await;
        receipt_mock.assert_async().await;
    }

    #[tokio::test]
    async fn failed_mined_receipt_retried_next_block() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("5555555555555555555555555555555555555555555555555555555555555555");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x5",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Phase 1 (block 5): receipt RPC fails
        let failing_receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let builder = test_utils::TestIndexerBuilder::new(server.url());
        builder
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([5; 32]),
                BidirectionalTx {
                    id: BidirectionalTxId(tx_hash.0),
                    sender: [0u8; 32],
                    serialized_transaction: vec![],
                    source_chain: Chain::Solana,
                    target_chain: Chain::Ethereum,
                    caip2_id: "eip155:31337".to_string(),
                    key_version: LATEST_MPC_KEY_VERSION,
                    deposit: 0,
                    path: "m/44'/60'/0'/0/0".to_string(),
                    algo: "secp256k1".to_string(),
                    dest: Chain::Ethereum.to_string(),
                    params: "{}".to_string(),
                    output_deserialization_schema: vec![],
                    respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
                    request_id: tx_hash.0,
                    from_address: **from_address,
                    nonce: 0,
                },
            )
            .await;
        let indexer = builder.build().await;

        let mut block5: Block = Block::default();
        block5.header.number = 5;
        block5.transactions = BlockTransactions::Hashes(vec![tx_hash]);

        let events = indexer
            .collect_execution_confirmations(&block5)
            .await
            .expect("receipt failure should not fail block processing");
        assert!(events.is_empty());
        failing_receipt_mock.assert_async().await;
        failing_receipt_mock.remove_async().await;

        // Phase 2 (block 6, NOT a tick): the failed watcher is retried via the
        // nonce gate without waiting for the next sweep
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0x6"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" }).to_string())
            .expect(1)
            .create_async()
            .await;

        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        let mut block6: Block = Block::default();
        block6.header.number = 6;
        block6.transactions = BlockTransactions::Hashes(Vec::new());

        let events = indexer
            .collect_execution_confirmations(&block6)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id,
                block_height,
                ..
            } => {
                assert_eq!(tx_id.0, tx_hash.0);
                assert_eq!(*block_height, 5, "event height is the mined block");
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }

        nonce_mock.assert_async().await;
        receipt_mock.assert_async().await;
    }

    #[tokio::test]
    async fn failed_nonce_fetch_retried_next_block() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("6666666666666666666666666666666666666666666666666666666666666666");

        // Phase 1 (block 10, tick): nonce fetch fails
        let failing_nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
            })))
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let builder = test_utils::TestIndexerBuilder::new(server.url());
        builder
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([6; 32]),
                BidirectionalTx {
                    id: BidirectionalTxId(tx_hash.0),
                    sender: [0u8; 32],
                    serialized_transaction: vec![],
                    source_chain: Chain::Solana,
                    target_chain: Chain::Ethereum,
                    caip2_id: "eip155:31337".to_string(),
                    key_version: LATEST_MPC_KEY_VERSION,
                    deposit: 0,
                    path: "m/44'/60'/0'/0/0".to_string(),
                    algo: "secp256k1".to_string(),
                    dest: Chain::Ethereum.to_string(),
                    params: "{}".to_string(),
                    output_deserialization_schema: vec![],
                    respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
                    request_id: tx_hash.0,
                    from_address: **from_address,
                    nonce: 0,
                },
            )
            .await;
        let indexer = builder.build().await;

        let mut block10: Block = Block::default();
        block10.header.number = 10;
        block10.transactions = BlockTransactions::Hashes(Vec::new());

        let events = indexer
            .collect_execution_confirmations(&block10)
            .await
            .expect("nonce failure should not fail block processing");
        assert!(events.is_empty());
        failing_nonce_mock.assert_async().await;
        failing_nonce_mock.remove_async().await;

        // Phase 2 (block 11, NOT a tick): retried via the nonce gate; nonce
        // consumed, no receipt -> Failed at block 11
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0xb"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" }).to_string())
            .expect(1)
            .create_async()
            .await;

        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string())
            .expect(1)
            .create_async()
            .await;

        let mut block11: Block = Block::default();
        block11.header.number = 11;
        block11.transactions = BlockTransactions::Hashes(Vec::new());

        let events = indexer
            .collect_execution_confirmations(&block11)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id,
                block_height,
                result,
                ..
            } => {
                assert_eq!(tx_id.0, tx_hash.0);
                assert_eq!(*block_height, 11);
                assert!(matches!(result, ExecutionOutcome::Failed));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }

        nonce_mock.assert_async().await;
        receipt_mock.assert_async().await;
    }

    #[tokio::test]
    async fn replaced_sibling_fails_at_replacement_block_without_rpc() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash_a = b256!("7777777777777777777777777777777777777777777777777777777777777777");
        let tx_hash_b = b256!("8888888888888888888888888888888888888888888888888888888888888888");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let receipt_response = json!({
            "transactionHash": format!("{tx_hash_a:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x5",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Phase 1 (block 4): both watchers appear; one-shot gate checks the
        // (deduped) sender once, nonce not yet consumed
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x0" }).to_string())
            .expect(1)
            .create_async()
            .await;

        let receipt_a_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash_a:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        // The replaced sibling must never be queried over RPC
        let receipt_b_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash_b:#x}")]
            })))
            .expect(0)
            .create_async()
            .await;

        let builder = test_utils::TestIndexerBuilder::new(server.url());
        let create_tx = |hash: alloy::primitives::B256| BidirectionalTx {
            id: BidirectionalTxId(hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: hash.0,
            from_address: **from_address,
            nonce: 0,
        };

        builder
            .state_manager
            .watch_execution(Chain::Ethereum, SignId::new([7; 32]), create_tx(tx_hash_a))
            .await;
        builder
            .state_manager
            .watch_execution(Chain::Ethereum, SignId::new([8; 32]), create_tx(tx_hash_b))
            .await;
        let indexer = builder.build().await;

        let mut block4: Block = Block::default();
        block4.header.number = 4;
        block4.transactions = BlockTransactions::Hashes(Vec::new());

        let events = indexer
            .collect_execution_confirmations(&block4)
            .await
            .expect("should succeed");
        assert!(events.is_empty());
        nonce_mock.assert_async().await;
        nonce_mock.remove_async().await;

        // Phase 2 (block 5, NOT a tick): tx A mines; sibling B is failed
        // purely from local watcher state, no nonce RPC
        let mut block5: Block = Block::default();
        block5.header.number = 5;
        block5.transactions = BlockTransactions::Hashes(vec![tx_hash_a]);

        let events = indexer
            .collect_execution_confirmations(&block5)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 2);
        let mut resolved: Vec<_> = events
            .iter()
            .map(|e| match e {
                ChainEvent::ExecutionConfirmed {
                    tx_id,
                    block_height,
                    result,
                    ..
                } => {
                    assert_eq!(*block_height, 5, "both events at the replacement block");
                    assert!(matches!(result, ExecutionOutcome::Failed));
                    tx_id.0
                }
                other => panic!("expected ExecutionConfirmed, got {other:?}"),
            })
            .collect();
        resolved.sort();
        let mut expected = vec![tx_hash_a.0, tx_hash_b.0];
        expected.sort();
        assert_eq!(resolved, expected);

        receipt_a_mock.assert_async().await;
        receipt_b_mock.assert_async().await;
    }
}
