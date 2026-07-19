use crate::abi::ChainSignatures;
use crate::client::{
    block_may_contain_logs, BlockNumber, CatchupItem, CatchupIter, EthereumClient, MaybeBlock,
};
use crate::event_parsing::{emit_respond_events, is_contract_call, parse_filtered_logs};
use crate::EthConfig;
use alloy::consensus::Transaction;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::rpc::types::{Block, BlockId, Log};
use alloy::sol_types::SolEvent;
use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::{stream, Stream, StreamExt};
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome, IndexedSignRequest,
    SignId,
};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration, Instant};
use tokio_util::sync::CancellationToken;

const MAX_LIVE_BLOCK_BUFFER: usize = 16384;
/// Limit of consecutive `get_block(Finalized)` total failures allowed before `wait_for_finalized_block` gives up.
const MAX_FINALIZED_FAILURES: u32 = 20;

fn live_blocks_channel() -> (mpsc::Sender<MaybeBlock>, mpsc::Receiver<MaybeBlock>) {
    mpsc::channel(MAX_LIVE_BLOCK_BUFFER)
}

/// Aborts the wrapped task on drop, prevents leaking a background task
/// if the indexer is dropped while the live block fetcher is still running.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

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
    /// The block number of the latest finalized block at the time catchup started. Used to determine which blocks are finalized during catchup.
    catchup_finalized_head: AtomicU64,
}

/// Result of a `backfill_execution_confirmation`. `Observed` carries an
/// optional event; the staleness check skips observed watchers so a mined tx
/// with a failed extraction can stay pending for retry. `NotObserved` covers
/// "no receipt yet" (pending or replaced).
#[allow(clippy::large_enum_variant)] // value is consumed in one match arm; never stored.
enum BackfillOutcome {
    NotObserved,
    Observed { event: Option<ChainEvent> },
}

impl<S: StateManager, T: ChainTelemetry> EthereumIndexer<S, T> {
    pub async fn new(eth: EthConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        let client = Arc::new(EthereumClient::new(eth.clone()).await?);
        let contract_address = format!("0x{}", eth.contract_address);
        let contract_address = Address::from_str(&contract_address).with_context(|| {
            format!("failed to parse ethereum contract address: {contract_address}")
        })?;

        Ok(Self {
            eth,
            state_manager,
            telemetry,
            client,
            contract_address,
            catchup_finalized_head: AtomicU64::new(0),
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
            catchup_finalized_head: AtomicU64::new(0),
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
            let Some(latest_block_number) = client.get_latest_block_number().await else {
                continue;
            };

            while current_block_number <= latest_block_number {
                let Some(block) = client
                    .get_block(BlockId::Number(BlockNumberOrTag::Number(
                        current_block_number,
                    )))
                    .await
                else {
                    tracing::warn!(
                        current_block_number,
                        "ethereum live block not yet available"
                    );
                    break;
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
    ///
    /// `is_finalized` indicates the block was already finalized at the time
    /// it was fetched, so it cannot reorg and `emit_processed_block` can skip
    /// the per-block re-fetch + reorg hash check (one `eth_getBlockByNumber`
    /// per block).
    ///
    /// For catchup, this is depth-gated against the finalized head sampled once
    /// at catchup start (`catchup_range`)
    ///
    /// For the live path, `is_finalized` is always `false`
    async fn process_block(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        block: &Block,
        relevant_logs: &[Log],
        is_finalized: bool,
    ) -> anyhow::Result<()> {
        // Emit telemetry for the indexed block number
        self.telemetry.block_indexed(block.header.number);

        let processed = self.parse_block(block, relevant_logs).await?;
        self.emit_processed_block(events_tx, processed, is_finalized)
            .await?;

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
        let exec_events = self.collect_execution_confirmations(block_number).await?;

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

    async fn collect_execution_confirmations(
        &self,
        block_number: u64,
    ) -> anyhow::Result<Vec<ChainEvent>> {
        let mut events = Vec::new();
        let mut resolved_tx_ids = HashSet::new();

        let watchers = self
            .state_manager
            .get_execution_watchers(Chain::Ethereum)
            .await;
        tracing::info!(
            watchers_count = watchers.len(),
            block_number,
            "collect_execution_confirmations checking watchers"
        );

        // Watchers whose receipt we saw this call, even if no event was
        // emitted. The staleness check below skips these so a mined tx with
        // a failed extraction stays pending for retry, not flagged Failed.
        let mut observed_tx_ids = HashSet::new();

        // TODO: submit as batch or parallelize the per-watcher `eth_getTransactionReceipt` calls once
        // we have a way to track rate-limits and backoff for all requests (right now we just retry individually on failure)
        // Per-watcher `eth_getTransactionReceipt`
        for (tx_id, (sign_id, pending_tx)) in watchers {
            tracing::info!(?tx_id, ?sign_id, "querying receipt for bidirectional tx");
            match self
                .backfill_execution_confirmation(tx_id, sign_id, &pending_tx, block_number)
                .await?
            {
                BackfillOutcome::Observed { event } => {
                    observed_tx_ids.insert(tx_id);
                    if let Some(event) = event {
                        events.push(event);
                        resolved_tx_ids.insert(tx_id);
                    }
                    // `None` means extraction failed — leave pending for retry.
                    // `observed_tx_ids` above exempts it from the staleness check.
                }
                BackfillOutcome::NotObserved => {}
            }
        }

        // Staleness checks (nonce too low)
        let remaining_pending = self
            .state_manager
            .get_execution_watchers(Chain::Ethereum)
            .await;

        for (tx_id, (sign_id, tx)) in remaining_pending {
            if resolved_tx_ids.contains(&tx_id) || observed_tx_ids.contains(&tx_id) {
                continue;
            }

            let current_nonce = match self
                .client
                .as_ref()
                .get_nonce(
                    tx.from_address.into(),
                    BlockId::Number(BlockNumberOrTag::Number(block_number)),
                )
                .await
            {
                Ok(nonce) => nonce,
                Err(err) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "Failed to fetch nonce for bidirectional tx"
                    );
                    continue;
                }
            };

            if tx.nonce < current_nonce {
                tracing::warn!(
                    ?sign_id,
                    "Nonce too low for tx {:?}: expected {}, got {}",
                    tx_id,
                    tx.nonce,
                    current_nonce
                );
                events.push(ChainEvent::ExecutionConfirmed {
                    tx_id,
                    sign_id,
                    source_chain: tx.source_chain,
                    block_height: block_number,
                    result: ExecutionOutcome::Failed,
                });
            }
        }

        Ok(events)
    }

    /// Emits the processed block in-order once we reach finality for it.
    ///
    /// `is_finalized` blocks skip the per-block re-fetch + reorg hash check
    /// (see `process_block`).
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
        is_finalized: bool,
    ) -> anyhow::Result<()> {
        if !self.eth.optimistic_requests {
            self.wait_for_finalized_block(block_number).await?;
        }

        // If the block is not finalized, re-fetch it and check that the hash matches
        if !is_finalized {
            let Some(block) = self
                .client
                .as_ref()
                .get_block(BlockId::Number(BlockNumberOrTag::Number(block_number)))
                .await
            else {
                anyhow::bail!("ethereum block {block_number} not found during emission");
            };

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
        );

        // Sample the finalized head once at catchup start, so that blocks at or below it can skip the per-block re-fetch + reorg hash check.
        if let Some(finalized_block) = self
            .client
            .get_block(BlockId::Number(BlockNumberOrTag::Finalized))
            .await
        {
            self.catchup_finalized_head
                .store(finalized_block.header.number, Ordering::Relaxed);
            tracing::info!(
                finalized_head = finalized_block.header.number,
                catchup_start,
                anchor_height,
                "sampled finalized head for catchup reorg-check gating"
            );
        } else {
            tracing::warn!(
                "could not sample finalized head for catchup; keeping reorg check for all blocks"
            );
        }

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
                let Some(block) = self.client.get_block(*block_id).await else {
                    anyhow::bail!(
                        "ethereum catchup block {block_id:?} is still unavailable after refetch"
                    )
                };
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

        // Determine if the block is finalized based on the sampled finalized head at catchup start
        let f0 = self.catchup_finalized_head.load(Ordering::Relaxed);
        let is_finalized = block.header.number <= f0;
        self.process_block(events_tx, block, logs, is_finalized)
            .await?;

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
                let Some(b) = self.client.get_block(*block_id).await else {
                    anyhow::bail!(
                        "ethereum live stream yielded missing block {block_id:?} and refetch failed"
                    )
                };
                _logs = self.fetch_block_logs(&b).await?;
                _block = b;
                (&_block, _logs.as_slice())
            }
        };

        // Live blocks are not yet finalized, so keep the reorg hash check
        self.process_block(events_tx, block, logs, false).await?;
        Ok(())
    }

    /// Blocks until the specified block number has been finalized on the Ethereum chain.
    async fn wait_for_finalized_block(&self, block_number: BlockNumber) -> anyhow::Result<()> {
        let retry_interval = Duration::from_millis(self.eth.refresh_finalized_interval);
        let mut last_final_block_number: Option<BlockNumber> = None;
        let mut consecutive_failures = 0u32;

        // Warn if the finalized block number has not advanced for this long
        let stall_warn_secs = Chain::Ethereum.expected_finality_time_secs();
        // Re-warn on this heartbeat interval if the finalized block number has not advanced
        const STALL_REWARN_SECS: u64 = 300;
        let mut last_advanced_at = Instant::now();
        let mut last_stall_warn_at = Instant::now();

        loop {
            let Some(finalized_block) = self
                .client
                .as_ref()
                .get_block(BlockId::Number(BlockNumberOrTag::Finalized))
                .await
            else {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_FINALIZED_FAILURES {
                    // Propagate error to the outer ChainIndexer loop to catch it,
                    // sleep for RETRY_DELAY, and attempt the entire block process again.
                    anyhow::bail!(
                        "get_block(Finalized) failed {MAX_FINALIZED_FAILURES} times consecutively; aborting wait"
                    );
                }
                tracing::warn!(
                    block_number,
                    "finalized ethereum block not found (failure {consecutive_failures}/{MAX_FINALIZED_FAILURES}); retrying"
                );
                sleep(retry_interval).await;
                continue;
            };

            consecutive_failures = 0;
            let new_final_block_number = finalized_block.header.number;
            let prev_final_block_number = last_final_block_number.replace(new_final_block_number);

            if prev_final_block_number.is_none_or(|n| new_final_block_number > n) {
                last_advanced_at = Instant::now();
                tracing::debug!(
                    new_final_block_number,
                    prev_final_block_number,
                    "New finalized block number"
                );
            }

            if let Some(prev_final_block_number) = prev_final_block_number {
                if new_final_block_number < prev_final_block_number {
                    tracing::warn!(
                        new_final_block_number,
                        prev_final_block_number,
                        "new finalized block number overflowed range of u64 and has wrapped around!"
                    );
                }

                if new_final_block_number == prev_final_block_number {
                    // Warn if the finalized block number has not advanced for `stall_warn_secs`
                    let now = Instant::now();
                    let secs_since_advance = now.duration_since(last_advanced_at).as_secs();
                    if secs_since_advance >= stall_warn_secs
                        && now.duration_since(last_stall_warn_at).as_secs() >= STALL_REWARN_SECS
                    {
                        tracing::warn!(
                            block_number,
                            new_final_block_number,
                            secs_since_advance,
                            stall_warn_secs,
                            "finalized ethereum head has not advanced; \
                             block will not be emitted until finality catches up. \
                             If this persists the stream watchdog will restart the pipeline"
                        );
                        last_stall_warn_at = now;
                    }
                    tracing::debug!(new_final_block_number, "no new finalized block");
                }
            }

            // If the finalized block number has advanced past the block we're waiting for,
            // we can proceed with emitting it.
            if new_final_block_number >= block_number {
                return Ok(());
            };

            sleep(retry_interval).await;
        }
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for EthereumIndexer<S, T> {
    const CHAIN: Chain = Chain::Ethereum;
    type Block = CatchupItem;
    type Iter = std::pin::Pin<Box<dyn stream::Stream<Item = Self::Block> + Send + 'static>>;

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
            if let Some(latest) = self.client.get_latest_block_number().await {
                break latest.saturating_add(1);
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = sleep(Self::RETRY_DELAY) => {}
            }
        };

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
        let (live_blocks_tx, mut live_blocks_rx) = live_blocks_channel();
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
    use alloy::rpc::types::BlockId;
    use mockito::{Matcher, Server};
    use mpc_chain_integration_core::utils::stream::chain_event_channel;
    use mpc_chain_integration_core::ChainIndexer;
    use mpc_chain_integration_core::StateManager;
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
        indexer.catchup_finalized_head.store(100, Ordering::Relaxed);

        let mut iter = crate::client::CatchupIter::new(
            indexer.client.clone(),
            1,
            33,
            indexer.contract_address,
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
        indexer.catchup_finalized_head.store(100, Ordering::Relaxed);

        let mut iter = crate::client::CatchupIter::new(
            indexer.client.clone(),
            10,
            12,
            indexer.contract_address,
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
        indexer.catchup_finalized_head.store(100, Ordering::Relaxed);

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
        indexer.catchup_finalized_head.store(100, Ordering::Relaxed);

        let mut iter = crate::client::CatchupIter::new(
            indexer.client.clone(),
            42,
            43,
            indexer.contract_address,
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
    async fn missing_catchup_block_returns_error_when_refetch_fails() {
        let indexer = test_utils::TestIndexerBuilder::new("http://127.0.0.1:1")
            .client_url("http://127.0.0.1:1")
            .rpc_urls("", "")
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();

        let err = indexer
            .process_catchup_item(
                &events_tx,
                &CatchupItem::Missing(BlockId::Number(BlockNumberOrTag::Number(12))),
            )
            .await
            .expect_err("missing catchup block should fail when refetch cannot recover it");

        assert!(events_rx.try_recv().is_err());
        assert!(err.to_string().contains("still unavailable after refetch"));
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
        indexer.catchup_finalized_head.store(100, Ordering::Relaxed);

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
        indexer.catchup_finalized_head.store(10, Ordering::Relaxed);

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
    async fn wait_for_finalized_block_fails_after_budget_exhaustion() {
        let mut server = Server::new_async().await;

        // Mock eth_getBlockByNumber(finalized) to always return null (simulating repeated 429/failure)
        // Should be called MAX_FINALIZED_FAILURES times
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": ["finalized", false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::missing_block_response(1).to_string())
            .expect(super::MAX_FINALIZED_FAILURES as usize)
            .create_async()
            .await;

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .optimistic_requests(false)
            .refresh_finalized_interval(1)
            .build()
            .await;

        let err = indexer
            .wait_for_finalized_block(100)
            .await
            .expect_err("should fail after budget exhaustion");

        assert!(err.to_string().contains("failed 20 times consecutively"));
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

        let events = indexer
            .collect_execution_confirmations(5)
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
}
