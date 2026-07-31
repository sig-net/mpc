use crate::abi::ChainSignatures;
use crate::client::{block_may_contain_logs, CatchupItem, CatchupIter, EthereumClient, MaybeBlock};
use crate::event_parsing::{emit_respond_events, parse_filtered_logs};
use crate::execution_watcher::{ExecutionWatcher, WatcherGateState};
use crate::finalized_head::FinalizedHeadTracker;
use crate::EthConfig;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::rpc::types::{Block, BlockId, Log};
use alloy::sol_types::SolEvent;
use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::{stream, Stream, StreamExt};
use mpc_chain_integration_core::utils::task::{retry_until_ok, AbortOnDrop, CancellationTokenExt};
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{Chain, ChainEvent, IndexedSignRequest};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::Duration;
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
    /// Cached finalized head, maintained by a background watcher and consulted by
    /// `emit_processed_block` so each block need not poll finality independently.
    finalized_head: FinalizedHeadTracker,
    /// Watcher nonce-gate scheduling state (first-appearance checks + retries).
    watcher_gate: Mutex<WatcherGateState>,
}

impl<S: StateManager, T: ChainTelemetry> EthereumIndexer<S, T> {
    /// Delay between retries of transient RPC failures
    const RETRY_DELAY: Duration = Duration::from_millis(500);

    pub async fn new(eth: EthConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        let client = Arc::new(EthereumClient::new(eth.clone()).await?);
        let contract_address = eth.contract_address;

        let finalized_head = FinalizedHeadTracker::new(&eth);
        Ok(Self {
            eth,
            state_manager,
            telemetry,
            client,
            contract_address,
            finalized_head,
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
        let finalized_head = FinalizedHeadTracker::new(&eth);
        Self {
            eth,
            state_manager,
            telemetry,
            client,
            contract_address,
            finalized_head,
            watcher_gate: Mutex::new(WatcherGateState::default()),
        }
    }

    /// Spawn the background finalized-head watcher. Returns a guard whose drop
    /// aborts the task, or `None` in optimistic mode (dev chains never report a
    /// finalized head).
    pub fn spawn_finalized_head_watcher(&self, cancel: CancellationToken) -> Option<AbortOnDrop> {
        self.finalized_head
            .spawn_watcher(self.client.clone(), cancel)
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
        let watcher = ExecutionWatcher::new(
            self.client.as_ref(),
            &self.state_manager,
            &self.eth.indexer,
            &self.watcher_gate,
        );
        let exec_events = watcher.collect(block).await?;

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
        // Wait for the finalized head to reach this block number before emitting events.)
        self.finalized_head.wait_for(block_number).await?;

        // Reorg hash-check: only for blocks not covered by the finalized head.
        if self.finalized_head.current() < block_number {
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
            if cancel.cancelled_within(Self::RETRY_DELAY).await {
                return Ok(());
            }
        };

        // Spawn the finalized head watcher.
        let _finalized_watcher = self
            .finalized_head
            .spawn_watcher(self.client.clone(), cancel.clone());

        let mut catchup_iter = self.catchup_blocks(anchor_height).await;
        loop {
            let item = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                item = catchup_iter.next() => item,
            };
            let Some(item) = item else { break };
            retry_until_ok(
                &cancel,
                Self::RETRY_DELAY,
                "ethereum catchup block processing",
                || async { self.process_catchup_item(&events_tx, &item).await },
            )
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
            retry_until_ok(
                &cancel,
                Self::RETRY_DELAY,
                "ethereum live block processing",
                || async { self.process_live_item(&events_tx, &item).await },
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::client::CatchupItem;
    use crate::test_utils;
    use alloy::eips::BlockNumberOrTag;
    use alloy::rpc::types::BlockId;
    use mockito::{Matcher, Server};
    use mpc_chain_integration_core::utils::stream::chain_event_channel;
    use mpc_chain_integration_core::{ChainIndexer, StateManager};
    use mpc_primitives::{Chain, ChainEvent};
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
        indexer.finalized_head.set_head(100);

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
        indexer.finalized_head.set_head(100);

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
        indexer.finalized_head.set_head(100);

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
        indexer.finalized_head.set_head(100);

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

        // Optimistic mode (default) so the finalized-head wait is skipped.
        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();
        // Block 42 was finalized at fetch time (head sampled at 100), so the
        // re-fetch + reorg check is skipped.
        indexer.finalized_head.set_head(100);

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
        indexer.finalized_head.set_head(10);

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
