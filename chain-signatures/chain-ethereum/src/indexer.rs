use crate::abi::ChainSignatures;
use crate::client::{block_may_contain_logs, CatchupItem, CatchupIter, EthereumClient};
use crate::event_parsing::{emit_respond_events, parse_filtered_logs};
use crate::execution_watcher::{ExecutionWatcher, WatcherGateState};
use crate::finalized_head::{FinalizedHeadTracker, FinalizedHeadWatcher};
use crate::EthConfig;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::rpc::types::{Block, BlockId, Log};
use alloy::sol_types::SolEvent;
use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::{stream, Stream};
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{Chain, ChainEvent, IndexedSignRequest};
use mpc_utils::task::{retry_until_ok, retry_until_some};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;

pub struct BlockAndRequests {
    block_number: u64,
    /// Block timestamp captured from the fetched block, used for
    /// `ChainEvent::SignRequest`'s `block_timestamp` field.
    block_timestamp: u64,
    indexed_requests: Vec<IndexedSignRequest>,
    respond_logs: Vec<Log>,
    execution_events: Vec<ChainEvent>,
}

impl BlockAndRequests {
    fn new(
        block_number: u64,
        block_timestamp: u64,
        indexed_requests: Vec<IndexedSignRequest>,
        respond_logs: Vec<Log>,
        execution_events: Vec<ChainEvent>,
    ) -> Self {
        Self {
            block_number,
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
    /// Finalized head tracker and watcher task, used to gate catchup and live tail processing.
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

    /// Spawn the background head watcher (`Finalized` in production, `Latest` in
    /// optimistic dev mode). Returns a guard whose drop aborts the task.
    pub fn spawn_finalized_head_watcher(&self, cancel: CancellationToken) -> FinalizedHeadWatcher {
        self.finalized_head
            .spawn_watcher(self.client.clone(), cancel)
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
        let block_number = block.header.number;

        // Log progress every 10 blocks
        if block_number.is_multiple_of(10) {
            tracing::info!(height = block_number, "processed ethereum block");
        }

        #[cfg(feature = "bench")]
        let start = std::time::Instant::now();

        self.telemetry.block_indexed(block_number);
        let parsed = self.parse_block(block, relevant_logs).await?;
        self.emit_block_events(events_tx, parsed).await?;

        #[cfg(feature = "bench")]
        {
            crate::bench::add_process_time(start.elapsed());
            if crate::bench::inc_block() % 100 == 0 {
                crate::bench::report_metrics("catchup_progress");
            }
        }

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

        // Filter relevant logs into request and respond categories
        let request_logs: Vec<Log> = relevant_logs
            .iter()
            .filter(|l| l.topic0() == Some(&ChainSignatures::SignatureRequested::SIGNATURE_HASH))
            .cloned()
            .collect();
        let respond_logs: Vec<Log> = relevant_logs
            .iter()
            .filter(|l| l.topic0() == Some(&ChainSignatures::SignatureResponded::SIGNATURE_HASH))
            .cloned()
            .collect();
        let sign_requests = parse_filtered_logs(request_logs);

        // Collect execution confirmations (if any) and emit ExecutionConfirmed events
        let watcher = ExecutionWatcher::new(
            self.client.as_ref(),
            &self.state_manager,
            &self.eth.indexer,
            &self.watcher_gate,
            &self.telemetry,
        );
        let exec_events = watcher.collect(block).await?;

        // Always produce a payload so `ChainEvent::Block` is emitted even when
        // the block has no relevant contract logs.
        Ok(BlockAndRequests::new(
            block_number,
            block.header.timestamp,
            sign_requests,
            respond_logs,
            exec_events,
        ))
    }

    /// Emit the parsed block's events in order.
    async fn emit_block_events(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        BlockAndRequests {
            block_number,
            block_timestamp,
            indexed_requests,
            respond_logs,
            execution_events,
        }: BlockAndRequests,
    ) -> anyhow::Result<()> {
        for event in execution_events {
            events_tx
                .send(event)
                .await
                .context("failed to emit ExecutionConfirmed event")?;
        }

        for request in indexed_requests {
            events_tx
                .send(ChainEvent::SignRequest {
                    request: Arc::new(request),
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

    /// Catchup blocks in `[processed + 1, anchor_height)` fetched in batches,
    /// clamped to the RPC's supported historical window.
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

    /// Process a single catchup item (batch block or missing-block refetch)
    /// and emit its events.
    pub async fn process_catchup_item(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        item: &CatchupItem,
    ) -> anyhow::Result<()> {
        match item {
            CatchupItem::BatchBlock { block, logs } => {
                self.process_block(events_tx, block, logs).await
            }
            CatchupItem::Missing(block_id) => {
                tracing::warn!(
                    ?block_id,
                    "ethereum catchup block missing from batch; refetching"
                );

                #[cfg(feature = "bench")]
                let start = std::time::Instant::now();

                let block = self.client.get_block(*block_id).await?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "ethereum catchup block {block_id:?} is still unavailable after refetch"
                    )
                })?;
                let logs = self.fetch_block_logs(&block).await?;

                #[cfg(feature = "bench")]
                crate::bench::add_refetch_time(start.elapsed());

                self.process_block(events_tx, &block, &logs).await
            }
        }
    }

    /// The catchup-live anchor: the first processable head + 1.
    /// Returns `None` on cancellation.
    async fn sample_anchor(&self, cancel: &CancellationToken) -> Option<u64> {
        let tag = if self.eth.optimistic_requests {
            BlockNumberOrTag::Latest
        } else {
            BlockNumberOrTag::Finalized
        };
        retry_until_some(
            cancel,
            Self::RETRY_DELAY,
            "ethereum startup head sampling",
            || async { self.client.get_block(BlockId::Number(tag)).await },
        )
        .await
        .map(|block| block.header.number.saturating_add(1))
    }

    /// Wait until `next` is processable (the head covers it), returning the
    /// ready upper bound. Returns `None` on cancellation.
    async fn wait_processable_bound(
        &self,
        watcher: &mut FinalizedHeadWatcher,
        next: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<u64>> {
        tokio::select! {
            _ = cancel.cancelled() => Ok(None),
            res = watcher.wait_for(next) => {
                match res {
                    Ok(head) => Ok(Some(head)),
                    Err(_err) if cancel.is_cancelled() => Ok(None),
                    Err(err) => Err(anyhow::anyhow!("head watcher exited: {err:?}")),
                }
            }
        }
    }

    /// Batch-fetch `[start, end)` via `CatchupIter` and process each item,
    /// retrying transient failures. Returns early on cancellation.
    async fn process_range(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        start: u64,
        end: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        let mut iter = CatchupIter::new(
            self.client.clone(),
            start,
            end,
            self.contract_address,
            self.eth.indexer.catchup_block_batch_size,
        );
        loop {
            let item = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                item = iter.next() => item,
            };
            let Some(item) = item else { break };
            retry_until_ok(
                cancel,
                Self::RETRY_DELAY,
                "ethereum block processing",
                || async { self.process_catchup_item(events_tx, &item).await },
            )
            .await;
        }
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
        tracing::info!("ethereum indexer started");

        // Spawn the finalized head watcher.
        let mut finalized_watcher = self
            .finalized_head
            .spawn_watcher(self.client.clone(), cancel.clone());

        // Anchor = tip-at-startup + 1: the catchup-live boundary.
        let Some(anchor) = self.sample_anchor(&cancel).await else {
            tracing::debug!("ethereum indexer cancelled before the startup tip was sampled");
            return Ok(());
        };

        // Next block to process, starting from the last processed block + 1
        // Or start from the anchor if no blocks have been processed yet.
        let mut next = self
            .state_manager
            .get_processed_block(Chain::Ethereum)
            .await
            .map(|n| n.saturating_add(1))
            .unwrap_or(anchor);
        next = self.client.clamp_oldest_supported(next, anchor);

        if next < anchor {
            tracing::info!(
                start = next,
                tip = anchor.saturating_sub(1),
                blocks = anchor - next,
                "ethereum indexer starting catchup"
            );
        } else {
            tracing::info!(
                height = next,
                "ethereum indexer already caught up; skipping catchup"
            );
        }

        // Catchup: process all blocks up to the anchor, then emit a CatchupCompleted event.
        while next < anchor {
            // Wait for the next block to be processable
            let Some(upper) = self
                .wait_processable_bound(&mut finalized_watcher, next, &cancel)
                .await?
            else {
                return Ok(()); // cancelled while waiting
            };
            // Clamp the upper bound to the anchor so we don't process beyond it.
            let end = upper.min(anchor.saturating_sub(1)) + 1;
            self.process_range(&events_tx, next, end, &cancel).await?;
            next = end;
        }

        if cancel.is_cancelled() {
            tracing::debug!("ethereum indexer cancelled after catchup; skipping CatchupCompleted");
            return Ok(());
        }
        tracing::info!(
            height = next,
            "ethereum catchup complete; entering live tail"
        );
        events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send catchup completed event")?;

        // Live tail: process each block as it becomes processable, waiting for the finalized head to reach it.
        loop {
            let Some(upper) = self
                .wait_processable_bound(&mut finalized_watcher, next, &cancel)
                .await?
            else {
                return Ok(()); // cancelled while waiting
            };
            self.process_range(&events_tx, next, upper + 1, &cancel)
                .await?;
            next = upper + 1;
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
    async fn sample_anchor_fetches_finalized_head_directly() {
        let mut server = Server::new_async().await;
        let finalized_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": ["finalized", false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(1, 42).to_string())
            .expect(1)
            .create_async()
            .await;
        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;

        assert_eq!(
            indexer.sample_anchor(&CancellationToken::new()).await,
            Some(43)
        );
        finalized_mock.assert_async().await;
    }

    #[tokio::test]
    async fn sample_anchor_fetches_latest_head_in_optimistic_mode() {
        let mut server = Server::new_async().await;
        let latest_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": ["latest", false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(2, 42).to_string())
            .expect(1)
            .create_async()
            .await;
        let mut builder = test_utils::TestIndexerBuilder::new(server.url());
        builder.eth.optimistic_requests = true;
        let indexer = builder.build().await;

        assert_eq!(
            indexer.sample_anchor(&CancellationToken::new()).await,
            Some(43)
        );
        latest_mock.assert_async().await;
    }

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
        let blocks: Vec<_> = (0..32)
            .map(|n| test_utils::block_response(n, n + 1))
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
                    test_utils::block_response(0, 10),
                    test_utils::block_response(1, 11)
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

        // One Missing item: process_catchup refetches the block once by number.
        let block_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": [format!("0x{block_number:x}"), false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(1, block_number).to_string())
            .expect(1) // refetched exactly once by the Missing path
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
            .with_body(json!([test_utils::block_response(0, block_number)]).to_string())
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
    async fn catchup_emits_block_without_refetching() {
        let mut server = Server::new_async().await;

        let item = test_utils::batch_block(42, vec![]);
        let CatchupItem::BatchBlock { block, .. } = &item else {
            unreachable!("test_utils::batch_block returns CatchupItem::BatchBlock")
        };
        let block_number = block.header.number;

        // `process_block` emits directly from the batch-supplied block; it must
        // never re-fetch the same block by number.
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

        let indexer = test_utils::TestIndexerBuilder::new(server.url())
            .build()
            .await;
        let (events_tx, mut events_rx) = chain_event_channel();

        indexer
            .process_catchup_item(&events_tx, &item)
            .await
            .expect("catchup over a present block should succeed");

        block_by_number_mock.assert_async().await;

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Block(n)) if n == block_number
        ));
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
    /// Holds the mock server, finalized block, and other state for running the indexer in tests.
    struct RunFixture {
        _server: mockito::ServerGuard,
        finalized: Arc<AtomicU64>,
        cancel: CancellationToken,
        run_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
        events_rx: mpsc::Receiver<ChainEvent>,
    }

    impl RunFixture {
        async fn spawn(processed: u64, finalized: u64) -> Self {
            let mut server = Server::new_async().await;
            let finalized = Arc::new(AtomicU64::new(finalized));

            // Anchor sampling + finalized head polling.
            server
                .mock("POST", "/")
                .match_body(Matcher::PartialJson(json!({
                    "method": "eth_getBlockByNumber",
                    "params": ["finalized", false]
                })))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body_from_request({
                    let finalized = finalized.clone();
                    move |req| block_reply(req, finalized.load(Ordering::Relaxed))
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
                finalized,
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

        f.finalized.store(10, Ordering::Relaxed);
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
    async fn wait_processable_bound_waits_for_finalized_head() {
        // Non-optimistic mode: wait_processable_bound blocks on the cached finalized
        // head, so no RPC is needed.
        let builder = test_utils::TestIndexerBuilder::new("http://127.0.0.1:1");
        let indexer = builder.build().await;
        let cancel = CancellationToken::new();

        let head = indexer.finalized_head.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            head.set_head(100);
        });

        let mut watcher = indexer
            .finalized_head
            .spawn_watcher(indexer.client.clone(), cancel.clone());
        let upper = indexer
            .wait_processable_bound(&mut watcher, 50, &cancel)
            .await
            .expect("wait_processable_bound resolves once the head covers next");
        assert_eq!(upper, Some(100));
    }

    #[tokio::test]
    async fn cancel_stops_block_processing_after_catchup() {
        let mut f = RunFixture::spawn(9, 9).await;
        assert!(matches!(f.next_event().await, ChainEvent::CatchupCompleted));

        f.finalized.store(10, Ordering::Relaxed);
        assert!(matches!(f.next_event().await, ChainEvent::Block(10)));

        f.cancel_and_join().await;

        // After cancellation, advancing the tip must not produce any more blocks.
        f.finalized.store(11, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            f.events_rx.try_recv().is_err(),
            "block processing continued after run() cancellation"
        );
    }
}
