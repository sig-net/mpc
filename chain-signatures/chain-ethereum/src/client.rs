use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256};
use alloy::rpc::types::{Block, BlockId, Log, TransactionReceipt};
use std::sync::Arc;

use crate::config::RpcConfig;
use crate::indexer_eth_direct_rpc;
use crate::EthConfig;
#[cfg(test)]
use mpc_chain_integration_core::utils::retry::RetryConfig;
use mpc_chain_integration_core::utils::retry::{retry_rpc_gated, SharedBackoff};

#[cfg(feature = "helios")]
use super::indexer_eth_helios;

/// Block number alias shared by the client and indexer.
pub type BlockNumber = u64;

/// Result of attempting to fetch a single block
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeBlock {
    Block(Block),
    Missing(BlockId),
}

/// Returns `true` if the block's logs bloom may contain logs emitted by `address`.
pub fn block_may_contain_logs(block: &Block, address: Address) -> bool {
    block.header.logs_bloom.contains_raw_log(address, &[])
}

/// Catchup item yielded by [`CatchupIter`] and consumed by `process_catchup`.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CatchupItem {
    /// A block fetched as part of a catchup batch, plus its logs.
    /// `logs` is `Vec::new()` for blocks with no relevant logs.
    BatchBlock { block: Block, logs: Vec<Log> },
    /// A block that was missing from the catchup batch response.
    /// `process_catchup` refetches both block and receipts individually.
    Missing(BlockId),
}

/// Intermediate state of a block during catchup batch processing.
enum BlockSlot {
    Missing(BlockId),
    NoLogs(Block),
    PendingLogs(Block, BlockId),
}

/// Lazy batching iterator over `[start_block, end_block)` range.
pub struct CatchupIter {
    client: Arc<EthereumClient>,
    contract_address: Address,
    batch_size: u64,
    next_block: BlockNumber,
    end_block: BlockNumber,
    buffered_blocks: std::vec::IntoIter<CatchupItem>,
}

impl CatchupIter {
    pub fn new(
        client: Arc<EthereumClient>,
        start_block: BlockNumber,
        end_block: BlockNumber,
        contract_address: Address,
        batch_size: u64,
    ) -> Self {
        Self {
            client,
            contract_address,
            batch_size,
            next_block: start_block,
            end_block,
            buffered_blocks: Vec::new().into_iter(),
        }
    }

    async fn fetch_next_batch(&mut self) {
        if self.next_block >= self.end_block {
            return;
        }

        let batch_end = self
            .next_block
            .saturating_add(self.batch_size)
            .min(self.end_block);

        let batch_block_ids: Vec<BlockId> = (self.next_block..batch_end)
            .map(|n| BlockId::Number(BlockNumberOrTag::Number(n)))
            .collect();

        #[cfg(feature = "bench")]
        let start = std::time::Instant::now();

        let blocks = self.client.get_blocks(&batch_block_ids).await;

        // Classify each block: missing, bloom-negative (no logs to fetch), or
        // bloom-positive (needs a slot in the logs batch request).
        let slots: Vec<BlockSlot> = blocks
            .into_iter()
            .zip(&batch_block_ids)
            .map(|(maybe, &block_id)| match maybe {
                MaybeBlock::Missing(_) => BlockSlot::Missing(block_id),
                MaybeBlock::Block(block) => {
                    if block_may_contain_logs(&block, self.contract_address) {
                        BlockSlot::PendingLogs(block, block_id)
                    } else {
                        BlockSlot::NoLogs(block)
                    }
                }
            })
            .collect();

        let logs_request_ids: Vec<BlockId> = slots
            .iter()
            .filter_map(|slot| match slot {
                BlockSlot::PendingLogs(_, id) => Some(*id),
                _ => None,
            })
            .collect();

        // Fetch logs for bloom-positive blocks. On failure, those blocks are
        // reported as missing so the caller refetches them individually.
        let (mut logs_iter, logs_failed) = if logs_request_ids.is_empty() {
            (Vec::new().into_iter(), false)
        } else {
            match self
                .client
                .get_logs_batch(self.contract_address, &logs_request_ids)
                .await
            {
                Ok(logs) => (logs.into_iter(), false),
                Err(_) => (Vec::new().into_iter(), true),
            }
        };

        // Reconstruct the batch items in the original order, with logs for bloom-positive blocks.
        let items: Vec<CatchupItem> = slots
            .into_iter()
            .map(|slot| match slot {
                BlockSlot::Missing(block_id) => CatchupItem::Missing(block_id),
                BlockSlot::NoLogs(block) => CatchupItem::BatchBlock {
                    block,
                    logs: Vec::new(),
                },
                BlockSlot::PendingLogs(_block, block_id) if logs_failed => {
                    CatchupItem::Missing(block_id)
                }
                BlockSlot::PendingLogs(block, _) => CatchupItem::BatchBlock {
                    block,
                    logs: logs_iter.next().unwrap_or_default(),
                },
            })
            .collect();

        #[cfg(feature = "bench")]
        crate::bench::add_batch_fetch_time(start.elapsed());

        self.buffered_blocks = items.into_iter();
        self.next_block = batch_end;
    }

    pub async fn next(&mut self) -> Option<CatchupItem> {
        loop {
            if let Some(block) = self.buffered_blocks.next() {
                return Some(block);
            }

            if self.next_block >= self.end_block {
                return None;
            }

            self.fetch_next_batch().await;
        }
    }
}

#[derive(Clone)]
pub struct EthereumClient {
    inner: EthereumClientInner,
    rpc: RpcConfig,
    /// Global 429 cooldown gate shared by all RPC calls through this client
    shared_backoff: SharedBackoff,
}

#[derive(Clone)]
pub enum EthereumClientInner {
    #[cfg(feature = "helios")]
    Helios(indexer_eth_helios::HeliosEthereumClient),
    DirectRpc(indexer_eth_direct_rpc::RpcEthereumClient),
}

impl EthereumClient {
    pub async fn new(eth: EthConfig) -> anyhow::Result<EthereumClient> {
        let inner = if eth.light_client {
            #[cfg(feature = "helios")]
            {
                EthereumClientInner::Helios(indexer_eth_helios::build_client(eth.clone()).await?)
            }
            #[cfg(not(feature = "helios"))]
            {
                anyhow::bail!(
                    "ethereum light client requested, but mpc-node was built without helios feature"
                );
            }
        } else {
            EthereumClientInner::DirectRpc(indexer_eth_direct_rpc::RpcEthereumClient::new(
                eth.execution_rpc_http_url,
            ))
        };

        Ok(Self {
            inner,
            rpc: eth.rpc.clone(),
            shared_backoff: SharedBackoff::new(),
        })
    }

    /// Overrides the RPC retry strategy
    #[cfg(test)]
    pub(crate) async fn new_with_strategy(
        eth: EthConfig,
        retry_strategy: RetryConfig,
    ) -> anyhow::Result<Self> {
        let mut client = Self::new(eth).await?;
        client.rpc.retry = retry_strategy;
        Ok(client)
    }

    /// Overrides the shared 429 cooldown gate
    #[cfg(test)]
    pub(crate) fn with_shared_backoff(mut self, shared_backoff: SharedBackoff) -> Self {
        self.shared_backoff = shared_backoff;
        self
    }

    fn client_name(&self) -> &str {
        match &self.inner {
            #[cfg(feature = "helios")]
            EthereumClientInner::Helios(_) => "Helios",
            EthereumClientInner::DirectRpc(_) => "DirectRpc",
        }
    }

    /// Retrieves a block by its ID. Returns `Ok(Some(Block))` if the block is found,
    /// `Ok(None)` if the block is not found, or an error if the request fails.
    pub async fn get_block(&self, block_id: BlockId) -> anyhow::Result<Option<Block>> {
        let max_attempts = self.rpc.retry.max_times;
        retry_rpc_gated!(
            self.rpc.timeout,
            self.rpc.retry,
            self.shared_backoff,
            |attempt, err, sleep| {
                tracing::warn!(
                    client = self.client_name(),
                    "get_block failed (attempt {attempt}/{max_attempts}) for {block_id:?}: {err:#}; retrying in {sleep:?}"
                );
            },
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => client.get_block(block_id).await,
                    EthereumClientInner::DirectRpc(client) => client.get_block(block_id).await,
                }
            }
        )
    }

    pub async fn get_blocks(&self, block_ids: &[BlockId]) -> Vec<MaybeBlock> {
        if block_ids.is_empty() {
            return Vec::new();
        }

        let max_attempts = self.rpc.retry.max_times;
        let num_blocks = block_ids.len();

        let res = retry_rpc_gated!(
            self.rpc.batch_timeout,
            self.rpc.retry,
            self.shared_backoff,
            |attempt, err, sleep| {
                tracing::warn!(
                    client = self.client_name(),
                    num_blocks,
                    "get_blocks failed (attempt {attempt}/{max_attempts}): {err:#}; retrying in {sleep:?}"
                );
            },
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => client.get_blocks(block_ids).await,
                    EthereumClientInner::DirectRpc(client) => client.get_blocks(block_ids).await,
                }
            }
        );

        match res {
            Ok(blocks) => blocks,
            Err(err) => {
                tracing::warn!(
                    client = self.client_name(),
                    num_blocks,
                    "get_blocks failed: {err:#}"
                );
                block_ids.iter().copied().map(MaybeBlock::Missing).collect()
            }
        }
    }

    /// Fetch a single transaction's receipt via `eth_getTransactionReceipt`.
    ///
    /// Returns `None` for an unknown or pending (not-yet-mined) tx.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        retry_rpc_gated!(
            self.rpc.timeout,
            self.rpc.retry,
            self.shared_backoff,
            "get_transaction_receipt",
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => {
                        client.get_transaction_receipt(tx_hash).await
                    }
                    EthereumClientInner::DirectRpc(client) => {
                        client.get_transaction_receipt(tx_hash).await
                    }
                }
            }
        )
    }

    /// Fetch all logs emitted by `address` within `block_id` via a single
    /// server-filtered `eth_getLogs`.
    pub async fn get_logs(&self, address: Address, block_id: BlockId) -> anyhow::Result<Vec<Log>> {
        retry_rpc_gated!(
            self.rpc.timeout,
            self.rpc.retry,
            self.shared_backoff,
            "get_logs",
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => client.get_logs(address, block_id).await,
                    EthereumClientInner::DirectRpc(client) => {
                        client.get_logs(address, block_id).await
                    }
                }
            }
        )
    }

    /// Fetch `eth_getLogs` for multiple blocks in a single JSON-RPC batch POST,
    /// returning one `Vec<Log>` per input `block_id`, in input order.
    /// Each request is address-filtered to the same `address`.
    pub async fn get_logs_batch(
        &self,
        address: Address,
        block_ids: &[BlockId],
    ) -> anyhow::Result<Vec<Vec<Log>>> {
        retry_rpc_gated!(
            self.rpc.batch_timeout,
            self.rpc.retry,
            self.shared_backoff,
            "get_logs_batch",
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => {
                        client.get_logs_batch(address, block_ids).await
                    }
                    EthereumClientInner::DirectRpc(client) => {
                        client.get_logs_batch(address, block_ids).await
                    }
                }
            }
        )
    }

    pub async fn get_nonce(&self, address: Address, block_id: BlockId) -> anyhow::Result<u64> {
        retry_rpc_gated!(
            self.rpc.timeout,
            self.rpc.retry,
            self.shared_backoff,
            "get_nonce",
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => {
                        client.get_nonce(address, block_id).await
                    }
                    EthereumClientInner::DirectRpc(client) => {
                        client.get_nonce(address, block_id).await
                    }
                }
            }
        )
    }

    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        retry_rpc_gated!(
            self.rpc.timeout,
            self.rpc.retry,
            self.shared_backoff,
            "get_transaction_by_hash",
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => {
                        client.get_transaction_by_hash(tx_hash).await
                    }
                    EthereumClientInner::DirectRpc(client) => {
                        client.get_transaction_by_hash(tx_hash).await
                    }
                }
            }
        )
    }

    pub async fn trace_transaction_output(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::primitives::Bytes>> {
        // TODO: trace_transaction_output can be slow, consider a longer timeout than the configured RPC timeout if necessary
        retry_rpc_gated!(
            self.rpc.timeout,
            self.rpc.retry,
            self.shared_backoff,
            "trace_transaction_output",
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => {
                        client.trace_transaction_output(tx_hash).await
                    }
                    EthereumClientInner::DirectRpc(client) => {
                        client.trace_transaction_output(tx_hash).await
                    }
                }
            }
        )
    }

    pub async fn get_latest_block_number(&self) -> anyhow::Result<Option<u64>> {
        Ok(self
            .get_block(BlockId::Number(BlockNumberOrTag::Latest))
            .await?
            .map(|block| block.header.number))
    }

    pub fn clamp_oldest_supported(
        &self,
        requested_start: u64,
        anchor_height: BlockNumber,
    ) -> BlockNumber {
        let max_catchup_blocks = match &self.inner {
            #[cfg(feature = "helios")]
            EthereumClientInner::Helios(_) => indexer_eth_helios::MAX_CATCHUP_BLOCKS,
            EthereumClientInner::DirectRpc(_) => indexer_eth_direct_rpc::MAX_CATCHUP_BLOCKS,
        };
        Self::clamp_oldest_supported_with(requested_start, anchor_height, max_catchup_blocks)
    }

    pub fn clamp_oldest_supported_with(
        requested_start: u64,
        anchor_height: BlockNumber,
        max_catchup_blocks: u64,
    ) -> BlockNumber {
        let catchup_end = anchor_height.saturating_sub(1);
        let oldest_supported = catchup_end.saturating_sub(max_catchup_blocks);

        if requested_start < oldest_supported {
            tracing::warn!(
                requested_start,
                anchor_height,
                oldest_supported,
                "ethereum catchup start is older than supported range; clamping"
            );
            oldest_supported
        } else {
            requested_start
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils;
    use alloy::primitives::Bloom;
    use mockito::{Matcher, Server};
    use serde_json::json;
    use std::time::Duration;

    // TODO: add more tests for non HTTP-related functionality, e.g. clamp_oldest_supported_with

    #[test]
    fn catchup_start_is_clamped_to_supported_window() {
        let max_catchup_blocks = 8191;
        let anchor_height = 10_000;
        let catchup_end = anchor_height - 1;
        let expected_oldest = catchup_end - max_catchup_blocks;

        assert_eq!(
            EthereumClient::clamp_oldest_supported_with(1, anchor_height, max_catchup_blocks),
            expected_oldest,
        );
    }

    #[tokio::test]
    async fn shared_backoff_gates_concurrent_calls_on_429() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/")
            // 1 initial + max_times(2) retries per op, 2 concurrent ops.
            // Ungated, all 6 would fire within ~25ms of local backoff.
            .expect(6)
            .with_status(429)
            .with_body("Too Many Requests")
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url())
            .await
            .with_shared_backoff(SharedBackoff::with_cooldowns(
                Duration::from_millis(50),
                Duration::from_millis(200),
            ));

        let start = std::time::Instant::now();
        let (r1, r2) = tokio::join!(
            client.get_logs(Address::ZERO, BlockId::Number(BlockNumberOrTag::Number(1))),
            client.get_logs(Address::ZERO, BlockId::Number(BlockNumberOrTag::Number(2))),
        );

        // HTTP status surfaces in the error (retry classification relies on
        // this string match) and retries are exhausted.
        assert!(r1.is_err() && r2.is_err());
        assert!(r1.unwrap_err().to_string().contains("429"));
        // The gate forces retries into separate >= 50ms cooldown windows.
        assert!(start.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn ethereum_client_get_blocks_preserves_request_order() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    test_utils::block_response(3, 9),
                    test_utils::block_response(1, 7),
                    test_utils::missing_block_response(2),
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url()).await;
        let block_ids = vec![
            BlockId::Number(BlockNumberOrTag::Number(7)),
            BlockId::Number(BlockNumberOrTag::Number(8)),
            BlockId::Number(BlockNumberOrTag::Number(9)),
        ];

        let blocks = client.get_blocks(&block_ids).await;

        assert_eq!(blocks.len(), 3);
        assert!(matches!(&blocks[0], MaybeBlock::Block(block) if block.header.number == 7));
        assert!(matches!(
            &blocks[1],
            MaybeBlock::Missing(BlockId::Number(BlockNumberOrTag::Number(8)))
        ));
        assert!(matches!(&blocks[2], MaybeBlock::Block(block) if block.header.number == 9));
    }

    #[tokio::test]
    async fn ethereum_client_get_blocks_retries_and_keeps_positions() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "result": "invalid-shape" }).to_string())
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    test_utils::block_response(4, 20),
                    test_utils::missing_block_response(5),
                    test_utils::block_response(6, 22),
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url()).await;
        let block_ids = vec![
            BlockId::Number(BlockNumberOrTag::Number(20)),
            BlockId::Number(BlockNumberOrTag::Number(21)),
            BlockId::Number(BlockNumberOrTag::Number(22)),
        ];

        let blocks = client.get_blocks(&block_ids).await;

        assert_eq!(blocks.len(), 3);
        assert!(matches!(&blocks[0], MaybeBlock::Block(block) if block.header.number == 20));
        assert!(matches!(
            &blocks[1],
            MaybeBlock::Missing(BlockId::Number(BlockNumberOrTag::Number(21)))
        ));
        assert!(matches!(&blocks[2], MaybeBlock::Block(block) if block.header.number == 22));
    }

    #[tokio::test]
    async fn catchup_iter_fetches_batches_lazily() {
        let mut server = mockito::Server::new_async().await;

        let first_batch = (10..42)
            .enumerate()
            .map(|(index, block_number)| test_utils::block_response(index as u64 + 1, block_number))
            .collect::<Vec<_>>();
        let second_batch = vec![test_utils::block_response(33, 42)];

        let second_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(
                r#"eth_getBlockByNumber.*\"0x2a\""#.to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(second_batch).to_string())
            .create_async()
            .await;

        let first_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(
                r#"eth_getBlockByNumber.*\"0xa\""#.to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(first_batch).to_string())
            .create_async()
            .await;

        let contract_address = Address::with_last_byte(0x42);

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let mut iter = CatchupIter::new(client, 10, 43, contract_address, 32);

        for expected_number in 10..42 {
            let next = iter.next().await;
            assert!(
                matches!(
                    &next,
                    Some(CatchupItem::BatchBlock { block, .. }) if block.header.number == expected_number
                ),
                "Expected block {}, got {:?}",
                expected_number,
                next
            );
        }

        assert!(first_batch_mock.matched_async().await);
        assert!(!second_batch_mock.matched_async().await);

        let next = iter.next().await;
        assert!(
            matches!(
                &next,
                Some(CatchupItem::BatchBlock { block, .. }) if block.header.number == 42
            ),
            "Expected block 42, got {:?}",
            next
        );
        assert!(second_batch_mock.matched_async().await);
        assert!(iter.next().await.is_none());
    }

    #[tokio::test]
    async fn catchup_iter_splits_requests_into_32_32_1_batches() {
        let mut server = mockito::Server::new_async().await;

        let first_batch = (0..32)
            .enumerate()
            .map(|(idx, block_number)| test_utils::block_response(idx as u64 + 1, block_number))
            .collect::<Vec<_>>();
        let second_batch = (0..32)
            .enumerate()
            .map(|(idx, block_number)| {
                test_utils::block_response((idx + 33) as u64, block_number + 32)
            })
            .collect::<Vec<_>>();
        let third_batch = vec![test_utils::block_response(65, 64)];

        let first_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(
                r#"eth_getBlockByNumber.*\"0x1f\""#.to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(first_batch).to_string())
            .create_async()
            .await;

        let second_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(
                r#"eth_getBlockByNumber.*\"0x3f\""#.to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(second_batch).to_string())
            .create_async()
            .await;

        let third_batch_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex(
                r#"eth_getBlockByNumber.*\"0x40\""#.to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(third_batch).to_string())
            .create_async()
            .await;

        let contract_address = Address::with_last_byte(0x42);

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let mut iter = CatchupIter::new(client, 0, 65, contract_address, 32);

        for expected_number in 0..65 {
            let next = iter.next().await;
            assert!(
                matches!(
                    &next,
                    Some(CatchupItem::BatchBlock { block, .. }) if block.header.number == expected_number
                ),
                "Expected block {}, got {:?}",
                expected_number,
                next
            );
        }

        assert!(iter.next().await.is_none());
        assert!(first_batch_mock.matched_async().await);
        assert!(second_batch_mock.matched_async().await);
        assert!(third_batch_mock.matched_async().await);
    }

    #[tokio::test]
    async fn get_block_returns_block_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(1, 99).to_string())
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url()).await;
        let block = client
            .get_block(BlockId::Number(BlockNumberOrTag::Number(99)))
            .await
            .unwrap();

        assert!(block.is_some());
        assert_eq!(block.unwrap().header.number, 99);
    }

    #[tokio::test]
    async fn get_block_returns_none_on_null_result() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":null}"#)
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url()).await;
        let block = client
            .get_block(BlockId::Number(BlockNumberOrTag::Number(1)))
            .await
            .unwrap();

        assert!(block.is_none());
    }

    #[tokio::test]
    async fn get_block_retries_on_500_then_succeeds() {
        let mut server = mockito::Server::new_async().await;
        // First call → 500, second call → valid block
        let _fail = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("error")
            .expect(1)
            .create_async()
            .await;
        let _ok = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(1, 7).to_string())
            .expect(1)
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url()).await;
        let block = client
            .get_block(BlockId::Number(BlockNumberOrTag::Number(7)))
            .await
            .unwrap();

        assert!(block.is_some());
    }

    #[tokio::test]
    async fn get_block_retries_on_500_then_fails() {
        let mut server = mockito::Server::new_async().await;
        // Always return 500
        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("error")
            .expect(5) // should retry 5 times
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url()).await;
        let block = client
            .get_block(BlockId::Number(BlockNumberOrTag::Number(8)))
            .await;

        assert!(block.is_err());
    }

    #[tokio::test]
    async fn get_block_does_not_retry_on_4xx() {
        let mut server = mockito::Server::new_async().await;
        // Always return 4xx
        let _mock = server
            .mock("POST", "/")
            .with_status(400)
            .with_body("bad request")
            .expect(1) // should not retry
            .create_async()
            .await;

        let client = test_utils::create_test_ethereum_client(&server.url()).await;
        let block = client
            .get_block(BlockId::Number(BlockNumberOrTag::Number(9)))
            .await;

        assert!(block.is_err());
    }

    #[tokio::test]
    async fn catchup_iter_logs_batch_order_preservation() {
        let mut server = mockito::Server::new_async().await;
        let contract_address = Address::with_last_byte(0x42);
        let bloom = test_utils::bloom_containing_address(contract_address);

        // 2 blocks: 10 and 11, both bloom-positive so both enter the logs batch.
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    test_utils::block_response_with_bloom(1, 10, &bloom),
                    test_utils::block_response_with_bloom(2, 11, &bloom),
                ])
                .to_string(),
            )
            .create_async()
            .await;

        // Logs batch: request IDs are 3 (block 10) and 4 (block 11). Return
        // them SWAPPED (4 then 3) to test batch_execute reorders by id so
        // block 10 → 1 log, block 11 → 2 logs.
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getLogs".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                test_utils::logs_batch_response(&[
                    (
                        4,
                        vec![
                            test_utils::log_value(contract_address, 11, 0),
                            test_utils::log_value(contract_address, 11, 1),
                        ],
                    ),
                    (3, vec![test_utils::log_value(contract_address, 10, 0)]),
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let mut iter = CatchupIter::new(client, 10, 12, contract_address, 32);

        let item1 = iter.next().await.unwrap();
        let item2 = iter.next().await.unwrap();

        if let CatchupItem::BatchBlock { block, logs } = item1 {
            assert_eq!(block.header.number, 10, "first item should be block 10");
            assert_eq!(logs.len(), 1, "block 10 should have 1 log");
            assert_eq!(logs[0].address(), contract_address);
        } else {
            panic!("Expected BatchBlock for block 10, got {:?}", item1);
        }

        if let CatchupItem::BatchBlock { block, logs } = item2 {
            assert_eq!(block.header.number, 11, "second item should be block 11");
            assert_eq!(logs.len(), 2, "block 11 should have 2 logs");
            assert_eq!(logs[0].address(), contract_address);
        } else {
            panic!("Expected BatchBlock for block 11, got {:?}", item2);
        }
    }

    #[tokio::test]
    async fn catchup_iter_bloom_negative_block_skips_logs_fetch() {
        let mut server = mockito::Server::new_async().await;
        let contract_address = Address::with_last_byte(0x42);

        // 2 blocks with empty blooms → both bloom-negative. The eth_getLogs
        // mock is set up to FAIL the test if hit.
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    test_utils::block_response(1, 10),
                    test_utils::block_response(2, 11),
                ])
                .to_string(),
            )
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

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let mut iter = CatchupIter::new(client, 10, 12, contract_address, 32);

        for expected_number in [10u64, 11] {
            let item = iter.next().await.expect("expected item");
            match item {
                CatchupItem::BatchBlock { block, logs } => {
                    assert_eq!(block.header.number, expected_number);
                    assert!(logs.is_empty(), "bloom-negative block must have no logs");
                }
                other => panic!("expected BatchBlock for {expected_number}, got {other:?}"),
            }
        }
        assert!(iter.next().await.is_none());
    }

    /// Build a `Block` with the given `logs_bloom`.
    fn block_with_bloom(bloom: alloy::primitives::Bloom) -> Block {
        let mut block: Block = serde_json::from_value(
            test_utils::block_response(1, 7)
                .get("result")
                .expect("envelope present")
                .clone(),
        )
        .expect("fixture should deserialize");
        block.header.logs_bloom = bloom;
        block
    }

    #[test]
    fn block_may_contain_logs_empty_bloom_returns_false() {
        let block = block_with_bloom(Bloom::default());
        let addr = Address::with_last_byte(0x42);

        assert!(!block_may_contain_logs(&block, addr));
    }

    #[test]
    fn block_may_contain_logs_accrued_address_returns_true() {
        let addr = Address::with_last_byte(0x42);
        let mut bloom = Bloom::default();
        bloom.accrue_raw_log(addr, &[]);

        let block = block_with_bloom(bloom);

        // Bloom accrued with our address → true (no false negative).
        assert!(block_may_contain_logs(&block, addr));
    }

    #[test]
    fn block_may_contain_logs_disjoint_address_returns_false() {
        let addr = Address::with_last_byte(0x42);
        let other = Address::with_last_byte(0x07);

        let mut bloom = Bloom::default();
        bloom.accrue_raw_log(other, &[]);

        let block = block_with_bloom(bloom);

        // Bloom accrued with a different address must NOT report our address → false (no false positive).
        assert!(!block_may_contain_logs(&block, addr));
    }

    #[test]
    fn block_may_contain_logs_saturated_bloom_is_false_positive_tolerated() {
        let addr = Address::with_last_byte(0x42);
        // An all-ones bloom matches every address — false positive, but we tolerate it.
        let block = block_with_bloom(Bloom::from([0xffu8; 256]));

        assert!(block_may_contain_logs(&block, addr));
    }
}
