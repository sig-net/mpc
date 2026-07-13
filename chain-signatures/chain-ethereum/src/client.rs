use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::rpc::types::{Block, BlockId, TransactionReceipt};
use std::sync::Arc;
use std::time::Duration;

use crate::indexer_eth_direct_rpc;
use crate::EthConfig;
use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig};

#[cfg(feature = "helios")]
use super::indexer_eth_helios;

// TODO: check if our RPC providers support higher batch sizes
/// Catchup batch size for [`CatchupIter`]
pub const CATCHUP_BLOCK_BATCH_SIZE: u64 = 32;

/// Maximum number of concurrent catchup batches to fetch in parallel
pub const CATCHUP_CONCURRENT_BATCHES: usize = 3;

/// Block number alias shared by the client and indexer.
pub type BlockNumber = u64;

/// Result of attempting to fetch a single block
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeBlock {
    Block(Block),
    Missing(BlockId),
}

/// Catchup item yielded by [`CatchupIter`] and consumed by `process_catchup`.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CatchupItem {
    /// A block fetched as part of a catchup batch, plus receipts.
    /// `receipts` is `Vec::new()` for blocks with no transactions.
    BatchBlock {
        block: Block,
        receipts: Vec<TransactionReceipt>,
    },
    /// A block that was missing from the catchup batch response.
    /// `process_catchup` refetches both block and receipts individually.
    Missing(BlockId),
    /// A block from the live stream. Receipts are fetched lazily in
    /// `process`.
    LiveBlock(Block),
}

/// Lazy batching iterator over `[start_block, end_block)` range.
pub struct CatchupIter {
    client: Arc<EthereumClient>,
    next_block: BlockNumber,
    end_block: BlockNumber,
    buffered_blocks: std::vec::IntoIter<CatchupItem>,
}

impl CatchupIter {
    pub fn new(
        client: Arc<EthereumClient>,
        start_block: BlockNumber,
        end_block: BlockNumber,
    ) -> Self {
        Self {
            client,
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
            .saturating_add(CATCHUP_BLOCK_BATCH_SIZE)
            .min(self.end_block);

        let items = self.client.fetch_batch(self.next_block, batch_end).await;

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

// Constants for Ethereum RPC client retry behavior
const ETH_RPC_TIMEOUT: Duration = Duration::from_secs(2);
const ETH_RPC_BATCH_TIMEOUT: Duration = Duration::from_secs(5);
const ETH_RPC_MIN_DELAY: Duration = Duration::from_millis(500);
const ETH_RPC_MAX_DELAY: Duration = Duration::from_secs(10);
const ETH_RPC_MAX_RETRIES: usize = 5;

/// Helper for consistent config
fn default_eth_retry_strategy() -> RetryConfig {
    RetryConfig {
        min_delay: ETH_RPC_MIN_DELAY,
        max_delay: ETH_RPC_MAX_DELAY,
        max_times: ETH_RPC_MAX_RETRIES,
        jitter: true,
    }
}

#[derive(Clone)]
pub struct EthereumClient {
    inner: EthereumClientInner,
    retry_strategy: RetryConfig,
}

#[derive(Clone)]
pub enum EthereumClientInner {
    #[cfg(feature = "helios")]
    Helios(indexer_eth_helios::HeliosEthereumClient),
    DirectRpc(indexer_eth_direct_rpc::RpcEthereumClient),
}

impl EthereumClient {
    pub async fn new(eth: EthConfig) -> anyhow::Result<EthereumClient> {
        Self::new_with_strategy(eth, default_eth_retry_strategy()).await
    }

    /// Creates a new Ethereum client with the specified retry strategy.
    pub async fn new_with_strategy(
        eth: EthConfig,
        retry_strategy: RetryConfig,
    ) -> anyhow::Result<Self> {
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
                &eth.execution_rpc_http_url,
            ))
        };

        Ok(Self {
            inner,
            retry_strategy,
        })
    }

    fn client_name(&self) -> &str {
        match &self.inner {
            #[cfg(feature = "helios")]
            EthereumClientInner::Helios(_) => "Helios",
            EthereumClientInner::DirectRpc(_) => "DirectRpc",
        }
    }

    pub async fn get_block(&self, block_id: BlockId) -> Option<Block> {
        let max_attempts = self.retry_strategy.max_times;
        let res = retry_rpc!(
            ETH_RPC_TIMEOUT,
            self.retry_strategy,
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
        );

        match res {
            Ok(Some(block)) => Some(block),
            Ok(None) => {
                tracing::warn!(client = self.client_name(), "Block {block_id:?} not found");
                None
            }
            Err(err) => {
                tracing::warn!(
                    client = self.client_name(),
                    "get_block failed for {block_id:?}: {err:#}"
                );
                None
            }
        }
    }

    pub async fn get_blocks(&self, block_ids: &[BlockId]) -> Vec<MaybeBlock> {
        if block_ids.is_empty() {
            return Vec::new();
        }

        let max_attempts = self.retry_strategy.max_times;
        let num_blocks = block_ids.len();

        let res = retry_rpc!(
            ETH_RPC_BATCH_TIMEOUT,
            self.retry_strategy,
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

    pub async fn get_block_receipts(
        &self,
        block_id: BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        retry_rpc!(
            ETH_RPC_TIMEOUT,
            self.retry_strategy,
            "get_block_receipts",
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => {
                        client.get_block_receipts(block_id).await
                    }
                    EthereumClientInner::DirectRpc(client) => {
                        client.get_block_receipts(block_id).await
                    }
                }
            }
        )
    }

    /// Fetch receipts for multiple blocks in a single JSON-RPC batch POST.
    ///
    /// Returns one `Option<Vec<TransactionReceipt>>` per input `block_id`,
    /// in the same order as `block_ids`
    ///
    /// On permanent failure the whole batch fails (consistent with
    /// `get_blocks`). The retry wrapper retries the entire batch.
    pub async fn get_block_receipts_batch(
        &self,
        block_ids: &[BlockId],
    ) -> anyhow::Result<Vec<Option<Vec<alloy::rpc::types::TransactionReceipt>>>> {
        retry_rpc!(
            ETH_RPC_BATCH_TIMEOUT,
            self.retry_strategy,
            "get_block_receipts_batch",
            {
                match &self.inner {
                    #[cfg(feature = "helios")]
                    EthereumClientInner::Helios(client) => {
                        client.get_block_receipts_batch(block_ids).await
                    }
                    EthereumClientInner::DirectRpc(client) => {
                        client.get_block_receipts_batch(block_ids).await
                    }
                }
            }
        )
    }

    pub async fn fetch_batch(&self, start: BlockNumber, end: BlockNumber) -> Vec<CatchupItem> {
        let batch_block_ids = (start..end)
            .map(|block_number| BlockId::Number(BlockNumberOrTag::Number(block_number)))
            .collect::<Vec<_>>();

        #[cfg(feature = "bench")]
        let start_time = std::time::Instant::now();

        let (blocks, receipts) = tokio::join!(
            self.get_blocks(&batch_block_ids),
            self.get_block_receipts_batch(&batch_block_ids)
        );

        let items: Vec<CatchupItem> = if let Ok(receipts) = receipts {
            blocks
                .into_iter()
                .zip(receipts)
                .zip(batch_block_ids)
                .map(
                    |((maybe_block, maybe_receipts), block_id)| match maybe_block {
                        MaybeBlock::Block(block) => CatchupItem::BatchBlock {
                            block,
                            receipts: maybe_receipts.unwrap_or_default(),
                        },
                        MaybeBlock::Missing(_) => CatchupItem::Missing(block_id),
                    },
                )
                .collect()
        } else {
            batch_block_ids
                .into_iter()
                .map(CatchupItem::Missing)
                .collect()
        };

        #[cfg(feature = "bench")]
        crate::bench::add_batch_fetch_time(start_time.elapsed());

        items
    }

    pub async fn get_nonce(&self, address: Address, block_id: BlockId) -> anyhow::Result<u64> {
        retry_rpc!(ETH_RPC_TIMEOUT, self.retry_strategy, "get_nonce", {
            match &self.inner {
                #[cfg(feature = "helios")]
                EthereumClientInner::Helios(client) => client.get_nonce(address, block_id).await,
                EthereumClientInner::DirectRpc(client) => client.get_nonce(address, block_id).await,
            }
        })
    }

    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        retry_rpc!(
            ETH_RPC_TIMEOUT,
            self.retry_strategy,
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
    ) -> anyhow::Result<alloy::primitives::Bytes> {
        // TODO: trace_transaction_output can be slow, consider a longer timeout than ETH_RPC_TIMEOUT if necessary
        retry_rpc!(
            ETH_RPC_TIMEOUT,
            self.retry_strategy,
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

    pub async fn get_latest_block_number(&self) -> Option<u64> {
        self.get_block(BlockId::Number(alloy::rpc::types::BlockNumberOrTag::Latest))
            .await
            .map(|block| block.header.number)
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
    use mockito::{Matcher, Server};
    use serde_json::json;

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
        let second_batch = vec![test_utils::block_response(65, 42)];

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

        // Receipt mocks: return an empty array for any eth_getBlockReceipts call.
        // This test verifies block-batch laziness, not receipt content.
        let _receipts_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockReceipts".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let mut iter = CatchupIter::new(client, 10, 43);

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
                test_utils::block_response((idx + 65) as u64, block_number + 32)
            })
            .collect::<Vec<_>>();
        let third_batch = vec![test_utils::block_response(129, 64)];

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

        // Receipt mocks: return an empty array for any eth_getBlockReceipts call.
        // This test verifies block-batch splitting, not receipt content.
        let _receipts_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockReceipts".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let mut iter = CatchupIter::new(client, 0, 65);

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
            .await;

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
            .await;

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
            .await;

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

        assert!(block.is_none());
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

        assert!(block.is_none());
    }

    #[tokio::test]
    async fn catchup_iter_receipt_batch_order_preservation() {
        let mut server = mockito::Server::new_async().await;

        // 2 blocks: 10 (0xa), 11 (0xb). IDs 1 and 2 (counter starts at 1).
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
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

        // Receipts batch IDs are 3 and 4. Return them SWAPPED (4 then 3) to test
        // that batch_execute reorders by ID so block 10 → 1 receipt, block 11 → 2 receipts.
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockReceipts".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                test_utils::receipts_batch_response(&[
                    // ID 4 first (block 11 → 2 receipts)
                    (
                        4,
                        Some(json!([
                            test_utils::receipt_value("0x0000000000000000000000000000000000000000000000000000000000000002", 11),
                            test_utils::receipt_value("0x0000000000000000000000000000000000000000000000000000000000000003", 11),
                        ])),
                    ),
                    // ID 3 second (block 10 → 1 receipt)
                    (
                        3,
                        Some(json!([
                            test_utils::receipt_value("0x0000000000000000000000000000000000000000000000000000000000000001", 10),
                        ])),
                    ),
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let mut iter = CatchupIter::new(client, 10, 12);

        let item1 = iter.next().await.unwrap();
        let item2 = iter.next().await.unwrap();

        // Block 10 → 1 receipt (ID 3 was second in response but maps to block 10)
        if let CatchupItem::BatchBlock { block, receipts } = item1 {
            assert_eq!(block.header.number, 10, "first item should be block 10");
            assert_eq!(receipts.len(), 1, "block 10 should have 1 receipt");
        } else {
            panic!("Expected BatchBlock for block 10, got {:?}", item1);
        }

        // Block 11 → 2 receipts (ID 4 was first in response but maps to block 11)
        if let CatchupItem::BatchBlock { block, receipts } = item2 {
            assert_eq!(block.header.number, 11, "second item should be block 11");
            assert_eq!(receipts.len(), 2, "block 11 should have 2 receipts");
        } else {
            panic!("Expected BatchBlock for block 11, got {:?}", item2);
        }
    }
}
