use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::{Block, BlockId};

use super::{indexer_eth_direct_rpc, BlockNumber, EthConfig, MaybeBlock};
use crate::util::retry::{retry_rpc, RetryConfig};

#[cfg(feature = "helios")]
use super::indexer_eth_helios;

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

    pub async fn get_nonce(&self, address: Address, block_id: BlockId) -> anyhow::Result<u64> {
        retry_rpc!(ETH_RPC_TIMEOUT, self.retry_strategy, "get_nonce", {
            match &self.inner {
                #[cfg(feature = "helios")]
                EthereumClientInner::Helios(client) => client.get_nonce(address, block_id).await,
                EthereumClientInner::DirectRpc(client) => client.get_nonce(address, block_id).await,
            }
        })
    }

    pub fn block_number_from_id(block_id: BlockId) -> BlockNumber {
        match block_id {
            BlockId::Number(BlockNumberOrTag::Number(block_number)) => block_number,
            BlockId::Number(tag) => panic!("expected numbered block id, got {tag:?}"),
            BlockId::Hash(hash) => panic!("expected numbered block id, got hash {hash:?}"),
        }
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

    pub async fn call(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        block_number: u64,
    ) -> anyhow::Result<Bytes> {
        retry_rpc!(ETH_RPC_TIMEOUT, self.retry_strategy, "call", {
            match &self.inner {
                #[cfg(feature = "helios")]
                EthereumClientInner::Helios(client) => {
                    client.call(from, to, data.clone(), block_number).await
                }
                EthereumClientInner::DirectRpc(client) => {
                    client.call(from, to, data.clone(), block_number).await
                }
            }
        })
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
    use crate::indexer_eth::test_utils;

    use super::*;

    // TODO: add more tests for non HTTP-related functionality, e.g. clamp_oldest_supported_with

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
}
