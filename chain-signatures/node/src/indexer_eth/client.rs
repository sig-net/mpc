use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::{Block, BlockId};

use super::{indexer_eth_direct_rpc, BlockNumber, EthConfig, MaybeBlock};
use crate::util::retry;

#[cfg(feature = "helios")]
use super::indexer_eth_helios;

#[derive(Clone)]
pub enum EthereumClient {
    #[cfg(feature = "helios")]
    Helios(indexer_eth_helios::HeliosEthereumClient),
    DirectRpc(indexer_eth_direct_rpc::RpcEthereumClient),
}

impl EthereumClient {
    pub async fn new(eth: EthConfig) -> anyhow::Result<EthereumClient> {
        if eth.light_client {
            #[cfg(feature = "helios")]
            {
                return Ok(EthereumClient::Helios(
                    indexer_eth_helios::build_client(eth.clone()).await?,
                ));
            }

            #[cfg(not(feature = "helios"))]
            {
                anyhow::bail!(
                    "ethereum light client requested, but mpc-node was built without helios feature"
                );
            }
        }

        {
            Ok(EthereumClient::DirectRpc(
                indexer_eth_direct_rpc::RpcEthereumClient::new(&eth.execution_rpc_http_url),
            ))
        }
    }

    fn client_name(&self) -> &str {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(_) => "Helios",
            EthereumClient::DirectRpc(_) => "DirectRpc",
        }
    }

    pub async fn get_block(&self, block_id: BlockId) -> Option<Block> {
        // Configure retry behaviour and delegate to shared retry_async helper.
        let retry_config = retry::RetryConfig::default();
        let get_block_op = |_attempt: usize| async {
            match self {
                #[cfg(feature = "helios")]
                EthereumClient::Helios(client) => client.get_block(block_id).await,
                EthereumClient::DirectRpc(client) => client.get_block(block_id).await,
            }
        };

        let res = retry::retry_async(
            retry_config,
            get_block_op,
            |_attempt, _reason| true,
            |attempt, reason, sleep_duration| match reason {
                retry::RetryReason::Error(e) => {
                    tracing::warn!(
                        client = self.client_name(),
                        "get_block failed (attempt {attempt}) for {block_id:?}: {e:#}; retrying in {sleep_duration:?}"
                    );
                }
                retry::RetryReason::Timeout(t) => {
                    tracing::warn!(
                        client = self.client_name(),
                        "get_block timed out after {t:?} (attempt {attempt}) for {block_id:?}; retrying in {sleep_duration:?}"
                    );
                }
            },
        )
        .await;

        match res {
            Ok(Some(block)) => Some(block),
            Ok(None) => {
                tracing::warn!(client = self.client_name(), "Block {block_id:?} not found");
                None
            }
            Err(retry::RetryError::Exhausted {
                attempts,
                last_error,
            }) => {
                tracing::warn!(
                    client = self.client_name(),
                    "get_block failed for {block_id:?}: {last_error:#}; exhausted after {attempts} attempts"
                );
                None
            }
            Err(retry::RetryError::TimeoutExhausted {
                attempts,
                last_timeout,
            }) => {
                tracing::warn!(
                    client = self.client_name(),
                    "get_block timed out for {block_id:?} (last timeout {last_timeout:?}); exhausted after {attempts} attempts"
                );
                None
            }
        }
    }

    pub async fn get_blocks(&self, block_ids: &[BlockId]) -> Vec<MaybeBlock> {
        if block_ids.is_empty() {
            return Vec::new();
        }

        let retry_config = retry::RetryConfig::default();
        let block_ids = block_ids.to_vec();
        let get_blocks_op = |_attempt: usize| {
            let block_ids = block_ids.clone();
            async move {
                match self {
                    #[cfg(feature = "helios")]
                    EthereumClient::Helios(client) => client.get_blocks(&block_ids).await,
                    EthereumClient::DirectRpc(client) => client.get_blocks(&block_ids).await,
                }
            }
        };

        match retry::retry_async(
            retry_config,
            get_blocks_op,
            |_attempt, _reason| true,
            |attempt, reason, sleep_duration| match reason {
                retry::RetryReason::Error(e) => {
                    tracing::warn!(
                        client = self.client_name(),
                        num_blocks = block_ids.len(),
                        "get_blocks failed (attempt {attempt}): {e:#}; retrying in {sleep_duration:?}"
                    );
                }
                retry::RetryReason::Timeout(t) => {
                    tracing::warn!(
                        client = self.client_name(),
                        num_blocks = block_ids.len(),
                        "get_blocks timed out after {t:?} (attempt {attempt}); retrying in {sleep_duration:?}"
                    );
                }
            },
        )
        .await
        {
            Ok(blocks) => blocks,
            Err(retry::RetryError::Exhausted { attempts, last_error }) => {
                tracing::warn!(
                    client = self.client_name(),
                    num_blocks = block_ids.len(),
                    "get_blocks failed: {last_error:#}; exhausted after {attempts} attempts"
                );
                block_ids.iter().copied().map(MaybeBlock::Missing).collect()
            }
            Err(retry::RetryError::TimeoutExhausted { attempts, last_timeout }) => {
                tracing::warn!(
                    client = self.client_name(),
                    num_blocks = block_ids.len(),
                    "get_blocks timed out (last timeout {last_timeout:?}); exhausted after {attempts} attempts"
                );
                block_ids.iter().copied().map(MaybeBlock::Missing).collect()
            }
        }
    }

    pub async fn get_block_receipts(
        &self,
        block_id: BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.get_block_receipts(block_id).await,
            EthereumClient::DirectRpc(client) => client.get_block_receipts(block_id).await,
        }
    }

    pub async fn get_nonce(&self, address: Address, block_id: BlockId) -> anyhow::Result<u64> {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.get_nonce(address, block_id).await,
            EthereumClient::DirectRpc(client) => client.get_nonce(address, block_id).await,
        }
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
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.get_transaction_by_hash(tx_hash).await,
            EthereumClient::DirectRpc(client) => client.get_transaction_by_hash(tx_hash).await,
        }
    }

    pub async fn trace_transaction_output(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<alloy::primitives::Bytes> {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.trace_transaction_output(tx_hash).await,
            EthereumClient::DirectRpc(client) => client.trace_transaction_output(tx_hash).await,
        }
    }

    pub async fn call(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        block_number: u64,
    ) -> anyhow::Result<Bytes> {
        match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(client) => client.call(from, to, data, block_number).await,
            EthereumClient::DirectRpc(client) => client.call(from, to, data, block_number).await,
        }
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
        let max_catchup_blocks = match self {
            #[cfg(feature = "helios")]
            EthereumClient::Helios(_) => indexer_eth_helios::MAX_CATCHUP_BLOCKS,
            EthereumClient::DirectRpc(_) => indexer_eth_direct_rpc::MAX_CATCHUP_BLOCKS,
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
