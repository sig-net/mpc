use crate::indexer_eth::EthConfig;
use crate::indexer_eth::EthereumClientTrait;
use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::primitives::Address;
use alloy::primitives::Bytes;
use alloy::rpc::types::TransactionRequest;
use async_trait::async_trait;
use helios::ethereum::{config::networks::Network, EthereumClient, EthereumClientBuilder};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::Duration;

#[derive(Clone)]
pub struct HeliosEthereumClient {
    client: Arc<EthereumClient>,
    max_retries: u8,
    base_delay: Duration,
}

#[async_trait]
impl EthereumClientTrait for HeliosEthereumClient {
    async fn get_block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> Option<alloy::rpc::types::Block> {
        self.fetch_block(block_id).await
    }

    async fn get_block_receipts(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        self.client
            .get_block_receipts(block_id)
            .await
            .map_err(|err| anyhow::anyhow!("Failed to get block receipts for block: {:?}", err))
    }

    async fn get_nonce(
        &self,
        address: Address,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<u64> {
        self.client
            .get_nonce(address, block_id)
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "Failed to get nonce for address {address:?} and block id {block_id:?}: {:?}",
                    err
                )
            })
    }

    async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        self.client.get_transaction(tx_hash).await.map_err(|err| {
            anyhow::anyhow!("Failed to get transaction by hash {tx_hash:?}: {:?}", err)
        })
    }

    async fn call(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        block_number: u64,
    ) -> anyhow::Result<Bytes> {
        self.call(from, to, data, block_number).await
    }

    async fn get_latest_block_number(&self) -> anyhow::Result<u64> {
        self.get_latest_block_number().await
    }

    async fn get_transaction_receipt(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::TransactionReceipt>> {
        self.get_transaction_receipt(tx_hash).await
    }
}

impl HeliosEthereumClient {
    fn new(client: EthereumClient, max_retries: u8, base_delay: Duration) -> Self {
        Self {
            client: Arc::new(client),
            max_retries,
            base_delay,
        }
    }

    // retry getting block from helios with exponential backoff
    async fn fetch_block(&self, block_id: BlockId) -> Option<alloy::rpc::types::Block> {
        let helios_client = self.client.clone();
        let mut retries = 0;
        loop {
            match helios_client.get_block(block_id, false).await {
                Ok(Some(block)) => return Some(block),
                Ok(None) => {
                    tracing::warn!("Block {block_id} not found from Helios client");
                    return None;
                }
                Err(e) => {
                    if retries < self.max_retries {
                        retries += 1;
                        let delay = self.base_delay * 2u32.pow((retries - 1) as u32);
                        tracing::warn!(
                        "Failed to fetch block number {block_id} from Helios client: {:?}, retrying",
                        e
                    );
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    tracing::warn!(
                    "Failed to fetch block number {block_id} from Helios client: {:?}, exceeded maximum retry",
                    e
                );
                    return None;
                }
            }
        }
    }

    async fn call(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        block_number: u64,
    ) -> anyhow::Result<Bytes> {
        let helios_client = self.client.clone();
        helios_client
            .call(
                &TransactionRequest::default()
                    .from(from)
                    .to(to)
                    .input(alloy::rpc::types::TransactionInput::both(data.clone())),
                BlockId::Number(BlockNumberOrTag::Number(block_number)),
            )
            .await
            .map_err(|err| anyhow::anyhow!("Failed to call: {err:?}"))
    }

    async fn get_latest_block_number(&self) -> anyhow::Result<u64> {
        let Some(block) = self
            .fetch_block(BlockId::Number(BlockNumberOrTag::Latest))
            .await
        else {
            return Err(anyhow::anyhow!("Latest block not found"));
        };
        Ok(block.header.number)
    }

    async fn get_transaction_receipt(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::TransactionReceipt>> {
        self.client
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|err| anyhow::anyhow!("Failed to get transaction receipt: {err:?}"))
    }
}

pub async fn build_client(eth: EthConfig) -> anyhow::Result<HeliosEthereumClient> {
    let Ok(network) = Network::from_str(eth.network.as_str()) else {
        return Err(anyhow::anyhow!("Network input incorrect: {}", eth.network));
    };
    let client: EthereumClient = {
        let builder = match EthereumClientBuilder::new()
            .network(network)
            .consensus_rpc(&eth.consensus_rpc_http_url)
        {
            Ok(builder) => builder,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to build consensus RPC: {err:?}"));
            }
        };

        let builder = match builder.execution_rpc(&eth.execution_rpc_http_url) {
            Ok(builder) => builder,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to build execution RPC: {err:?}"));
            }
        };

        match builder
            .data_dir(PathBuf::from(&eth.helios_data_path))
            .with_file_db()
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to build Helios client: {err:?}"));
            }
        }
    };
    tracing::info!("Built Helios client on network {}", network);
    client
        .wait_synced()
        .await
        .map_err(|err| anyhow::anyhow!("Failed to wait for synced: {err:?}"))?;

    Ok(HeliosEthereumClient::new(
        client,
        6,
        Duration::from_millis(200),
    ))
}
