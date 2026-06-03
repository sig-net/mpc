use crate::indexer_eth::{EthConfig, MaybeBlock};
use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::primitives::Address;
use alloy::primitives::Bytes;
use alloy::rpc::types::TransactionRequest;
use futures_util::future::join_all;
use helios::ethereum::{config::networks::Network, EthereumClient, EthereumClientBuilder};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

// This is the maximum number of blocks that Helios can look back to
pub const MAX_CATCHUP_BLOCKS: u64 = 8191;

#[derive(Clone)]
pub struct HeliosEthereumClient {
    client: Arc<EthereumClient>,
}

impl HeliosEthereumClient {
    fn new(client: EthereumClient) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    pub async fn get_block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<alloy::rpc::types::Block>> {
        self.fetch_block(block_id).await
    }

    /// Fetch multiple blocks in parallel. Missing blocks stay associated with requested height.
    pub async fn get_blocks(
        &self,
        block_ids: &[alloy::rpc::types::BlockId],
    ) -> anyhow::Result<Vec<MaybeBlock>> {
        if block_ids.is_empty() {
            return Ok(Vec::new());
        }

        let blocks = join_all(
            block_ids
                .iter()
                .copied()
                .map(|block_id| async move { (block_id, self.get_block(block_id).await) }),
        )
        .await
        .into_iter()
        .map(|(block_id, result)| match result {
            Ok(Some(block)) => MaybeBlock::Block(block),
            Ok(None) => MaybeBlock::Missing(block_id),
            Err(err) => {
                tracing::warn!(?err, "helios batch block fetch failed");
                MaybeBlock::Missing(block_id)
            }
        })
        .collect::<Vec<_>>();

        Ok(blocks)
    }

    pub async fn get_block_receipts(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        self.client
            .get_block_receipts(block_id)
            .await
            .map_err(|err| anyhow::anyhow!("Failed to get block receipts for block: {:?}", err))
    }

    pub async fn get_nonce(
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

    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        self.client.get_transaction(tx_hash).await.map_err(|err| {
            anyhow::anyhow!("Failed to get transaction by hash {tx_hash:?}: {:?}", err)
        })
    }

    pub async fn trace_transaction_output(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Bytes> {
        tracing::warn!(
            ?tx_hash,
            "debug_traceTransaction is not supported by Helios; refusing to fall back to eth_call"
        );

        anyhow::bail!(
            "debug_traceTransaction is not supported by Helios; use direct RPC, e.g. Alchemy, for bidirectional transaction output extraction"
        )
    }

    pub async fn call(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        block_number: u64,
    ) -> anyhow::Result<Bytes> {
        // Build a base tx *without* the sentinel max gas
        let mut tx = TransactionRequest::default()
            .from(from)
            .to(to)
            .input(alloy::rpc::types::TransactionInput::both(data.clone()));

        // 1) Estimate
        let est = self
            .client
            .estimate_gas(&tx, BlockId::Number(BlockNumberOrTag::Number(block_number)))
            .await
            .unwrap_or(3_000_000u64); // fallback

        // 2) Add 20% buffer, but keep < 16,777,216
        let mut gas = (est as f64 * 1.2) as u64;
        if gas > 16_777_216 {
            gas = 16_777_216;
        }

        // 3) Apply gas limit
        tx = tx.gas_limit(gas);

        // 4) Execute the call
        self.client
            .call(&tx, BlockId::Number(BlockNumberOrTag::Number(block_number)))
            .await
            .map_err(|err| anyhow::anyhow!("Failed to call: {err:?}"))
    }

    async fn fetch_block(
        &self,
        block_id: BlockId,
    ) -> anyhow::Result<Option<alloy::rpc::types::Block>> {
        self.client.get_block(block_id, false).await.map_err(|err| {
            anyhow::anyhow!("Failed to fetch block for block id {block_id:?}: {:?}", err)
        })
    }
}

pub async fn build_client(eth: EthConfig) -> anyhow::Result<HeliosEthereumClient> {
    let Ok(network) = Network::from_str(eth.network.as_str()) else {
        return Err(anyhow::anyhow!("Network input incorrect: {}", eth.network));
    };
    let client = EthereumClientBuilder::new()
        .network(network)
        .consensus_rpc(&eth.consensus_rpc_http_url)
        .map_err(|err| anyhow::anyhow!("failed to build consensus rpc: {err:?}"))?
        .execution_rpc(&eth.execution_rpc_http_url)
        .map_err(|err| anyhow::anyhow!("failed to build execution rpc: {err:?}"))?
        .data_dir(PathBuf::from(&eth.helios_data_path))
        .with_file_db()
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build helios client: {err:?}"))?;
    tracing::info!("Built Helios client on network {}", network);
    client
        .wait_synced()
        .await
        .map_err(|err| anyhow::anyhow!("Failed to wait for synced: {err:?}"))?;

    Ok(HeliosEthereumClient::new(client))
}
