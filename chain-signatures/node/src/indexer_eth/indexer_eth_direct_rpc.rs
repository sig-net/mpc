use crate::indexer_eth::EthereumClientTrait;
use crate::indexer_eth::SignatureRequested;
use crate::indexer_eth::SignatureResponded;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::Log;
use alloy::rpc::types::Transaction;
use alloy::rpc::types::TransactionReceipt;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct RpcEthereumClient {
    http: reqwest::Client,
    url: String,
    id: Arc<AtomicU64>,
}

#[async_trait]
impl EthereumClientTrait for RpcEthereumClient {
    async fn get_block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> Option<alloy::rpc::types::Block> {
        self.block(block_id).await.unwrap_or(None)
    }

    async fn get_block_receipts(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        self.block_receipts(block_id).await
    }

    async fn get_nonce(
        &self,
        address: Address,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<u64> {
        self.nonce(address, block_id).await
    }

    async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        self.transaction_by_hash(tx_hash).await
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
        self.block_number().await
    }

    async fn get_transaction_receipt(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.transaction_receipt(tx_hash).await
    }
}

impl RpcEthereumClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: endpoint.to_owned(),
            id: Arc::new(AtomicU64::new(1)),
        }
    }

    fn next_id(&self) -> u64 {
        self.id.fetch_add(1, Ordering::Relaxed)
    }

    async fn rpc_call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> anyhow::Result<T> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": self.next_id(),
            "method": method,
            "params": params,
        });

        let response = self.http.post(&self.url).json(&request).send().await?;
        let value: serde_json::Value = response.json().await?;

        if let Some(error) = value.get("error") {
            anyhow::bail!("rpc {method} failed: {error}");
        }

        let result = value
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(serde_json::from_value(result)?)
    }

    async fn block_number(&self) -> anyhow::Result<u64> {
        let hex: String = self.rpc_call("eth_blockNumber", Vec::new()).await?;
        hex_to_u64(&hex)
    }

    async fn block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<alloy::rpc::types::Block>> {
        match block_id {
            alloy::rpc::types::BlockId::Number(_) => {
                self.rpc_call(
                    "eth_getBlockByNumber",
                    vec![json!(to_hex_block_id(block_id)), json!(false)],
                )
                .await
            }
            alloy::rpc::types::BlockId::Hash(hash) => {
                self.rpc_call(
                    "eth_getBlockByHash",
                    vec![json!(format!("{:#x}", hash.block_hash))],
                )
                .await
            }
        }
    }

    async fn block_receipts(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        self.rpc_call(
            "eth_getBlockReceipts",
            vec![json!(to_hex_block_id(block_id))],
        )
        .await
    }

    #[allow(unused)]
    async fn get_logs(
        &self,
        block_hash: alloy::primitives::B256,
        contract_address: Address,
    ) -> anyhow::Result<Vec<Log>> {
        let topic_requested = format!("0x{}", SignatureRequested::SIGNATURE_HASH.encode_hex());
        let topic_responded = format!("0x{}", SignatureResponded::SIGNATURE_HASH.encode_hex());
        let filter = json!({
            "address": format_address(contract_address),
            "blockHash": format!("{:#x}", block_hash),
            "topics": [[topic_requested, topic_responded]],
        });
        self.rpc_call("eth_getLogs", vec![filter]).await
    }

    async fn transaction_receipt(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.rpc_call(
            "eth_getTransactionReceipt",
            vec![json!(format!("{:#x}", tx_hash))],
        )
        .await
    }

    async fn transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<Transaction>> {
        self.rpc_call(
            "eth_getTransactionByHash",
            vec![json!(format!("{:#x}", tx_hash))],
        )
        .await
    }

    async fn nonce(
        &self,
        address: Address,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<u64> {
        self.rpc_call::<String>(
            "eth_getTransactionCount",
            vec![
                json!(format_address(address)),
                json!(to_hex_block_id(block_id)),
            ],
        )
        .await
        .and_then(|nonce| {
            hex_to_u64(&nonce).map_err(|err| anyhow::anyhow!("Failed to parse nonce: {err}"))
        })
    }

    async fn call(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        block_number: u64,
    ) -> anyhow::Result<Bytes> {
        let params = json!({
            "from": format_address(from),
            "to": format_address(to),
            "data": format_bytes(&data),
        });
        let block = json!(to_hex_u64(block_number));
        let result: String = self.rpc_call("eth_call", vec![params, block]).await?;
        let stripped = result.trim_start_matches("0x");
        if stripped.is_empty() {
            return Ok(Bytes::default());
        }
        let decoded = hex::decode(stripped)?;
        Ok(Bytes::from(decoded))
    }
}

fn format_address(address: Address) -> String {
    format!("0x{}", address.encode_hex())
}

fn format_bytes(data: &Bytes) -> String {
    if data.is_empty() {
        "0x".to_string()
    } else {
        format!("0x{}", hex::encode(data))
    }
}

fn to_hex_u64(value: u64) -> String {
    format!("0x{:x}", value)
}

fn hex_to_u64(value: &str) -> anyhow::Result<u64> {
    let trimmed = value.trim_start_matches("0x");
    if trimmed.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(trimmed, 16)
        .map_err(|err| anyhow::anyhow!("failed to parse hex value '{value}': {err}"))
}

fn to_hex_block_id(block_id: alloy::rpc::types::BlockId) -> String {
    match block_id {
        alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Number(number)) => to_hex_u64(number),
        alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Latest) => "latest".to_string(),
        alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Finalized) => "finalized".to_string(),
        alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Safe) => "safe".to_string(),
        alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Earliest) => "earliest".to_string(),
        alloy::rpc::types::BlockId::Number(BlockNumberOrTag::Pending) => "pending".to_string(),
        alloy::rpc::types::BlockId::Hash(hash) => format!("{:#x}", hash.block_hash),
    }
}
