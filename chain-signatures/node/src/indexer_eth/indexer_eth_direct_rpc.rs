use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::Transaction;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// This is more than likely limited by the RPC provider, but alchemy
// supports archive nodes, so we effectively can go as far back as needed
// for direct RPC client.
pub const MAX_CATCHUP_BLOCKS: u64 = u64::MAX;

#[derive(Clone)]
pub struct RpcEthereumClient {
    http: reqwest::Client,
    url: String,
    id: Arc<AtomicU64>,
}

impl RpcEthereumClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: endpoint.to_owned(),
            id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub async fn get_block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<alloy::rpc::types::Block>> {
        self.block(block_id).await
    }

    pub async fn get_block_receipts(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        self.block_receipts(block_id).await
    }

    pub async fn get_nonce(
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

    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        self.transaction_by_hash(tx_hash).await
    }

    pub async fn trace_transaction_output(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Bytes> {
        let trace: serde_json::Value = self
            .rpc_call(
                "debug_traceTransaction",
                vec![
                    json!(format!("{:#x}", tx_hash)),
                    json!({
                        "tracer": "callTracer",
                        "tracerConfig": {
                            "onlyTopCall": true
                        },
                        "timeout": "30s"
                    }),
                ],
            )
            .await?;

        let call_frame = debug_trace_call_frame(&trace)?;
        trace_output_to_bytes(tx_hash, call_frame)
    }

    pub async fn call(
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
}

fn debug_trace_call_frame(trace: &serde_json::Value) -> anyhow::Result<&serde_json::Value> {
    if trace.get("output").is_some()
        || trace.get("returnValue").is_some()
        || trace.get("error").is_some()
        || trace.get("failed").is_some()
    {
        return Ok(trace);
    }

    let Some(items) = trace.as_array() else {
        anyhow::bail!("Unexpected debug_traceTransaction response: {:?}", trace);
    };

    let item = items
        .iter()
        .find(|item| {
            item.get("name")
                .and_then(serde_json::Value::as_str)
                .map(|name| name == "transaction trace")
                .unwrap_or(false)
        })
        .or_else(|| items.first())
        .ok_or_else(|| anyhow::anyhow!("debug_traceTransaction returned an empty trace array"))?;

    item.get("value").ok_or_else(|| {
        anyhow::anyhow!(
            "debug_traceTransaction trace item is missing `value`: {:?}",
            item
        )
    })
}

fn trace_output_to_bytes(
    tx_hash: alloy::primitives::B256,
    frame: &serde_json::Value,
) -> anyhow::Result<Bytes> {
    if frame
        .get("failed")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        anyhow::bail!(
            "debug_traceTransaction reports transaction {:#x} failed: {:?}",
            tx_hash,
            frame
        );
    }

    if let Some(error) = frame
        .get("error")
        .and_then(serde_json::Value::as_str)
        .filter(|error| !error.is_empty())
    {
        anyhow::bail!(
            "debug_traceTransaction reports transaction {:#x} errored: {}",
            tx_hash,
            error
        );
    }

    let output = frame
        .get("output")
        .or_else(|| frame.get("returnValue"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "debug_traceTransaction response for {:#x} is missing output/returnValue: {:?}",
                tx_hash,
                frame
            )
        })?;

    let stripped = output.strip_prefix("0x").unwrap_or(output);
    if stripped.is_empty() {
        return Ok(Bytes::default());
    }

    Ok(Bytes::from(hex::decode(stripped)?))
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
