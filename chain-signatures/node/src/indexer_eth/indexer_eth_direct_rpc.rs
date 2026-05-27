use crate::indexer_eth::{BlockNumber, EthereumConnection, MaybeBlock};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, B256};
use alloy::rpc::types::{Block, BlockId, Transaction, TransactionReceipt};
use futures_util::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde_json::json;
use tokio::time::{timeout, Duration};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use std::collections::HashMap;
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

    pub async fn subscribe(&self) -> EthereumConnection {
        let Some(ws_url) = websocket_url(&self.url) else {
            tracing::info!("ethereum RPC URL has no websocket scheme");
            return EthereumConnection::Disconnected;
        };

        let mut connection = match EthereumConnection::connect(ws_url.as_str()).await {
            Ok(connection) => connection,
            Err(err) => {
                tracing::info!(%err, "failed to connect ethereum websocket");
                return EthereumConnection::Disconnected;
            }
        };

        if let Err(err) = connection.subscribe_new_heads(self.next_id()).await {
            tracing::info!(%err, "failed to subscribe to ethereum newHeads");
            let _ = connection.close().await;
            return EthereumConnection::Disconnected;
        }

        connection
    }

    pub async fn get_block(&self, block_id: BlockId) -> anyhow::Result<Option<Block>> {
        self.block(block_id).await
    }

    pub async fn get_blocks(&self, block_ids: &[BlockId]) -> anyhow::Result<Vec<MaybeBlock>> {
        if block_ids.is_empty() {
            return Ok(Vec::new());
        }

        let requests = block_ids
            .iter()
            .map(|block_id| {
                let request_id = self.next_id();
                let params = match block_id {
                    BlockId::Number(_) => {
                        vec![json!(to_hex_block_id(*block_id)), json!(false)]
                    }
                    BlockId::Hash(hash) => {
                        vec![json!(format!("{:#x}", hash.block_hash)), json!(false)]
                    }
                };

                (
                    request_id,
                    *block_id,
                    json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": match block_id {
                            BlockId::Number(_) => "eth_getBlockByNumber",
                            BlockId::Hash(_) => "eth_getBlockByHash",
                        },
                        "params": params,
                    }),
                )
            })
            .collect::<Vec<_>>();

        let request_ids = requests
            .iter()
            .map(|(request_id, block_id, _)| (*request_id, *block_id))
            .collect::<Vec<_>>();
        let payload = requests
            .into_iter()
            .map(|(_, _, request)| request)
            .collect::<Vec<_>>();

        let response = self.http.post(&self.url).json(&payload).send().await?;
        let value: serde_json::Value = response.json().await?;
        let serde_json::Value::Array(items) = value else {
            anyhow::bail!("batch rpc response was not an array: {value}");
        };

        #[derive(serde::Deserialize)]
        struct BatchResponse<T> {
            id: u64,
            result: Option<T>,
            error: Option<serde_json::Value>,
        }

        let requested_blocks = request_ids.iter().copied().collect::<HashMap<_, _>>();
        let mut blocks_by_id = HashMap::with_capacity(request_ids.len());
        for item in items {
            let response: BatchResponse<Block> = serde_json::from_value(item)?;
            if let Some(error) = response.error {
                anyhow::bail!("batch rpc call failed for id {}: {error}", response.id);
            }

            let Some(block_id) = requested_blocks.get(&response.id).copied() else {
                anyhow::bail!("batch rpc response contained unknown id {}", response.id);
            };

            let block = match response.result {
                Some(block) => MaybeBlock::Block(block),
                None => MaybeBlock::Missing(block_id),
            };
            blocks_by_id.insert(response.id, block);
        }

        let blocks = request_ids
            .into_iter()
            .map(|(request_id, block_id)| {
                blocks_by_id
                    .remove(&request_id)
                    .unwrap_or_else(|| MaybeBlock::Missing(block_id))
            })
            .collect();
        Ok(blocks)
    }

    pub async fn get_block_receipts(
        &self,
        block_id: BlockId,
    ) -> anyhow::Result<Option<Vec<TransactionReceipt>>> {
        self.block_receipts(block_id).await
    }

    pub async fn get_nonce(&self, address: Address, block_id: BlockId) -> anyhow::Result<u64> {
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
        tx_hash: B256,
    ) -> anyhow::Result<Option<Transaction>> {
        self.transaction_by_hash(tx_hash).await
    }

    /// Re-execute `tx_hash` via `debug_traceTransaction` (`callTracer`,
    /// `onlyTopCall: true`) and return the top call's return data. The RPC
    /// response is the call frame directly — see `trace_output_to_bytes` for
    /// the field reference and worked examples.
    pub async fn trace_transaction_output(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Bytes> {
        let call_frame: serde_json::Value = self
            .rpc_call(
                "debug_traceTransaction",
                vec![
                    json!(format!("{:#x}", tx_hash)),
                    json!({
                        "tracer": "callTracer",
                        "tracerConfig": {
                            "onlyTopCall": true
                        },
                        "timeout": "5s"
                    }),
                ],
            )
            .await?;

        trace_output_to_bytes(tx_hash, &call_frame)
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

    async fn block(&self, block_id: BlockId) -> anyhow::Result<Option<Block>> {
        match block_id {
            BlockId::Number(_) => {
                self.rpc_call(
                    "eth_getBlockByNumber",
                    vec![json!(to_hex_block_id(block_id)), json!(false)],
                )
                .await
            }
            BlockId::Hash(hash) => {
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
        block_id: BlockId,
    ) -> anyhow::Result<Option<Vec<TransactionReceipt>>> {
        self.rpc_call(
            "eth_getBlockReceipts",
            vec![json!(to_hex_block_id(block_id))],
        )
        .await
    }

    async fn transaction_by_hash(&self, tx_hash: B256) -> anyhow::Result<Option<Transaction>> {
        self.rpc_call(
            "eth_getTransactionByHash",
            vec![json!(format!("{:#x}", tx_hash))],
        )
        .await
    }
}

/// Parse a `callTracer` (`onlyTopCall: true`) call-frame JSON into the
/// top call's return data. Bails on revert or error, surfacing the decoded
/// Solidity revert reason when present.
///
/// The RPC `result` is the top call frame directly — no wrapper. Fields we
/// care about:
///
/// - `output` (hex): the bytes we extract. For CALL-family this is the
///   function's return data; for CREATE/CREATE2 it's the deployed runtime
///   bytecode.
/// - `error` (string, optional): set when the top call failed (revert, OOG,
///   invalid opcode, etc.).
/// - `revertReason` (string, optional): the decoded `Error(string)` payload,
///   only present for Solidity `revert("...")` aborts.
///
/// Other fields (`type`, `from`, `to`, `value`, `gas`, `gasUsed`, `input`)
/// are part of the response but unused here. `calls` is omitted by
/// `onlyTopCall: true`.
///
/// # Examples
///
/// Successful call returning `bool true`:
/// ```json
/// { "type": "CALL", "output": "0x0000...0001" }
/// ```
///
/// Solidity revert with a decoded reason:
/// ```json
/// {
///   "type": "CALL",
///   "error": "execution reverted",
///   "revertReason": "InsufficientBalance"
/// }
/// ```
fn trace_output_to_bytes(
    tx_hash: alloy::primitives::B256,
    frame: &serde_json::Value,
) -> anyhow::Result<Bytes> {
    // `callTracer` populates `error` when the top-level call failed (revert,
    // OOG, invalid opcode, etc.). `revertReason` is the decoded `Error(string)`,
    // only present for Solidity `revert("...")` aborts.
    if let Some(error) = frame
        .get("error")
        .and_then(serde_json::Value::as_str)
        .filter(|e| !e.is_empty())
    {
        let revert_reason = frame
            .get("revertReason")
            .and_then(serde_json::Value::as_str)
            .filter(|r| !r.is_empty());
        match revert_reason {
            Some(reason) => anyhow::bail!(
                "debug_traceTransaction reports transaction {:#x} reverted: {} ({})",
                tx_hash,
                error,
                reason
            ),
            None => anyhow::bail!(
                "debug_traceTransaction reports transaction {:#x} errored: {}",
                tx_hash,
                error
            ),
        }
    }

    let output = frame
        .get("output")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "debug_traceTransaction response for {:#x} is missing `output`: {:?}",
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

impl EthereumConnection {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    const MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);
    const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    async fn connect(ws_url: &str) -> anyhow::Result<Self> {
        let (ws_stream, _) = timeout(Self::CONNECT_TIMEOUT, connect_async(ws_url))
            .await
            .map_err(|_| anyhow::anyhow!("ethereum websocket connect timeout"))??;
        let (ws_write, ws_read) = ws_stream.split();
        Ok(Self::Connected(ws_read, ws_write))
    }

    async fn subscribe_new_heads(&mut self, request_id: u64) -> anyhow::Result<()> {
        let Self::Connected(_, ws_write) = self else {
            anyhow::bail!("ethereum websocket not connected")
        };

        let subscribe_request = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "eth_subscribe",
            "params": ["newHeads"],
        });

        timeout(
            Self::CONNECT_TIMEOUT,
            ws_write.send(Message::Text(subscribe_request.to_string().into())),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ethereum websocket subscription send timeout"))??;

        loop {
            let Some(msg) = self.next_message().await else {
                anyhow::bail!("ethereum websocket closed before subscription ack")
            };

            let Message::Text(text) = msg else {
                continue;
            };

            let value: serde_json::Value = serde_json::from_str(&text)?;
            if let Some(error) = value.get("error") {
                anyhow::bail!("ethereum eth_subscribe failed: {error}");
            }

            let Some(id) = value.get("id").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            if id != request_id {
                continue;
            }

            let Some(subscription_id) = value.get("result").and_then(serde_json::Value::as_str)
            else {
                anyhow::bail!("ethereum eth_subscribe ack missing subscription id")
            };

            tracing::info!(%subscription_id, "ethereum websocket subscribed to newHeads");
            return Ok(());
        }
    }

    pub async fn next_block_number(&mut self) -> Option<BlockNumber> {
        loop {
            let msg = self.next_message().await?;

            let Message::Text(text) = msg else {
                continue;
            };

            let value: serde_json::Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(err) => {
                    tracing::warn!(%err, "failed to parse ethereum websocket message");
                    continue;
                }
            };

            if let Some(error) = value.get("error") {
                tracing::warn!(?error, "ethereum websocket returned rpc error");
                continue;
            }

            let Some(params) = value.get("params") else {
                continue;
            };
            let Some(result) = params.get("result") else {
                continue;
            };
            let Some(number_hex) = result.get("number").and_then(serde_json::Value::as_str) else {
                continue;
            };

            match hex_to_u64(number_hex) {
                Ok(block_number) => return Some(block_number),
                Err(err) => {
                    tracing::warn!(%err, %number_hex, "failed to parse ethereum head number");
                }
            }
        }
    }

    async fn next_message(&mut self) -> Option<Message> {
        let Self::Connected(ws_read, _) = self else {
            return None;
        };

        let Ok(maybe_msg) = timeout(Self::MESSAGE_TIMEOUT, ws_read.next()).await else {
            tracing::warn!(timeout = ?Self::MESSAGE_TIMEOUT, "ethereum websocket stalled");
            *self = Self::Disconnected;
            return None;
        };

        let Some(msg) = maybe_msg else {
            *self = Self::Disconnected;
            return None;
        };

        match msg {
            Ok(Message::Close(_)) => {
                tracing::info!("ethereum websocket received close frame");
                if let Err(err) = self.close().await {
                    tracing::debug!(%err, "failed to flush ethereum websocket close reply");
                }
                None
            }
            Ok(msg) => Some(msg),
            Err(err) => {
                tracing::warn!(%err, "ethereum websocket error");
                *self = Self::Disconnected;
                None
            }
        }
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        let Self::Connected(_, ws_write) = self else {
            return Ok(());
        };

        timeout(Self::DISCONNECT_TIMEOUT, ws_write.close())
            .await
            .map_err(|_| anyhow::anyhow!("ethereum websocket close timeout"))??;
        *self = Self::Disconnected;
        Ok(())
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

fn to_hex_block_id(block_id: BlockId) -> String {
    match block_id {
        BlockId::Number(BlockNumberOrTag::Number(number)) => to_hex_u64(number),
        BlockId::Number(BlockNumberOrTag::Latest) => "latest".to_string(),
        BlockId::Number(BlockNumberOrTag::Finalized) => "finalized".to_string(),
        BlockId::Number(BlockNumberOrTag::Safe) => "safe".to_string(),
        BlockId::Number(BlockNumberOrTag::Earliest) => "earliest".to_string(),
        BlockId::Number(BlockNumberOrTag::Pending) => "pending".to_string(),
        BlockId::Hash(hash) => format!("{:#x}", hash.block_hash),
    }
}

fn websocket_url(rpc_url: &str) -> Option<Url> {
    let mut url = Url::parse(rpc_url).ok()?;

    match url.scheme() {
        "ws" | "wss" => Some(url),
        "http" => {
            url.set_scheme("ws").ok()?;
            Some(url)
        }
        "https" => {
            url.set_scheme("wss").ok()?;
            Some(url)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer_eth::MaybeBlock;
    use alloy::eips::BlockNumberOrTag;
    use alloy::primitives::B256;
    use alloy::rpc::types::BlockId;
    use mockito::{Matcher, Server};
    use serde_json::json;

    #[tokio::test]
    async fn get_blocks_keeps_request_order_when_rpc_responses_are_reordered() {
        let mut server = Server::new_async().await;
        let client = RpcEthereumClient::new(&server.url());
        let block_ids = vec![
            BlockId::Number(BlockNumberOrTag::Number(7)),
            BlockId::Number(BlockNumberOrTag::Number(8)),
        ];

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "result": null
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "number": "0x7",
                            "hash": format!("0x{:064x}", 7),
                            "parentHash": format!("0x{:064x}", 6),
                            "sha3Uncles": format!("0x{:064x}", 1),
                            "logsBloom": format!("0x{}", "0".repeat(512)),
                            "transactionsRoot": format!("0x{:064x}", 2),
                            "stateRoot": format!("0x{:064x}", 3),
                            "receiptsRoot": format!("0x{:064x}", 4),
                            "miner": format!("0x{:040x}", 5),
                            "difficulty": "0x0",
                            "totalDifficulty": "0x0",
                            "extraData": "0x",
                            "size": "0x1",
                            "gasLimit": "0x1c9c380",
                            "gasUsed": "0x0",
                            "timestamp": "0x1",
                            "uncles": [],
                            "nonce": "0x0000000000000000",
                            "mixHash": format!("0x{:064x}", 9),
                            "baseFeePerGas": "0x1",
                            "transactions": []
                        }
                    }
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let blocks = client
            .get_blocks(&block_ids)
            .await
            .expect("batch fetch should succeed");

        assert!(matches!(&blocks[0], MaybeBlock::Block(block) if block.header.number == 7));
        assert!(matches!(
            &blocks[1],
            MaybeBlock::Missing(BlockId::Number(BlockNumberOrTag::Number(8)))
        ));
    }

    #[test]
    fn parses_successful_call_output() {
        let frame = json!({
            "type": "CALL",
            "output": "0x0000000000000000000000000000000000000000000000000000000000000001",
        });
        let bytes = trace_output_to_bytes(B256::ZERO, &frame).expect("should parse");
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[31], 1);
    }

    #[test]
    fn bails_on_revert_with_reason() {
        let frame = json!({
            "type": "CALL",
            "error": "execution reverted",
            "revertReason": "InsufficientBalance",
        });
        let err = trace_output_to_bytes(B256::ZERO, &frame).expect_err("should bail");
        let msg = format!("{err}");
        assert!(msg.contains("execution reverted"));
        assert!(msg.contains("InsufficientBalance"));
    }

    #[test]
    fn bails_when_output_missing_and_no_error() {
        let frame = json!({ "type": "CALL" });
        let err = trace_output_to_bytes(B256::ZERO, &frame).expect_err("should bail");
        assert!(format!("{err}").contains("missing `output`"));
    }

    #[test]
    fn websocket_url_promotes_http_to_ws() {
        let ws_url = super::websocket_url("https://rpc.example.com/path")
            .expect("https URL should convert to websocket URL");

        assert_eq!(ws_url.as_str(), "wss://rpc.example.com/path");
    }
}
