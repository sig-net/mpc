use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex::{self, ToHexExt};
use alloy::primitives::{Address, Bytes, B256};
use alloy::rpc::types::{Block, BlockId, Log, Transaction, TransactionReceipt};
use serde::de::DeserializeOwned;
use serde_json::json;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[cfg(feature = "bench")]
use crate::bench;
use crate::client::MaybeBlock;

// This is more than likely limited by the RPC provider, but alchemy
// supports archive nodes, so we effectively can go as far back as needed
// for direct RPC client.
pub const MAX_CATCHUP_BLOCKS: u64 = u64::MAX;

#[derive(Clone)]
pub struct RpcEthereumClient {
    http: reqwest::Client,
    url: reqwest::Url,
    id: Arc<AtomicU64>,
}

impl RpcEthereumClient {
    pub fn new(url: reqwest::Url) -> Self {
        Self {
            http: reqwest::Client::new(),
            url,
            id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub async fn get_block(&self, block_id: BlockId) -> anyhow::Result<Option<Block>> {
        self.block(block_id).await
    }

    pub async fn get_blocks(&self, block_ids: &[BlockId]) -> anyhow::Result<Vec<MaybeBlock>> {
        if block_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Bench: count the number of `eth_getBlockByNumber` vs `eth_getBlockByHash` calls in the batch
        // Catchup should only request by number, keep by hash for completeness
        #[cfg(feature = "bench")]
        {
            let n_number = block_ids
                .iter()
                .filter(|b| matches!(b, BlockId::Number(_)))
                .count() as u64;
            let n_hash = block_ids
                .iter()
                .filter(|b| matches!(b, BlockId::Hash(_)))
                .count() as u64;
            if n_number > 0 {
                bench::rpc_inc_n("eth_getBlockByNumber(batch)", n_number);
            }
            if n_hash > 0 {
                bench::rpc_inc_n("eth_getBlockByHash(batch)", n_hash);
            }
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

        let results: Vec<Option<Block>> = self.batch_execute(requests).await?;

        Ok(results
            .into_iter()
            .zip(block_ids.iter())
            .map(|(maybe, block_id)| match maybe {
                Some(block) => MaybeBlock::Block(block),
                None => MaybeBlock::Missing(*block_id),
            })
            .collect())
    }

    /// Fetch a single transaction's receipt via `eth_getTransactionReceipt`.
    ///
    /// Returns `None` if the tx is unknown or not yet mined (pending).
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        #[cfg(feature = "bench")]
        bench::rpc_inc("eth_getTransactionReceipt");

        self.transaction_receipt(tx_hash).await
    }

    /// Fetch all logs emitted by `address` within `block_id` via a single
    /// `eth_getLogs` call, server-filtered to that address.
    ///
    /// A block with no logs at `address` returns an empty `Vec`.
    pub async fn get_logs(&self, address: Address, block_id: BlockId) -> anyhow::Result<Vec<Log>> {
        #[cfg(feature = "bench")]
        bench::rpc_inc("eth_getLogs");

        self.logs(address, block_id).await
    }

    /// Fetch `eth_getLogs` for multiple blocks in a single JSON-RPC batch POST,
    /// returning one `Vec<Log>` per input `block_id`, in input order.
    ///
    /// All requests share the same `address`. Each entry corresponds to the
    /// request at the same index. A server-returned `null` result (or a
    /// missing response) maps to an empty `Vec` (no logs from `address` in
    /// that block).
    pub async fn get_logs_batch(
        &self,
        address: Address,
        block_ids: &[BlockId],
    ) -> anyhow::Result<Vec<Vec<Log>>> {
        if block_ids.is_empty() {
            return Ok(Vec::new());
        }

        #[cfg(feature = "bench")]
        bench::rpc_inc_n("eth_getLogs(batch)", block_ids.len() as u64);

        let requests = block_ids
            .iter()
            .map(|block_id| {
                let request_id = self.next_id();
                (
                    request_id,
                    json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "eth_getLogs",
                        "params": [logs_filter_object(address, *block_id)],
                    }),
                )
            })
            .collect::<Vec<_>>();

        let results: Vec<Option<Vec<Log>>> = self.batch_execute(requests).await?;

        Ok(results
            .into_iter()
            .map(|opt| opt.unwrap_or_default())
            .collect())
    }

    pub async fn get_nonce(&self, address: Address, block_id: BlockId) -> anyhow::Result<u64> {
        #[cfg(feature = "bench")]
        bench::rpc_inc("eth_getTransactionCount");

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
        #[cfg(feature = "bench")]
        bench::rpc_inc("eth_getTransactionByHash");

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
        #[cfg(feature = "bench")]
        bench::rpc_inc("debug_traceTransaction");

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

        let response = self
            .http
            .post(self.url.clone())
            .json(&request)
            .send()
            .await?;
        let response = ensure_http_success(response, &format!("rpc {method}")).await?;
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

    /// Send a pre-assembled JSON-RPC batch and return results in input order.
    /// Each entry in the returned `Vec` corresponds to the request at the same
    /// index. A server-returned `null` result or a missing response both map to
    /// `None`.
    async fn batch_execute<T: DeserializeOwned>(
        &self,
        requests: Vec<(u64, serde_json::Value)>,
    ) -> anyhow::Result<Vec<Option<T>>> {
        #[derive(serde::Deserialize)]
        struct BatchResponse<T> {
            id: u64,
            result: Option<T>,
            error: Option<serde_json::Value>,
        }

        // Extract the request IDs and build a set of valid IDs for validation. The
        // payload is the JSON-RPC batch array of request objects.
        let ordered_ids: Vec<u64> = requests.iter().map(|(id, _)| *id).collect();
        let valid_ids: HashSet<u64> = ordered_ids.iter().copied().collect();
        let payload: Vec<serde_json::Value> = requests.into_iter().map(|(_, body)| body).collect();

        // Send the batch request and parse the response. The response is expected to be an array of JSON-RPC response objects.
        let response = self
            .http
            .post(self.url.clone())
            .json(&payload)
            .send()
            .await?;
        let response = ensure_http_success(response, "batch rpc").await?;
        let value: serde_json::Value = response.json().await?;
        let items = if let serde_json::Value::Array(items) = value {
            items
        } else {
            anyhow::bail!("batch rpc response was not an array: {value}");
        };

        // Build a map of response IDs to results.
        let mut results_by_id: HashMap<u64, Option<T>> = HashMap::with_capacity(ordered_ids.len());

        for item in items {
            let response: BatchResponse<T> = serde_json::from_value(item)?;
            if let Some(error) = response.error {
                anyhow::bail!("batch rpc call failed for id {}: {error}", response.id);
            }
            if !valid_ids.contains(&response.id) {
                anyhow::bail!("batch rpc response contained unknown id {}", response.id);
            }
            results_by_id.insert(response.id, response.result);
        }

        Ok(ordered_ids
            .into_iter()
            .map(|id| results_by_id.remove(&id).flatten())
            .collect())
    }

    async fn block(&self, block_id: BlockId) -> anyhow::Result<Option<Block>> {
        // Bench: distinguish `eth_getBlockByNumber(Finalized)` (used by
        // `wait_for_finalized_block`) from `eth_getBlockByNumber(Number)` (catchup batch / single
        // fetches).
        #[cfg(feature = "bench")]
        bench::rpc_inc(match &block_id {
            BlockId::Number(BlockNumberOrTag::Number(_)) => "eth_getBlockByNumber(Number)",
            BlockId::Number(BlockNumberOrTag::Finalized) => "eth_getBlockByNumber(Finalized)",
            BlockId::Number(_) => "eth_getBlockByNumber(other)", // Latest, Earliest, Safe, Pending (all expected to be zero)
            BlockId::Hash(_) => "eth_getBlockByHash", // Not expected in catchup, keep for completeness
        });

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

    /// Issue `eth_getTransactionReceipt` and deserialize the result as an
    /// optional `TransactionReceipt`. `null` (pending / unknown tx) → `None`.
    async fn transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.rpc_call(
            "eth_getTransactionReceipt",
            vec![json!(format!("{:#x}", tx_hash))],
        )
        .await
    }

    /// Issue a single-block `eth_getLogs` address filter via the raw RPC
    /// path and deserialize the result array as `Vec<Log>`.
    async fn logs(&self, address: Address, block_id: BlockId) -> anyhow::Result<Vec<Log>> {
        self.rpc_call::<Vec<Log>>("eth_getLogs", vec![logs_filter_object(address, block_id)])
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

/// Bails with the HTTP status and a truncated body when the response is not
/// successful, keeping status codes (e.g. 429) visible to retry classification.
async fn ensure_http_success(
    response: reqwest::Response,
    label: &str,
) -> anyhow::Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body: String = response
        .text()
        .await
        .unwrap_or_default()
        .chars()
        .take(256)
        .collect();
    anyhow::bail!("{label} HTTP error {status}: {body}")
}

fn format_address(address: Address) -> String {
    format!("0x{}", address.encode_hex())
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

/// Build the `eth_getLogs` filter object for a single `address` scoped to one
/// block.
///
/// - `BlockId::Hash` → `{ "blockHash": "0x..", "address": "0x.." }` (pins to
///   the exact block, immune to reorgs).
/// - `BlockId::Number(tag)` → `{ "fromBlock": tag, "toBlock": tag,
///   "address": "0x.." }` (request by number/tag).
fn logs_filter_object(address: Address, block_id: BlockId) -> serde_json::Value {
    match block_id {
        BlockId::Hash(hash) => json!({
            "blockHash": format!("{:#x}", hash.block_hash),
            "address": format_address(address),
        }),
        BlockId::Number(_) => json!({
            "fromBlock": to_hex_block_id(block_id),
            "toBlock": to_hex_block_id(block_id),
            "address": format_address(address),
        }),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::eips::BlockNumberOrTag;
    use alloy::primitives::B256;
    use alloy::rpc::types::BlockId;
    use mockito::{Matcher, Server};
    use serde_json::json;

    #[tokio::test]
    async fn get_blocks_keeps_request_order_when_rpc_responses_are_reordered() {
        let mut server = Server::new_async().await;
        let client = RpcEthereumClient::new(server.url().parse().unwrap());
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

    /// Helper: a fully-populated `eth_getLogs` log entry
    fn log_value(addr: Address, block_number: u64, log_index: u64) -> serde_json::Value {
        let block_hash = format!("0x{:064x}", block_number);
        let tx_hash = format!("0x{:064x}", block_number);
        json!({
            "logIndex": format!("0x{log_index:x}"),
            "blockNumber": format!("0x{block_number:x}"),
            "blockHash": block_hash,
            "transactionHash": tx_hash,
            "transactionIndex": "0x0",
            "address": format!("{:#x}", addr),
            "topics": [],
            "data": "0x",
        })
    }

    fn filter_response(id: u64, logs: Vec<serde_json::Value>) -> serde_json::Value {
        json!({ "jsonrpc": "2.0", "id": id, "result": logs })
    }

    #[tokio::test]
    async fn get_logs_issues_address_filtered_eth_getlogs_for_number() {
        let mut server = Server::new_async().await;
        let client = RpcEthereumClient::new(server.url().parse().unwrap());
        let addr = Address::with_last_byte(0x42);

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"eth_getLogs"#.to_string()))
            .match_body(Matcher::Regex(
                // "0x42" appears at the end of a checksummed address
                r#"42"#.to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(filter_response(1, vec![log_value(addr, 7, 0)]).to_string())
            .create_async()
            .await;

        let logs = client
            .get_logs(addr, BlockId::Number(BlockNumberOrTag::Number(7)))
            .await
            .expect("get_logs should succeed");

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].address(), addr);
    }

    #[tokio::test]
    async fn get_logs_empty_array_maps_to_empty_vec() {
        let mut server = Server::new_async().await;
        let client = RpcEthereumClient::new(server.url().parse().unwrap());
        let addr = Address::with_last_byte(0x07);

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"eth_getLogs"#.to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(filter_response(1, vec![]).to_string())
            .create_async()
            .await;

        let logs = client
            .get_logs(addr, BlockId::Number(BlockNumberOrTag::Number(11215038)))
            .await
            .expect("get_logs should succeed");

        assert!(logs.is_empty());
    }

    #[tokio::test]
    async fn get_logs_uses_block_hash_filter_for_hash_block_id() {
        let mut server = Server::new_async().await;
        let client = RpcEthereumClient::new(server.url().parse().unwrap());
        let addr = Address::with_last_byte(0x99);
        let block_hash = B256::with_last_byte(0xab);

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"eth_getLogs"#.to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                filter_response(1, vec![log_value(addr, 0xab, 0), log_value(addr, 0xab, 1)])
                    .to_string(),
            )
            .create_async()
            .await;

        let logs = client
            .get_logs(addr, BlockId::Hash(block_hash.into()))
            .await
            .expect("get_logs should succeed");

        assert_eq!(logs.len(), 2);
    }

    #[tokio::test]
    async fn get_logs_batch_preserves_request_order_when_responses_reordered() {
        let mut server = Server::new_async().await;
        let client = RpcEthereumClient::new(server.url().parse().unwrap());
        let addr = Address::with_last_byte(0x42);
        let block_ids = vec![
            BlockId::Number(BlockNumberOrTag::Number(10)),
            BlockId::Number(BlockNumberOrTag::Number(11)),
            BlockId::Number(BlockNumberOrTag::Number(12)),
        ];

        // Match any eth_getLogs batch POST; respond with 2 results in
        // reversed order: id 3 first, then 1, then 2 (note: id 2 returns null).
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"eth_getLogs"#.to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    filter_response(3, vec![log_value(addr, 12, 0)]),
                    filter_response(1, vec![]),          // empty for block 10
                    { "jsonrpc": "2.0", "id": 2, "result": null }, // null → empty vec for block 11
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let results = client
            .get_logs_batch(addr, &block_ids)
            .await
            .expect("batch fetch should succeed");

        assert_eq!(results.len(), 3);
        // block 10 → id 1 → empty array
        assert!(results[0].is_empty());
        // block 11 → id 2 → null → empty vec
        assert!(results[1].is_empty());
        // block 12 → id 3 → 1 log
        assert_eq!(results[2].len(), 1);
        assert_eq!(results[2][0].address(), addr);
    }

    #[tokio::test]
    async fn get_transaction_receipt_returns_receipt_for_mined_tx() {
        let mut server = Server::new_async().await;
        let client = RpcEthereumClient::new(server.url().parse().unwrap());
        let tx_hash = B256::with_last_byte(0x42);

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"eth_getTransactionReceipt"#.to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": crate::test_utils::receipt_value(
                        &format!("{:#x}", tx_hash),
                        7,
                    ),
                })
                .to_string(),
            )
            .create_async()
            .await;

        let receipt = client
            .get_transaction_receipt(tx_hash)
            .await
            .expect("get_transaction_receipt should succeed");

        let receipt = receipt.expect("mined tx should yield Some(receipt)");
        assert_eq!(receipt.transaction_hash, tx_hash);
    }

    #[tokio::test]
    async fn get_transaction_receipt_returns_none_on_null_result() {
        let mut server = Server::new_async().await;
        let client = RpcEthereumClient::new(server.url().parse().unwrap());
        let tx_hash = B256::with_last_byte(0x07);

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"eth_getTransactionReceipt"#.to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string())
            .create_async()
            .await;

        let receipt = client
            .get_transaction_receipt(tx_hash)
            .await
            .expect("get_transaction_receipt should succeed");

        assert!(receipt.is_none(), "null result should map to None");
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
}
