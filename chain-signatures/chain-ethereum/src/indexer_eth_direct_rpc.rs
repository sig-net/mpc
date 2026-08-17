#[cfg(feature = "bench")]
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::hex;
use alloy::primitives::{Address, Bytes, B256};
use alloy::rpc::client::{ClientBuilder, RpcClient};
use alloy::rpc::types::{Block, BlockId, Filter, Log, Transaction, TransactionReceipt};
use serde_json::json;

#[cfg(feature = "bench")]
use crate::bench;
use crate::client::MaybeBlock;

// This is more than likely limited by the RPC provider, but alchemy
// supports archive nodes, so we effectively can go as far back as needed
// for direct RPC client.
pub const MAX_CATCHUP_BLOCKS: u64 = u64::MAX;

/// JSON-RPC read client over a plain alloy HTTP transport. Retry, timeout,
/// and 429-gating policy live one layer up in [`crate::client::EthereumClient`];
/// this type only frames and executes requests.
#[derive(Clone)]
pub struct RpcEthereumClient {
    client: RpcClient,
}

impl RpcEthereumClient {
    pub fn new(url: reqwest::Url) -> Self {
        Self {
            client: ClientBuilder::default().http(url),
        }
    }

    pub async fn get_block(&self, block_id: BlockId) -> anyhow::Result<Option<Block>> {
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

        let result = match block_id {
            BlockId::Number(_) => self
                .client
                .request::<_, Option<Block>>("eth_getBlockByNumber", (block_id, false))
                .await,
            BlockId::Hash(hash) => self
                .client
                .request::<_, Option<Block>>("eth_getBlockByHash", (hash.block_hash,))
                .await,
        };
        result.map_err(|err| anyhow::anyhow!("failed to fetch block {block_id:?}: {err}"))
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

        let mut batch = self.client.new_batch();
        let mut waiters = Vec::with_capacity(block_ids.len());
        for &block_id in block_ids {
            let waiter = match block_id {
                BlockId::Number(_) => batch
                    .add_call::<_, Option<Block>>("eth_getBlockByNumber", &(block_id, false)),
                BlockId::Hash(hash) => batch
                    .add_call::<_, Option<Block>>("eth_getBlockByHash", &(hash.block_hash,)),
            }
            .map_err(|err| anyhow::anyhow!("failed to queue batch block fetch {block_id:?}: {err}"))?;
            waiters.push(waiter);
        }

        batch
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("eth_getBlock batch failed: {err}"))?;

        let mut blocks = Vec::with_capacity(block_ids.len());
        for (waiter, &block_id) in waiters.into_iter().zip(block_ids) {
            let block = waiter.await.map_err(|err| {
                anyhow::anyhow!("eth_getBlock batch member for {block_id:?} failed: {err}")
            })?;
            blocks.push(match block {
                Some(block) => MaybeBlock::Block(block),
                None => MaybeBlock::Missing(block_id),
            });
        }
        Ok(blocks)
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

        self.client
            .request::<_, Option<TransactionReceipt>>("eth_getTransactionReceipt", (tx_hash,))
            .await
            .map_err(|err| anyhow::anyhow!("failed to get receipt for {tx_hash:#x}: {err}"))
    }

    /// Fetch all logs emitted by `address` within `block_id` via a single
    /// `eth_getLogs` call, server-filtered to that address.
    ///
    /// A block with no logs at `address` returns an empty `Vec`.
    pub async fn get_logs(&self, address: Address, block_id: BlockId) -> anyhow::Result<Vec<Log>> {
        #[cfg(feature = "bench")]
        bench::rpc_inc("eth_getLogs");

        self.client
            .request::<_, Vec<Log>>("eth_getLogs", (logs_filter(address, block_id),))
            .await
            .map_err(|err| {
                anyhow::anyhow!("failed to get logs for {address:#x} at {block_id:?}: {err}")
            })
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

        let mut batch = self.client.new_batch();
        let mut waiters = Vec::with_capacity(block_ids.len());
        for &block_id in block_ids {
            let waiter = batch
                .add_call::<_, Option<Vec<Log>>>("eth_getLogs", &(logs_filter(address, block_id),))
                .map_err(|err| {
                    anyhow::anyhow!("failed to queue batch logs fetch for {block_id:?}: {err}")
                })?;
            waiters.push(waiter);
        }

        batch
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("eth_getLogs batch failed: {err}"))?;

        let mut results = Vec::with_capacity(block_ids.len());
        for waiter in waiters {
            let logs = waiter
                .await
                .map_err(|err| anyhow::anyhow!("eth_getLogs batch member failed: {err}"))?;
            results.push(logs.unwrap_or_default());
        }
        Ok(results)
    }

    pub async fn get_nonce(&self, address: Address, block_id: BlockId) -> anyhow::Result<u64> {
        #[cfg(feature = "bench")]
        bench::rpc_inc("eth_getTransactionCount");

        let nonce: alloy::primitives::U64 = self
            .client
            .request("eth_getTransactionCount", (address, block_id))
            .await
            .map_err(|err| {
                anyhow::anyhow!("failed to get nonce for {address:#x} at {block_id:?}: {err}")
            })?;
        Ok(nonce.to::<u64>())
    }

    pub async fn get_transaction_by_hash(
        &self,
        tx_hash: B256,
    ) -> anyhow::Result<Option<Transaction>> {
        #[cfg(feature = "bench")]
        bench::rpc_inc("eth_getTransactionByHash");

        self.client
            .request::<_, Option<Transaction>>("eth_getTransactionByHash", (tx_hash,))
            .await
            .map_err(|err| anyhow::anyhow!("failed to get transaction {tx_hash:#x}: {err}"))
    }

    /// Re-execute `tx_hash` via `debug_traceTransaction` (`callTracer`,
    /// `onlyTopCall: true`) and return the top call's return data. The RPC
    /// response is the call frame directly — see `trace_output_to_bytes` for
    /// the field reference and worked examples.
    pub async fn trace_transaction_output(&self, tx_hash: B256) -> anyhow::Result<Option<Bytes>> {
        #[cfg(feature = "bench")]
        bench::rpc_inc("debug_traceTransaction");

        let call_frame: serde_json::Value = self
            .client
            .request(
                "debug_traceTransaction",
                (
                    tx_hash,
                    json!({
                        "tracer": "callTracer",
                        "tracerConfig": {
                            "onlyTopCall": true
                        },
                        "timeout": "5s"
                    }),
                ),
            )
            .await
            .map_err(|err| anyhow::anyhow!("debug_traceTransaction failed for {tx_hash:#x}: {err}"))?;

        trace_output_to_bytes(tx_hash, &call_frame)
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
) -> anyhow::Result<Option<Bytes>> {
    let Some(frame) = frame.as_object() else {
        anyhow::bail!(
            "debug_traceTransaction response for {:#x} is not a call frame: {:?}",
            tx_hash,
            frame
        );
    };

    if !frame.contains_key("type") {
        anyhow::bail!(
            "debug_traceTransaction response for {:#x} has no call frame `type`: {:?}",
            tx_hash,
            frame
        );
    }

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

    let Some(output) = frame.get("output").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };

    let stripped = output.strip_prefix("0x").unwrap_or(output);
    if stripped.is_empty() {
        return Ok(Some(Bytes::default()));
    }

    Ok(Some(Bytes::from(hex::decode(stripped)?)))
}

/// Build the `eth_getLogs` filter for a single `address` scoped to one block.
///
/// - `BlockId::Hash` → pins to the exact block, immune to reorgs.
/// - `BlockId::Number(tag)` → requests by number/tag.
fn logs_filter(address: Address, block_id: BlockId) -> Filter {
    let mut filter = Filter::new().address(address);
    filter = match block_id {
        BlockId::Hash(hash) => filter.at_block_hash(hash.block_hash),
        BlockId::Number(tag) => filter.from_block(tag).to_block(tag),
    };
    filter
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

        // Responses deliberately out of request order: null (block 8) first,
        // then block 7.
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getBlockByNumber".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": null
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 0,
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
                // "42" appears at the end of the (lowercase-hex) address
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

        // Match any eth_getLogs batch POST; respond with results in
        // reversed order: id 2 first, then 0, then 1 (id 1 returns null).
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r#"eth_getLogs"#.to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    filter_response(2, vec![log_value(addr, 12, 0)]),
                    filter_response(0, vec![]),          // empty for block 10
                    { "jsonrpc": "2.0", "id": 1, "result": null }, // null → empty vec for block 11
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
        // block 10 → id 0 → empty array
        assert!(results[0].is_empty());
        // block 11 → id 1 → null → empty vec
        assert!(results[1].is_empty());
        // block 12 → id 2 → 1 log
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
        let bytes = bytes.expect("output should be present");
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
    fn returns_none_when_output_missing_and_no_error() {
        let frame = json!({ "type": "CALL" });
        let output = trace_output_to_bytes(B256::ZERO, &frame).expect("should parse");
        assert!(output.is_none());
    }

    #[test]
    fn bails_when_trace_result_is_null() {
        let err = trace_output_to_bytes(B256::ZERO, &serde_json::Value::Null)
            .expect_err("null trace result should fail");
        assert!(format!("{err}").contains("is not a call frame"));
    }

    #[test]
    fn bails_when_trace_result_has_no_call_type() {
        let frame = json!({});
        let err =
            trace_output_to_bytes(B256::ZERO, &frame).expect_err("empty trace object should fail");
        assert!(format!("{err}").contains("has no call frame `type`"));
    }
}
