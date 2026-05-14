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

/// Parse a geth `callTracer` (onlyTopCall) call-frame JSON into its return-data
/// bytes. Bails when the call reverted/errored, including the decoded Solidity
/// revert reason when available.
///
/// # Expected response shape from geth `callTracer` + `onlyTopCall: true`
///
/// The whole JSON-RPC `result` IS the top call frame (no wrapper, no array).
/// Common fields:
///
/// - `type` (string): `"CALL"` | `"STATICCALL"` | `"DELEGATECALL"` | `"CREATE"` | `"CREATE2"`.
/// - `from` (hex string): caller address — the EOA for the top-level frame.
/// - `to` (hex string or `null`): callee address. For `CREATE`/`CREATE2` this
///   is the address of the newly deployed contract; for plain ETH transfers
///   to an EOA it may be present but with empty `input`/`output`.
/// - `value` (hex string): ETH value sent, in wei.
/// - `gas` / `gasUsed` (hex strings): gas allowance and gas consumed.
/// - `input` (hex string): calldata; for `CREATE`/`CREATE2` this is the init bytecode.
/// - `output` (hex string, optional): **what we extract**. For a successful
///   `CALL`/`STATICCALL`/`DELEGATECALL` this is the function's return data;
///   for `CREATE`/`CREATE2` this is the deployed runtime bytecode.
/// - `error` (string, optional): present iff the top call failed
///   (revert / out-of-gas / invalid opcode / stack overflow / etc.).
/// - `revertReason` (string, optional): present iff Solidity `revert("...")`
///   ran and the error payload could be decoded as `Error(string)`.
/// - `calls` (array, optional): nested call frames. Omitted when
///   `onlyTopCall: true`, so the parser never looks at it.
///
/// # Example: successful contract call
///
/// User calls `Token.transfer(addr, 100)`; returns `bool success`.
/// ```json
/// {
///   "type": "CALL",
///   "from": "0xabc...",
///   "to": "0xdef...",
///   "value": "0x0",
///   "gas": "0x5208",
///   "gasUsed": "0x4f0a",
///   "input": "0xa9059cbb000000000000000000000000...0064",
///   "output": "0x0000000000000000000000000000000000000000000000000000000000000001"
/// }
/// ```
/// `output` = 32 bytes encoding `true`. `trace_output_to_bytes` returns those bytes.
///
/// # Example: CREATE / CREATE2 deployment
///
/// User deploys a contract.
/// ```json
/// {
///   "type": "CREATE",
///   "from": "0xabc...",
///   "to":   "0xnew...",         // address of the deployed contract
///   "value": "0x0",
///   "gas":  "0x...", "gasUsed": "0x...",
///   "input":  "0x60806040...",   // init bytecode
///   "output": "0x60806040..."    // deployed runtime bytecode
/// }
/// ```
/// `output` = runtime bytecode. Same extraction path; no special-casing for CREATE.
///
/// # Example: Solidity revert with a reason string
///
/// Contract executes `revert("InsufficientBalance")`.
/// ```json
/// {
///   "type": "CALL",
///   "from": "0xabc...", "to": "0xdef...",
///   "value": "0x0", "gas": "0x...", "gasUsed": "0x...",
///   "input": "0x...",
///   "output": "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000013496e73756666696369656e7442616c616e6365000000000000000000000000",
///   "error": "execution reverted",
///   "revertReason": "InsufficientBalance"
/// }
/// ```
/// `error` is set so we bail; the error message includes `revertReason` when present.
///
/// # Example: out-of-gas / invalid opcode
///
/// No Solidity reason — `revertReason` is absent, only `error`:
/// ```json
/// {
///   "type": "CALL",
///   "from": "0xabc...", "to": "0xdef...",
///   "value": "0x0", "gas": "0x...", "gasUsed": "0x...",
///   "input": "0x...",
///   "error": "out of gas"
/// }
/// ```
/// We bail with just the `error` string.
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;
    use serde_json::json;

    /// Happy path: successful contract call whose `output` is the 32-byte
    /// ABI-encoded `bool true`. Verifies prefix stripping + hex decoding.
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

    /// Reverted call with a decoded Solidity reason. Verifies the error
    /// message includes both the raw `error` and the decoded `revertReason`.
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

    /// Regression test for the Codex-flagged empty-output bug: a response
    /// missing both `output` and `error` must bail loudly rather than
    /// silently producing empty bytes (which would then get signed as a
    /// successful bidirectional response).
    #[test]
    fn bails_when_output_missing_and_no_error() {
        let frame = json!({ "type": "CALL" });
        let err = trace_output_to_bytes(B256::ZERO, &frame).expect_err("should bail");
        assert!(format!("{err}").contains("missing `output`"));
    }
}
