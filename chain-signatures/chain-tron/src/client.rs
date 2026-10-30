use std::time::Duration;

use alloy::primitives::{Bytes, Log, B256};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use url::Url;

use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig, SharedBackoff};

use crate::config::TronConfig;
use crate::types::{BroadcastOutcome, NowBlock, TronLog, TronReceipt};
use mpc_tron_wire::{encoding::decode_bytes, parse_hex, TronAddress};

/// Tron HTTP client for interacting with the Tron blockchain.
pub struct TronHttp {
    http: reqwest::Client,
    endpoint: Url,
    api_key: Option<String>,
    request_timeout: Duration,
    retry: RetryConfig,
    gate: SharedBackoff,
}

impl TronHttp {
    pub fn new(config: &TronConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .context("building tron http client")?;

        Ok(Self {
            http,
            endpoint: config.endpoint.clone(),
            api_key: config.api_key.clone(),
            request_timeout: config.request_timeout,
            retry: config.retry,
            gate: SharedBackoff::new(),
        })
    }

    /// `POST /wallet/getnowblock`. Tron has no nonces, this feeds the
    /// ref-block replay fields filled at assembly.
    pub async fn get_now_block(&self) -> anyhow::Result<NowBlock> {
        retry_rpc!(
            self.request_timeout,
            self.retry,
            self.gate,
            "get_now_block",
            {
                let response: NowBlockResponse = self
                    .post_json("wallet/getnowblock", &serde_json::json!({}))
                    .await?;
                response.into_now_block()
            }
        )
    }

    /// `POST /walletsolidity/getnowblock` — the solidified head; used for the
    /// expiration check.
    pub async fn get_now_block_solidity(&self) -> anyhow::Result<NowBlock> {
        retry_rpc!(
            self.request_timeout,
            self.retry,
            self.gate,
            "get_now_block_solidity",
            {
                let response: NowBlockResponse = self
                    .post_json("walletsolidity/getnowblock", &serde_json::json!({}))
                    .await?;
                response.into_now_block()
            }
        )
    }

    /// `POST /wallet/broadcasthex` with the raw (protobuf-serialized)
    /// transaction. Congestion errors (`SERVER_BUSY`, `NO_CONNECTION`,
    /// `NOT_ENOUGH_EFFECTIVE_CONNECTION`) become `Err` so the gate retries
    /// identical bytes. Other rejections are terminal.
    pub async fn broadcast_transaction(&self, raw_tx: &[u8]) -> anyhow::Result<BroadcastOutcome> {
        retry_rpc!(
            self.request_timeout,
            self.retry,
            self.gate,
            "broadcast_transaction",
            { self.broadcast_once(raw_tx).await }
        )
    }

    /// `POST /walletsolidity/gettransactioninfobyid`; `Ok(None)` means
    /// not solidified yet, not an error.
    pub async fn get_transaction_info_solidity(
        &self,
        tx_id: &B256,
    ) -> anyhow::Result<Option<TronReceipt>> {
        retry_rpc!(
            self.request_timeout,
            self.retry,
            self.gate,
            "get_transaction_info_solidity",
            {
                let response: TransactionInfoResponse = self
                    .post_json(
                        "walletsolidity/gettransactioninfobyid",
                        &serde_json::json!({ "value": hex::encode(tx_id), "visible": false }),
                    )
                    .await?;

                match response.id {
                    Some(id) => Ok(Some(TronReceipt {
                        id: id.parse().context("receipt id")?,
                        block_number: response.block_number,
                        block_timestamp: response.block_timestamp,
                        fee: response.fee,
                        result: response.result,
                        res_message: response.res_message.as_deref().map(decode_hex_ascii),
                        receipt_result: response.receipt.result,
                        logs: response.log,
                    })),
                    None => Ok(None),
                }
            }
        )
    }

    /// `POST /wallet/getaccount`, returning the TRX balance in sun. Zero
    /// for an account the chain has never seen.
    pub async fn get_account_balance(&self, address: &TronAddress) -> anyhow::Result<u64> {
        retry_rpc!(
            self.request_timeout,
            self.retry,
            self.gate,
            "get_account_balance",
            {
                let response: AccountResponse = self
                    .post_json(
                        "wallet/getaccount",
                        &serde_json::json!({
                            "address": address.to_hex(),
                            "visible": false
                        }),
                    )
                    .await?;
                Ok(response.balance)
            }
        )
    }

    /// Broadcasts a raw transaction to the Tron network once.
    async fn broadcast_once(&self, raw_tx: &[u8]) -> anyhow::Result<BroadcastOutcome> {
        let response: BroadcastResponse = self
            .post_json(
                "wallet/broadcasthex",
                &serde_json::json!({ "transaction": hex::encode(raw_tx) }),
            )
            .await?;
        response.into_outcome()
    }

    /// Sends a JSON POST request to the Tron node and deserializes the response.
    async fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> anyhow::Result<T> {
        let url = self
            .endpoint
            .join(path)
            .with_context(|| format!("joining {path} onto {}", self.endpoint))?;

        let mut request = self.http.post(url).json(body);

        if let Some(api_key) = &self.api_key {
            request = request.header("TRON-PRO-API-KEY", api_key);
        }

        let response = request.send().await.context("sending tron request")?;
        let status = response.status();
        let text = response.text().await.context("reading tron response")?;

        if !status.is_success() {
            return Err(anyhow!("tron http {path}: {status}: {text}"));
        }

        serde_json::from_str(&text)
            .with_context(|| format!("decoding tron {path} response: {text}"))
    }
}

/// Tron error/reason strings (`message`, `resMessage`) are hex-encoded ASCII.
fn decode_hex_ascii(s: &str) -> String {
    decode_bytes(s)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| s.to_string())
}

/// Response structure for the `now` block query.
#[derive(Deserialize)]
struct NowBlockResponse {
    #[serde(rename = "blockID")]
    block_id: String,
    block_header: NowBlockHeader,
}

/// Response structure for the header of the `now` block.
#[derive(Deserialize)]
struct NowBlockHeader {
    raw_data: NowBlockRawData,
}

/// Response structure for the raw data of the `now` block header.
#[derive(Deserialize)]
struct NowBlockRawData {
    number: u64,
    timestamp: u64,
}

impl NowBlockResponse {
    fn into_now_block(self) -> anyhow::Result<NowBlock> {
        Ok(NowBlock {
            block_id: self.block_id.parse().context("blockID")?,
            number: self.block_header.raw_data.number,
            timestamp: self.block_header.raw_data.timestamp,
        })
    }
}

/// Response structure for `getaccount`; `{}` for unseen accounts.
#[derive(Deserialize)]
struct AccountResponse {
    #[serde(default)]
    balance: u64,
}

/// Response structure for the broadcast transaction result.
#[derive(Deserialize)]
struct BroadcastResponse {
    #[serde(default)]
    result: bool,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

impl BroadcastResponse {
    /// Codes are java-tron `Return.response_code` names. Congestion and
    /// duplicates must not be terminal
    fn into_outcome(self) -> anyhow::Result<BroadcastOutcome> {
        let code = self.code.as_deref().unwrap_or_default();
        match (self.result, code) {
            (true, _) => Ok(BroadcastOutcome::Accepted),
            (_, "DUP_TRANSACTION_ERROR") => Ok(BroadcastOutcome::AlreadyKnown),
            (false, "SERVER_BUSY" | "NO_CONNECTION" | "NOT_ENOUGH_EFFECTIVE_CONNECTION") => {
                Err(anyhow!("broadcast rejected: {code}"))
            }
            (false, _) => Ok(BroadcastOutcome::Rejected {
                code: if code.is_empty() { "OTHER" } else { code }.to_string(),
                message: self
                    .message
                    .as_deref()
                    .map(decode_hex_ascii)
                    .unwrap_or_default(),
            }),
        }
    }
}

/// Response structure for the transaction info query.
#[derive(Deserialize)]
struct TransactionInfoResponse {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "blockNumber")]
    block_number: u64,
    #[serde(default, rename = "blockTimeStamp")]
    block_timestamp: u64,
    #[serde(default)]
    fee: u64,
    #[serde(default)]
    result: Option<String>,
    #[serde(default, rename = "resMessage")]
    res_message: Option<String>,
    #[serde(default)]
    receipt: ReceiptUsage,
    #[serde(default, deserialize_with = "deserialize_logs")]
    log: Vec<TronLog>,
}

/// `receipt.result` classification; success carries its verdict here alone
/// (the top-level `code` is proto3-zero-omitted), failure alongside the
/// top-level `FAILED`. Usage counters stay unread.
#[derive(Deserialize, Default)]
struct ReceiptUsage {
    #[serde(default)]
    result: Option<String>,
}

/// Receipt logs arrive as Tron-encoded hex JSON; parse them into
/// EVM-shaped [`TronLog`]s, with the address normalized to 20-byte EVM form.
fn deserialize_logs<'de, D>(deserializer: D) -> Result<Vec<TronLog>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct RawLog {
        #[serde(default)]
        address: String,
        #[serde(default)]
        topics: Vec<String>,
        #[serde(default)]
        data: String,
    }

    Vec::<RawLog>::deserialize(deserializer)?
        .into_iter()
        .map(|raw| {
            let topics = raw
                .topics
                .iter()
                .map(|t| t.parse::<B256>().with_context(|| format!("log topic {t}")))
                .collect::<anyhow::Result<Vec<_>>>()
                .map_err(serde::de::Error::custom)?;

            let data = decode_bytes(&raw.data)
                .context("decoding log data")
                .map_err(serde::de::Error::custom)?;

            Log::new(
                parse_hex(&raw.address).map_err(serde::de::Error::custom)?,
                topics,
                Bytes::from(data),
            )
            .ok_or_else(|| serde::de::Error::custom("invalid log: needs 1-4 topics"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy::primitives::{address, Address};
    use mockito::Matcher;

    use super::*;

    fn fast_retry() -> RetryConfig {
        RetryConfig {
            min_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            max_times: 2,
            jitter: false,
        }
    }

    fn once_retry() -> RetryConfig {
        RetryConfig {
            max_times: 1,
            ..fast_retry()
        }
    }

    /// Generates a deterministic test hash based on the given seed.
    fn test_hash(seed: u8) -> B256 {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_mul(31).wrapping_add(i as u8);
        }
        bytes.into()
    }

    /// Generates a deterministic test client with the given retry configuration.
    async fn test_client(retry: RetryConfig) -> (mockito::ServerGuard, TronHttp) {
        let server = mockito::Server::new_async().await;
        let client = TronHttp::new(&TronConfig {
            endpoint: Url::parse(&server.url()).unwrap(),
            api_key: Some("test-key".to_string()),
            retry,
            ..TronConfig::default()
        })
        .unwrap();
        (server, client)
    }

    #[tokio::test]
    async fn get_now_block_parses() {
        let (mut server, client) = test_client(fast_retry()).await;
        let block_hash = test_hash(7);
        server
            .mock("POST", "/wallet/getnowblock")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{ "blockID": "{}",
                     "block_header": {{ "raw_data": {{ "number": 3035019, "timestamp": 1730000000000 }} }} }}"#,
                hex::encode(block_hash)
            ))
            .create_async()
            .await;

        let block = client.get_now_block().await.unwrap();
        assert_eq!(block.number, 3035019);
        assert_eq!(block.timestamp, 1730000000000);
        assert_eq!(block.block_id, block_hash);
    }

    #[tokio::test]
    async fn solidity_head_parses_the_recorded_nile_body() {
        let (mut server, client) = test_client(fast_retry()).await;
        // Recorded 2026-10-30 off nile.trongrid.io
        server
            .mock("POST", "/walletsolidity/getnowblock")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(include_str!(
                "../tests/fixtures/nile/nowblock-solidity.json"
            ))
            .create_async()
            .await;

        let block = client.get_now_block_solidity().await.unwrap();
        assert_eq!(block.number, 72_266_582);
        assert_eq!(block.timestamp, 1_793_335_731_000);
    }

    #[test]
    fn broadcast_codes_classify() {
        fn outcome(result: bool, code: Option<&str>) -> anyhow::Result<BroadcastOutcome> {
            BroadcastResponse {
                result,
                code: code.map(str::to_string),
                message: None,
            }
            .into_outcome()
        }

        // java-tron `Return.response_code` names.
        assert_eq!(outcome(true, None).unwrap(), BroadcastOutcome::Accepted);
        assert_eq!(
            outcome(false, Some("DUP_TRANSACTION_ERROR")).unwrap(),
            BroadcastOutcome::AlreadyKnown
        );
        // `result: true` outranks a stale code field.
        assert_eq!(
            outcome(true, Some("DUP_TRANSACTION_ERROR")).unwrap(),
            BroadcastOutcome::Accepted
        );
        for code in [
            "SERVER_BUSY",
            "NO_CONNECTION",
            "NOT_ENOUGH_EFFECTIVE_CONNECTION",
        ] {
            let err = outcome(false, Some(code)).unwrap_err();
            assert!(err.to_string().contains(code), "{code} must be retryable");
        }
        for code in [
            Some("CONTRACT_VALIDATE_ERROR"),
            Some("SIGERROR"),
            Some("BANDWITH_ERROR"),
            None,
        ] {
            assert!(
                matches!(
                    outcome(false, code).unwrap(),
                    BroadcastOutcome::Rejected { .. }
                ),
                "{code:?} must be terminal"
            );
        }
    }

    #[tokio::test]
    async fn broadcast_accepted() {
        let (mut server, client) = test_client(fast_retry()).await;
        server
            .mock("POST", "/wallet/broadcasthex")
            .match_body(Matcher::Json(
                serde_json::json!({ "transaction": "0a020801" }),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(include_str!("../tests/fixtures/nile/broadcast-accept.json"))
            .create_async()
            .await;

        let outcome = client
            .broadcast_transaction(&[0x0a, 0x02, 0x08, 0x01])
            .await
            .unwrap();
        assert_eq!(outcome, BroadcastOutcome::Accepted);
    }

    #[tokio::test]
    async fn broadcast_duplicate_is_already_known_without_retry() {
        let (mut server, client) = test_client(fast_retry()).await;
        let mock = server
            .mock("POST", "/wallet/broadcasthex")
            .match_body(Matcher::Json(serde_json::json!({ "transaction": "0a" })))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(include_str!("../tests/fixtures/nile/broadcast-dup.json"))
            .create_async()
            .await;

        let outcome = client.broadcast_transaction(&[0x0a]).await.unwrap();
        assert_eq!(outcome, BroadcastOutcome::AlreadyKnown);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn broadcast_terminal_rejection_is_not_retried() {
        let (mut server, client) = test_client(fast_retry()).await;
        let mock = server
            .mock("POST", "/wallet/broadcasthex")
            .match_body(Matcher::Json(serde_json::json!({ "transaction": "0a" })))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(include_str!(
                "../tests/fixtures/nile/broadcast-codeless.json"
            ))
            .create_async()
            .await;

        let outcome = client.broadcast_transaction(&[0x0a]).await.unwrap();
        assert_eq!(
            outcome,
            BroadcastOutcome::Rejected {
                code: "CONTRACT_VALIDATE_ERROR".into(),
                message: "Contract validate error : No contract or not a smart contract".into()
            }
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn broadcast_congestion_is_an_error() {
        let (mut server, client) = test_client(once_retry()).await;
        server
            .mock("POST", "/wallet/broadcasthex")
            .match_body(Matcher::Json(serde_json::json!({ "transaction": "0a" })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{ "result": false, "code": "SERVER_BUSY", "message": "" }"#)
            .create_async()
            .await;

        let err = client.broadcast_transaction(&[0x0a]).await.unwrap_err();
        assert!(format!("{err:#}").contains("SERVER_BUSY"));
    }

    #[tokio::test]
    async fn transport_errors_are_retried() {
        let (mut server, client) = test_client(fast_retry()).await;
        let mock = server
            .mock("POST", "/wallet/getaccount")
            .with_status(429)
            .expect_at_least(2)
            .create_async()
            .await;

        let err = client
            .get_account_balance(&TronAddress::from_evm(Address::ZERO))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("exhausted"),
            "unexpected error: {err}"
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn solidity_receipt_empty_means_pending() {
        let (mut server, client) = test_client(fast_retry()).await;
        server
            .mock("POST", "/walletsolidity/gettransactioninfobyid")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create_async()
            .await;

        let tx_id = test_hash(9);
        assert!(client
            .get_transaction_info_solidity(&tx_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn solidity_receipt_parses() {
        let (mut server, client) = test_client(fast_retry()).await;
        // The recorded nile receipt, verbatim; its id is this test's hash.
        let tx_id: B256 = "24157817b0db1a156e7244d4417cbd7303f32b06449fcbad739f124b6b8e4c82"
            .parse()
            .unwrap();
        server
            .mock("POST", "/walletsolidity/gettransactioninfobyid")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(include_str!("../tests/fixtures/nile/receipt-success.json"))
            .create_async()
            .await;

        let receipt = client
            .get_transaction_info_solidity(&tx_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.id, tx_id);
        assert_eq!(receipt.block_number, 71896097);
        assert_eq!(receipt.fee, 472800);
        // Recorded receipts carry the outcome in receipt.result only.
        assert_eq!(receipt.result, None);
        assert_eq!(receipt.receipt_result.as_deref(), Some("SUCCESS"));
        assert_eq!(receipt.res_message, None);

        let usdt = address!("eca9bc828a3005b9a3b909f2cc5c2a54794de05f");
        let holder = "000000000000000000000000bdf81069827deba7d39729eb387eda8827e5525c";
        let topics = [
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            holder,
            holder,
        ]
        .iter()
        .map(|t| t.parse::<B256>().unwrap())
        .collect::<Vec<_>>();
        let expected_log = Log::new(
            usdt,
            topics,
            Bytes::from(
                hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(receipt.logs, vec![expected_log]);
    }

    #[tokio::test]
    async fn receipt_tolerates_prefixed_addresses_and_hex_messages() {
        // Deliberate parser leniencies, not node shapes: a 0x41-prefixed
        // log address and a hex-ASCII resMessage (plain text is the other
        // live encoding).
        let (mut server, client) = test_client(fast_retry()).await;
        let tx_id = test_hash(9);
        server
            .mock("POST", "/walletsolidity/gettransactioninfobyid")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{ "id": "{tx_id}", "resMessage": "53554343455353",
                     "log": [{{ "address": "41eca9bc828a3005b9a3b909f2cc5c2a54794de05f",
                                "topics": ["ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],
                                "data": "" }}] }}"#
            ))
            .create_async()
            .await;

        let receipt = client
            .get_transaction_info_solidity(&tx_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.id, tx_id);
        assert_eq!(receipt.res_message.as_deref(), Some("SUCCESS"));
        assert_eq!(
            receipt.logs.first().unwrap().address,
            address!("eca9bc828a3005b9a3b909f2cc5c2a54794de05f")
        );
    }
}
