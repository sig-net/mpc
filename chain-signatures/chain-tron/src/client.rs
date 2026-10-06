use std::time::Duration;

use alloy::primitives::{Bytes, Log, B256};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use url::Url;

use mpc_chain_integration_core::utils::retry::{retry_rpc_gated, RetryConfig, SharedBackoff};

use crate::address::{parse_hex, TronAddress};
use crate::config::TronConfig;
use crate::types::{AccountResources, BroadcastOutcome, NowBlock, TronLog, TronReceipt};

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
        retry_rpc_gated!(
            self.request_timeout,
            self.retry,
            self.gate,
            "get_now_block",
            {
                let response: NowBlockResponse = self
                    .post_json("wallet/getnowblock", &serde_json::json!({}))
                    .await?;
                Ok(NowBlock {
                    block_id: response.block_id.parse().context("blockID")?,
                    number: response.block_header.raw_data.number,
                    timestamp: response.block_header.raw_data.timestamp,
                })
            }
        )
    }

    /// `POST /wallet/broadcasthex` with the raw (protobuf-serialized)
    /// transaction. Congestion errors (`TooManyTransactions`,
    /// `CONNECTION_CLOSED`) become `Err` so the gate rebroadcasts identical
    /// bytes. Other rejections are terminal.
    pub async fn broadcast_transaction(&self, raw_tx: &[u8]) -> anyhow::Result<BroadcastOutcome> {
        retry_rpc_gated!(
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
        retry_rpc_gated!(
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
                        contract_ret: response.contract_ret,
                        res_message: response.res_message.as_deref().map(decode_hex_ascii),
                        energy_usage: response.receipt.energy_usage,
                        net_usage: response.receipt.net_usage,
                        receipt_result: response.receipt.result,
                        logs: response.log,
                    })),
                    None => Ok(None),
                }
            }
        )
    }

    /// `POST /wallet/getaccountresource`.
    pub async fn get_account_resource(
        &self,
        address: &TronAddress,
    ) -> anyhow::Result<AccountResources> {
        retry_rpc_gated!(
            self.request_timeout,
            self.retry,
            self.gate,
            "get_account_resource",
            {
                self.post_json(
                    "wallet/getaccountresource",
                    &serde_json::json!({
                        "value": hex::encode(address.as_bytes()),
                        "visible": false
                    }),
                )
                .await
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

        let code = response.code.as_deref().unwrap_or_default();

        match (response.result, code) {
            // Accepted cases: either a duplicate transaction or a successful broadcast.
            (_, "DUP_TRANSACTION") | (true, _) => Ok(BroadcastOutcome::Accepted),
            (false, "TooManyTransactions" | "CONNECTION_CLOSED") => {
                Err(anyhow!("broadcast rejected: {code}"))
            }
            // Rejected cases
            (false, _) => Ok(BroadcastOutcome::Rejected {
                code: if code.is_empty() { "OTHER" } else { code }.to_string(),
                message: response
                    .message
                    .as_deref()
                    .map(decode_hex_ascii)
                    .unwrap_or_default(),
            }),
        }
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
    hex::decode(s)
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
    #[serde(default, rename = "contractRet")]
    contract_ret: Option<String>,
    #[serde(default, rename = "resMessage")]
    res_message: Option<String>,
    #[serde(default)]
    receipt: ReceiptUsage,
    #[serde(default, deserialize_with = "deserialize_logs")]
    log: Vec<TronLog>,
}

/// Response structure for the usage information in a transaction receipt.
#[derive(Deserialize, Default)]
struct ReceiptUsage {
    #[serde(default, rename = "energy_usage")]
    energy_usage: u64,
    #[serde(default, rename = "net_usage")]
    net_usage: u64,
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
            let data = hex::decode(raw.data.strip_prefix("0x").unwrap_or(&raw.data))
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
    async fn broadcast_accepted() {
        let (mut server, client) = test_client(fast_retry()).await;
        server
            .mock("POST", "/wallet/broadcasthex")
            .match_body(Matcher::Json(
                serde_json::json!({ "transaction": "0a020801" }),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{ "result": true, "txid": "aa11…22" }"#)
            .create_async()
            .await;

        let outcome = client
            .broadcast_transaction(&[0x0a, 0x02, 0x08, 0x01])
            .await
            .unwrap();
        assert_eq!(outcome, BroadcastOutcome::Accepted);
    }

    #[tokio::test]
    async fn broadcast_dup_transaction_is_accepted_without_retry() {
        let (mut server, client) = test_client(fast_retry()).await;
        let mock = server
            .mock("POST", "/wallet/broadcasthex")
            .match_body(Matcher::Json(serde_json::json!({ "transaction": "0a" })))
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{ "result": false, "code": "DUP_TRANSACTION", "message": "" }"#)
            .create_async()
            .await;

        let outcome = client.broadcast_transaction(&[0x0a]).await.unwrap();
        assert_eq!(outcome, BroadcastOutcome::Accepted);
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
            .with_body(
                r#"{ "result": false, "code": "TRANSACTION_EXPIRATION",
                      "message": "65787069726564" }"#,
            )
            .create_async()
            .await;

        let outcome = client.broadcast_transaction(&[0x0a]).await.unwrap();
        assert_eq!(
            outcome,
            BroadcastOutcome::Rejected {
                code: "TRANSACTION_EXPIRATION".into(),
                message: "expired".into()
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
            .with_body(r#"{ "result": false, "code": "TooManyTransactions", "message": "" }"#)
            .create_async()
            .await;

        let err = client.broadcast_transaction(&[0x0a]).await.unwrap_err();
        assert!(err.to_string().contains("TooManyTransactions"));
    }

    #[tokio::test]
    async fn transport_errors_are_retried() {
        let (mut server, client) = test_client(fast_retry()).await;
        let mock = server
            .mock("POST", "/wallet/getaccountresource")
            .with_status(429)
            .expect_at_least(2)
            .create_async()
            .await;

        let err = client
            .get_account_resource(&TronAddress::from_evm(Address::ZERO))
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
        let tx_id = test_hash(9);
        let usdt_topic = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
        let data_hex = "00000000000000000000000000000000000000000000000000000000001e8480";
        // Log address is the 20-byte EVM form.
        // The 21-byte 0x41-prefixed form stays tolerated.
        server
            .mock("POST", "/walletsolidity/gettransactioninfobyid")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{
                    "id": "{tx_id}",
                    "fee": 2765000,
                    "blockNumber": 3035010,
                    "blockTimeStamp": 1730000031000,
                    "contractRet": "SUCCESS",
                    "resMessage": "53554343455353",
                    "receipt": {{ "energy_usage": 262, "net_usage": 343, "result": "SUCCESS" }},
                    "log": [
                        {{
                            "address": "41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
                            "topics": ["{usdt_topic}"],
                            "data": "{data_hex}"
                        }},
                        {{
                            "address": "a614f803b6fd780986a42c78ec9c7f77e6ded13c",
                            "topics": ["{usdt_topic}"],
                            "data": "{data_hex}"
                        }}
                    ]
                }}"#
            ))
            .create_async()
            .await;

        let receipt = client
            .get_transaction_info_solidity(&tx_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.id, tx_id);
        assert_eq!(receipt.block_number, 3035010);
        assert_eq!(receipt.fee, 2765000);
        assert_eq!(receipt.contract_ret.as_deref(), Some("SUCCESS"));
        assert_eq!(receipt.receipt_result.as_deref(), Some("SUCCESS"));
        assert_eq!(receipt.res_message.as_deref(), Some("SUCCESS"));
        assert_eq!(receipt.energy_usage, 262);
        assert_eq!(receipt.net_usage, 343);

        let expected_log = Log::new(
            address!("a614f803b6fd780986a42c78ec9c7f77e6ded13c"),
            vec![usdt_topic.parse::<B256>().unwrap()],
            Bytes::from(hex::decode(data_hex).unwrap()),
        )
        .unwrap();
        assert_eq!(receipt.logs, vec![expected_log.clone(), expected_log]);
    }

    #[tokio::test]
    async fn account_resources_parse() {
        let (mut server, client) = test_client(fast_retry()).await;
        server
            .mock("POST", "/wallet/getaccountresource")
            .match_header("TRON-PRO-API-KEY", "test-key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "freeNetUsed": 0,
                    "freeNetLimit": 600,
                    "NetUsed": 0,
                    "NetLimit": 5000,
                    "energyUsed": 131,
                    "energyLimit": 100000
                }"#,
            )
            .create_async()
            .await;

        let address = TronAddress::from_evm(Address::ZERO);
        let resources = client.get_account_resource(&address).await.unwrap();
        assert_eq!(resources.free_net_limit, 600);
        assert_eq!(resources.net_limit, 5000);
        assert_eq!(resources.energy_used, 131);
        assert_eq!(resources.energy_limit, 100000);
    }
}
