//! HTTP client for the `midnight-publisher-ts` sidecar, the pure codec seam.

use std::time::Duration;

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig};
use serde::Deserialize;

use crate::config::MidnightConfig;

/// Ledger serialization tags this client was written against
/// (`midnight-publisher-ts/src/ledger.ts`).
const EXPECTED_CONTRACT_STATE_TAG: &str = "midnight:contract-state[v8]";
const EXPECTED_ZSWAP_TAG: &str = "midnight:zswap-ledger-state[v5]";
const EXPECTED_LEDGER_PARAMETERS_TAG: &str = "midnight:ledger-parameters[v8]";
const EXPECTED_TRANSACTION_TAG: &str = "midnight:transaction[v12]";

/// Decoded transactions.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DecodedTransactions {
    pub transactions: Vec<DecodedTransaction>,
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DecodedTransaction {
    pub index: usize,
    pub calls: Vec<DecodedCall>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DecodedCall {
    pub address: String,
    pub communication_commitment: String,
    pub claimed: Vec<ClaimedCall>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ClaimedCall {
    pub address: String,
    pub entry_point: String,
    pub commitment: String,
}

/// `GET /health` body.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Health {
    /// `"ok"` when the sidecar considers itself serviceable.
    pub(crate) status: String,
    #[serde(rename = "networkId")]
    pub network_id: String,
    pub ledger: LedgerTags,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerTags {
    pub contract_state: String,
    pub zswap_chain_state: String,
    pub ledger_parameters: String,
    pub transaction: String,
}

/// The sidecar's error body shape: zod validation failures and route errors answer
/// `{code, message, stage, detail}`; surface it verbatim.
#[derive(Debug, Deserialize)]
struct SidecarErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    stage: Option<String>,
    #[serde(default)]
    detail: Option<serde_json::Value>,
}

/// HTTP client for the sidecar's codec routes.
pub struct SidecarClient {
    http: reqwest::Client,
    base_url: String,
    /// The network id this node expects; compared against `/health` at startup because
    /// a sidecar on another network answers every decode happily and posts every
    /// respond into the void.
    expected_network_id: String,
    request_timeout: Duration,
    retry: RetryConfig,
}

impl SidecarClient {
    pub fn new(config: &MidnightConfig) -> anyhow::Result<Self> {
        // No global timeout: each call carries its own per-attempt one.
        let http = reqwest::Client::builder()
            .connect_timeout(config.sidecar.request_timeout)
            .build()
            .context("failed to build the sidecar http client")?;
        Ok(Self {
            http,
            base_url: config.sidecar_url.trim_end_matches('/').to_string(),
            expected_network_id: config.network_id.clone(),
            request_timeout: config.sidecar.request_timeout,
            retry: config.sidecar.retry,
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Decodes raw `send_mn_transaction` blobs into call structures for the advisory
    /// provenance join.
    pub async fn decode_transactions(
        &self,
        transactions: &[Vec<u8>],
    ) -> anyhow::Result<DecodedTransactions> {
        let hexes: Vec<String> = transactions.iter().map(hex::encode).collect();
        let body = serde_json::json!({ "transactions": hexes });
        retry_rpc!(
            self.request_timeout,
            self.retry,
            "sidecar_decode_transactions",
            {
                let resp = self
                    .http
                    .post(self.endpoint("/decode/transactions"))
                    .json(&body)
                    .send()
                    .await
                    .context("sidecar /decode/transactions request failed")?;
                let resp = check_response(resp, "/decode/transactions").await?;
                resp.json::<DecodedTransactions>()
                    .await
                    .context("sidecar /decode/transactions returned an unparseable body")
            }
        )
    }

    pub async fn health(&self) -> anyhow::Result<Health> {
        retry_rpc!(self.request_timeout, self.retry, "sidecar_health", {
            let resp = self
                .http
                .get(self.endpoint("/health"))
                .send()
                .await
                .context("sidecar /health request failed")?;
            let resp = check_response(resp, "/health").await?;
            resp.json::<Health>()
                .await
                .context("sidecar /health returned an unparseable body")
        })
    }

    /// Startup gate: the sidecar must decode the ledger versions this client was
    /// written against and sit on the network this node is configured for.
    pub async fn assert_compatible(&self) -> anyhow::Result<()> {
        check_health(&self.health().await?, &self.expected_network_id)
    }
}

/// The pure half of the startup gate, split out so the rejection paths are testable
/// without a service: a healthy sidecar only ever exercises the passing side.
fn check_health(health: &Health, expected_network_id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        health.status == "ok",
        "sidecar reports status {:?}, not \"ok\": refusing to start against a sidecar \
         that says it is not serviceable",
        health.status
    );
    anyhow::ensure!(
        health.network_id == expected_network_id,
        "sidecar networkId mismatch: sidecar is on {:?}, this node is configured for {:?}",
        health.network_id,
        expected_network_id
    );
    let pairs = [
        (
            "contractState",
            &health.ledger.contract_state,
            EXPECTED_CONTRACT_STATE_TAG,
        ),
        (
            "zswapChainState",
            &health.ledger.zswap_chain_state,
            EXPECTED_ZSWAP_TAG,
        ),
        (
            "ledgerParameters",
            &health.ledger.ledger_parameters,
            EXPECTED_LEDGER_PARAMETERS_TAG,
        ),
        (
            "transaction",
            &health.ledger.transaction,
            EXPECTED_TRANSACTION_TAG,
        ),
    ];
    for (name, actual, expected) in pairs {
        anyhow::ensure!(
            actual == expected,
            "sidecar ledger tag mismatch on {name}: sidecar decodes {actual:?}, this client was written against {expected:?}"
        );
    }
    Ok(())
}

/// Surfaces a non-2xx sidecar response with its `{code, message, stage, detail}` body
/// verbatim.
async fn check_response(
    resp: reqwest::Response,
    context: &str,
) -> anyhow::Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let marker = failure_marker(status);
    let text = resp.text().await.unwrap_or_default();
    if let Ok(body) = serde_json::from_str::<SidecarErrorBody>(&text) {
        anyhow::bail!(
            "{marker}: {context} {status}: code={} message={} stage={:?} detail={:?}",
            body.code,
            body.message,
            body.stage,
            body.detail
        );
    }
    anyhow::bail!("{marker}: {context} {status}: {text}");
}

/// A 4xx means the sidecar read what we sent and refused it, which is a property of the
/// bytes.
fn failure_marker(status: reqwest::StatusCode) -> &'static str {
    if status.is_client_error() {
        REFUSED_BYTES_MSG
    } else {
        "sidecar could not answer"
    }
}

/// Marks a sidecar answer that refused the BYTES, as opposed to a transport fault, a
/// timeout or a 5xx.
pub(crate) const REFUSED_BYTES_MSG: &str = "sidecar refused the submitted bytes";

/// The offline cross-language check plus the startup gate's rejection paths.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_client_error_is_a_refusal() {
        use reqwest::StatusCode;
        for refused in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::NOT_FOUND,
        ] {
            assert_eq!(failure_marker(refused), REFUSED_BYTES_MSG, "{refused}");
        }
        for unanswered in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert_ne!(
                failure_marker(unanswered),
                REFUSED_BYTES_MSG,
                "{unanswered}"
            );
        }
    }

    fn healthy() -> Health {
        Health {
            status: "ok".to_string(),
            network_id: "undeployed".to_string(),
            ledger: LedgerTags {
                contract_state: EXPECTED_CONTRACT_STATE_TAG.to_string(),
                zswap_chain_state: EXPECTED_ZSWAP_TAG.to_string(),
                ledger_parameters: EXPECTED_LEDGER_PARAMETERS_TAG.to_string(),
                transaction: EXPECTED_TRANSACTION_TAG.to_string(),
            },
        }
    }

    #[test]
    fn check_health_accepts_a_matching_sidecar() {
        check_health(&healthy(), "undeployed").expect("a matching sidecar passes the gate");
    }

    #[test]
    fn check_health_rejects_unserviceable_status() {
        let mut health = healthy();
        health.status = "degraded".to_string();
        let err = check_health(&health, "undeployed")
            .expect_err("a sidecar that says it is not serviceable must fail startup")
            .to_string();
        assert!(err.contains("degraded"), "status must be named: {err}");
    }

    #[test]
    fn check_health_rejects_network_id_mismatch() {
        let err = check_health(&healthy(), "testnet")
            .expect_err("a sidecar on another network must fail startup")
            .to_string();
        assert!(err.contains("networkId"), "unexpected error: {err}");
        assert!(err.contains("testnet"), "expected network named: {err}");
    }

    #[test]
    fn check_health_rejects_ledger_tag_mismatch() {
        let mut health = healthy();
        health.ledger.contract_state = "midnight:contract-state[v9]".to_string();
        let err = check_health(&health, "undeployed")
            .expect_err("a contractState tag mismatch must fail startup")
            .to_string();
        assert!(err.contains("contractState"), "unexpected error: {err}");
        assert!(err.contains("v9"), "the actual tag must be named: {err}");
    }
}
