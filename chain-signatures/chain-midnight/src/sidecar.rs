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

/// One atom's declared shape, the ledger's `AlignmentAtom` verbatim.
///
/// Only `Bytes` carries a width. `Compress` and `Field` have none, which is why the
/// wire form cannot be a flat width list.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
pub enum AlignmentAtom {
    Compress,
    Field,
    Bytes { length: u32 },
}

/// One segment of a cell's alignment, the ledger's `AlignmentSegment` verbatim.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
pub enum AlignmentSegment {
    Atom { value: AlignmentAtom },
    Option { value: Vec<Vec<AlignmentSegment>> },
}

/// Decoded contract state, internally tagged on `kind` exactly as the sidecar emits it
/// (`{"kind":"cell","atoms":[..],"alignment":[..]}`, `{"kind":"null"}`).
///
/// A cell's `alignment` runs one segment per atom, in atom order. It is load-bearing:
/// stored atoms are trailing-zero-trimmed, so the declared width of a field is
/// recoverable only from here. Consumers decode by the declared width and never by
/// what a stored atom happens to be.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum StateNode {
    Cell {
        atoms: Vec<String>,
        alignment: Vec<AlignmentSegment>,
    },
    Array {
        children: Vec<StateNode>,
    },
    Map {
        entries: Vec<MapEntry>,
    },
    Null,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct MapEntry {
    pub key: Vec<String>,
    pub value: StateNode,
}

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

    /// Decodes raw contract state bytes into the sidecar's atom tree.
    pub async fn decode_contract_state(&self, state: &[u8]) -> anyhow::Result<StateNode> {
        let body = serde_json::json!({ "state": hex::encode(state) });
        retry_rpc!(
            self.request_timeout,
            self.retry,
            "sidecar_decode_contract_state",
            {
                let resp = self
                    .http
                    .post(self.endpoint("/decode/contract-state"))
                    .json(&body)
                    .send()
                    .await
                    .context("sidecar /decode/contract-state request failed")?;
                let resp = check_response(resp, "/decode/contract-state").await?;
                resp.json::<StateNode>()
                    .await
                    .context("sidecar /decode/contract-state returned an unparseable body")
            }
        )
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

/// True when `err` is the sidecar refusing the bytes rather than failing to answer.
pub(crate) fn is_refused_bytes(err: &anyhow::Error) -> bool {
    err.to_string().contains(REFUSED_BYTES_MSG)
}

/// The offline cross-language check plus the startup gate's rejection paths.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IndexerConfig, RpcConfig, SidecarConfig};

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

    #[tokio::test]
    async fn unreachable_sidecar_is_not_a_refusal() {
        // Port 1 on loopback refuses immediately, so this needs no server.
        let config = MidnightConfig {
            sidecar_url: "http://127.0.0.1:1".to_string(),
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".to_string(),
            rpc: RpcConfig::default(),
            sidecar: SidecarConfig {
                request_timeout: Duration::from_millis(200),
                retry: RetryConfig {
                    min_delay: Duration::from_millis(1),
                    max_delay: Duration::from_millis(2),
                    max_times: 1,
                    jitter: false,
                },
            },
            indexer: IndexerConfig::default(),
        };
        let err = SidecarClient::new(&config)
            .expect("client")
            .decode_contract_state(&[0u8; 4])
            .await
            .expect_err("an unreachable sidecar cannot decode");
        assert!(
            !is_refused_bytes(&err),
            "a transport fault must propagate, not be charged to the contract: {err:#}"
        );
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

    #[test]
    fn state_node_parses_sidecar_golden() {
        assert_eq!(
            serde_json::from_str::<StateNode>(r#"{"kind":"null"}"#).expect("null node parses"),
            StateNode::Null
        );

        const GOLDEN: &str = include_str!(
            "../../midnight-publisher-ts/tests/fixtures/golden-state-singleton-1366.json"
        );
        let tree: StateNode = serde_json::from_str(GOLDEN)
            .expect("the sidecar's own golden must parse into this client's StateNode");

        let StateNode::Array { children } = &tree else {
            panic!("the singleton's state root is an array of ledger fields, got {tree:?}");
        };

        // Field 0's key is a single `RequestId` atom; field 1's is the composite
        // `SignetMapKey { count, requestId }` whose `count` of 0 trims to the empty
        // atom.
        let key_of = |field: usize| -> Vec<String> {
            let StateNode::Map { entries } = &children[field] else {
                panic!("ledger field {field} is a map in this capture");
            };
            assert_eq!(entries.len(), 1, "field {field} holds one entry here");
            entries[0].key.clone()
        };

        let counter_key = key_of(0);
        let notification_key = key_of(1);
        assert_eq!(counter_key.len(), 1, "the counter map key is ONE atom");
        assert_eq!(
            notification_key.len(),
            2,
            "the notification map key is TWO atoms, boundary preserved"
        );
        assert_eq!(
            notification_key[0], "",
            "count 0 trims to the empty atom rather than disappearing"
        );
        assert_eq!(
            notification_key[1], counter_key[0],
            "both entries are filed under the same request id"
        );
        assert_eq!(
            notification_key.concat(),
            counter_key.concat(),
            "the two structurally different keys concatenate identically, which \
             is exactly the ambiguity the atom array removes"
        );
    }
}
