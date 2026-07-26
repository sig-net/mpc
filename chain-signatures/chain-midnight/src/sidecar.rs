//! HTTP client for the `midnight-publisher-ts` sidecar, the pure codec seam.
//!
//! The sidecar decodes bytes; every trust decision stays on this side. A
//! sidecar decode bug must be able to cause a dropped request, never a wrong
//! signature: nothing returned by these routes is signed over without the
//! Rust-side recompute-and-drop downstream.
//!
//! Wire-shape assumptions this client pins with its own tests until the
//! sidecar lands in-tree (mpc PR #1058): the `/decode/*` request bodies
//! (`{"state": hex}` and `{"transactions": [hex]}`), the untagged JSON form
//! of `StateNode` (variants have disjoint field names, and `null` is the
//! `Null` node), and camelCase keys on `/health` only. Any divergence fails
//! loudly in deserialization or in the sidecar's zod validation, never
//! silently.

use std::time::Duration;

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig};
use serde::{Deserialize, Serialize};

use crate::config::MidnightConfig;

/// Ledger serialization tags this client was written against
/// (`midnight-publisher-ts/src/ledger.ts`). A sidecar reporting different
/// tags decodes a different wire format; refuse it at startup.
const EXPECTED_CONTRACT_STATE_TAG: &str = "midnight:contract-state[v8]";
const EXPECTED_ZSWAP_TAG: &str = "midnight:zswap-ledger-state[v5]";
const EXPECTED_LEDGER_PARAMETERS_TAG: &str = "midnight:ledger-parameters[v8]";
const EXPECTED_TRANSACTION_TAG: &str = "midnight:transaction[v12]";

/// Decoded contract state (`src/state.ts`). Untagged on the wire: the
/// variants carry disjoint field names and the null node is JSON `null`, so
/// deserialization is unambiguous and a shape divergence fails loudly.
///
/// Map keys are the entry's atoms hex-CONCATENATED into one string, which is
/// lossy for composite keys (D9): the split point is not recoverable here,
/// and consumers must construct-and-match rather than parse.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum StateNode {
    Cell {
        /// Per-atom hex, trailing-zero-TRIMMED on the wire.
        atoms: Vec<String>,
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
    pub key: String,
    pub value: StateNode,
}

/// Decoded transactions (`src/block.ts`). A `DecodedCall` has NO entry
/// point: only the CLAIMED calls (caller side) carry one, the callee's own
/// entry carries a commitment. The provenance join matches
/// `claimed[i].commitment` on one call against `communication_commitment`
/// on another call in the SAME transaction.
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
    pub position: u32,
    pub address: String,
    pub entry_point: String,
    /// Little-endian Fr bytes, tag stripped.
    pub commitment: String,
}

/// `POST /respond` body (`src/respond.ts`), a discriminated union on
/// `circuit` whose ids match the singleton's circuit names (D6). The sidecar
/// STRIPS unknown keys rather than rejecting them, so the variants here stay
/// non-overlapping and the wire shape is pinned by this crate's own tests.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "circuit")]
pub enum RespondRequest {
    #[serde(rename = "respond")]
    Respond {
        contract_address: String,
        request_id: String,
        signature: WireSignature,
    },
    #[serde(rename = "respondBidirectional")]
    RespondBidirectional {
        contract_address: String,
        request_id: String,
        signature: WireSignature,
        /// EXACTLY 128 bytes of hex, the full zero-padded buffer (D4).
        serialized_output: String,
        /// 0..=128; not covered by the attestation digest.
        output_len: u8,
    },
}

/// SEC1 BIG-ENDIAN hex, 32 bytes per coordinate; the MPC posts big-endian
/// and must not pre-reverse.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WireSignature {
    pub big_r: WirePoint,
    pub s: String,
    /// 0 or 1 only.
    pub recovery_id: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WirePoint {
    pub x: String,
    pub y: String,
}

/// `GET /health` body. This route alone uses camelCase keys.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Health {
    pub status: String,
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

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RespondReceipt {
    pub status: String,
    pub tx_id: String,
    pub block_hash: String,
}

/// The sidecar's error body shape: zod validation failures and route errors
/// answer `{code, message, stage, detail}`; surface it verbatim.
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
    /// The network id this node expects; compared against `/health` at
    /// startup because a sidecar on another network answers every decode
    /// happily and posts every respond into the void.
    expected_network_id: String,
    request_timeout: Duration,
    /// `POST /respond` proves a circuit and can take minutes; it gets this
    /// budget instead of `request_timeout`, per `SidecarConfig`'s split.
    respond_timeout: Duration,
    retry: RetryConfig,
}

impl SidecarClient {
    pub fn new(config: &MidnightConfig) -> anyhow::Result<Self> {
        config.validate()?;
        // No global reqwest timeout: /respond needs its own proving budget,
        // so every call carries a per-attempt timeout instead. Connecting is
        // not proving, though: without a connect timeout an unreachable
        // sidecar burns a full per-attempt budget per attempt just dialing,
        // so the dial is bounded separately. Do not collapse these into one
        // client-wide timeout; that silently caps the respond budget.
        let http = reqwest::Client::builder()
            .connect_timeout(config.sidecar.request_timeout)
            .build()
            .context("failed to build the sidecar http client")?;
        Ok(Self {
            http,
            base_url: config.sidecar_url.trim_end_matches('/').to_string(),
            expected_network_id: config.network_id.clone(),
            request_timeout: config.sidecar.request_timeout,
            respond_timeout: config.sidecar.respond_timeout,
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

    /// Decodes raw `send_mn_transaction` blobs into call structures for the
    /// advisory provenance join.
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

    /// Submits a respond transaction. Budgeted with `respond_timeout`: the
    /// sidecar proves a circuit here and its own `RESPOND_TIMEOUT` is six
    /// minutes, so the client-side timeout must exceed it rather than abort
    /// a proof part way.
    pub async fn respond(&self, request: &RespondRequest) -> anyhow::Result<RespondReceipt> {
        retry_rpc!(self.respond_timeout, self.retry, "sidecar_respond", {
            let resp = self
                .http
                .post(self.endpoint("/respond"))
                .json(request)
                .send()
                .await
                .context("sidecar /respond request failed")?;
            let resp = check_response(resp, "/respond").await?;
            resp.json::<RespondReceipt>()
                .await
                .context("sidecar /respond returned an unparseable body")
        })
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

    /// Startup compatibility gate: the sidecar must decode the ledger
    /// versions this client was written against AND sit on the network this
    /// node is configured for. Both mismatches are silent at decode time,
    /// so both are checked here, once, loudly.
    pub async fn assert_compatible(&self) -> anyhow::Result<()> {
        let health = self.health().await?;
        anyhow::ensure!(
            health.network_id == self.expected_network_id,
            "sidecar networkId mismatch: sidecar is on {:?}, this node is configured for {:?}",
            health.network_id,
            self.expected_network_id
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
}

/// Surfaces a non-2xx sidecar response with its `{code, message, stage,
/// detail}` body verbatim.
///
/// `wallet_busy` is special-cased to a message WITHOUT the HTTP status: the
/// shared `is_retryable` treats most 4xx digits in an error string as
/// terminal, and wallet contention on the single-dust-UTXO wallet is a
/// retry-later by contract, whatever status carries it.
async fn check_response(
    resp: reqwest::Response,
    context: &str,
) -> anyhow::Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if let Ok(body) = serde_json::from_str::<SidecarErrorBody>(&text) {
        if body.code == "wallet_busy" {
            anyhow::bail!(
                "sidecar {context}: wallet_busy: {} (single-dust-UTXO wallet contention, retrying later)",
                body.message
            );
        }
        anyhow::bail!(
            "sidecar {context} failed: {status}: code={} message={} stage={:?} detail={:?}",
            body.code,
            body.message,
            body.stage,
            body.detail
        );
    }
    anyhow::bail!("sidecar {context} failed: {status}: {text}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IndexerConfig, MidnightConfig, RpcConfig, SidecarConfig};
    use mpc_chain_integration_core::utils::retry::RetryConfig;
    use serde_json::json;
    use std::time::Duration;

    /// Config pointed at a mockito server, with a fast retry budget so the
    /// retry tests run in milliseconds.
    fn test_config(sidecar_url: &str) -> MidnightConfig {
        MidnightConfig {
            sidecar_url: sidecar_url.to_string(),
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".to_string(),
            rpc: RpcConfig::default(),
            sidecar: SidecarConfig {
                request_timeout: Duration::from_secs(5),
                respond_timeout: Duration::from_secs(5),
                retry: RetryConfig {
                    min_delay: Duration::from_millis(1),
                    max_delay: Duration::from_millis(2),
                    max_times: 2,
                    jitter: false,
                },
            },
            indexer: IndexerConfig::default(),
        }
    }

    fn healthy_body(network_id: &str, contract_state_tag: &str) -> serde_json::Value {
        json!({
            "status": "ok",
            "networkId": network_id,
            "ledger": {
                "contractState": contract_state_tag,
                "zswapChainState": "midnight:zswap-ledger-state[v5]",
                "ledgerParameters": "midnight:ledger-parameters[v8]",
                "transaction": "midnight:transaction[v12]",
            },
        })
    }

    #[tokio::test]
    async fn decodes_a_contract_state_atom_tree() {
        let mut server = mockito::Server::new_async().await;
        let state_bytes = vec![0x01, 0x02, 0x03];
        // The request-body shape {"state": hex} is this client's documented
        // assumption; matching on it pins the assumption visibly.
        let mock = server
            .mock("POST", "/decode/contract-state")
            .match_body(mockito::Matcher::Json(json!({"state": "010203"})))
            .with_status(200)
            .with_body(
                json!({
                    "entries": [
                        {"key": "07", "value": {"atoms": ["ab", ""]}},
                        {"key": "ff00", "value": null},
                        {"key": "01", "value": {"children": [{"atoms": ["cd"]}]}},
                    ]
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        let node = client
            .decode_contract_state(&state_bytes)
            .await
            .expect("decode");

        let expected = StateNode::Map {
            entries: vec![
                MapEntry {
                    key: "07".to_string(),
                    value: StateNode::Cell {
                        atoms: vec!["ab".to_string(), String::new()],
                    },
                },
                MapEntry {
                    key: "ff00".to_string(),
                    value: StateNode::Null,
                },
                MapEntry {
                    key: "01".to_string(),
                    value: StateNode::Array {
                        children: vec![StateNode::Cell {
                            atoms: vec!["cd".to_string()],
                        }],
                    },
                },
            ],
        };
        assert_eq!(node, expected);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn decodes_transactions_with_the_provenance_join_fields() {
        let mut server = mockito::Server::new_async().await;
        // The request-body shape {"transactions": [hex]} is this client's
        // documented assumption, pinned here like the contract-state one.
        // The response exercises every decode DTO, including a populated
        // claimed array: B4's provenance join reads address,
        // communication_commitment, and claimed[].commitment, so their
        // snake_case wire names must deserialize.
        let mock = server
            .mock("POST", "/decode/transactions")
            .match_body(mockito::Matcher::Json(
                json!({"transactions": ["0102", "aabb"]}),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "transactions": [
                        {
                            "index": 0,
                            "calls": [
                                {
                                    "address": "ab".repeat(32),
                                    "communication_commitment": "cc01",
                                    "claimed": [
                                        {
                                            "position": 2,
                                            "address": "cd".repeat(32),
                                            "entry_point": "signBidirectional",
                                            "commitment": "cc02",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                    "skipped": ["1: unsupported segment"],
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        let decoded = client
            .decode_transactions(&[vec![0x01, 0x02], vec![0xaa, 0xbb]])
            .await
            .expect("decode");

        assert_eq!(decoded.skipped, vec!["1: unsupported segment".to_string()]);
        assert_eq!(decoded.transactions.len(), 1);
        let tx = &decoded.transactions[0];
        assert_eq!(tx.index, 0);
        let call = &tx.calls[0];
        assert_eq!(call.address, "ab".repeat(32));
        assert_eq!(call.communication_commitment, "cc01");
        let claimed = &call.claimed[0];
        assert_eq!(claimed.position, 2);
        assert_eq!(claimed.address, "cd".repeat(32));
        assert_eq!(claimed.entry_point, "signBidirectional");
        assert_eq!(claimed.commitment, "cc02");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn assert_compatible_accepts_a_matching_sidecar() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/health")
            .with_status(200)
            .with_body(healthy_body("undeployed", "midnight:contract-state[v8]").to_string())
            .expect(1)
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        client.assert_compatible().await.expect("compatible");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn assert_compatible_rejects_a_ledger_tag_mismatch() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/health")
            .with_status(200)
            .with_body(healthy_body("undeployed", "midnight:contract-state[v9]").to_string())
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        let err = client
            .assert_compatible()
            .await
            .expect_err("a contractState tag mismatch must fail startup")
            .to_string();
        assert!(err.contains("contractState"), "unexpected error: {err}");
        assert!(err.contains("v9"), "the actual tag must be named: {err}");
    }

    #[tokio::test]
    async fn assert_compatible_rejects_a_network_id_mismatch() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/health")
            .with_status(200)
            .with_body(healthy_body("mainnet-ish", "midnight:contract-state[v8]").to_string())
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        let err = client
            .assert_compatible()
            .await
            .expect_err("a sidecar on another network answers decodes happily and posts responds into the void")
            .to_string();
        assert!(err.contains("networkId"), "unexpected error: {err}");
        assert!(
            err.contains("mainnet-ish") && err.contains("undeployed"),
            "both sides of the mismatch must be named: {err}"
        );
    }

    #[tokio::test]
    async fn retries_a_500_then_succeeds() {
        let mut server = mockito::Server::new_async().await;
        // First attempt fails, second succeeds; expect(1) on each mock is
        // the attempt-count assertion.
        let fail = server
            .mock("GET", "/health")
            .with_status(500)
            .with_body("Internal Server Error")
            .expect(1)
            .create_async()
            .await;
        let ok = server
            .mock("GET", "/health")
            .with_status(200)
            .with_body(healthy_body("undeployed", "midnight:contract-state[v8]").to_string())
            .expect(1)
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        let health = client.health().await.expect("retry must recover");
        assert_eq!(health.network_id, "undeployed");
        fail.assert_async().await;
        ok.assert_async().await;
    }

    #[tokio::test]
    async fn wallet_busy_is_classified_retryable() {
        let mut server = mockito::Server::new_async().await;
        // Worst case on purpose: wallet_busy under HTTP 400. The shared
        // is_retryable treats a 400 in the message as terminal, so this only
        // retries if the client's wallet_busy classification wins. With
        // max_times = 2 the route must be hit exactly 3 times.
        let mock = server
            .mock("POST", "/respond")
            .with_status(400)
            .with_body(
                json!({
                    "code": "wallet_busy",
                    "message": "single-dust-UTXO wallet has a pending spend",
                    "stage": "submit",
                    "detail": null,
                })
                .to_string(),
            )
            .expect(3)
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        let err = client
            .respond(&sample_respond_bidirectional())
            .await
            .expect_err("exhausting the retry budget still errors")
            .to_string();
        assert!(err.contains("wallet_busy"), "unexpected error: {err}");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn bad_request_is_not_retried_and_surfaces_the_body() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/respond")
            .with_status(400)
            .with_body(
                json!({
                    "code": "bad_request",
                    "message": "serialized_output must be 128 bytes of hex",
                    "stage": "validate",
                    "detail": {"path": ["serialized_output"]},
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        let err = client
            .respond(&sample_respond_bidirectional())
            .await
            .expect_err("a validation reject is terminal")
            .to_string();
        assert!(
            err.contains("bad_request") && err.contains("serialized_output"),
            "the sidecar body must be surfaced verbatim: {err}"
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn respond_serializes_the_circuit_discriminator_and_snake_fields() {
        let mut server = mockito::Server::new_async().await;
        let request = sample_respond_bidirectional();
        let expected_body = json!({
            "circuit": "respondBidirectional",
            "contract_address": "ab".repeat(32),
            "request_id": "22".repeat(32),
            "signature": {
                "big_r": {"x": "11".repeat(32), "y": "12".repeat(32)},
                "s": "13".repeat(32),
                "recovery_id": 1,
            },
            "serialized_output": "00".repeat(128),
            "output_len": 32,
        });
        let mock = server
            .mock("POST", "/respond")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(200)
            .with_body(
                json!({"status": "submitted", "tx_id": "cd".repeat(32), "block_hash": "ef".repeat(32)})
                    .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        let receipt = client.respond(&request).await.expect("respond");
        assert_eq!(receipt.tx_id, "cd".repeat(32));
        mock.assert_async().await;
    }

    fn sample_respond_bidirectional() -> RespondRequest {
        RespondRequest::RespondBidirectional {
            contract_address: "ab".repeat(32),
            request_id: "22".repeat(32),
            signature: WireSignature {
                big_r: WirePoint {
                    x: "11".repeat(32),
                    y: "12".repeat(32),
                },
                s: "13".repeat(32),
                recovery_id: 1,
            },
            serialized_output: "00".repeat(128),
            output_len: 32,
        }
    }
}
