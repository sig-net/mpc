//! HTTP client for the `midnight-publisher-ts` sidecar, the pure codec seam.
//!
//! The sidecar decodes bytes; every trust decision stays on this side. A decode
//! bug there must be able to drop a request, never to produce a wrong
//! signature, which is what the Rust-side recompute-and-drop downstream buys.
//!
//! Wire shapes pinned here: the `/decode/*` request bodies, the `kind`-tagged
//! JSON form of [`StateNode`], and camelCase keys on `/health` only.
//! `tests/sidecar_live.rs` checks them against the running service.

use std::time::Duration;

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig};
use serde::Deserialize;

use crate::config::MidnightConfig;

/// Ledger serialization tags this client was written against
/// (`midnight-publisher-ts/src/ledger.ts`). A sidecar reporting different
/// tags decodes a different wire format; refuse it at startup.
const EXPECTED_CONTRACT_STATE_TAG: &str = "midnight:contract-state[v8]";
const EXPECTED_ZSWAP_TAG: &str = "midnight:zswap-ledger-state[v5]";
const EXPECTED_LEDGER_PARAMETERS_TAG: &str = "midnight:ledger-parameters[v8]";
const EXPECTED_TRANSACTION_TAG: &str = "midnight:transaction[v12]";

/// Decoded contract state, internally tagged on `kind` exactly as the sidecar
/// emits it (`{"kind":"cell","atoms":[..]}`, `{"kind":"null"}`).
///
/// Tagged rather than untagged, and not for style: an untagged enum matched
/// cell/array/map only by accident, since serde ignores the unknown `kind`
/// field, while `{"kind":"null"}` matched nothing at all, because a unit
/// variant deserializes from bare JSON `null` rather than an object. The chunk
/// tree is full of unset slots, so that made every real response unparseable.
///
/// Map keys are per-atom hex in an array with boundaries preserved, so a
/// composite `SignetMapKey`'s variable trim point never needs guessing.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
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
    /// Per-atom hex of the entry's key, trailing-zero-trimmed like all wire
    /// atoms, boundaries preserved (one element per atom).
    pub key: Vec<String>,
    pub value: StateNode,
}

/// Decoded transactions. A `DecodedCall` has no entry point: only the claimed
/// calls on the caller side carry one, the callee's own entry carries a
/// commitment. The provenance join matches `claimed[i].commitment` on one call
/// against `communication_commitment` on another in the same transaction.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DecodedTransactions {
    pub transactions: Vec<DecodedTransaction>,
    /// Why the sidecar could not decode a submitted blob. Logged, never fatal:
    /// provenance is advisory, so an unreadable blob must not stop signing.
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DecodedTransaction {
    /// Index of this transaction within the submitted batch, so a `skipped`
    /// entry can be matched back to its input.
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
    /// Little-endian Fr bytes, tag stripped.
    pub commitment: String,
}

/// `GET /health` body. This route alone uses camelCase keys.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Health {
    /// `"ok"` when the sidecar considers itself serviceable. Checked by
    /// [`SidecarClient::assert_compatible`].
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
    retry: RetryConfig,
}

impl SidecarClient {
    pub fn new(config: &MidnightConfig) -> anyhow::Result<Self> {
        // No global timeout: each call carries its own per-attempt one.
        // Connecting is bounded separately, or an unreachable sidecar burns a
        // full per-attempt budget just dialing.
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

    /// Startup gate: the sidecar must decode the ledger versions this client
    /// was written against and sit on the network this node is configured for.
    /// Both mismatches are silent at decode time, so both are checked here.
    pub async fn assert_compatible(&self) -> anyhow::Result<()> {
        check_health(&self.health().await?, &self.expected_network_id)
    }
}

/// The pure half of the startup gate, split out so the rejection paths are
/// testable without a service: a healthy sidecar only ever exercises the
/// passing side.
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

/// Surfaces a non-2xx sidecar response with its `{code, message, stage,
/// detail}` body verbatim.
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

/// The offline cross-language check plus the startup gate's rejection paths.
/// Everything the sidecar actually answers is covered against the running
/// service in `tests/sidecar_live.rs`.
#[cfg(test)]
mod tests {
    use super::*;

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

    /// Parses the golden output `midnight-publisher-ts` commits from its real
    /// decoder over a captured chain blob, so neither side of the contract is
    /// authored by the side it is checked against. Needs no running service,
    /// which is what keeps it in `unit.yml`.
    ///
    /// The capture holds only `array`, `map` and `cell` nodes, so it does not
    /// by itself catch a revert to `untagged`; the literal below covers the
    /// `Null` variant that made every real response unparseable.
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
        // `SignetMapKey { count, requestId }` whose `count` of 0 trims to the
        // empty atom. Both concatenate to the same 64-character hex run, which
        // is why keys must stay per-atom: joined, a consumer cannot tell a
        // one-atom key from a two-atom key whose first atom vanished, and the
        // indexer's diff could not recover a request id from field 1. Real
        // captured chain data, not a constructed case.
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
