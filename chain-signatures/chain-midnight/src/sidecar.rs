//! HTTP client for the `midnight-publisher-ts` sidecar, the pure codec seam.
//!
//! The sidecar decodes bytes; every trust decision stays on this side. A
//! sidecar decode bug must be able to cause a dropped request, never a wrong
//! signature: nothing returned by these routes is signed over without the
//! Rust-side recompute-and-drop downstream.
//!
//! Wire-shape assumptions this client pins: the `/decode/*` request bodies
//! (`{"state": hex}` and `{"transactions": [hex]}`), the `kind`-tagged JSON
//! form of `StateNode`, and camelCase keys on `/health` only. They are pinned
//! against the RUNNING sidecar in `tests/sidecar_live.rs`, which boots the
//! in-tree `midnight-publisher-ts` and drives these routes over HTTP. Any
//! divergence fails loudly in deserialization or in the sidecar's zod
//! validation, never silently.

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

/// Decoded contract state (`src/state.ts`), INTERNALLY TAGGED on `kind`
/// exactly as the sidecar emits it (`{"kind":"cell","atoms":[..]}`,
/// `{"kind":"null"}`).
///
/// Tagged rather than untagged, and the difference is not stylistic. An
/// untagged enum matched cell/array/map only by accident, because serde
/// ignores the unknown `kind` field, while `{"kind":"null"}` matched NO
/// variant at all: a unit variant deserializes from bare JSON `null`, not
/// from an object. Since the chunk tree is full of unset slots, that made
/// every real response unparseable. Reading the discriminant the sender
/// already provides also turns a future shape change into an error naming
/// the variant instead of "data did not match any variant".
///
/// Map keys are the entry's atoms as an ARRAY of per-atom hex, boundaries
/// preserved: D9's chosen resolution (option 1, atom-preserving keys), which
/// exists precisely so a composite `SignetMapKey`'s variable trim point
/// never needs guessing.
///
/// Three tests hold this, and none holds all of it:
/// `state_node_parses_the_sidecars_own_golden` pins the tagged envelope and
/// the atom-array keys against the sidecar's own committed golden output and
/// needs no service to do it; `tests/sidecar_live.rs` reads both back off the
/// RUNNING sidecar, `{"kind":"null"}` included, since the caller's captured
/// state carries null nodes; and the `Null` variant is pinned offline by
/// `reader::tests::golden_records_decode_from_captured_state`, because no
/// committed publisher golden contains a null node.
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

/// Decoded transactions (`src/block.ts`). A `DecodedCall` has NO entry
/// point: only the CLAIMED calls (caller side) carry one, the callee's own
/// entry carries a commitment. The provenance join matches
/// `claimed[i].commitment` on one call against `communication_commitment`
/// on another call in the SAME transaction.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DecodedTransactions {
    pub transactions: Vec<DecodedTransaction>,
    /// Per-item reasons the sidecar could not decode a submitted blob. Logged
    /// by `LiveSource::decoded_transactions`, never fatal: provenance is
    /// advisory, so a blob the sidecar cannot read must not stop signing.
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
        // No global reqwest timeout: every call carries its own per-attempt
        // timeout instead. Connecting is bounded separately, because without a
        // connect timeout an unreachable sidecar burns a full per-attempt
        // budget per attempt just dialing.
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

    /// Startup compatibility gate: the sidecar must decode the ledger
    /// versions this client was written against AND sit on the network this
    /// node is configured for. Both mismatches are silent at decode time,
    /// so both are checked here, once, loudly.
    pub async fn assert_compatible(&self) -> anyhow::Result<()> {
        let health = self.health().await?;
        anyhow::ensure!(
            health.status == "ok",
            "sidecar reports status {:?}, not \"ok\": refusing to start against a sidecar \
             that says it is not serviceable",
            health.status
        );
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

/// Four tests, and the reason each one is not in `tests/sidecar_live.rs`.
///
/// The decode and health CONTRACTS are covered there, against the running
/// service: it boots `midnight-publisher-ts` and drives these routes over
/// HTTP, so the request keys are read by the SERVER, the trees are its own
/// decoder's output over real captured chain blobs, and `bad_request`,
/// `decode_failed` and `ledger_mismatch` are its own answers rather than
/// bodies this crate wrote. Five mocks that pinned those were deleted, each
/// only after the live test was shown to kill every mutation the mock killed.
///
/// What is left is what a live suite cannot reach.
/// `state_node_parses_the_sidecars_own_golden` needs no service at all and so
/// is the cross-language check that survives in `unit.yml`, where the
/// sidecar's dependencies are not installed. The other three ask for answers
/// a healthy service does not give: a 500, a ledger tag other than its own,
/// and a status that is not `"ok"`.
/// Simulating a fault is honest; simulating a decode answer is not, and that
/// is the line this module now draws.
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

    /// The sidecar's OWN golden output, parsed by this client's types.
    ///
    /// Every other test here answers a mock whose body this crate wrote, so it
    /// can only prove the client agrees with itself. This one reads the file
    /// `midnight-publisher-ts` commits as the frozen output of its real decoder
    /// over a real captured chain blob, which makes it the only cross-language
    /// check in the crate. Three live mismatches got in behind mocks that
    /// agreed with themselves: a `{"state":..}` body the server read as
    /// `bytes`, and `kind`-tagged nodes this enum tried to read untagged.
    ///
    /// It needs no running sidecar, so it is an ordinary unit test rather than
    /// an ignored integration one.
    ///
    /// What it does NOT cover, measured rather than assumed: this capture holds
    /// only `array`, `map` and `cell` nodes, so reverting the enum to
    /// `untagged` leaves this test PASSING (untagged simply ignores the unknown
    /// `kind`). The `Null` variant is the one that made every real response
    /// unparseable, and `reader::tests::golden_records_decode_from_captured_state`
    /// is what catches that, on captured state that does contain nulls. The
    /// small literal below covers it here too, transcribed from `state.ts`'s
    /// own type rather than captured, since no committed golden supplies one.
    #[test]
    fn state_node_parses_the_sidecars_own_golden() {
        // `{ readonly kind: "null" }` per the sidecar's `StateNode` union. A
        // unit variant would need bare JSON `null`, which is the mismatch that
        // broke every response containing an unset ledger slot.
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

        // Field 0 is `signBidirectionalEventNotificationCounterMap`, keyed by a
        // single `RequestId` atom. Field 1 is
        // `signBidirectionalEventNotificationMap`, keyed by the composite
        // `SignetMapKey { count, requestId }` whose `count` of 0 trims to the
        // EMPTY atom.
        //
        // This capture is why D9's joined key was unusable rather than merely
        // inconvenient: both of these keys concatenate to the same 64-character
        // hex run, so before the atoms were kept apart a consumer could not
        // tell a one-atom key from a two-atom key whose first atom vanished.
        // Recovering a request id from field 1, which the indexer's diff must
        // do, was impossible. Real captured chain data, not a constructed case.
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
    async fn assert_compatible_rejects_a_sidecar_that_says_it_is_not_serviceable() {
        // The same family as the tag mismatch: a fault a healthy service will
        // not produce on demand, so the live suite reaches the gate only from
        // the passing side. Without this, DELETING the status check breaks no
        // test at all.
        let mut server = mockito::Server::new_async().await;
        let mut body = healthy_body("undeployed", "midnight:contract-state[v8]");
        body["status"] = json!("degraded");
        let _mock = server
            .mock("GET", "/health")
            .with_status(200)
            .with_body(body.to_string())
            .create_async()
            .await;

        let client = SidecarClient::new(&test_config(&server.url())).expect("client");
        let err = client
            .assert_compatible()
            .await
            .expect_err("a sidecar that says it is not serviceable must fail startup")
            .to_string();
        assert!(
            err.contains("degraded"),
            "the reported status must be named: {err}"
        );
    }

    /// The one mock kept for what it simulates rather than for what it
    /// answers, and the only test of recovery: a failed attempt followed by a
    /// successful one.
    ///
    /// A healthy sidecar cannot be asked to produce this. `internal` has two
    /// producers over there, a client that hangs up mid-body (where no reply
    /// can be delivered) and `/respond`'s six-minute deadline, so 500 is a
    /// status the live suite cannot reach at all. Classifying it terminal is
    /// survived by every live test and fails only this one. The live suite does
    /// cover the loop half on real answers: a real 422 spends the whole budget
    /// against the real service.
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
}
