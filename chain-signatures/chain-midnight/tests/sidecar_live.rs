//! The sidecar client against the running sidecar, over real HTTP.

use std::io::{BufRead as _, BufReader};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mpc_chain_integration_core::utils::retry::RetryConfig;
use mpc_chain_midnight::{
    DecodedTransactions, IndexerConfig, MidnightConfig, RpcConfig, SidecarClient, SidecarConfig,
    StateNode,
};

/// The sidecar package, and the chain-free entry point inside it.
const PUBLISHER_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../midnight-publisher-ts");
const ENTRY: &str = "tests/serve-decode-only.ts";

/// Long enough for a cold `tsx` to load the ledger WASM (~3 s observed).
const BOOT_TIMEOUT: Duration = Duration::from_secs(60);

/// Real captured chain blobs and the sidecar's own frozen output for them.
const STATE_1366: &[u8] =
    include_bytes!("../../midnight-publisher-ts/tests/fixtures/singleton-post-state-1366.mn");
const STATE_1365: &[u8] =
    include_bytes!("../../midnight-publisher-ts/tests/fixtures/singleton-pre-state-1365.mn");
const CALLER_STATE_1366: &[u8] =
    include_bytes!("../../midnight-publisher-ts/tests/fixtures/caller-state-1366.mn");
const GOLDEN_STATE_1366: &str =
    include_str!("../../midnight-publisher-ts/tests/fixtures/golden-state-singleton-1366.json");
const GOLDEN_STATE_1365: &str =
    include_str!("../../midnight-publisher-ts/tests/fixtures/golden-state-singleton-1365.json");
/// `{"tx":{"Midnight":"<hex>"}}`, the `send_mn_transaction` wrapper as captured.
const NOTIFY_TX: &str = include_str!("../../midnight-publisher-ts/tests/fixtures/notify-tx.mn");
const GOLDEN_BLOCK_1366: &str =
    include_str!("../../midnight-publisher-ts/tests/fixtures/golden-block-1366.json");

/// The ledger tag `sidecar.rs` pins `EXPECTED_CONTRACT_STATE_TAG` against, as it
/// appears in the captured bytes themselves.
const CONTRACT_STATE_TAG: &[u8] = b"midnight:contract-state[v8]";

struct Sidecar {
    child: Child,
    base_url: String,
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        // `node --import tsx` runs the script in THIS process rather than re-spawning,
        // so killing the child is what frees the port.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Sidecar {
    /// Boots the real service on a free loopback port and waits for it to listen.
    async fn boot() -> Self {
        let dir = Path::new(PUBLISHER_DIR);
        assert!(
            dir.join("node_modules/tsx").is_dir(),
            "the sidecar's dependencies are not installed, so these tests cannot boot it:\n    \
             (cd chain-signatures/midnight-publisher-ts && npm ci)\n\
             looked for {}",
            dir.join("node_modules/tsx").display()
        );

        let port = TcpListener::bind("127.0.0.1:0")
            .expect("a free loopback port")
            .local_addr()
            .expect("the bound address")
            .port();
        let mut child = Command::new("node")
            .current_dir(dir)
            .args(["--import", "tsx", ENTRY])
            // `configFromEnv` takes the full set or throws.
            .env("MIDNIGHT_PUB_PORT", port.to_string())
            .env("MIDNIGHT_PUB_BIND_HOST", "127.0.0.1")
            .env("MIDNIGHT_PUB_NETWORK_ID", "undeployed")
            .env("MIDNIGHT_PUB_NODE_URL", "ws://127.0.0.1:1")
            .env("MIDNIGHT_PUB_PROOF_SERVER_URL", "http://127.0.0.1:1")
            .env("MIDNIGHT_PUB_INDEXER_URL", "http://127.0.0.1:1")
            .env("MIDNIGHT_PUB_INDEXER_WS_URL", "ws://127.0.0.1:1")
            .env("MIDNIGHT_PUB_MANAGED_DIR", dir.join("tests/fixtures"))
            .env("MIDNIGHT_PUB_FUNDING_SEED", "00".repeat(32))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| {
                panic!("could not spawn `node` for the sidecar ({err}); these tests need node >= 22 on PATH")
            });

        // Drained on a thread, so the pipe cannot fill and stall the service, and so a
        // boot failure can say what the service printed.
        let log = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&log);
        let stderr = child.stderr.take().expect("stderr is piped");
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut printed = sink.lock().expect("sidecar log");
                printed.push_str(&line);
                printed.push('\n');
            }
        });

        let sidecar = Self {
            child,
            base_url: format!("http://127.0.0.1:{port}"),
        };
        // Readiness is checked with a plain request rather than through
        // `SidecarClient`, so a broken client fails its own test instead of arriving as
        // a boot timeout.
        let http = reqwest::Client::new();
        let deadline = Instant::now() + BOOT_TIMEOUT;
        loop {
            if http
                .get(format!("{}/health", sidecar.base_url))
                .send()
                .await
                .is_ok()
            {
                return sidecar;
            }
            let printed = || log.lock().expect("sidecar log").clone();
            assert!(
                Instant::now() < deadline,
                "the sidecar did not listen on {} within {BOOT_TIMEOUT:?}. Its stderr:\n{}",
                sidecar.base_url,
                printed()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn client(&self, network_id: &str) -> SidecarClient {
        SidecarClient::new(&MidnightConfig {
            sidecar_url: self.base_url.clone(),
            node_ws_url: "ws://127.0.0.1:1".to_string(),
            central_address: "ab".repeat(32),
            network_id: network_id.to_string(),
            rpc: RpcConfig::default(),
            sidecar: SidecarConfig {
                request_timeout: Duration::from_secs(30),
                retry: RetryConfig {
                    min_delay: Duration::from_millis(1),
                    max_delay: Duration::from_millis(2),
                    max_times: 2,
                    jitter: false,
                },
            },
            indexer: IndexerConfig::default(),
        })
        .expect("the live config is valid")
    }
}

/// Every `Null` in a decoded tree.
fn count_nulls(node: &StateNode) -> usize {
    match node {
        StateNode::Null => 1,
        StateNode::Cell { .. } => 0,
        StateNode::Array { children } => children.iter().map(count_nulls).sum(),
        StateNode::Map { entries } => entries.iter().map(|entry| count_nulls(&entry.value)).sum(),
    }
}

#[tokio::test]
#[ignore = "boots the midnight-publisher-ts sidecar; run with --ignored"]
async fn health_satisfies_startup_compatibility_gate() {
    // The whole of `assert_compatible`, against the tags the sidecar really declares.
    let sidecar = Sidecar::boot().await;
    let client = sidecar.client("undeployed");

    let health = client.health().await.expect("the real /health answers");
    assert_eq!(health.network_id, "undeployed");
    // The camelCase spellings are the route's own, and this route's alone: a rename on
    // either side lands in this deserialization.
    assert_eq!(health.ledger.contract_state, "midnight:contract-state[v8]");
    assert_eq!(
        health.ledger.zswap_chain_state,
        "midnight:zswap-ledger-state[v5]"
    );
    assert_eq!(
        health.ledger.ledger_parameters,
        "midnight:ledger-parameters[v8]"
    );
    assert_eq!(health.ledger.transaction, "midnight:transaction[v12]");

    client
        .assert_compatible()
        .await
        .expect("this client and this sidecar decode the same ledger line");

    // The same live sidecar, refused by a node configured for another network: it would
    // answer every decode happily and post every respond into the void.
    let err = sidecar
        .client("testnet")
        .assert_compatible()
        .await
        .expect_err("a network mismatch must fail startup")
        .to_string();
    assert!(err.contains("networkId"), "unexpected error: {err}");
    assert!(
        err.contains("undeployed") && err.contains("testnet"),
        "both sides of the mismatch must be named: {err}"
    );
}

#[tokio::test]
#[ignore = "boots the midnight-publisher-ts sidecar; run with --ignored"]
async fn decode_contract_state_matches_sidecar_goldens() {
    // Real chain blobs in, the sidecar's frozen output for those same blobs out, over
    // HTTP.
    let sidecar = Sidecar::boot().await;
    let client = sidecar.client("undeployed");

    for (name, bytes, golden) in [
        ("singleton-post-state-1366", STATE_1366, GOLDEN_STATE_1366),
        ("singleton-pre-state-1365", STATE_1365, GOLDEN_STATE_1365),
    ] {
        let live = client
            .decode_contract_state(bytes)
            .await
            .unwrap_or_else(|err| panic!("{name}: the live sidecar must decode it: {err:#}"));
        let frozen: StateNode = serde_json::from_str(golden)
            .unwrap_or_else(|err| panic!("{name}: its committed golden must parse: {err}"));
        assert_eq!(
            live, frozen,
            "{name}: the live decode diverges from the sidecar's own committed golden"
        );
    }

    // The caller's capture has no golden, and is here for the node vocabulary no golden
    // carries: `{"kind":"null"}`, the unset ledger slot.
    let caller = client
        .decode_contract_state(CALLER_STATE_1366)
        .await
        .expect("the caller's captured state decodes");
    assert!(
        count_nulls(&caller) > 0,
        "the caller capture must carry null nodes, or this proves nothing: {caller:?}"
    );
}

#[tokio::test]
#[ignore = "boots the midnight-publisher-ts sidecar; run with --ignored"]
async fn decode_transactions_yields_provenance_join() {
    let sidecar = Sidecar::boot().await;
    let client = sidecar.client("undeployed");

    let wrapper: serde_json::Value = serde_json::from_str(NOTIFY_TX)
        .expect("the capture is the toolkit's `SerializedTx` wrapper");
    let blob = hex::decode(
        wrapper["tx"]["Midnight"]
            .as_str()
            .expect("`tx.Midnight` is the transaction hex"),
    )
    .expect("valid hex");

    let live = client
        .decode_transactions(std::slice::from_ref(&blob))
        .await
        .expect("the live sidecar must decode the captured notify");
    let frozen: DecodedTransactions =
        serde_json::from_str(GOLDEN_BLOCK_1366).expect("the committed golden must parse");
    assert_eq!(
        live, frozen,
        "the live decode diverges from the sidecar's own committed golden"
    );

    // The provenance join, over a real cross-contract call rather than over a body this
    // crate wrote: one call claims another call in the SAME transaction, and the claim
    // names that call's communication commitment.
    let calls = &live.transactions[0].calls;
    let caller = calls
        .iter()
        .find(|call| !call.claimed.is_empty())
        .expect("the captured transaction has a claiming call");
    let claim = &caller.claimed[0];
    let callee = calls
        .iter()
        .find(|call| call.address == claim.address)
        .expect("the claimed call is in this transaction");
    assert_eq!(
        claim.commitment, callee.communication_commitment,
        "the claim must point at the callee's communication commitment"
    );
    assert_ne!(
        caller.communication_commitment, callee.communication_commitment,
        "a claiming call's own commitment is distinct from the one it claims"
    );
    assert!(live.skipped.is_empty(), "nothing was skipped: {live:?}");

    // One bad blob costs that blob and nothing else, and never renumbers what follows
    // it: `index` is the position in the REQUEST array, which is how a caller maps a
    // result back to the bytes it sent.
    let mixed = client
        .decode_transactions(&[vec![0xde, 0xad, 0xbe, 0xef], blob])
        .await
        .expect("a poisoned blob must cost its own entry, not the batch");
    assert_eq!(
        mixed
            .transactions
            .iter()
            .map(|tx| tx.index)
            .collect::<Vec<_>>(),
        vec![1],
        "the surviving transaction keeps its index in the request array"
    );
    assert_eq!(
        mixed.skipped.len(),
        1,
        "the dropped blob must be reported: {mixed:?}"
    );
    assert!(
        mixed.skipped[0].starts_with("tx[0]:"),
        "the report names which blob was dropped: {:?}",
        mixed.skipped[0]
    );
}

#[tokio::test]
#[ignore = "boots the midnight-publisher-ts sidecar; run with --ignored"]
async fn malformed_body_is_bad_request_and_not_retried() {
    // The real `bad_request`, provoked rather than canned.
    let sidecar = Sidecar::boot().await;
    let client = sidecar.client("undeployed");

    let err = client
        .decode_contract_state(&[])
        .await
        .expect_err("empty bytes are not a contract state")
        .to_string();
    assert!(err.contains("bad_request"), "unexpected error: {err}");
    assert!(
        err.contains("`state`"),
        "the sidecar names the key the client sent, so the message proves the request shape: {err}"
    );
    // A 4xx is terminal: `check_response` surfaces the status, `is_retryable` reads it,
    // and the budget is never spent.
    assert!(
        err.contains("exhausted after 1 attempts"),
        "a validation reject must not be retried: {err}"
    );

    // The other route's envelope, whose key and array shape are equally the server's to
    // read: it answers by index.
    let err = client
        .decode_transactions(&[Vec::new()])
        .await
        .expect_err("an empty transaction blob is not hex")
        .to_string();
    assert!(
        err.contains("bad_request") && err.contains("transactions[0]"),
        "the sidecar must name the offending element: {err}"
    );
}

#[tokio::test]
#[ignore = "boots the midnight-publisher-ts sidecar; run with --ignored"]
async fn unreadable_bytes_are_decode_failed_and_retried() {
    // The 400/422 split, live: the envelope is fine and the LEDGER refuses the bytes.
    let sidecar = Sidecar::boot().await;
    let client = sidecar.client("undeployed");

    let err = client
        .decode_contract_state(&[0xde, 0xad, 0xbe, 0xef])
        .await
        .expect_err("the ledger refuses these bytes")
        .to_string();
    assert!(err.contains("decode_failed"), "unexpected error: {err}");
    assert!(
        err.contains("ContractState"),
        "the sidecar's own diagnosis is surfaced verbatim: {err}"
    );
    // 422 is not one of the terminal 4xx codes, so the budget IS spent here: the same
    // request really goes out three times.
    assert!(
        err.contains("exhausted after 3 attempts"),
        "a retryable status must spend the whole budget: {err}"
    );
}

#[tokio::test]
#[ignore = "boots the midnight-publisher-ts sidecar; run with --ignored"]
async fn newer_ledger_is_named_ledger_mismatch() {
    // The diagnosis `assert_compatible` exists to preempt, taken from the other end: a
    // real captured state whose version tag has been advanced by one byte.
    let sidecar = Sidecar::boot().await;
    let client = sidecar.client("undeployed");

    let mut skewed = STATE_1366.to_vec();
    let tag = skewed
        .windows(CONTRACT_STATE_TAG.len())
        .position(|window| window == CONTRACT_STATE_TAG)
        .expect("the captured state carries the tag this client is written against");
    // `midnight:contract-state[v8]` -> `[v9]`, leaving an otherwise real blob.
    skewed[tag + CONTRACT_STATE_TAG.len() - 2] = b'9';

    let err = client
        .decode_contract_state(&skewed)
        .await
        .expect_err("this build cannot read a v9 contract state")
        .to_string();
    assert!(err.contains("ledger_mismatch"), "unexpected error: {err}");
    assert!(
        err.contains("502"),
        "a chain that moved ahead is the sidecar's fault to report, not the caller's: {err}"
    );
}
