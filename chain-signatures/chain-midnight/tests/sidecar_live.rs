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
};

/// The sidecar package, and the chain-free entry point inside it.
const PUBLISHER_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../midnight-publisher-ts");
const ENTRY: &str = "tests/serve-decode-only.ts";

/// Long enough for a cold `tsx` to load the ledger WASM (~3 s observed).
const BOOT_TIMEOUT: Duration = Duration::from_secs(60);

/// Real captured chain blobs and the sidecar's own frozen output for them.
/// `{"tx":{"Midnight":"<hex>"}}`, the `send_mn_transaction` wrapper as captured.
const NOTIFY_TX: &str = include_str!("../../midnight-publisher-ts/tests/fixtures/notify-tx.mn");
const GOLDEN_BLOCK_1366: &str =
    include_str!("../../midnight-publisher-ts/tests/fixtures/golden-block-1366.json");

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
