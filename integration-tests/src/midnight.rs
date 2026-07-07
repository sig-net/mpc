//! Midnight sandbox: spawns the ledger-9 stack as testcontainers, deploys the
//! signet-signer via the pinned midnight-node-toolkit, and runs the isolated
//! midnight-publisher service — all driven from Rust (no shell harness).
//!
//! Prereqs: docker with the pinned images (node 2.0.0-rc.3, indexer c7c267cc
//! built via integration-tests/fixtures/midnight/stack/build-indexer-image.sh,
//! toolkit-033 via .../stack/toolkit-033/build-toolkit-image.sh), prover keys
//! under fixtures/midnight/signet-signer/keys (compiled in midnight-erc20-vault
//! — the small artifacts are committed, the ~1 GB provers are regenerable and
//! gitignored, Canton-DAR style), and release builds of the isolated workspace
//! binaries (cargo build --locked --release -p midnight-node-toolkit
//! -p midnight-publisher in chain-signatures/midnight-publisher/).

use crate::containers::{DockerClient, MidnightStack};
use anyhow::{Context as _, Result};
use async_process::{Child, Command};
use mpc_chain_midnight::{MidnightConfig, MidnightGraphql};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const GOLDEN_CALLER_SECRET_KEY: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
pub const GOLDEN_COMMITMENT_HEX: &str =
    "e093949750afc5ff6d25764fe81ea991c7cd7659d1aa802eaa651a48aa436859";
pub const GOLDEN_SIGN_PAYLOAD_0: &str =
    "8b275b04a2c8dcf5bbcaa31205a052c4b34ea2fb0a161485b682a768170666a5";
pub const GOLDEN_SIGN_PAYLOAD_1: &str =
    "c855c55c51ea7140701c32fed8e666d7e887f2c08c1dfd2a272aa27039c2f776";
pub const GOLDEN_SIGN_REQUEST_ID_0: &str =
    "cca92908be86c5c618109f3811ee550cdf026a2387fa49b9d4db6fe73c507874";

const TOOLKIT_IMAGE: &str = "signet/midnight-node-toolkit:2.0.0-rc.3-compact033";
const COMPACTC_VERSION: &str = "0.33.0";
const DEV_FUNDING_SEED: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const DEV_COIN_PUBLIC: &str = "aa0d72bb77ea46f986a800c66d75c4e428a95bd7e1244f1ed059374e6266eb98";
const CIRCUITS: [&str; 4] = [
    "sign",
    "sign_bidirectional",
    "respond",
    "respond_bidirectional",
];

/// toolkit-js CLI codec helper: ASCII → zero-padded Bytes<N> hex.
pub fn pad_ascii_hex(s: &str, n: usize) -> String {
    assert!(s.len() <= n, "{s:?} exceeds {n} bytes");
    let mut bytes = s.as_bytes().to_vec();
    bytes.resize(n, 0);
    hex::encode(bytes)
}

#[derive(Clone, Debug)]
pub struct MidnightBiParams {
    pub evm_to: String, // 40-char hex, no 0x
    pub evm_chain_id: u64,
    pub evm_nonce: u64,
    pub evm_gas_limit: u64,
    pub evm_max_fee: u128,
    pub evm_priority_fee: u128,
    pub evm_value: u128,
    pub func_sig: String,
    pub args: Vec<String>, // 64-char hex words
    pub arg_count: u8,
    pub caip2: String,
    pub key_version: u32,
    pub dest: String,
    pub params: String,
    pub output_schema: String,
    pub respond_schema: String,
}

impl MidnightBiParams {
    fn to_call_args(&self) -> Vec<String> {
        let mut words = self.args.clone();
        words.resize(4, "00".repeat(32));
        vec![
            self.evm_to.clone(),
            self.evm_chain_id.to_string(),
            self.evm_nonce.to_string(),
            self.evm_gas_limit.to_string(),
            self.evm_max_fee.to_string(),
            self.evm_priority_fee.to_string(),
            self.evm_value.to_string(),
            pad_ascii_hex(&self.func_sig, 64),
            serde_json::to_string(&words).expect("args json"),
            self.arg_count.to_string(),
            pad_ascii_hex(&self.caip2, 32),
            self.key_version.to_string(),
            pad_ascii_hex(&self.dest, 32),
            pad_ascii_hex(&self.params, 64),
            pad_ascii_hex(&self.output_schema, 128),
            pad_ascii_hex(&self.respond_schema, 128),
        ]
    }
}

fn repo_root() -> PathBuf {
    // integration-tests/ → repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn env_path(key: &str, default: PathBuf) -> PathBuf {
    std::env::var(key).map(PathBuf::from).unwrap_or(default)
}

async fn run_ok(cmd: &mut Command, what: &str) -> Result<Vec<u8>> {
    let out = cmd
        .output()
        .await
        .with_context(|| format!("spawning {what}"))?;
    anyhow::ensure!(
        out.status.success(),
        "{what} failed: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(out.stdout)
}

/// Rust driver for the pinned midnight-node-toolkit: intent generation runs in
/// the toolkit-033 docker image (it needs node/toolkit-js), build/prove/submit
/// run through the native binary built from the isolated publisher workspace —
/// the exact command sequence Phase 3 validated.
struct MidnightToolkit {
    bin: PathBuf,
    contract_dir: PathBuf,
    network: String,
    node_ws_native: String,
    node_ws_docker: String,
}

impl MidnightToolkit {
    fn run_dir(&self) -> PathBuf {
        self.contract_dir.join(".run")
    }

    /// Native toolkit invocation with the warm fetch/ledger caches.
    fn native(&self) -> Command {
        let cache = self.contract_dir.join(".cache-native");
        let mut cmd = Command::new(&self.bin);
        cmd.env("MIDNIGHT_PP", cache.join("zk-params"))
            .env(
                "MN_FETCH_CACHE",
                format!("redb:{}", cache.join("toolkit_fetch_cache.db").display()),
            )
            .env("MN_LEDGER_CACHE_DB", cache.join("toolkit_ledger_cache_db"));
        cmd
    }

    /// toolkit-033 docker invocation (generate-intent needs toolkit-js). The
    /// contract dir is mounted at /work, matching signer.config.ts paths.
    fn docker(&self) -> Command {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "--network", &self.network])
            .args(["-e", &format!("COMPACTC_VERSION={COMPACTC_VERSION}")])
            .args([
                "-e",
                &format!("SIGNER_SECRET_KEY={GOLDEN_CALLER_SECRET_KEY}"),
            ])
            .args(["-v", &format!("{}:/work", self.contract_dir.display())])
            .args([
                "-v",
                &format!("{}:/.cache", self.contract_dir.join(".cache").display()),
            ])
            .args(["-w", "/work", TOOLKIT_IMAGE]);
        cmd
    }

    async fn deploy(&self) -> Result<String> {
        let run_dir = self.run_dir();
        let _ = std::fs::remove_dir_all(&run_dir);
        std::fs::create_dir_all(&run_dir)?;
        std::fs::create_dir_all(self.contract_dir.join(".cache"))?;
        std::fs::create_dir_all(self.contract_dir.join(".cache-native"))?;

        let mut intent = self.docker();
        intent.args([
            "generate-intent",
            "deploy",
            "--toolkit-js-path",
            "/toolkit-js",
            "--config",
            "/work/signer.config.ts",
            "--coin-public",
            DEV_COIN_PUBLIC,
            "--output-intent",
            "/work/.run/deploy.intent",
            "--output-private-state",
            "/work/.run/private-state.json",
            "--output-zswap-state",
            "/work/.run/deploy.zswap.json",
        ]);
        run_ok(&mut intent, "toolkit generate-intent deploy").await?;

        let tx_file = run_dir.join("deploy-tx.mn");
        let mut send = self.native();
        send.args([
            "send-intent",
            "--src-url",
            &self.node_ws_native,
            "--dest-file",
            &tx_file.display().to_string(),
            "--funding-seed",
            DEV_FUNDING_SEED,
            "--intent-file",
            &run_dir.join("deploy.intent").display().to_string(),
            "--compiled-contract-dir",
            &self
                .contract_dir
                .join("signet-signer")
                .display()
                .to_string(),
        ]);
        run_ok(&mut send, "toolkit send-intent (deploy build)").await?;

        let mut addr_cmd = self.native();
        addr_cmd.args([
            "contract-address",
            "--src-file",
            &tx_file.display().to_string(),
        ]);
        let stdout = run_ok(&mut addr_cmd, "toolkit contract-address").await?;
        let address = String::from_utf8_lossy(&stdout).trim().to_string();
        anyhow::ensure!(
            address.len() == 64 && address.bytes().all(|b| b.is_ascii_hexdigit()),
            "unexpected contract address form: {address:?}"
        );

        let mut submit = self.native();
        submit.args([
            "generate-txs",
            "--src-file",
            &tx_file.display().to_string(),
            "--dest-url",
            &self.node_ws_native,
            "send",
        ]);
        run_ok(&mut submit, "toolkit generate-txs send (deploy)").await?;

        self.layout_resolver(&address)?;
        Ok(address)
    }

    /// Lay out the proving-key resolver tree the toolkit expects for circuit
    /// calls: <dir>/keys|zkir/contract:<addr>/<circuit>?vk=<sha256(verifier)>.*
    fn layout_resolver(&self, address: &str) -> Result<()> {
        let managed = self.contract_dir.join("signet-signer");
        let resolver = self.run_dir().join("resolver");
        let keys_dir = resolver.join("keys").join(format!("contract:{address}"));
        let zkir_dir = resolver.join("zkir").join(format!("contract:{address}"));
        std::fs::create_dir_all(&keys_dir)?;
        std::fs::create_dir_all(&zkir_dir)?;
        for circuit in CIRCUITS {
            let verifier = managed.join(format!("keys/{circuit}.verifier"));
            let prover = managed.join(format!("keys/{circuit}.prover"));
            anyhow::ensure!(
                prover.exists(),
                "missing {} — compile in midnight-erc20-vault and copy the prover keys",
                prover.display()
            );
            let vk = hex::encode(Sha256::digest(std::fs::read(&verifier)?));
            std::fs::copy(&prover, keys_dir.join(format!("{circuit}?vk={vk}.prover")))?;
            std::fs::copy(
                &verifier,
                keys_dir.join(format!("{circuit}?vk={vk}.verifier")),
            )?;
            std::fs::copy(
                managed.join(format!("zkir/{circuit}.bzkir")),
                zkir_dir.join(format!("{circuit}?vk={vk}.bzkir")),
            )?;
        }
        Ok(())
    }

    /// Submit a circuit call: fetch state → generate intent (docker) →
    /// build/prove/fund/submit (native).
    async fn call(&self, address: &str, circuit: &str, args: &[String]) -> Result<()> {
        let run_dir = self.run_dir();
        let mut state = self.native();
        state.args([
            "contract-state",
            "--src-url",
            &self.node_ws_native,
            "--contract-address",
            address,
            "--dest-file",
            &run_dir.join("state.mn").display().to_string(),
        ]);
        run_ok(&mut state, "toolkit contract-state").await?;

        let mut intent = self.docker();
        intent
            .args([
                "generate-intent",
                "circuit",
                "--toolkit-js-path",
                "/toolkit-js",
                "--config",
                "/work/signer.config.ts",
                "--src-url",
                &self.node_ws_docker,
                "--coin-public",
                DEV_COIN_PUBLIC,
                "--input-onchain-state",
                "/work/.run/state.mn",
                "--input-private-state",
                "/work/.run/private-state.json",
                "--output-intent",
                "/work/.run/call.intent",
                "--output-private-state",
                "/work/.run/private-state.json",
                "--output-zswap-state",
                "/work/.run/call.zswap.json",
                "--output-result",
                "/work/.run/call-result.json",
                "--contract-address",
                address,
                circuit,
            ])
            .args(args);
        run_ok(
            &mut intent,
            &format!("toolkit generate-intent circuit {circuit}"),
        )
        .await?;

        let mut send = self.native();
        send.args([
            "send-intent",
            "--src-url",
            &self.node_ws_native,
            "--dest-url",
            &self.node_ws_native,
            "--funding-seed",
            DEV_FUNDING_SEED,
            "--intent-file",
            &run_dir.join("call.intent").display().to_string(),
            "--compiled-contract-dir",
            &run_dir.join("resolver").display().to_string(),
        ]);
        run_ok(&mut send, &format!("toolkit send-intent ({circuit})")).await?;
        Ok(())
    }
}

pub struct MidnightSandbox {
    pub stack: MidnightStack,
    toolkit: MidnightToolkit,
    publisher: Child,
    publisher_url: String,
    pub contract_address: String,
}

impl MidnightSandbox {
    /// Spawn on an existing test docker network (cluster path).
    pub async fn run(docker: &DockerClient, network: &str) -> Result<Self> {
        let contract_dir = env_path(
            "MIDNIGHT_FIXTURES_DIR",
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/midnight"),
        );
        let toolkit_bin = env_path(
            "MIDNIGHT_TOOLKIT_BIN",
            repo_root()
                .join("chain-signatures/midnight-publisher/target/release/midnight-node-toolkit"),
        );
        let publisher_bin = env_path(
            "MIDNIGHT_PUBLISHER_BIN",
            repo_root()
                .join("chain-signatures/midnight-publisher/target/release/midnight-publisher"),
        );
        anyhow::ensure!(
            contract_dir.join("signer.config.ts").exists(),
            "MIDNIGHT_FIXTURES_DIR does not look like the midnight fixtures dir: {}",
            contract_dir.display()
        );
        anyhow::ensure!(
            contract_dir.join("signet-signer/keys/sign.prover").exists(),
            "prover keys missing under {} — compile the contract in midnight-erc20-vault \
             (npm run compact:signer) and copy managed/signet-signer/keys/*.prover here \
             (provers are regenerable and gitignored; only the small artifacts are committed)",
            contract_dir.join("signet-signer/keys").display()
        );
        // signer.config.ts is tsc-compiled by toolkit-js and needs its type
        // deps resolvable next to it — install the pinned dev deps on demand.
        if !contract_dir
            .join("node_modules/@midnight-ntwrk/compact-js")
            .exists()
        {
            run_ok(
                Command::new("npm").arg("install").current_dir(&contract_dir),
                "npm install (midnight fixtures)",
            )
            .await?;
        }
        anyhow::ensure!(
            toolkit_bin.exists(),
            "toolkit binary missing at {} — build the isolated workspace",
            toolkit_bin.display()
        );
        anyhow::ensure!(
            publisher_bin.exists(),
            "publisher binary missing at {}",
            publisher_bin.display()
        );

        // 1. Stack up + readiness (node finalizes, indexer answers GraphQL).
        let stack = MidnightStack::run(docker, network).await?;
        let node_http = stack.node_external_http.clone();
        wait_for(Duration::from_secs(120), "node finalized head", || {
            let node_http = node_http.clone();
            async move {
                finalized_height(&node_http)
                    .await
                    .map(|h| h >= 1)
                    .unwrap_or(false)
            }
        })
        .await?;
        let indexer_url = stack.indexer_graphql_url.clone();
        wait_for(Duration::from_secs(120), "indexer GraphQL", || {
            let indexer_url = indexer_url.clone();
            async move {
                reqwest::Client::new()
                    .post(&indexer_url)
                    .json(&serde_json::json!({"query": "{ __typename }"}))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            }
        })
        .await?;

        // 2. Deploy the signer and lay out the resolver keys.
        let toolkit = MidnightToolkit {
            bin: toolkit_bin.clone(),
            contract_dir: contract_dir.clone(),
            network: network.to_string(),
            node_ws_native: stack.node_external_ws.clone(),
            node_ws_docker: stack.node_internal_ws.clone(),
        };
        let contract_address = toolkit.deploy().await?;

        // 3. Start the publisher service on a free port.
        let publisher_port = crate::utils::pick_unused_port().await?;
        let publisher = Command::new(&publisher_bin)
            .env("MIDNIGHT_PUB_PORT", publisher_port.to_string())
            .env("MIDNIGHT_PUB_WORK_DIR", &contract_dir)
            .env("MIDNIGHT_PUB_NODE_URL", &stack.node_external_ws)
            .env("MIDNIGHT_PUB_NODE_URL_DOCKER", &stack.node_internal_ws)
            .env("MIDNIGHT_PUB_TOOLKIT_BIN", &toolkit_bin)
            .env("MIDNIGHT_PUB_TOOLKIT_IMAGE", TOOLKIT_IMAGE)
            .env("MIDNIGHT_PUB_DOCKER_NETWORK", network)
            .env("MIDNIGHT_PUB_FUNDING_SEED", DEV_FUNDING_SEED)
            .env("MIDNIGHT_PUB_COIN_PUBLIC", DEV_COIN_PUBLIC)
            .env("MIDNIGHT_PUB_SIGNER_SECRET_KEY", GOLDEN_CALLER_SECRET_KEY)
            .spawn()
            .context("spawning midnight-publisher")?;
        let publisher_url = format!("http://127.0.0.1:{publisher_port}");
        let health_url = format!("{publisher_url}/health");
        wait_for(Duration::from_secs(30), "publisher /health", || {
            let health_url = health_url.clone();
            async move {
                reqwest::get(&health_url)
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            }
        })
        .await?;

        tracing::info!(%contract_address, "midnight sandbox ready");
        Ok(Self {
            stack,
            toolkit,
            publisher,
            publisher_url,
            contract_address,
        })
    }

    /// Spawn with a private docker network (stream-tier tests, no cluster).
    pub async fn run_standalone() -> Result<Self> {
        let docker = DockerClient::default();
        let network = format!("midnight-test-{}", std::process::id());
        docker.create_network(&network).await?;
        Self::run(&docker, &network).await
    }

    pub fn get_config(&self) -> MidnightConfig {
        MidnightConfig {
            indexer_graphql_url: self.stack.indexer_graphql_url.clone(),
            indexer_graphql_ws_url: self.stack.indexer_graphql_ws_url.clone(),
            node_rpc_url: self.stack.node_external_http.clone(),
            publisher_url: self.publisher_url.clone(),
            contract_address: self.contract_address.clone(),
            network_id: "undeployed".into(),
        }
    }

    pub fn graphql(&self) -> MidnightGraphql {
        MidnightGraphql::new(
            &self.stack.indexer_graphql_url,
            &self.stack.indexer_graphql_ws_url,
            &self.contract_address,
        )
    }

    pub async fn submit_sign(&self, payload_hex: &str, key_version: u32) -> Result<()> {
        self.toolkit
            .call(
                &self.contract_address,
                "sign",
                &[payload_hex.to_string(), key_version.to_string()],
            )
            .await
    }

    pub async fn submit_respond(
        &self,
        request_id: &str,
        big_r_x: &str,
        big_r_y: &str,
        s: &str,
        recovery_id: u8,
    ) -> Result<()> {
        self.toolkit
            .call(
                &self.contract_address,
                "respond",
                &[
                    request_id.to_string(),
                    big_r_x.to_string(),
                    big_r_y.to_string(),
                    s.to_string(),
                    recovery_id.to_string(),
                ],
            )
            .await
    }

    pub async fn submit_sign_bidirectional(&self, p: &MidnightBiParams) -> Result<()> {
        self.toolkit
            .call(
                &self.contract_address,
                "sign_bidirectional",
                &p.to_call_args(),
            )
            .await
    }
}

impl Drop for MidnightSandbox {
    fn drop(&mut self) {
        // Containers are removed by their testcontainers Drop impls.
        let _ = self.publisher.kill();
        tracing::info!("midnight sandbox cleaned up");
    }
}

async fn finalized_height(node_http: &str) -> Result<u64> {
    let client = reqwest::Client::new();
    let head: serde_json::Value = client
        .post(node_http)
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"chain_getFinalizedHead","params":[]}))
        .send()
        .await?
        .json()
        .await?;
    let hash = head["result"].as_str().context("no finalized head")?;
    let header: serde_json::Value = client
        .post(node_http)
        .json(
            &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"chain_getHeader","params":[hash]}),
        )
        .send()
        .await?
        .json()
        .await?;
    let number = header["result"]["number"].as_str().context("no number")?;
    Ok(u64::from_str_radix(number.trim_start_matches("0x"), 16)?)
}

async fn wait_for<F, Fut>(limit: Duration, what: &str, probe: F) -> Result<()>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if probe().await {
            return Ok(());
        }
        anyhow::ensure!(start.elapsed() < limit, "timeout waiting for {what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Kept for API clarity at call sites that hold a `Path`.
#[allow(dead_code)]
fn display(p: &Path) -> String {
    p.display().to_string()
}
