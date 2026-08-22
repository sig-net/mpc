use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use mpc_chain_midnight::{MidnightConfig, MidnightPublisherRpc, PublisherConfig};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use testcontainers::core::logs::LogFrame;
use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::{GenericImage, ImageExt as _};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::cluster::spawner::ClusterSpawner;
use crate::containers::{start_container_with_network_retry, Container};

const NODE_IMAGE: (&str, &str) = ("midnightntwrk/midnight-node", "2.0.0-rc.4");
const INDEXER_IMAGE: (&str, &str) = (
    "midnightntwrk/indexer-standalone",
    "4.4.0-pre-alpha.16-l91r3-n2r3-bridge-and-events-epics-contract-zswap-16c656df",
);
const PROOF_IMAGE: (&str, &str) = ("midnightntwrk/proof-server", "9.0.0-rc.5_experimental");

const NODE_PORT: u16 = 9944;
const INDEXER_PORT: u16 = 8088;
const PROOF_PORT: u16 = 6300;
const INDEXER_SECRET: &str = "303132333435363738393031323334353637383930313233343536373839303132";
const SIDECHAIN_BLOCK_BENEFICIARY: &str =
    "04bcf7ad3be7a5c790460be82a713af570f22e0f801f6659ab8e84a52be6969e";

struct MidnightEndpoints {
    node_ws_url: String,
    node_http_url: String,
    indexer_url: String,
    indexer_ws_url: String,
    proof_server_url: String,
}

fn host_endpoints(
    node_host_port: u16,
    indexer_host_port: u16,
    proof_host_port: u16,
) -> MidnightEndpoints {
    MidnightEndpoints {
        node_ws_url: format!("ws://127.0.0.1:{node_host_port}"),
        node_http_url: format!("http://127.0.0.1:{node_host_port}"),
        indexer_url: format!("http://127.0.0.1:{indexer_host_port}/api/v3/graphql"),
        indexer_ws_url: format!("ws://127.0.0.1:{indexer_host_port}/api/v3/graphql/ws"),
        proof_server_url: format!("http://127.0.0.1:{proof_host_port}"),
    }
}

struct MidnightStack {
    _node: Container,
    _indexer: Container,
    _proof_server: Container,
    endpoints: MidnightEndpoints,
    network_id: String,
    artifact_dir: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapResult {
    central_address: String,
    caller_address: String,
    publisher_seed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedEvmTransaction {
    pub serialized: String,
    pub unsigned_hash: String,
    pub from: String,
    pub to: String,
    pub data: String,
    pub chain_id: String,
}

pub struct MidnightContext {
    _stack: MidnightStack,
    pub config: MidnightConfig,
    driver: Mutex<MidnightDriver>,
}

impl MidnightContext {
    pub async fn run(
        spawner: &ClusterSpawner,
        root_public_key: mpc_crypto::PublicKey,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !cfg!(feature = "docker-test"),
            "the Midnight real-stack integration currently launches host mpc-node binaries"
        );
        let stack = MidnightStack::run(spawner).await?;
        let mut driver = MidnightDriver::spawn(&stack.artifact_dir).await?;
        let bootstrap = driver
            .request::<BootstrapResult>(&serde_json::json!({
                "op": "bootstrap",
                "config": DriverConfig::new(&stack),
                "artifactDir": stack.artifact_dir,
            }))
            .await
            .context("bootstrapping fresh Midnight wallets and contracts")?;
        let caller = bootstrap.caller_address.trim_start_matches("0x");
        let caller_bytes = hex::decode(caller).context("decoding Midnight caller address")?;
        anyhow::ensure!(
            caller_bytes.len() == 32,
            "Midnight caller address must be 32 bytes, got {}",
            caller_bytes.len()
        );
        let epsilon = mpc_crypto::derive_epsilon_midnight(
            mpc_primitives::LATEST_MPC_KEY_VERSION,
            &hex::encode(caller_bytes),
            mpc_node::respond_bidirectional::MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH,
        );
        let response_public_key = mpc_crypto::derive_key(root_public_key, epsilon);
        let response_public_key = format!(
            "0x{}",
            hex::encode(response_public_key.to_encoded_point(false).as_bytes())
        );
        let _: serde_json::Value = driver
            .request(&serde_json::json!({
                "op": "initialise",
                "responsePublicKey": response_public_key,
            }))
            .await
            .context("initialising the Midnight caller with the MPC response key")?;
        let publisher_entrypoint = publisher_package_dir()?.join("dist/main.js");
        anyhow::ensure!(
            publisher_entrypoint.is_file(),
            "Midnight publisher entry point {} is missing; run npm run build in {}",
            publisher_entrypoint.display(),
            publisher_package_dir()?.display()
        );
        let config = responder_config(
            &stack.endpoints,
            &bootstrap,
            node_executable()?,
            publisher_entrypoint,
        );
        config.validate()?;
        Ok(Self {
            _stack: stack,
            config,
            driver: Mutex::new(driver),
        })
    }

    pub async fn submit_is_even(
        &self,
        nonce: u64,
        target: [u8; 20],
        argument: [u8; 32],
    ) -> anyhow::Result<()> {
        let mut driver = self.driver.lock().await;
        let _: serde_json::Value = driver
            .request(&serde_json::json!({
                "op": "submitIsEven",
                "nonce": nonce.to_string(),
                "target": hex::encode(target),
                "argument": hex::encode(argument),
            }))
            .await?;
        Ok(())
    }

    pub async fn signed_evm_transaction(
        &self,
        request_id: [u8; 32],
        expected_signer: &str,
    ) -> anyhow::Result<SignedEvmTransaction> {
        let mut driver = self.driver.lock().await;
        driver
            .request(&serde_json::json!({
                "op": "signedTransaction",
                "requestId": format!("0x{}", hex::encode(request_id)),
                "expectedSigner": expected_signer,
            }))
            .await
    }

    pub async fn settle_response(&self, request_id: [u8; 32]) -> anyhow::Result<()> {
        let mut driver = self.driver.lock().await;
        let _: serde_json::Value = driver
            .request(&serde_json::json!({
                "op": "settleResponse",
                "requestId": format!("0x{}", hex::encode(request_id)),
            }))
            .await?;
        Ok(())
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        let mut driver = self.driver.lock().await;
        let _: serde_json::Value = driver
            .request(&serde_json::json!({ "op": "shutdown" }))
            .await?;
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DriverConfig<'a> {
    indexer_url: &'a str,
    indexer_ws_url: &'a str,
    node_url: &'a str,
    proof_server_url: &'a str,
    network_id: &'a str,
}

impl<'a> DriverConfig<'a> {
    fn new(stack: &'a MidnightStack) -> Self {
        Self {
            indexer_url: &stack.endpoints.indexer_url,
            indexer_ws_url: &stack.endpoints.indexer_ws_url,
            node_url: &stack.endpoints.node_http_url,
            proof_server_url: &stack.endpoints.proof_server_url,
            network_id: &stack.network_id,
        }
    }
}

fn responder_config(
    endpoints: &MidnightEndpoints,
    bootstrap: &BootstrapResult,
    node_executable: String,
    publisher_entrypoint: PathBuf,
) -> MidnightConfig {
    MidnightConfig {
        node_ws_url: endpoints.node_ws_url.clone(),
        central_address: bootstrap.central_address.clone(),
        publisher: PublisherConfig {
            intent_gen_command: vec![
                node_executable,
                publisher_entrypoint.to_string_lossy().into_owned(),
            ],
            funding_seed: bootstrap.publisher_seed.clone(),
            proof_server_url: endpoints.proof_server_url.clone(),
            indexer_url: endpoints.indexer_url.clone(),
            indexer_ws_url: endpoints.indexer_ws_url.clone(),
            ..Default::default()
        },
        rpc: Default::default(),
        indexer: Default::default(),
    }
}

fn node_executable() -> anyhow::Result<String> {
    let output = std::process::Command::new("node")
        .args(["--print", "process.execPath"])
        .output()
        .context("resolving the Node executable for the Midnight publisher")?;
    anyhow::ensure!(
        output.status.success(),
        "resolving the Node executable failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = String::from_utf8(output.stdout).context("Node's executable path is not UTF-8")?;
    let path = path.trim();
    anyhow::ensure!(
        Path::new(path).is_absolute(),
        "Node returned a non-absolute executable path: {path}"
    );
    Ok(path.to_string())
}

struct MidnightDriver {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl MidnightDriver {
    async fn spawn(artifact_dir: &Path) -> anyhow::Result<Self> {
        let package_dir = publisher_package_dir()?;
        let executable = package_dir.join("node_modules/.bin/tsx");
        let source = package_dir.join("devtools/real-stack/driver.ts");
        anyhow::ensure!(
            executable.is_file(),
            "tsx executable {} is missing; run npm ci in {}",
            executable.display(),
            package_dir.display()
        );
        let stderr = std::fs::File::create(artifact_dir.join("driver.log"))?;
        let mut child = Command::new(&executable)
            .arg(&source)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting Midnight fixture driver {}", source.display()))?;
        let stdin = child
            .stdin
            .take()
            .context("Midnight fixture driver stdin")?;
        let stdout = child
            .stdout
            .take()
            .context("Midnight fixture driver stdout")?;
        Ok(Self {
            _child: child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    async fn request<T: DeserializeOwned>(
        &mut self,
        request: &serde_json::Value,
    ) -> anyhow::Result<T> {
        let mut encoded = serde_json::to_vec(request)?;
        encoded.push(b'\n');
        self.stdin.write_all(&encoded).await?;
        self.stdin.flush().await?;
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line).await?;
        anyhow::ensure!(read != 0, "Midnight fixture driver exited without replying");
        #[derive(Deserialize)]
        struct Reply<T> {
            ok: bool,
            result: Option<T>,
            error: Option<String>,
        }
        let reply: Reply<T> = serde_json::from_str(&line)
            .with_context(|| format!("decoding Midnight fixture reply: {line}"))?;
        anyhow::ensure!(
            reply.ok,
            "Midnight fixture operation failed: {}",
            reply.error.unwrap_or_else(|| "unknown error".into())
        );
        reply
            .result
            .context("Midnight fixture reply omitted its result")
    }
}

fn publisher_package_dir() -> anyhow::Result<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(|root| root.join("chain-signatures/midnight-publisher-ts"))
        .context("integration-tests manifest has no repository parent")
}

impl MidnightStack {
    pub async fn run(spawner: &ClusterSpawner) -> anyhow::Result<Self> {
        let artifact_dir = spawner.tmp_dir.join("midnight");
        std::fs::create_dir_all(&artifact_dir).with_context(|| {
            format!(
                "creating Midnight integration artifact directory {}",
                artifact_dir.display()
            )
        })?;

        let node_log = log_consumer(&artifact_dir.join("node.log"));
        let node = start_container_with_network_retry(
            || {
                GenericImage::new(NODE_IMAGE.0, NODE_IMAGE.1)
                    .with_exposed_port(NODE_PORT.tcp())
                    .with_wait_for(WaitFor::Nothing)
                    .with_env_var("CFG_PRESET", "dev")
                    .with_env_var("THRESHOLD", "0")
                    .with_env_var("SHOW_CONFIG", "false")
                    .with_env_var("RUST_BACKTRACE", "1")
                    .with_env_var("SIDECHAIN_BLOCK_BENEFICIARY", SIDECHAIN_BLOCK_BENEFICIARY)
                    .with_network(&spawner.network)
                    .with_log_consumer(node_log.clone())
            },
            &spawner.network,
        )
        .await
        .context("starting Midnight node container")?;
        let node_ip = spawner
            .docker
            .get_network_ip_address(&node, &spawner.network)
            .await
            .context("resolving Midnight node network address")?;
        let node_host_port = node
            .get_host_port_ipv4(NODE_PORT)
            .await
            .context("resolving Midnight node host port")?;

        let node_internal_ws = format!("ws://{node_ip}:{NODE_PORT}");
        let indexer_log = log_consumer(&artifact_dir.join("indexer.log"));
        let indexer = start_container_with_network_retry(
            || {
                GenericImage::new(INDEXER_IMAGE.0, INDEXER_IMAGE.1)
                    .with_exposed_port(INDEXER_PORT.tcp())
                    .with_wait_for(WaitFor::Nothing)
                    .with_env_var(
                        "RUST_LOG",
                        "indexer_standalone=info,chain_indexer=info,indexer_api=info,info",
                    )
                    .with_env_var("APP__INFRA__NODE__URL", &node_internal_ws)
                    .with_env_var("APP__INFRA__SECRET", INDEXER_SECRET)
                    .with_env_var("APP__INFRA__SPO_NODE__URL", &node_internal_ws)
                    .with_env_var("APP__INFRA__SPO_NODE__BLOCKFROST_ID", "unused-local")
                    .with_network(&spawner.network)
                    .with_log_consumer(indexer_log.clone())
            },
            &spawner.network,
        )
        .await
        .context("starting Midnight indexer container")?;
        let indexer_host_port = indexer
            .get_host_port_ipv4(INDEXER_PORT)
            .await
            .context("resolving Midnight indexer host port")?;

        let proof_log = log_consumer(&artifact_dir.join("proof-server.log"));
        let proof_server = start_container_with_network_retry(
            || {
                GenericImage::new(PROOF_IMAGE.0, PROOF_IMAGE.1)
                    .with_exposed_port(PROOF_PORT.tcp())
                    .with_wait_for(WaitFor::Nothing)
                    .with_network(&spawner.network)
                    .with_log_consumer(proof_log.clone())
            },
            &spawner.network,
        )
        .await
        .context("starting Midnight proof-server container")?;
        let proof_host_port = proof_server
            .get_host_port_ipv4(PROOF_PORT)
            .await
            .context("resolving Midnight proof-server host port")?;

        let endpoints = host_endpoints(node_host_port, indexer_host_port, proof_host_port);
        let network_id = wait_for_node(&endpoints.node_ws_url).await?;
        wait_for_indexer(&endpoints.indexer_url).await?;
        wait_for_http("proof server", &endpoints.proof_server_url).await?;

        Ok(Self {
            _node: node,
            _indexer: indexer,
            _proof_server: proof_server,
            endpoints,
            network_id,
            artifact_dir,
        })
    }
}

fn log_consumer(path: &Path) -> impl Fn(&LogFrame) + Clone + Send + Sync + 'static {
    let path = path.to_path_buf();
    move |frame: &LogFrame| {
        let bytes = match frame {
            LogFrame::StdOut(bytes) | LogFrame::StdErr(bytes) => bytes,
        };
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = file.write_all(bytes);
        }
    }
}

async fn wait_for_node(node_ws_url: &str) -> anyhow::Result<String> {
    let config = MidnightConfig {
        node_ws_url: node_ws_url.to_string(),
        central_address: "00".repeat(32),
        publisher: Default::default(),
        rpc: Default::default(),
        indexer: Default::default(),
    };
    let mut last_error = None;
    for _ in 0..120 {
        match MidnightPublisherRpc::connect(&config).await {
            Ok(rpc) => return Ok(rpc.network_id().to_string()),
            Err(error) => last_error = Some(format!("connect: {error:#}")),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!(
        "Midnight node at {node_ws_url} did not become ready: {}",
        last_error.unwrap_or_else(|| "no response".into())
    )
}

async fn wait_for_indexer(indexer_url: &str) -> anyhow::Result<()> {
    let client = Client::new();
    let mut last_error = None;
    for _ in 0..180 {
        match client
            .post(indexer_url)
            .json(&serde_json::json!({ "query": "{ __typename }" }))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => last_error = Some(format!("status {}", response.status())),
            Err(error) => last_error = Some(error.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!(
        "Midnight indexer at {indexer_url} did not become ready: {}",
        last_error.unwrap_or_else(|| "no response".into())
    )
}

async fn wait_for_http(label: &str, url: &str) -> anyhow::Result<()> {
    let client = Client::new();
    let mut last_error = None;
    for _ in 0..120 {
        match client.get(url).send().await {
            Ok(_) => return Ok(()),
            Err(error) => last_error = Some(error.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!(
        "Midnight {label} at {url} did not become ready: {}",
        last_error.unwrap_or_else(|| "no response".into())
    )
}
