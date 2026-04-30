use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use crate::cluster::spawner::ClusterSpawner;
use crate::local::NodeEnvConfig;
use crate::utils::pick_preferred_or_unused_port;
use crate::NodeConfig;

use anyhow::{anyhow, Context};
use async_process::{Child, Command};
use bollard::container::LogsOptions;
use bollard::network::CreateNetworkOptions;
use bollard::secret::Ipam;
use bollard::Docker;
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::FullSignature;
use elliptic_curve::rand_core::OsRng;
use futures::StreamExt as _;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::Secp256k1;
use mpc_contract::primitives::Participants;
use mpc_keys::hpke;
use mpc_node::config::OverrideConfig;
use mpc_node::indexer_eth::EthArgs;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::triple::Triple;
use mpc_node::storage::triple_storage::TriplePair;
use mpc_primitives::Chain;
use near_account_id::AccountId;
use near_workspaces::Account;
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_client::nonblocking::pubsub_client::PubsubClient as SolanaPubsubClient;
use solana_client::nonblocking::rpc_client::RpcClient as SolanaRpcClient;
use solana_sdk::instruction::AccountMeta;
use solana_sdk::pubkey::Pubkey as SolanaPubkey;
use solana_sdk::signature::Keypair as SolanaKeypair;
use solana_sdk::signature::{EncodableKey as _, Signature as SolanaSignature};
use solana_sdk::signer::{SeedDerivable as _, Signer as _};
use testcontainers::core::ExecCommand;
use testcontainers::ContainerAsync;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Duration};
use tracing;

pub type Container = ContainerAsync<GenericImage>;

pub struct Node {
    pub container: Container,
    pub address: String,
    pub account: Account,
    pub local_address: String,
    pub cipher_sk: hpke::SecretKey,
    pub sign_sk: near_crypto::SecretKey,
    cfg: NodeConfig,
    // near rpc address, after proxy
    near_rpc: String,
}

impl Node {
    // Container port used for the docker network, does not have to be unique
    const CONTAINER_PORT: u16 = 3000;

    pub async fn run(
        ctx: &super::Context,
        cfg: &NodeConfig,
        account: &Account,
    ) -> anyhow::Result<Self> {
        tracing::info!(id = %account.id(), "running node container");
        let (cipher_sk, _cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");
        let near_rpc = ctx.worker.rpc_addr();

        Self::spawn(
            ctx,
            NodeEnvConfig {
                web_port: Self::CONTAINER_PORT,
                account: account.clone(),
                cipher_sk,
                sign_sk,
                cfg: cfg.clone(),
                near_rpc,
                binary_path: None,
            },
        )
        .await
    }

    pub async fn kill(self) -> NodeEnvConfig {
        // Give the container a brief moment to clean up connections gracefully
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        self.container.stop().await.unwrap();
        NodeEnvConfig {
            web_port: Self::CONTAINER_PORT,
            account: self.account,
            cipher_sk: self.cipher_sk,
            sign_sk: self.sign_sk,
            cfg: self.cfg,
            near_rpc: self.near_rpc,
            binary_path: None,
        }
    }

    pub async fn spawn(ctx: &super::Context, config: NodeEnvConfig) -> anyhow::Result<Self> {
        let indexer_options = mpc_node::indexer::Options {
            running_threshold: 120,
        };
        let eth_args = EthArgs::from_config(config.cfg.eth.clone());
        let sol_args = mpc_node::indexer_sol::SolArgs::from_config(config.cfg.sol.clone());
        let hydration_args =
            mpc_node::indexer_hydration::HydrationArgs::from_config(config.cfg.hydration.clone());
        let canton_args =
            mpc_node::indexer_canton::CantonArgs::from_config(config.cfg.canton.clone());
        let args = mpc_node::cli::Cli::Start {
            near_rpc: config.near_rpc.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account_id: config.account.id().clone(),
            account_sk: config.account.secret_key().to_string().parse()?,
            web_port: Some(Self::CONTAINER_PORT),
            cipher_sk: hex::encode(config.cipher_sk.to_bytes()),
            indexer_options: indexer_options.clone(),
            eth: eth_args,
            sol: sol_args,
            hydration: hydration_args,
            canton: canton_args,
            my_address: None,
            storage_options: ctx.storage_options.clone(),
            log_options: ctx.log_options.clone(),
            sign_sk: Some(config.sign_sk.clone()),
            override_config: Some(OverrideConfig::new(serde_json::to_value(
                config.cfg.protocol.clone(),
            )?)),
            client_header_referer: None,
            mesh_options: ctx.mesh_options.clone(),
            message_options: ctx.message_options.clone(),
        }
        .into_str_args();
        let container = GenericImage::new("near/mpc-node", "latest")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_PORT.tcp())
            .with_env_var("RUST_LOG", "mpc_node=DEBUG")
            .with_env_var("RUST_BACKTRACE", "1")
            .with_network(&ctx.docker_network)
            .with_cmd(args)
            .start()
            .await
            .unwrap();

        let ip_address = ctx
            .docker_client
            .get_network_ip_address(&container, &ctx.docker_network)
            .await
            .unwrap();
        let host_port = container
            .get_host_port_ipv4(Self::CONTAINER_PORT)
            .await
            .unwrap();

        container.exec(ExecCommand::new(
                format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::CONTAINER_PORT)
                    .split_whitespace()
            )
            .with_container_ready_conditions(vec![WaitFor::message_on_stdout("node is ready to accept connections")])
        ).await.unwrap();

        let full_address = format!("http://{ip_address}:{}", Self::CONTAINER_PORT);
        tracing::info!(
            full_address,
            node_account_id = %config.account.id(),
            "node container is running",
        );
        Ok(Node {
            container,
            address: full_address,
            account: config.account,
            local_address: format!("http://localhost:{host_port}"),
            cipher_sk: config.cipher_sk,
            sign_sk: config.sign_sk,
            cfg: config.cfg,
            near_rpc: config.near_rpc,
        })
    }
}

#[derive(Clone)]
pub struct DockerClient {
    pub docker: Docker,
}

impl DockerClient {
    pub async fn get_network_ip_address(
        &self,
        container: &Container,
        network: &str,
    ) -> anyhow::Result<String> {
        let network_settings = self
            .docker
            .inspect_container(container.id(), None)
            .await?
            .network_settings
            .ok_or_else(|| anyhow!("missing NetworkSettings on container '{}'", container.id()))?;
        let ip_address = network_settings
            .networks
            .ok_or_else(|| {
                anyhow!(
                    "missing NetworkSettings.Networks on container '{}'",
                    container.id()
                )
            })?
            .get(network)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "container '{}' is not a part of network '{}'",
                    container.id(),
                    network
                )
            })?
            .ip_address
            .ok_or_else(|| {
                anyhow!(
                    "container '{}' belongs to network '{}', but is not assigned an IP address",
                    container.id(),
                    network
                )
            })?;

        Ok(ip_address)
    }

    pub async fn create_network(&self, network: &str) -> anyhow::Result<()> {
        let list = self.docker.list_networks::<&str>(None).await?;
        if list.iter().any(|n| n.name == Some(network.to_string())) {
            return Ok(());
        }

        let create_network_options = CreateNetworkOptions {
            name: network,
            check_duplicate: true,
            driver: if cfg!(windows) {
                "transparent"
            } else {
                "bridge"
            },
            ipam: Ipam {
                config: None,
                ..Default::default()
            },
            ..Default::default()
        };
        let _response = &self.docker.create_network(create_network_options).await?;

        Ok(())
    }

    pub async fn continuously_print_logs(&self, id: &str) -> anyhow::Result<()> {
        let mut output = self.docker.logs::<String>(
            id,
            Some(LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );

        // Asynchronous process that pipes docker attach output into stdout.
        // Will die automatically once Docker container output is closed.
        tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();

            while let Some(Ok(output)) = output.next().await {
                stdout
                    .write_all(output.into_bytes().as_ref())
                    .await
                    .unwrap();
                stdout.flush().await.unwrap();
            }
        });

        Ok(())
    }

    pub async fn output_logs(&self, id: &str, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let mut output = self.docker.logs::<String>(
            id,
            Some(LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );

        let mut out = std::fs::File::create(path)?;
        tokio::spawn(async move {
            while let Some(Ok(output)) = output.next().await {
                std::io::Write::write_all(&mut out, output.into_bytes().as_ref()).unwrap();
            }
        });

        Ok(())
    }
}

impl Default for DockerClient {
    fn default() -> Self {
        let timeout = 600;
        let api_version = bollard::API_DEFAULT_VERSION;

        let docker = match bollard::Docker::connect_with_defaults() {
            Ok(docker) => docker,
            Err(default_err) => {
                let home_socket = env::var("HOME")
                    .ok()
                    .map(|home| format!("unix://{home}/.docker/run/docker.sock"));
                let Some(home_socket) = home_socket else {
                    panic!("failed to connect to Docker using defaults: {default_err}");
                };

                bollard::Docker::connect_with_unix(&home_socket, timeout, api_version)
                    .unwrap_or_else(|home_err| {
                        panic!(
                            "failed to connect to Docker using defaults ({default_err}) or Docker Desktop socket {home_socket} ({home_err})"
                        )
                    })
            }
        };

        Self { docker }
    }
}

pub struct Redis {
    pub container: Container,
    pub internal_address: String,
    pub external_address: String,
}

impl Redis {
    const DEFAULT_REDIS_PORT: u16 = 6379;

    pub async fn run(spawner: &ClusterSpawner) -> Self {
        tracing::info!("Running Redis container...");
        let container = GenericImage::new("redis", "7.4.2")
            .with_exposed_port(Self::DEFAULT_REDIS_PORT.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .with_network(&spawner.network)
            .start()
            .await
            .unwrap();
        let network_ip = spawner
            .docker
            .get_network_ip_address(&container, &spawner.network)
            .await
            .unwrap();

        let external_address = format!("redis://{}:{}", network_ip, Self::DEFAULT_REDIS_PORT);

        let host_port = container
            .get_host_port_ipv4(Self::DEFAULT_REDIS_PORT)
            .await
            .unwrap();
        let internal_address = format!("redis://127.0.0.1:{host_port}");

        tracing::info!(
            external_address,
            internal_address,
            "Redis container is running",
        );

        Self {
            container,
            internal_address,
            external_address,
        }
    }

    pub fn pool(&self) -> deadpool_redis::Pool {
        let redis_url = url::Url::parse(self.internal_address.as_str()).unwrap();
        let redis_cfg = deadpool_redis::Config::from_url(redis_url);
        redis_cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap()
    }

    pub fn triple_storage(
        &self,
        id: &AccountId,
        me: Participant,
    ) -> mpc_node::storage::TripleStorage {
        let storage = TriplePair::storage(&self.pool(), id);
        storage.set_me(me);
        storage
    }

    pub fn presignature_storage(
        &self,
        id: &AccountId,
        me: Participant,
    ) -> mpc_node::storage::PresignatureStorage {
        let storage = Presignature::storage(&self.pool(), id);
        storage.set_me(me);
        storage
    }

    pub async fn stockpile_triples(&self, cfg: &NodeConfig, participants: &Participants, mul: u32) {
        let pool = self.pool();
        let storage = participants
            .participants
            .keys()
            .map(|account_id| {
                let me = Participant::from(
                    *participants
                        .account_to_participant_id
                        .get(account_id)
                        .unwrap(),
                );
                let storage = TriplePair::storage(&pool, account_id);
                storage.set_me(me);
                (me, storage)
            })
            .collect::<HashMap<_, _>>();

        let participant_ids = participants
            .account_to_participant_id
            .values()
            .map(|id| Participant::from(*id))
            .collect::<Vec<_>>();
        let (public, shares): (TriplePub<Secp256k1>, Vec<TripleShare<Secp256k1>>) =
            cait_sith::triples::deal(&mut OsRng, &participant_ids, cfg.threshold);

        // - first/second loop add at least min_triples per node
        // - third loop: for each pair, store the shares as pairs per node
        let mut num_pairs = 0;
        for owner in &participant_ids {
            for _ in 0..(cfg.protocol.triple.min_triples * mul / 2) {
                num_pairs += 1;
                let pair_id = rand::random();
                for ((me, triple0), triple1) in participant_ids
                    .iter()
                    .zip(shares_to_triples(&public, &shares))
                    .zip(shares_to_triples(&public, &shares))
                {
                    let pair = TriplePair {
                        id: pair_id,
                        triple0,
                        triple1,
                        holders: Some(participant_ids.clone()),
                    };
                    storage
                        .get(me)
                        .unwrap()
                        .create_slot(pair_id, *owner)
                        .await
                        .unwrap()
                        .insert(pair, *owner)
                        .await;
                }
            }
        }

        tracing::info!("stockpiled {num_pairs} triple pairs");
    }
}

pub struct EthereumSandbox {
    pub container: Container,
    pub internal_http_endpoint: String,
    pub external_http_endpoint: String,
    pub secret_key: String,
    pub chain_id: u64,
}

impl EthereumSandbox {
    const RPC_PORT: u16 = 8545;
    const DEFAULT_CHAIN_ID: u64 = 31337;
    const DEFAULT_MNEMONIC: &'static str =
        "test test test test test test test test test test test junk";

    pub async fn run(spawner: &ClusterSpawner) -> anyhow::Result<Self> {
        let chain_id_arg = Self::DEFAULT_CHAIN_ID.to_string();
        let command = format!(
            "anvil --host 0.0.0.0 --chain-id {} --mnemonic '{}' --block-time 1",
            chain_id_arg,
            Self::DEFAULT_MNEMONIC,
        );

        let request = GenericImage::new("ghcr.io/foundry-rs/foundry", "nightly")
            .with_exposed_port(Self::RPC_PORT.tcp())
            .with_network(&spawner.network)
            .with_cmd(vec![command]);

        let container = request.start().await?;

        let secret_key = derive_secret_key(Self::DEFAULT_MNEMONIC)?;

        let network_ip = spawner
            .docker
            .get_network_ip_address(&container, &spawner.network)
            .await?;
        let external_port = container
            .get_host_port_ipv4(Self::RPC_PORT)
            .await
            .context("ethereum sandbox port mapping")?;

        let internal_http_endpoint = format!("http://{}:{}", network_ip, Self::RPC_PORT);
        let external_http_endpoint = format!("http://127.0.0.1:{external_port}");

        wait_for_rpc(&external_http_endpoint).await?;

        Ok(Self {
            internal_http_endpoint,
            external_http_endpoint,
            secret_key,
            chain_id: Self::DEFAULT_CHAIN_ID,
            container,
        })
    }
}

async fn wait_for_rpc(endpoint: &str) -> anyhow::Result<()> {
    const MAX_ATTEMPTS: usize = 120;
    let client = Client::new();
    let mut last_err: Option<String> = None;
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_chainId",
        "params": []
    });

    for _ in 0..MAX_ATTEMPTS {
        match client.post(endpoint).json(&payload).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(body) if body.get("result").is_some() => return Ok(()),
                        Ok(body) => {
                            last_err = Some(format!("missing result in response: {body:?}"));
                        }
                        Err(err) => {
                            last_err = Some(format!("json parse error: {err}"));
                        }
                    }
                } else {
                    last_err = Some(format!("status {}", response.status()));
                }
            }
            Err(err) => {
                last_err = Some(err.to_string());
            }
        }

        sleep(Duration::from_millis(500)).await;
    }

    Err(anyhow!(
        "ethereum sandbox rpc '{}' did not become ready: {:?}",
        endpoint,
        last_err
    ))
}

fn derive_secret_key(mnemonic: &str) -> anyhow::Result<String> {
    use ethers::signers::{coins_bip39::English, MnemonicBuilder};

    let wallet = MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .derivation_path("m/44'/60'/0'/0/0")?
        .build()?;
    let bytes = wallet.signer().to_bytes();

    Ok(format!("0x{}", hex::encode(bytes)))
}

fn shares_to_triples(
    public: &TriplePub<Secp256k1>,
    shares: &[TripleShare<Secp256k1>],
) -> Vec<Triple> {
    shares
        .iter()
        .map(|share| Triple {
            public: public.clone(),
            share: share.clone(),
        })
        .collect()
}

pub struct Solana {
    pub process: Child,
    pub rpc_address: String,
    pub ws_address: String,
    pub program_keypair: SolanaKeypair,
    pub payer_keypair: SolanaKeypair,
    pub rpc_port: u16,
    pub ws_port: u16,
    pub faucet_port: u16,
    pub rpc_client: SolanaRpcClient,
    ledger_dir: PathBuf,
}

impl Solana {
    /// Program ID hardcoded in the solana program/contract.
    pub const PROGRAM_ID: &str = "FR5pWwinRBn35GNhg7bsvw8Q13kRept2pm561DwZCQzT";
    /// Precompiled with https://github.com/sig-net/solana-signet-program @ 0.4.0
    pub const PROGRAM_PATH: &str = "chain-signatures/contract-sol/artifacts/chain_signatures.so";

    /// Fixed keypair for deterministic program address/id. This is embedded in the declare_id!
    /// macro of our Solana program/contract.
    pub fn program_keypair() -> SolanaKeypair {
        SolanaKeypair::from_seed(&[101u8; 32]).unwrap()
    }

    pub async fn run() -> Self {
        tracing::info!("Starting Solana Test Validator process...");

        // Check if solana-test-validator is available
        match Command::new("solana-test-validator")
            .arg("--help")
            .output()
            .await
        {
            Err(_) => {
                panic!(
                    "solana-test-validator not found in PATH: install Solana CLI tools via
                    https://docs.solana.com/cli/install-solana-cli-tools"
                );
            }
            Ok(output) if !output.status.success() => {
                panic!("solana-test-validator exists but returned error when checking --help");
            }
            Ok(_) => {
                tracing::info!("found solana-test-validator in PATH");
            }
        }

        // Generate a new keypair for the test validator
        let program_keypair = Solana::program_keypair();
        let payer_keypair = SolanaKeypair::from_seed(&[102u8; 32]).unwrap();

        // Find available ports for RPC and WebSocket
        // Find available ports (websocket is automatically rpc_port + 1)
        let rpc_port = pick_preferred_or_unused_port(8899).await;
        let ws_port = rpc_port + 1;
        let faucet_port = pick_preferred_or_unused_port(9900).await;
        let gossip_port = pick_preferred_or_unused_port(8000).await;
        let dynamic_port_start = pick_preferred_or_unused_port(gossip_port + 1).await;
        let dynamic_port_end = dynamic_port_start + 32;

        let rpc_address = format!("http://127.0.0.1:{}", rpc_port);
        let ws_address = format!("ws://127.0.0.1:{}", ws_port);
        let ledger_dir =
            std::env::temp_dir().join(format!("solana-test-ledger-{}", uuid::Uuid::new_v4()));
        // Start the solana-test-validator process
        let mut command = Command::new("solana-test-validator");
        command
            .arg("--ledger")
            .arg(&ledger_dir)
            .arg("--rpc-port")
            .arg(rpc_port.to_string())
            .arg("--faucet-port")
            .arg(faucet_port.to_string())
            .arg("--gossip-port")
            .arg(gossip_port.to_string())
            .arg("--dynamic-port-range")
            .arg(format!("{dynamic_port_start}-{dynamic_port_end}"))
            .arg("--bind-address")
            .arg("127.0.0.1")
            .arg("--mint")
            .arg(payer_keypair.pubkey().to_string())
            .arg("--reset")
            .arg("--quiet");

        let process = command
            .spawn()
            .expect("failed to start solana-test-validator");

        let rpc_client = SolanaRpcClient::new_with_commitment(
            rpc_address.clone(),
            solana_sdk::commitment_config::CommitmentConfig::confirmed(),
        );
        Self::wait_for_validator_ready(&rpc_client, &ws_address, &payer_keypair.pubkey()).await;

        tracing::info!(
            rpc_address,
            ws_address,
            "solana-test-validator process is running",
        );

        Self {
            process,
            rpc_address,
            ws_address,
            program_keypair,
            payer_keypair,
            rpc_port,
            ws_port,
            faucet_port,
            rpc_client,
            ledger_dir,
        }
    }

    async fn wait_for_validator_ready(
        rpc_client: &SolanaRpcClient,
        ws_address: &str,
        payer: &SolanaPubkey,
    ) {
        const MAX_ATTEMPTS: usize = 60;

        for attempt in 1..=MAX_ATTEMPTS {
            let version_ready = rpc_client.get_version().await.is_ok();
            let blockhash_ready = rpc_client.get_latest_blockhash().await.is_ok();
            let ws_ready = SolanaPubsubClient::new(ws_address).await.is_ok();
            let funded = rpc_client
                .get_balance(payer)
                .await
                .ok()
                .is_some_and(|balance| balance > 0);

            if version_ready && blockhash_ready && ws_ready {
                if !funded {
                    tracing::warn!(
                        attempt,
                        "solana validator RPC is ready but payer balance is still zero"
                    );
                }
                return;
            }

            tracing::debug!(
                attempt,
                version_ready,
                blockhash_ready,
                ws_ready,
                funded,
                "waiting for solana-test-validator readiness"
            );
            sleep(Duration::from_secs(1)).await;
        }

        panic!("solana-test-validator did not become ready in time");
    }

    pub fn get_config(&self, program_address: String) -> mpc_node::indexer_sol::SolConfig {
        mpc_node::indexer_sol::SolConfig {
            account_sk: bs58::encode(self.payer_keypair.to_bytes()).into_string(),
            rpc_http_url: self.rpc_address.clone(),
            rpc_ws_url: self.ws_address.clone(),
            program_address,
        }
    }

    /// Deploy the Solana core contracts and return the program address
    pub async fn deploy_contract(&self) -> anyhow::Result<String> {
        // Check if solana CLI is available
        if let Err(err) = tokio::process::Command::new("solana")
            .arg("--version")
            .output()
            .await
        {
            anyhow::bail!("Solana CLI not available: {err}");
        }

        let program_address = match self.deploy().await {
            Ok(program_address) => program_address,
            Err(e) => {
                anyhow::bail!("program deployment failed: {e}");
            }
        };

        // Wait a bit for deployment to be fully processed
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Initialize the program after deployment
        if let Err(e) = self.initialize_program().await {
            anyhow::bail!("program initialization failed: {e}");
        }

        Ok(program_address)
    }

    /// Perform real contract deployment using Solana CLI
    async fn deploy(&self) -> anyhow::Result<String> {
        let contract_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(Self::PROGRAM_PATH);
        if !contract_path.exists() {
            anyhow::bail!("contract artifact not found at: {contract_path:?}");
        }

        // Create temporary files for keypairs
        let temp_dir = std::env::temp_dir();
        let payer_keypair_path =
            temp_dir.join(format!("payer-keypair-{}.json", uuid::Uuid::new_v4()));
        let program_keypair_path =
            temp_dir.join(format!("program-keypair-{}.json", uuid::Uuid::new_v4()));

        self.payer_keypair
            .write_to_file(&payer_keypair_path)
            .unwrap();
        self.program_keypair
            .write_to_file(&program_keypair_path)
            .unwrap();

        // Deploy the program using solana CLI
        tracing::info!("deploying solana program via CLI...");

        // Best-effort cleanup in case a previous test run left the program account around.
        // This avoids `account already in use` errors when redeploying with the same
        // deterministic program id.
        let program_pubkey = self.program_keypair.pubkey().to_string();
        let close_args = [
            "program",
            "close",
            &program_pubkey,
            "--url",
            &self.rpc_address,
            "--keypair",
            payer_keypair_path.to_str().unwrap(),
        ];
        let close_output = tokio::process::Command::new("solana")
            .args(close_args)
            .output()
            .await?;
        if close_output.status.success() {
            tracing::info!(program_id = %program_pubkey, "closed existing solana program account");
        } else {
            tracing::debug!(program_id = %program_pubkey, "no existing program account closed");
        }

        let deploy_output = tokio::process::Command::new("solana")
            .args([
                "program",
                "deploy",
                contract_path.to_str().unwrap(),
                "--keypair",
                payer_keypair_path.to_str().unwrap(),
                "--url",
                &self.rpc_address,
                "--program-id",
                program_keypair_path.to_str().unwrap(),
                "-v", // verbose output
            ])
            .output()
            .await?;

        // Clean up temporary files
        let _ = std::fs::remove_file(&payer_keypair_path);
        let _ = std::fs::remove_file(&program_keypair_path);

        if !deploy_output.status.success() {
            let stderr = String::from_utf8_lossy(&deploy_output.stderr);
            let stdout = String::from_utf8_lossy(&deploy_output.stdout);
            anyhow::bail!("failed to deploy solana program. stdout: {stdout}, stderr: {stderr}",);
        }

        let stdout = String::from_utf8_lossy(&deploy_output.stdout);
        tracing::info!(%stdout, "solana deploy successful");

        let program_address = self.program_keypair.pubkey().to_string();
        tracing::info!(
            program_address = %program_address,
            contract_path = ?contract_path,
            "successfully deployed solana program via CLI"
        );

        Ok(program_address)
    }

    /// Initialize the deployed Solana program
    async fn initialize_program(&self) -> anyhow::Result<()> {
        tracing::info!("initializing solana program...");

        // Create payer keypair - recreate since it doesn't implement Clone
        let payer = std::sync::Arc::new(SolanaKeypair::from_bytes(&self.payer_keypair.to_bytes())?);
        let program_id = self.program_keypair.pubkey();

        // Define program state PDA
        let (program_state_pda, _bump) =
            SolanaPubkey::find_program_address(&[b"program-state"], &program_id);

        // Call initialize function
        let signature_deposit = 1_000_000u64; // 0.001 SOL in lamports
        let chain_id = Chain::Solana.caip2_chain_id().to_string(); // CAIP-2 format for local testnet

        tracing::info!(
            program_id = %program_id,
            program_state = %program_state_pda,
            signature_deposit,
            chain_id = %chain_id,
            "calling initialize on solana program"
        );

        // Create initialize instruction manually
        let mut data = Vec::new();
        // Add discriminator for initialize function (first 8 bytes of sha256("global:initialize"))
        let discriminator = solana_sdk::hash::hash(b"global:initialize").to_bytes();
        data.extend_from_slice(&discriminator[..8]);

        // Serialize arguments using borsh: signature_deposit (u64) and chain_id (String)
        let mut args_data = Vec::new();
        signature_deposit.serialize(&mut args_data)?;
        chain_id.serialize(&mut args_data)?;
        data.extend_from_slice(&args_data);

        let instruction = solana_sdk::instruction::Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(program_state_pda, false),
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            data,
        };

        let recent_blockhash = self.rpc_client.get_latest_blockhash().await?;
        let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer.pubkey()),
            &[&*payer],
            recent_blockhash,
        );

        let tx = self
            .rpc_client
            .send_and_confirm_transaction(&transaction)
            .await?;

        tracing::info!(
            transaction = %tx,
            "successfully initialized solana program"
        );

        Ok(())
    }

    /// Sign with custom parameters from SignAction
    pub async fn sign(
        &self,
        payload: [u8; 32],
        path: &str,
        key_version: u32,
        algo: &str,
        dest: &str,
        params: &str,
    ) -> anyhow::Result<SolanaSignature> {
        // Check if the RPC client can get the version (basic readiness check)
        if self.rpc_client.get_version().await.is_err() {
            anyhow::bail!("solana container is not ready");
        }

        let program_id = self.program_keypair.pubkey();
        tracing::info!("using program_id for sign: {program_id}");

        // Define program state PDA (required by the sign function)
        let (program_state_pda, _bump) =
            SolanaPubkey::find_program_address(&[b"program-state"], &program_id);

        // Define event authority PDA for CPI events
        let (event_authority_pda, _bump) =
            SolanaPubkey::find_program_address(&[b"__event_authority"], &program_id);

        // Manually construct the instruction data
        // Anchor instructions start with an 8-byte discriminator
        let mut data = Vec::new();
        // Correct discriminator for "sign" function: first 8 bytes of sha256("global:sign")
        data.extend_from_slice(&[5, 221, 155, 46, 237, 91, 28, 236]);
        // Serialize the arguments using Borsh
        let args = SignArgs {
            payload,
            key_version,
            path: path.to_string(),
            algo: algo.to_string(),
            dest: dest.to_string(),
            params: params.to_string(),
        };
        args.serialize(&mut data)?;

        // Create the instruction with correct accounts matching the external contract
        // note that #[event_cpi] requires additional accounts
        let instruction = solana_sdk::instruction::Instruction {
            program_id,
            accounts: vec![
                // program_state account (writable, not signer)
                AccountMeta::new(program_state_pda, false),
                // requester (writable, signer)
                AccountMeta::new(self.payer_keypair.pubkey(), true),
                // fee_payer (writable, signer) - same as requester for simplicity
                AccountMeta::new(self.payer_keypair.pubkey(), true),
                // system_program (readonly, not signer)
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                // event_authority (readonly, not signer) - required for #[event_cpi]
                AccountMeta::new_readonly(event_authority_pda, false),
                // program account (readonly, not signer) - required for #[event_cpi]
                AccountMeta::new_readonly(program_id, false),
            ],
            data,
        };

        // Create and send the transaction to solana
        let recent_blockhash = self.rpc_client.get_latest_blockhash().await?;
        let mut transaction = solana_sdk::transaction::Transaction::new_with_payer(
            &[instruction],
            Some(&self.payer_keypair.pubkey()),
        );
        transaction.sign(&[&self.payer_keypair], recent_blockhash);
        let signature = self
            .rpc_client
            .send_and_confirm_transaction(&transaction)
            .await?;

        tracing::info!(
            ?signature,
            payload = hex::encode(payload),
            path,
            key_version,
            "sign transaction successful",
        );

        Ok(signature)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn sign_bidirectional(
        &self,
        serialized_transaction: &[u8],
        caip2_id: &str,
        key_version: u32,
        path: &str,
        algo: &str,
        dest: &str,
        params: &str,
        callback_program_id: SolanaPubkey,
        output_deserialization_schema: &[u8],
        respond_serialization_schema: &[u8],
    ) -> anyhow::Result<SolanaSignature> {
        if self.rpc_client.get_version().await.is_err() {
            anyhow::bail!("solana container is not ready");
        }

        let contract_program_id = self.program_keypair.pubkey();
        tracing::info!("using program_id for sign_bidirectional: {contract_program_id}");

        let (program_state_pda, _bump) =
            SolanaPubkey::find_program_address(&[b"program-state"], &contract_program_id);
        let (event_authority_pda, _bump) =
            SolanaPubkey::find_program_address(&[b"__event_authority"], &contract_program_id);

        let mut data = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(b"global:sign_bidirectional");
        let discriminator = hasher.finalize();
        data.extend_from_slice(&discriminator[..8]);

        let args = SignBidirectionalArgs {
            serialized_transaction: serialized_transaction.to_vec(),
            caip2_id: caip2_id.to_string(),
            key_version,
            path: path.to_string(),
            algo: algo.to_string(),
            dest: dest.to_string(),
            params: params.to_string(),
            program_id: callback_program_id.to_bytes(),
            output_deserialization_schema: output_deserialization_schema.to_vec(),
            respond_serialization_schema: respond_serialization_schema.to_vec(),
        };
        args.serialize(&mut data)?;

        let instruction = solana_sdk::instruction::Instruction {
            program_id: contract_program_id,
            accounts: vec![
                AccountMeta::new(program_state_pda, false),
                AccountMeta::new(self.payer_keypair.pubkey(), true),
                AccountMeta::new(self.payer_keypair.pubkey(), true),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
                AccountMeta::new_readonly(event_authority_pda, false),
                AccountMeta::new_readonly(contract_program_id, false),
            ],
            data,
        };

        let recent_blockhash = self.rpc_client.get_latest_blockhash().await?;
        let mut transaction = solana_sdk::transaction::Transaction::new_with_payer(
            &[instruction],
            Some(&self.payer_keypair.pubkey()),
        );
        transaction.sign(&[&self.payer_keypair], recent_blockhash);
        let signature = self
            .rpc_client
            .send_and_confirm_transaction(&transaction)
            .await?;

        tracing::info!(
            ?signature,
            caip2_id,
            path,
            key_version,
            "sign_bidirectional transaction successful",
        );

        Ok(signature)
    }

    pub async fn respond_bidirectional(
        &self,
        request_id: [u8; 32],
        serialized_output: Vec<u8>,
        signature: &FullSignature<Secp256k1>,
        recovery_id: u8,
    ) -> anyhow::Result<SolanaSignature> {
        if self.rpc_client.get_version().await.is_err() {
            anyhow::bail!("solana container is not ready");
        }

        let program_id = self.program_keypair.pubkey();
        let mut data = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(b"global:respond_bidirectional");
        let discriminator = hasher.finalize();
        data.extend_from_slice(&discriminator[..8]);

        let encoded_point = signature.big_r.to_encoded_point(false);
        let point_bytes = encoded_point.as_bytes();
        debug_assert_eq!(point_bytes.len(), 65);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&point_bytes[1..33]);
        y.copy_from_slice(&point_bytes[33..65]);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(signature.s.to_bytes().as_slice());

        let args = RespondBidirectionalArgs {
            request_id,
            serialized_output,
            signature: RespondBidirectionalSignature {
                big_r: RespondBidirectionalAffinePoint { x, y },
                s: s_bytes,
                recovery_id,
            },
        };
        args.serialize(&mut data)?;

        let instruction = solana_sdk::instruction::Instruction {
            program_id,
            accounts: vec![AccountMeta::new(self.payer_keypair.pubkey(), true)],
            data,
        };

        let recent_blockhash = self.rpc_client.get_latest_blockhash().await?;
        let mut transaction = solana_sdk::transaction::Transaction::new_with_payer(
            &[instruction],
            Some(&self.payer_keypair.pubkey()),
        );
        transaction.sign(&[&self.payer_keypair], recent_blockhash);

        let signature = self
            .rpc_client
            .send_and_confirm_transaction(&transaction)
            .await?;

        tracing::info!(
            ?signature,
            request_id = %hex::encode(request_id),
            "respond_bidirectional transaction successful",
        );

        Ok(signature)
    }
}

impl Drop for Solana {
    fn drop(&mut self) {
        if let Err(e) = self.process.kill() {
            tracing::warn!("failed to kill solana-test-validator process: {e}");
        } else {
            tracing::info!("solana-test-validator process terminated");
        }

        if let Err(e) = std::fs::remove_dir_all(&self.ledger_dir) {
            tracing::debug!(?self.ledger_dir, "failed to remove solana ledger dir: {e}");
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
struct SignArgs {
    payload: [u8; 32],
    key_version: u32,
    path: String,
    algo: String,
    dest: String,
    params: String,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct SignBidirectionalArgs {
    serialized_transaction: Vec<u8>,
    caip2_id: String,
    key_version: u32,
    path: String,
    algo: String,
    dest: String,
    params: String,
    program_id: [u8; 32],
    output_deserialization_schema: Vec<u8>,
    respond_serialization_schema: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RespondBidirectionalArgs {
    request_id: [u8; 32],
    serialized_output: Vec<u8>,
    signature: RespondBidirectionalSignature,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RespondBidirectionalSignature {
    big_r: RespondBidirectionalAffinePoint,
    s: [u8; 32],
    recovery_id: u8,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RespondBidirectionalAffinePoint {
    x: [u8; 32],
    y: [u8; 32],
}
