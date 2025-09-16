use std::collections::HashMap;
use std::path::Path;

use crate::cluster::spawner::ClusterSpawner;
use crate::local::NodeEnvConfig;
use crate::utils::pick_preferred_or_unused_port;
use crate::NodeConfig;

use anyhow::anyhow;
use async_process::{Child, Command};
use bollard::container::LogsOptions;
use bollard::network::CreateNetworkOptions;
use bollard::secret::Ipam;
use bollard::Docker;
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use elliptic_curve::rand_core::OsRng;
use futures::StreamExt as _;
use k256::Secp256k1;
use mpc_contract::primitives::Participants;
use mpc_keys::hpke;
use mpc_node::config::OverrideConfig;
use mpc_node::indexer_eth::EthArgs;
use mpc_node::protocol::triple::Triple;
use near_account_id::AccountId;
use near_workspaces::Account;
use solana_client::nonblocking::rpc_client::RpcClient as SolRpcClient;
use solana_sdk::signature::EncodableKey as _;
use solana_sdk::signature::Keypair as SolKeypair;
use solana_sdk::signer::{SeedDerivable, Signer};
use testcontainers::core::ExecCommand;
use testcontainers::ContainerAsync;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};
use tokio::io::AsyncWriteExt;
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
            },
        )
        .await
    }

    pub async fn kill(self) -> NodeEnvConfig {
        self.container.stop().await.unwrap();
        NodeEnvConfig {
            web_port: Self::CONTAINER_PORT,
            account: self.account,
            cipher_sk: self.cipher_sk,
            sign_sk: self.sign_sk,
            cfg: self.cfg,
            near_rpc: self.near_rpc,
        }
    }

    pub async fn spawn(ctx: &super::Context, config: NodeEnvConfig) -> anyhow::Result<Self> {
        let indexer_options = mpc_node::indexer::Options {
            running_threshold: 120,
        };
        let eth_args = EthArgs::from_config(config.cfg.eth.clone());
        let sol_args = mpc_node::indexer_sol::SolArgs::from_config(config.cfg.sol.clone());
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
        Self {
            docker: Docker::connect_with_local(
                "unix:///var/run/docker.sock",
                // 10 minutes timeout for all requests in case a lot of tests are being ran in parallel.
                600,
                bollard::API_DEFAULT_VERSION,
            )
            .unwrap(),
        }
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

    pub fn triple_storage(&self, id: &AccountId) -> mpc_node::storage::TripleStorage {
        mpc_node::storage::triple_storage::init(&self.pool(), id)
    }

    pub fn presignature_storage(&self, id: &AccountId) -> mpc_node::storage::PresignatureStorage {
        mpc_node::storage::presignature_storage::init(&self.pool(), id)
    }

    pub async fn stockpile_triples(&self, cfg: &NodeConfig, participants: &Participants, mul: u32) {
        let pool = self.pool();
        let storage = participants
            .participants
            .keys()
            .map(|account_id| {
                (
                    Participant::from(
                        *participants
                            .account_to_participant_id
                            .get(account_id)
                            .unwrap(),
                    ),
                    mpc_node::storage::triple_storage::init(&pool, account_id),
                )
            })
            .collect::<HashMap<_, _>>();

        let participant_ids = participants
            .account_to_participant_id
            .values()
            .map(|id| Participant::from(*id))
            .collect::<Vec<_>>();
        let (public, shares) =
            cait_sith::triples::deal(&mut OsRng, &participant_ids, cfg.threshold);

        // - first/second loop add at least min_triples per node
        // - third loop: for each triple, store the shares individually per node
        let mut num_triples = 0;
        for owner in &participant_ids {
            for _ in 0..(cfg.protocol.triple.min_triples * mul) {
                num_triples += 1;
                let triple_id = rand::random();
                for (me, triple) in participant_ids
                    .iter()
                    .zip(shares_to_triples(triple_id, &public, &shares))
                {
                    storage
                        .get(me)
                        .unwrap()
                        .reserve(triple.id)
                        .await
                        .unwrap()
                        .insert(triple, *owner)
                        .await;
                }
            }
        }

        tracing::info!("stockpiled {num_triples} triples");
    }
}

fn shares_to_triples(
    id: u64,
    public: &TriplePub<Secp256k1>,
    shares: &[TripleShare<Secp256k1>],
) -> Vec<Triple> {
    shares
        .iter()
        .map(|share| Triple {
            id,
            public: public.clone(),
            share: share.clone(),
        })
        .collect()
}

pub struct Solana {
    pub process: Child,
    pub rpc_address: String,
    pub ws_address: String,
    pub program_keypair: SolKeypair,
    pub payer_keypair: SolKeypair,
    pub rpc_port: u16,
    pub ws_port: u16,
    pub rpc_client: SolRpcClient,
}

impl Solana {
    /// Program ID hardcoded in the solana program/contract.
    pub const PROGRAM_ID: &str = "FR5pWwinRBn35GNhg7bsvw8Q13kRept2pm561DwZCQzT";
    pub const PROGRAM_PATH: &str = "chain-signatures/contract-sol/artifacts/chain_signatures.so";

    /// Fixed keypair for deterministic program address/id. This is embedded in the declare_id!
    /// macro of our Solana program/contract.
    pub fn program_keypair() -> SolKeypair {
        SolKeypair::from_seed(&[101u8; 32]).unwrap()
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

        // Find available ports for RPC and WebSocket
        // Find available ports (websocket is automatically rpc_port + 1)
        let rpc_port = pick_preferred_or_unused_port(8899).await;
        let ws_port = rpc_port + 1;

        let rpc_address = format!("http://127.0.0.1:{}", rpc_port);
        let ws_address = format!("ws://127.0.0.1:{}", ws_port);

        // Start the solana-test-validator process
        let process = Command::new("solana-test-validator")
            .arg("--rpc-port")
            .arg(rpc_port.to_string())
            .arg("--bind-address")
            .arg("127.0.0.1")
            .arg("--reset")
            .arg("--quiet")
            .spawn()
            .expect("failed to start solana-test-validator");

        // Wait a bit for the validator to start up
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        tracing::info!(
            rpc_address,
            ws_address,
            "solana-test-validator process is running",
        );

        let payer_keypair = SolKeypair::from_seed(&[102u8; 32]).unwrap();
        let rpc_client = SolRpcClient::new_with_commitment(
            rpc_address.clone(),
            solana_sdk::commitment_config::CommitmentConfig::confirmed(),
        );

        Self {
            process,
            rpc_address,
            ws_address,
            program_keypair,
            payer_keypair,
            rpc_port,
            ws_port,
            rpc_client,
        }
    }

    pub fn get_config(&self, program_address: String) -> mpc_node::indexer_sol::SolConfig {
        mpc_node::indexer_sol::SolConfig {
            account_sk: bs58::encode(self.payer_keypair.to_bytes()).into_string(),
            rpc_http_url: self.rpc_address.clone(),
            rpc_ws_url: self.ws_address.clone(),
            program_address,
            total_timeout: 60, // Default timeout in seconds
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

        // Request airdrop for the payer to fund deployment
        tracing::info!(
            ?payer_keypair_path,
            "requesting solana airdrop for deployment..."
        );
        let airdrop_output = tokio::process::Command::new("solana")
            .args([
                "airdrop",
                "10", // 10 SOL should be enough for whatever action
                "--url",
                &self.rpc_address,
                "--keypair",
                payer_keypair_path.to_str().unwrap(),
            ])
            .output()
            .await?;

        if !airdrop_output.status.success() {
            let stderr = String::from_utf8_lossy(&airdrop_output.stderr);
            tracing::warn!(?payer_keypair_path, "failed to airdrop SOL: {stderr}",);
        }

        // Deploy the program using solana CLI
        tracing::info!("deploying solana program via CLI...");
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
        let payer = std::sync::Arc::new(SolKeypair::from_bytes(&self.payer_keypair.to_bytes())?);
        let program_id = self.program_keypair.pubkey();

        // Define program state PDA
        let (program_state_pda, _bump) =
            solana_sdk::pubkey::Pubkey::find_program_address(&[b"program-state"], &program_id);

        // Call initialize function
        let signature_deposit = 1_000_000u64; // 0.001 SOL in lamports
        let chain_id = "solana:localnet".to_string(); // CAIP-2 format for local testnet

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
                solana_sdk::instruction::AccountMeta::new(program_state_pda, false),
                solana_sdk::instruction::AccountMeta::new(payer.pubkey(), true),
                solana_sdk::instruction::AccountMeta::new_readonly(
                    solana_sdk::system_program::id(),
                    false,
                ),
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
    ) -> anyhow::Result<solana_sdk::signature::Signature> {
        // Check if the RPC client can get the version (basic readiness check)
        if self.rpc_client.get_version().await.is_err() {
            anyhow::bail!("solana container is not ready");
        }

        let program_id = self.program_keypair.pubkey();
        tracing::info!("using program_id for sign: {program_id}");

        // Define program state PDA (required by the sign function)
        let (program_state_pda, _bump) =
            solana_sdk::pubkey::Pubkey::find_program_address(&[b"program-state"], &program_id);

        // Define event authority PDA for CPI events
        let (event_authority_pda, _bump) =
            solana_sdk::pubkey::Pubkey::find_program_address(&[b"__event_authority"], &program_id);

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
            algo: "secp256k1".to_string(),
            dest: "integration_test".to_string(),
            params: "{}".to_string(),
        };
        args.serialize(&mut data)?;

        // Create the instruction with correct accounts matching the external contract
        // note that #[event_cpi] requires additional accounts
        let instruction = solana_sdk::instruction::Instruction {
            program_id,
            accounts: vec![
                // program_state account (writable, not signer)
                solana_sdk::instruction::AccountMeta::new(program_state_pda, false),
                // requester (writable, signer)
                solana_sdk::instruction::AccountMeta::new(self.payer_keypair.pubkey(), true),
                // fee_payer (writable, signer) - same as requester for simplicity
                solana_sdk::instruction::AccountMeta::new(self.payer_keypair.pubkey(), true),
                // system_program (readonly, not signer)
                solana_sdk::instruction::AccountMeta::new_readonly(
                    solana_sdk::system_program::id(),
                    false,
                ),
                // event_authority (readonly, not signer) - required for #[event_cpi]
                solana_sdk::instruction::AccountMeta::new_readonly(event_authority_pda, false),
                // program account (readonly, not signer) - required for #[event_cpi]
                solana_sdk::instruction::AccountMeta::new_readonly(program_id, false),
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
}

impl Drop for Solana {
    fn drop(&mut self) {
        if let Err(e) = self.process.kill() {
            tracing::warn!("failed to kill solana-test-validator process: {e}");
        } else {
            tracing::info!("solana-test-validator process terminated");
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
