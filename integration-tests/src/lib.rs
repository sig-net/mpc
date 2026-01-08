pub mod actions;
pub mod cluster;
pub mod containers;
pub mod eth;
pub mod execute;
pub mod local;
pub mod mpc_fixture;
pub mod utils;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use self::local::NodeEnvConfig;
use crate::containers::DockerClient;

use anyhow::Context as _;
use cluster::spawner::ClusterSpawner;
use deadpool_redis::Pool;
use ethers::types::{Address, U256};
use mpc_contract::config::{PresignatureConfig, ProtocolConfig, TripleConfig};
use mpc_contract::primitives::CandidateInfo;
use mpc_node::gcp::GcpService;
use mpc_node::indexer_eth::EthConfig;
use mpc_node::indexer_hydration::HydrationConfig;
use mpc_node::indexer_sol::SolConfig;
use mpc_node::storage::triple_storage::{TriplePair, TripleStorage};
use mpc_node::{logs, mesh, node_client, storage};
use mpc_primitives::{Chain, Checkpoint};
use near_workspaces::network::Sandbox;
use near_workspaces::types::{KeyType, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::json;

/// Specifies which binary to use when spawning a node
#[derive(Clone, Debug)]
pub enum NodeBinarySource {
    /// Use the current compiled code from target/release
    CurrentCode,
    /// Use the tagged mainnet binary compiled under target/compat/mainnet/<version>
    Mainnet,
    /// Use the tagged testnet binary compiled under target/compat/testnet/<version>
    Testnet,
}

impl NodeBinarySource {
    /// Get the binary path for this source
    pub fn binary_path(&self) -> anyhow::Result<Option<PathBuf>> {
        match self {
            // Will use default executable lookup
            NodeBinarySource::CurrentCode => Ok(None),
            NodeBinarySource::Mainnet => Ok(Some(execute::compatibility_binary("mainnet")?)),
            NodeBinarySource::Testnet => Ok(Some(execute::compatibility_binary("testnet")?)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub nodes: usize,
    pub threshold: usize,
    pub protocol: ProtocolConfig,
    pub eth: Option<EthConfig>,
    pub sol: Option<SolConfig>,
    pub hydration: Option<HydrationConfig>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            nodes: 3,
            threshold: 2,
            protocol: ProtocolConfig {
                max_concurrent_generation: 16,
                max_concurrent_introduction: 2,
                triple: TripleConfig {
                    min_triples: 16,
                    max_triples: 320,
                    ..Default::default()
                },
                presignature: PresignatureConfig {
                    min_presignatures: 16,
                    max_presignatures: 320,
                    ..Default::default()
                },
                ..Default::default()
            },
            eth: None,
            sol: None,
            hydration: None,
        }
    }
}

pub enum Nodes {
    Local {
        next_id: usize,
        ctx: Context,
        nodes: Vec<local::Node>,
    },
    Docker {
        next_id: usize,
        ctx: Context,
        nodes: Vec<containers::Node>,
    },
}

impl Nodes {
    pub fn len(&self) -> usize {
        match self {
            Nodes::Local { nodes, .. } => nodes.len(),
            Nodes::Docker { nodes, .. } => nodes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn ctx(&self) -> &Context {
        match self {
            Nodes::Local { ctx, .. } => ctx,
            Nodes::Docker { ctx, .. } => ctx,
        }
    }

    pub fn url(&self, id: usize) -> &str {
        match self {
            Nodes::Local { nodes, .. } => &nodes[id].address,
            Nodes::Docker { nodes, .. } => &nodes[id].address,
        }
    }

    pub fn account_id(&self, id: usize) -> &AccountId {
        match self {
            Nodes::Local { nodes, .. } => nodes[id].account.id(),
            Nodes::Docker { nodes, .. } => nodes[id].account.id(),
        }
    }

    pub fn near_accounts(&self) -> Vec<&Account> {
        match self {
            Nodes::Local { nodes, .. } => nodes.iter().map(|node| &node.account).collect(),
            Nodes::Docker { nodes, .. } => nodes.iter().map(|node| &node.account).collect(),
        }
    }

    pub async fn start_node(
        &mut self,
        cfg: &NodeConfig,
        new_account: &Account,
    ) -> anyhow::Result<usize> {
        tracing::info!(id = %new_account.id(), "adding one more node");
        match self {
            Nodes::Local {
                next_id,
                ctx,
                nodes,
            } => {
                nodes.push(local::Node::run(ctx, cfg, new_account).await?);
                *next_id += 1;
                Ok(nodes.len() - 1)
            }
            Nodes::Docker {
                next_id,
                ctx,
                nodes,
            } => {
                nodes.push(containers::Node::run(ctx, cfg, new_account).await?);
                *next_id += 1;
                Ok(nodes.len() - 1)
            }
        }
    }

    pub async fn kill_node(&mut self, account_id: &AccountId) -> NodeEnvConfig {
        let killed_node_config = match self {
            Nodes::Local { nodes, .. } => {
                let index = nodes
                    .iter()
                    .position(|node| node.account.id() == account_id)
                    .unwrap();
                nodes.remove(index).kill()
            }
            Nodes::Docker { nodes, .. } => {
                let index = nodes
                    .iter()
                    .position(|node| node.account.id() == account_id)
                    .unwrap();
                nodes.remove(index).kill().await
            }
        };

        // wait for the node to be removed from the network
        tokio::time::sleep(Duration::from_secs(3)).await;

        killed_node_config
    }

    pub fn kill_all(&mut self) {
        match self {
            Nodes::Local { nodes, .. } => {
                for node in nodes.drain(..) {
                    node.kill();
                }
            }
            Nodes::Docker { nodes, .. } => {
                for node in nodes.drain(..) {
                    tokio::spawn(node.kill());
                }
            }
        }
    }

    pub async fn restart_node(&mut self, config: NodeEnvConfig) -> anyhow::Result<()> {
        tracing::info!(node_account_id = %config.account.id(), "restarting node");
        match self {
            Nodes::Local {
                next_id,
                ctx,
                nodes,
            } => {
                nodes.push(local::Node::spawn(ctx, config).await?);
                *next_id += 1;
            }
            Nodes::Docker {
                next_id,
                ctx,
                nodes,
            } => {
                nodes.push(containers::Node::spawn(ctx, config).await?);
                *next_id += 1;
            }
        }
        // wait for the node to be added to the network
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(())
    }

    pub async fn triple_storage(&self, redis_pool: &Pool, account_id: &AccountId) -> TripleStorage {
        TriplePair::storage(redis_pool, account_id)
    }

    pub async fn gcp_services(&self) -> anyhow::Result<Vec<GcpService>> {
        let mut gcp_services = Vec::new();
        match self {
            Nodes::Local { nodes, .. } => {
                for node in nodes {
                    gcp_services.push(
                        GcpService::init(node.account.id(), &self.ctx().storage_options).await?,
                    );
                }
            }
            Nodes::Docker { nodes, .. } => {
                for node in nodes {
                    gcp_services.push(
                        GcpService::init(node.account.id(), &self.ctx().storage_options).await?,
                    );
                }
            }
        }
        Ok(gcp_services)
    }

    pub fn proxy_name_for_node(&self, id: usize) -> String {
        let account_id = self.near_accounts();
        format!("rpc_from_node_{}", account_id[id].id())
    }

    pub fn contract(&self) -> &Contract {
        &self.ctx().mpc_contract
    }

    pub async fn fetch_checkpoint(&self, id: usize, chain: Chain) -> anyhow::Result<Checkpoint> {
        let url = format!("{}/checkpoint?query={chain}", self.url(id));
        let response = reqwest::get(&url).await?;
        let status = response.status();
        let body = response.bytes().await?;
        let mut value: HashMap<Chain, Checkpoint> =
            ciborium::from_reader(body.as_ref()).context("failed to decode checkpoint CBOR")?;
        if let Ok(pretty) = serde_json::to_string(&value) {
            tracing::info!(?status, raw_body = %pretty, "checkpoint response body");
        } else {
            tracing::info!(?status, raw_body = %hex::encode(&body), "checkpoint response body");
        }
        value
            .remove(&chain)
            .context("checkpoint not found for chain")
    }

    pub async fn fetch_checkpoints(&self, id: usize) -> anyhow::Result<HashMap<Chain, Checkpoint>> {
        let url = format!("{}/checkpoint", self.url(id));
        let response = reqwest::get(&url).await?;
        let status = response.status();
        let body = response.bytes().await?;
        let value: HashMap<Chain, Checkpoint> =
            ciborium::from_reader(body.as_ref()).context("failed to decode checkpoint CBOR")?;
        if let Ok(pretty) = serde_json::to_string(&value) {
            tracing::info!(?status, raw_body = %pretty, "checkpoint response body");
        } else {
            tracing::info!(?status, raw_body = %hex::encode(&body), "checkpoint response body");
        }
        Ok(value)
    }
}

impl Drop for Nodes {
    fn drop(&mut self) {
        self.kill_all();
    }
}

pub struct EthereumContext {
    pub sandbox: containers::EthereumSandbox,
    pub contract_address: Address,
    pub deployer_address: Address,
}

pub struct Context {
    pub docker_client: DockerClient,
    pub docker_network: String,
    pub release: bool,

    pub worker: Worker<Sandbox>,
    pub mpc_contract: Contract,
    pub redis: containers::Redis,
    pub storage_options: storage::Options,
    pub log_options: logs::Options,
    pub mesh_options: mesh::Options,
    pub message_options: node_client::Options,
    pub ethereum: Option<EthereumContext>,
}

pub async fn setup(spawner: &mut ClusterSpawner) -> anyhow::Result<Context> {
    let worker = spawner.take_worker().await;
    spawner.create_accounts(&worker).await;

    let mpc_contract = worker
        .dev_deploy(&std::fs::read(
            execute::target_dir()
                .context("could not find target dir")?
                .join("wasm32-unknown-unknown/release/mpc_contract.wasm"),
        )?)
        .await?;
    tracing::info!(contract_id = %mpc_contract.id(), "deployed mpc contract");

    let redis = spawner.take_redis().await;

    let sk_share_local_path = spawner.tmp_dir.join("secrets");
    std::fs::create_dir_all(&sk_share_local_path).expect("could not create secrets dir");
    let sk_share_local_path = sk_share_local_path.to_string_lossy().to_string();

    let mut ethereum = None;
    if spawner.use_ethereum {
        let sandbox = containers::EthereumSandbox::run(spawner).await?;

        let (client, deployer_address) = eth::client(
            &sandbox.external_http_endpoint,
            &sandbox.secret_key,
            sandbox.chain_id,
        )?;
        let contract_address =
            eth::deploy_chain_signatures(client, deployer_address, U256::zero()).await?;

        let rpc_endpoint = if cfg!(feature = "docker-test") {
            sandbox.internal_http_endpoint.clone()
        } else {
            sandbox.external_http_endpoint.clone()
        };

        let contract_address_hex = hex::encode(contract_address);
        spawner.cfg.eth = Some(EthConfig {
            account_sk: sandbox.secret_key.clone(),
            consensus_rpc_http_url: rpc_endpoint.clone(),
            execution_rpc_http_url: rpc_endpoint,
            contract_address: contract_address_hex.clone(),
            network: "sepolia".to_string(),
            helios_data_path: format!("/tmp/helios-{}", contract_address_hex),
            refresh_finalized_interval: 1_000,
            total_timeout: 600,
            optimistic_requests: true,
            light_client: false,
        });

        ethereum = Some(EthereumContext {
            sandbox,
            contract_address,
            deployer_address,
        });
    }

    let storage_options = mpc_node::storage::Options {
        env: spawner.env.clone(),
        gcp_project_id: spawner.gcp_project_id.clone(),
        sk_share_secret_id: None,
        sk_share_local_path: Some(sk_share_local_path),
        redis_url: redis.internal_address.clone(),
    };

    let log_options = logs::Options::test();

    let mesh_options = mpc_node::mesh::Options {
        ping_interval: 1000,
    };

    let message_options = node_client::Options {
        timeout: 1000,
        state_timeout: 1000,
    };

    // If using pregenerated keys, inject them into storage before nodes start
    if spawner.pregenerated_keys.is_enabled() {
        tracing::info!("injecting pregenerated keyshares into storage...");
        for (i, account) in spawner.accounts.iter().enumerate() {
            let participant = cait_sith::protocol::Participant::from(i as u32);
            if let Some(key_info) = spawner.pregenerated_keys.get(&participant) {
                let mut secret_storage = storage::secret_storage::init(
                    None, // No GCP service for tests
                    &storage_options,
                    account.id(),
                );

                let persistent_data = mpc_node::protocol::state::PersistentNodeData {
                    epoch: 0,
                    private_share: key_info.private_share,
                    public_key: key_info.public_key,
                };

                let account_id = account.id().to_string();
                if let Err(err) = secret_storage.store(&persistent_data).await {
                    tracing::error!(?err, "failed to store pregenerated key");
                    continue;
                }

                tracing::info!(?account_id, "stored key share for participant");
            }
        }
    }

    Ok(Context {
        docker_client: spawner.docker.clone(),
        docker_network: spawner.network.clone(),
        release: spawner.release,
        worker,
        mpc_contract,
        redis,
        storage_options,
        log_options,
        mesh_options,
        message_options,
        ethereum,
    })
}

pub async fn docker(spawner: &mut ClusterSpawner) -> anyhow::Result<Nodes> {
    let ctx = setup(spawner).await?;
    let cfg = &spawner.cfg;

    let node_futures = spawner
        .accounts
        .iter()
        .map(|account| containers::Node::run(&ctx, cfg, account));
    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let candidates: HashMap<AccountId, CandidateInfo> = spawner
        .accounts
        .iter()
        .zip(&nodes)
        .map(|(account, node)| {
            (
                account.id().clone(),
                CandidateInfo {
                    account_id: account.id().as_str().parse().unwrap(),
                    url: node.address.clone(),
                    cipher_pk: node.cipher_sk.public_key().to_bytes(),
                    sign_pk: node.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();

    if let Some(public_key) = spawner.pregenerated_keys.public_key() {
        // Use init_running to skip key generation
        let participants =
            mpc_contract::primitives::Participants::from(mpc_contract::primitives::Candidates {
                candidates: candidates.clone().into_iter().collect(),
            });
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let near_pk = near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(
                &public_key.to_encoded_point(false).as_bytes()[1..65],
            )
            .unwrap(),
        );
        ctx.mpc_contract
            .call("init_running")
            .args_json(json!({
                "epoch": 0,
                "participants": participants,
                "threshold": cfg.threshold,
                "public_key": near_pk,
            }))
            .transact()
            .await?
            .into_result()?;
        tracing::info!("contract initialized with pregenerated keys (skipped keygen)");
    } else {
        ctx.mpc_contract
            .call("init")
            .args_json(json!({
                "threshold": cfg.threshold,
                "candidates": candidates
            }))
            .transact()
            .await?
            .into_result()?;
        tracing::info!("contract initialized, will generate keys...");
    }

    Ok(Nodes::Docker {
        next_id: nodes.len(),
        ctx,
        nodes,
    })
}

pub async fn dry_host(spawner: &mut ClusterSpawner) -> anyhow::Result<Context> {
    let ctx = setup(spawner).await?;
    let cfg = &spawner.cfg;

    let mut node_cfgs = Vec::new();
    for account in spawner.accounts.iter() {
        node_cfgs.push(local::Node::dry_run(&ctx, account, cfg).await?);
    }

    let candidates: HashMap<AccountId, CandidateInfo> = spawner
        .accounts
        .iter()
        .zip(&node_cfgs)
        .map(|(account, node_cfg)| {
            (
                account.id().clone(),
                CandidateInfo {
                    account_id: account.id().as_str().parse().unwrap(),
                    url: format!("http://127.0.0.1:{0}", node_cfg.web_port),
                    cipher_pk: node_cfg.cipher_sk.public_key().to_bytes(),
                    sign_pk: node_cfg.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();

    println!("\nPlease call below to update localnet:\n");
    let near_rpc = ctx.worker.rpc_addr();
    println!("near config add-connection --network-name local --connection-name local --rpc-url {near_rpc} --wallet-url http://127.0.0.1/ --explorer-transaction-url http://127.0.0.1:6666/");
    println!("\nAfter run the nodes, please call the following command to init contract: ");
    let args = json!({
        "threshold": cfg.threshold,
        "candidates": candidates
    })
    .to_string();
    let sk = SecretKey::from_seed(KeyType::ED25519, "testificate");

    println!("near contract call-function as-transaction {} init json-args '{}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as {} network-config local sign-with-plaintext-private-key --signer-public-key {} --signer-private-key {} send",
             ctx.mpc_contract.id(),
             args,
             ctx.mpc_contract.id(),
             sk.public_key(),
             sk
    );
    println!();

    Ok(ctx)
}

pub async fn host(spawner: &mut ClusterSpawner) -> anyhow::Result<Nodes> {
    let setup_start = std::time::Instant::now();
    let ctx = setup(spawner).await?;
    tracing::info!("⏱️  setup (total) took: {:?}", setup_start.elapsed());

    let cfg = &spawner.cfg;

    let spawn_nodes_start = std::time::Instant::now();
    let node_futures = spawner
        .accounts
        .iter()
        .zip(std::mem::take(&mut spawner.node_binary_sources).into_iter())
        .map(|(account, source)| {
            let binary_path = source.binary_path().unwrap();
            local::Node::run_with_binary(&ctx, cfg, account, binary_path)
        });
    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    tracing::info!(
        elapsed = ?spawn_nodes_start.elapsed(),
        "all mpc nodes have been spawned",
    );
    let candidates: HashMap<AccountId, CandidateInfo> = spawner
        .accounts
        .iter()
        .zip(&nodes)
        .map(|(account, node)| {
            (
                account.id().clone(),
                CandidateInfo {
                    account_id: account.id().as_str().parse().unwrap(),
                    url: node.address.clone(),
                    cipher_pk: node.cipher_sk.public_key().to_bytes(),
                    sign_pk: node.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();

    // Initialize contract based on whether we're using pregenerated keys
    let init_contract_start = std::time::Instant::now();
    if let Some(public_key) = spawner.pregenerated_keys.public_key() {
        // Use init_running to skip key generation
        let candidates_struct = mpc_contract::primitives::Candidates {
            candidates: candidates.clone().into_iter().collect(),
        };
        let participants = mpc_contract::primitives::Participants::from(candidates_struct);
        // Convert secp256k1 public key to NEAR public key format (secp256k1)
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let near_pk = near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(
                &public_key.to_encoded_point(false).as_bytes()[1..65],
            )
            .unwrap(),
        );
        ctx.mpc_contract
            .call("init_running")
            .args_json(json!({
                "epoch": 0,
                "participants": participants,
                "threshold": cfg.threshold,
                "public_key": near_pk,
            }))
            .transact()
            .await?
            .into_result()?;
        tracing::info!("contract initialized with pregenerated keys (skipped keygen)");
    } else {
        // Standard init - will trigger key generation
        ctx.mpc_contract
            .call("init")
            .args_json(json!({
                "threshold": cfg.threshold,
                "candidates": candidates
            }))
            .transact()
            .await?
            .into_result()?;
    }
    tracing::info!(
        elapsed = ?init_contract_start.elapsed(),
        "governance contract initialized"
    );

    Ok(Nodes::Local {
        next_id: nodes.len(),
        ctx,
        nodes,
    })
}

pub async fn run(spawner: &mut ClusterSpawner) -> anyhow::Result<Nodes> {
    #[cfg(feature = "docker-test")]
    return docker(spawner).await;

    #[cfg(not(feature = "docker-test"))]
    return host(spawner).await;
}

pub async fn dry_run(spawner: &mut ClusterSpawner) -> anyhow::Result<Context> {
    #[cfg(feature = "docker-test")]
    unimplemented!("dry_run only works with native node");

    #[cfg(not(feature = "docker-test"))]
    return dry_host(spawner).await;
}
