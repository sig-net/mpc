pub mod containers;
pub mod execute;
pub mod local;
pub mod types;
pub mod utils;

use crate::containers::Container;
use crate::containers::{DockerClient, LocalStack};
use crate::types::{NodeConfig, NodeEnvConfig, NodeSpawnConfig};

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Context as _;
use bollard::exec::{CreateExecOptions, StartExecResults};
use deadpool_redis::Pool;
use futures::StreamExt;
use mpc_contract::primitives::CandidateInfo;
use mpc_node::gcp::GcpService;
use mpc_node::http_client;
use mpc_node::mesh;
use mpc_node::storage;
use mpc_node::storage::triple_storage::TripleStorage;
use near_crypto::KeyFile;
use near_sdk::NearToken;
use near_workspaces::network::{Sandbox, ValidatorKey};
use near_workspaces::types::{KeyType, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::json;

const NETWORK: &str = "mpc_it_network";

pub enum Nodes {
    Local {
        ctx: Context,
        nodes: Vec<local::Node>,
    },
    Docker {
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

    pub fn near_accounts(&self) -> Vec<&Account> {
        match self {
            Nodes::Local { nodes, .. } => nodes.iter().map(|node| &node.account).collect(),
            Nodes::Docker { nodes, .. } => nodes.iter().map(|node| &node.account).collect(),
        }
    }

    pub async fn start_node(&mut self, spawn_cfg: NodeSpawnConfig) -> anyhow::Result<()> {
        tracing::info!(id = %spawn_cfg.account.id(), "adding one more node");
        match self {
            Nodes::Local { ctx, nodes } => nodes.push(local::Node::run(ctx, spawn_cfg).await?),
            Nodes::Docker { ctx, nodes } => {
                nodes.push(containers::Node::run(ctx, spawn_cfg).await?)
            }
        }

        Ok(())
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
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        killed_node_config
    }

    pub async fn restart_node(&mut self, config: NodeEnvConfig) -> anyhow::Result<()> {
        tracing::info!(node_account_id = %config.account.id(), "restarting node");
        match self {
            Nodes::Local { ctx, nodes } => nodes.push(local::Node::spawn(ctx, config).await?),
            Nodes::Docker { ctx, nodes } => nodes.push(containers::Node::spawn(ctx, config).await?),
        }
        // wait for the node to be added to the network
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        Ok(())
    }

    pub async fn triple_storage(&self, redis_pool: &Pool, account_id: &AccountId) -> TripleStorage {
        storage::triple_storage::init(redis_pool, account_id)
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
}

pub struct Context {
    pub docker_client: DockerClient,
    pub docker_network: String,
    pub release: bool,

    pub localstack: containers::LocalStack,
    pub lake_indexer: containers::LakeIndexer,
    pub worker: Worker<Sandbox>,
    pub mpc_contract: Contract,
    pub redis: containers::Redis,
    pub storage_options: storage::Options,
    pub mesh_options: mesh::Options,
    pub message_options: http_client::Options,
    pub candidates: HashMap<AccountId, CandidateInfo>,

    /// Path to a temporary directory either located in /tmp or our target folder.
    pub test_env: PathBuf,
}

pub async fn setup(
    cfg: &NodeConfig,
    docker_client: &DockerClient,
    accounts: Option<Vec<Account>>,
) -> anyhow::Result<(Vec<NodeSpawnConfig>, Context)> {
    let release = true;
    let docker_network = NETWORK;
    docker_client.create_network(docker_network).await?;

    let LakeIndexer {
        localstack,
        lake_indexer,
        worker,
    } = LakeIndexer::spawn(docker_client, docker_network).await?;

    let accounts = if let Some(accounts) = accounts {
        accounts
    } else {
        let root = worker.root_account().unwrap();
        let mut accounts = Vec::with_capacity(cfg.nodes);
        for i in 0..cfg.nodes {
            let account = root
                .create_subaccount(&format!("node{i}"))
                .initial_balance(NearToken::from_near(100))
                .transact()
                .await?
                .into_result()?;
            accounts.push(account);
        }
        accounts
    };

    let mut spawn_configs = Vec::with_capacity(cfg.nodes);
    for account in &accounts {
        spawn_configs.push(NodeSpawnConfig::new(cfg, account).await);
    }

    let candidates: HashMap<AccountId, CandidateInfo> = accounts
        .iter()
        .cloned()
        .zip(&spawn_configs)
        .map(|(account, spawn_cfg)| {
            (
                account.id().clone(),
                CandidateInfo {
                    account_id: account.id().as_str().parse().unwrap(),
                    url: spawn_cfg.address(),
                    cipher_pk: spawn_cfg.secrets.cipher_pk.to_bytes(),
                    sign_pk: spawn_cfg
                        .secrets
                        .sign_sk
                        .public_key()
                        .to_string()
                        .parse()
                        .unwrap(),
                },
            )
        })
        .collect();

    let mpc_contract = worker
        .dev_deploy(&std::fs::read(
            forge::target_dir()
                .context("could not find target dir")?
                .join("wasm32-unknown-unknown/release/mpc_contract.wasm"),
        )?)
        .await?;
    tracing::info!(contract_id = %mpc_contract.id(), "deployed mpc contract");

    mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": cfg.threshold,
            "candidates": &candidates
        }))
        .transact()
        .await?
        .into_result()?;
    tracing::info!("initialized mpc contract");

    let redis = containers::Redis::run(docker_client, docker_network).await;
    let redis_url = redis.internal_address.clone();

    let test_env = forge::new_test_env_dir()?;
    let sk_share_local_path = test_env.join("secrets");
    std::fs::create_dir_all(&sk_share_local_path)?;
    let sk_share_local_path = sk_share_local_path
        .join("persistent-node-data")
        .to_string_lossy()
        .to_string();
    let storage_options = mpc_node::storage::Options {
        env: "local-test".to_string(),
        gcp_project_id: "multichain-integration".to_string(),
        sk_share_secret_id: None,
        sk_share_local_path: Some(sk_share_local_path),
        redis_url,
    };

    let mesh_options = mpc_node::mesh::Options {
        fetch_participant_timeout: 1000,
        refresh_active_timeout: 1000,
    };

    let message_options = http_client::Options { timeout: 1000 };

    Ok((
        spawn_configs,
        Context {
            docker_client: docker_client.clone(),
            docker_network: docker_network.to_string(),
            release,
            localstack,
            lake_indexer,
            worker,
            mpc_contract,
            redis,
            storage_options,
            mesh_options,
            message_options,
            candidates,
            test_env,
        },
    ))
}

pub async fn docker(
    cfg: &NodeConfig,
    docker_client: &DockerClient,
    accounts: Option<Vec<Account>>,
) -> anyhow::Result<Nodes> {
    let (spawn_configs, ctx) = setup(cfg, docker_client, accounts).await?;
    let node_futures = spawn_configs
        .into_iter()
        .map(|spawn_cfg| containers::Node::run(&ctx, spawn_cfg));

    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Nodes::Docker { ctx, nodes })
}

pub async fn dry_host(cfg: &NodeConfig, docker_client: &DockerClient) -> anyhow::Result<Context> {
    let (spawn_configs, ctx) = setup(cfg, docker_client, None).await?;

    let _node_futures = spawn_configs
        .into_iter()
        .map(|spawn_cfg| local::Node::dry_run(&ctx, spawn_cfg));

    println!("\nPlease call below to update localnet:\n");
    let near_rpc = ctx.lake_indexer.rpc_host_address.clone();
    println!("near config add-connection --network-name local --connection-name local --rpc-url {} --wallet-url http://127.0.0.1/ --explorer-transaction-url http://127.0.0.1:6666/", near_rpc);
    println!("\nAfter run the nodes, please call the following command to init contract: ");
    let args = json!({
        "threshold": cfg.threshold,
        "candidates": ctx.candidates,
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

pub async fn host(
    cfg: &NodeConfig,
    docker_client: &DockerClient,
    accounts: Option<Vec<Account>>,
) -> anyhow::Result<Nodes> {
    let (spawn_configs, ctx) = setup(cfg, docker_client, accounts).await?;
    let node_futures = spawn_configs
        .into_iter()
        .map(|spawn_cfg| local::Node::run(&ctx, spawn_cfg));

    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Nodes::Local { ctx, nodes })
}

pub async fn run(
    cfg: &NodeConfig,
    docker_client: &DockerClient,
    accounts: Option<Vec<Account>>,
) -> anyhow::Result<Nodes> {
    if let Some(accounts) = &accounts {
        if accounts.len() != cfg.nodes {
            anyhow::bail!(
                "number of accounts does not match number of nodes: {} != {}",
                accounts.len(),
                cfg.nodes
            );
        }
    }

    #[cfg(feature = "docker-test")]
    return docker(cfg, docker_client, accounts).await;

    #[cfg(not(feature = "docker-test"))]
    return host(cfg, docker_client, accounts).await;
}

pub async fn dry_run(cfg: &NodeConfig, docker_client: &DockerClient) -> anyhow::Result<Context> {
    #[cfg(feature = "docker-test")]
    unimplemented!("dry_run only works with native node");

    #[cfg(not(feature = "docker-test"))]
    return dry_host(cfg, docker_client).await;
}

async fn fetch_from_validator(
    docker_client: &DockerClient,
    container: &Container,
    path: &str,
) -> anyhow::Result<Vec<u8>> {
    tracing::info!(path, "fetching data from validator");
    let create_result = docker_client
        .docker
        .create_exec(
            container.id(),
            CreateExecOptions::<&str> {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec!["cat", path]),
                ..Default::default()
            },
        )
        .await?;

    let start_result = docker_client
        .docker
        .start_exec(&create_result.id, None)
        .await?;

    match start_result {
        StartExecResults::Attached { mut output, .. } => {
            let mut stream_contents = Vec::new();
            while let Some(chunk) = output.next().await {
                stream_contents.extend_from_slice(&chunk?.into_bytes());
            }

            tracing::info!("data fetched");
            Ok(stream_contents)
        }
        StartExecResults::Detached => unreachable!("unexpected detached output"),
    }
}

async fn fetch_validator_keys(
    docker_client: &DockerClient,
    container: &Container,
) -> anyhow::Result<KeyFile> {
    let _span = tracing::info_span!("fetch_validator_keys");
    let key_data =
        fetch_from_validator(docker_client, container, "/root/.near/validator_key.json").await?;
    Ok(serde_json::from_slice(&key_data)?)
}

pub struct LakeIndexer {
    pub localstack: containers::LocalStack,
    pub lake_indexer: containers::LakeIndexer,
    pub worker: Worker<Sandbox>,
}

impl LakeIndexer {
    pub async fn spawn(docker_client: &DockerClient, network: &str) -> anyhow::Result<Self> {
        let s3_bucket = "near-lake-custom";
        let s3_region = "us-east-1";
        let localstack = LocalStack::run(docker_client, network, s3_bucket, s3_region).await;

        let lake_indexer = containers::LakeIndexer::run(
            docker_client,
            network,
            &localstack.s3_address,
            s3_bucket,
            s3_region,
        )
        .await;

        let validator_key = fetch_validator_keys(docker_client, &lake_indexer.container).await?;

        tracing::info!("initializing sandbox worker");
        let worker = near_workspaces::sandbox()
            // use not proxied rpc address because workspace is used in setup (create dev account, deploy
            // contract which we can assume succeed
            .rpc_addr(&lake_indexer.rpc_host_address)
            .validator_key(ValidatorKey::Known(
                validator_key.account_id.to_string().parse()?,
                validator_key.secret_key.to_string().parse()?,
            ))
            .await?;

        Ok(Self {
            localstack,
            lake_indexer,
            worker,
        })
    }
}
