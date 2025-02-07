pub mod actions;
pub mod cluster;
pub mod containers;
pub mod execute;
pub mod local;
pub mod utils;

use cluster::spawner::ClusterSpawner;
use containers::Container;
use deadpool_redis::Pool;
use mpc_node::indexer_eth::EthConfig;
use std::collections::HashMap;

use self::local::NodeEnvConfig;
use crate::containers::DockerClient;
use crate::containers::LocalStack;

use anyhow::Context as _;
use bollard::exec::{CreateExecOptions, StartExecResults};
use futures::StreamExt;
use mpc_contract::config::{PresignatureConfig, ProtocolConfig, TripleConfig};
use mpc_contract::primitives::CandidateInfo;
use mpc_node::gcp::GcpService;
use mpc_node::storage::triple_storage::TripleStorage;
use mpc_node::{mesh, node_client, storage};
use near_crypto::KeyFile;
use near_workspaces::network::{Sandbox, ValidatorKey};
use near_workspaces::types::{KeyType, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::json;

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub nodes: usize,
    pub threshold: usize,
    pub protocol: ProtocolConfig,
    pub eth: EthConfig,
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
                    min_triples: 8,
                    max_triples: 80,
                    ..Default::default()
                },
                presignature: PresignatureConfig {
                    min_presignatures: 2,
                    max_presignatures: 20,
                    ..Default::default()
                },
                ..Default::default()
            },
            eth: EthConfig {
                rpc_http_url: "http://localhost:8545".to_string(),
                rpc_ws_url: "ws://localhost:8545".to_string(),
                contract_address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512".to_string(),
                account_sk: "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
                    .to_string(),
            },
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
                nodes.push(local::Node::run(*next_id, ctx, cfg, new_account).await?);
                *next_id += 1;
                Ok(nodes.len() - 1)
            }
            Nodes::Docker {
                next_id,
                ctx,
                nodes,
            } => {
                nodes.push(containers::Node::run(*next_id, ctx, cfg, new_account).await?);
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
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

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
                nodes.push(local::Node::spawn(*next_id, ctx, config).await?);
                *next_id += 1;
            }
            Nodes::Docker {
                next_id,
                ctx,
                nodes,
            } => {
                nodes.push(containers::Node::spawn(*next_id, ctx, config).await?);
                *next_id += 1;
            }
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

impl Drop for Nodes {
    fn drop(&mut self) {
        self.kill_all();
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
    pub message_options: node_client::Options,
}

pub async fn setup(spawner: &mut ClusterSpawner) -> anyhow::Result<Context> {
    let LakeIndexerCtx {
        localstack,
        lake_indexer,
        worker,
    } = initialize_lake_indexer(spawner).await?;
    spawner.create_accounts(&worker).await;

    let mpc_contract = worker
        .dev_deploy(&std::fs::read(
            execute::target_dir()
                .context("could not find target dir")?
                .join("wasm32-unknown-unknown/release/mpc_contract.wasm"),
        )?)
        .await?;
    tracing::info!(contract_id = %mpc_contract.id(), "deployed mpc contract");

    let redis = containers::Redis::run(spawner).await;
    let sk_share_local_path = spawner.tmp_dir.join("secrets");
    std::fs::create_dir_all(&sk_share_local_path).expect("could not create secrets dir");
    let sk_share_local_path = sk_share_local_path.to_string_lossy().to_string();

    let storage_options = mpc_node::storage::Options {
        env: spawner.env.clone(),
        gcp_project_id: spawner.gcp_project_id.clone(),
        sk_share_secret_id: None,
        sk_share_local_path: Some(sk_share_local_path),
        redis_url: redis.internal_address.clone(),
    };

    let mesh_options = mpc_node::mesh::Options {
        refresh_active_timeout: 1000,
    };

    let message_options = node_client::Options {
        timeout: 1000,
        state_timeout: 1000,
    };

    Ok(Context {
        docker_client: spawner.docker.clone(),
        docker_network: spawner.network.clone(),
        release: spawner.release,
        localstack,
        lake_indexer,
        worker,
        mpc_contract,
        redis,
        storage_options,
        mesh_options,
        message_options,
    })
}

pub async fn docker(spawner: &mut ClusterSpawner) -> anyhow::Result<Nodes> {
    let ctx = setup(spawner).await?;
    let cfg = &spawner.cfg;

    let node_futures = spawner
        .accounts
        .iter()
        .enumerate()
        .map(|(node_id, account)| containers::Node::run(node_id, &ctx, cfg, account));
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
                    cipher_pk: node.cipher_pk.to_bytes(),
                    sign_pk: node.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();
    ctx.mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": cfg.threshold,
            "candidates": candidates
        }))
        .transact()
        .await?
        .into_result()?;

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
    for (node_id, account) in spawner.accounts.iter().enumerate() {
        node_cfgs.push(local::Node::dry_run(node_id, &ctx, account, cfg).await?);
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
                    cipher_pk: node_cfg.cipher_pk.to_bytes(),
                    sign_pk: node_cfg.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();

    println!("\nPlease call below to update localnet:\n");
    let near_rpc = ctx.lake_indexer.rpc_host_address.clone();
    println!("near config add-connection --network-name local --connection-name local --rpc-url {} --wallet-url http://127.0.0.1/ --explorer-transaction-url http://127.0.0.1:6666/", near_rpc);
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
    let ctx = setup(spawner).await?;
    let cfg = &spawner.cfg;

    let node_futures = spawner
        .accounts
        .iter()
        .enumerate()
        .map(|(node_id, account)| local::Node::run(node_id, &ctx, cfg, account));
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
                    cipher_pk: node.cipher_pk.to_bytes(),
                    sign_pk: node.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();
    ctx.mpc_contract
        .call("init")
        .args_json(json!({
            "threshold": cfg.threshold,
            "candidates": candidates
        }))
        .transact()
        .await?
        .into_result()?;

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

pub struct LakeIndexerCtx {
    pub localstack: containers::LocalStack,
    pub lake_indexer: containers::LakeIndexer,
    pub worker: Worker<Sandbox>,
}

pub async fn initialize_lake_indexer(spawner: &ClusterSpawner) -> anyhow::Result<LakeIndexerCtx> {
    let s3_bucket = "near-lake-custom";
    let s3_region = "us-east-1";
    let localstack = LocalStack::run(spawner, s3_bucket, s3_region).await;

    let lake_indexer =
        containers::LakeIndexer::run(spawner, &localstack.s3_address, s3_bucket, s3_region).await;

    let validator_key = fetch_validator_keys(&spawner.docker, &lake_indexer.container).await?;

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

    Ok(LakeIndexerCtx {
        localstack,
        lake_indexer,
        worker,
    })
}
