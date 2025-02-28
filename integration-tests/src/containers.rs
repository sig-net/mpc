use std::collections::HashMap;
use std::path::Path;

use crate::cluster::spawner::ClusterSpawner;
use crate::local::NodeEnvConfig;
use crate::{utils, NodeConfig};

use anyhow::{anyhow, Context};
use async_process::Child;
use bollard::container::LogsOptions;
use bollard::exec::CreateExecOptions;
use bollard::network::CreateNetworkOptions;
use bollard::secret::Ipam;
use bollard::Docker;
use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use elliptic_curve::rand_core::OsRng;
use futures::StreamExt as _;
use k256::Secp256k1;
use mpc_contract::primitives::Participants;
use mpc_keys::hpke;
use mpc_node::config::OverrideConfig;
use mpc_node::protocol::triple::Triple;
use near_account_id::AccountId;
use near_workspaces::Account;
use serde_json::json;
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
    pub cipher_pk: hpke::PublicKey,
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
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");

        // Use proxied address to mock slow, congested or unstable rpc connection
        let near_rpc = ctx.lake_indexer.rpc_host_address.clone();
        let proxy_name = format!("rpc_from_node_{}", account.id());
        let rpc_port_proxied = utils::pick_unused_port().await?;
        let rpc_address_proxied = format!("{near_rpc}:{rpc_port_proxied}");
        tracing::info!(
            "Proxy RPC address {} accessed by node@{} to {}",
            near_rpc,
            account.id(),
            rpc_address_proxied
        );
        LakeIndexer::populate_proxy(&proxy_name, true, &rpc_address_proxied, &near_rpc)
            .await
            .unwrap();

        Self::spawn(
            ctx,
            NodeEnvConfig {
                web_port: Self::CONTAINER_PORT,
                account: account.clone(),
                cipher_pk,
                cipher_sk,
                sign_sk,
                cfg: cfg.clone(),
                near_rpc: rpc_address_proxied,
            },
        )
        .await
    }

    pub async fn kill(self) -> NodeEnvConfig {
        self.container.stop().await.unwrap();
        NodeEnvConfig {
            web_port: Self::CONTAINER_PORT,
            account: self.account,
            cipher_pk: self.cipher_pk,
            cipher_sk: self.cipher_sk,
            sign_sk: self.sign_sk,
            cfg: self.cfg,
            near_rpc: self.near_rpc,
        }
    }

    pub async fn spawn(ctx: &super::Context, config: NodeEnvConfig) -> anyhow::Result<Self> {
        let indexer_options = mpc_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            running_threshold: 120,
            behind_threshold: 120,
        };
        let eth_args = mpc_node::indexer_eth::EthArgs {
            eth_account_sk: Some(config.cfg.eth.account_sk.clone()),
            eth_rpc_ws_url: Some(config.cfg.eth.rpc_ws_url.clone()),
            eth_rpc_http_url: Some(config.cfg.eth.rpc_http_url.clone()),
            eth_contract_address: Some(config.cfg.eth.contract_address.clone()),
        };
        let args = mpc_node::cli::Cli::Start {
            near_rpc: config.near_rpc.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account_id: config.account.id().clone(),
            account_sk: config.account.secret_key().to_string().parse()?,
            web_port: Self::CONTAINER_PORT,
            cipher_pk: hex::encode(config.cipher_pk.to_bytes()),
            cipher_sk: hex::encode(config.cipher_sk.to_bytes()),
            indexer_options: indexer_options.clone(),
            eth: eth_args,
            my_address: None,
            storage_options: ctx.storage_options.clone(),
            logging_options: ctx.logging_options.clone(),
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
            cipher_pk: config.cipher_pk,
            cipher_sk: config.cipher_sk,
            sign_sk: config.sign_sk,
            cfg: config.cfg,
            near_rpc: config.near_rpc,
        })
    }
}

pub struct LocalStack {
    pub container: Container,
    pub address: String,
    pub s3_address: String,
    pub s3_host_address: String,
    pub s3_bucket: String,
    pub s3_region: String,
}

impl LocalStack {
    const S3_CONTAINER_PORT: u16 = 4566;

    pub async fn run(spawner: &ClusterSpawner, s3_bucket: &str, s3_region: &str) -> Self {
        tracing::info!("running LocalStack container...");
        let container = GenericImage::new("localstack/localstack", "3.5.0")
            .with_wait_for(WaitFor::message_on_stdout("Ready."))
            .with_network(&spawner.network)
            .start()
            .await
            .unwrap();
        let address = spawner
            .docker
            .get_network_ip_address(&container, &spawner.network)
            .await
            .unwrap();

        // Create the bucket
        let create_result = spawner
            .docker
            .docker
            .create_exec(
                container.id(),
                CreateExecOptions::<&str> {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(vec![
                        "awslocal",
                        "s3api",
                        "create-bucket",
                        "--bucket",
                        s3_bucket,
                        "--region",
                        s3_region,
                    ]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let result = spawner
            .docker
            .docker
            .start_exec(&create_result.id, None)
            .await
            .unwrap();
        tracing::info!(?result, s3_bucket, s3_region, "localstack created bucket");

        let s3_address = format!("http://{}:{}", address, Self::S3_CONTAINER_PORT);
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let s3_host_address = {
            let s3_host_port = container
                .get_host_port_ipv4(Self::S3_CONTAINER_PORT)
                .await
                .unwrap();
            format!("http://127.0.0.1:{s3_host_port}")
        };
        #[cfg(target_arch = "x86_64")]
        let s3_host_address = {
            let s3_host_port = container
                .get_host_port_ipv6(Self::S3_CONTAINER_PORT)
                .await
                .unwrap();
            format!("http://[::1]:{s3_host_port}")
        };

        tracing::info!(
            s3_address,
            s3_host_address,
            "LocalStack container is running"
        );
        LocalStack {
            container,
            address,
            s3_address,
            s3_host_address,
            s3_bucket: s3_bucket.to_string(),
            s3_region: s3_region.to_string(),
        }
    }
}

pub struct LakeIndexer {
    pub container: Container,
    pub bucket_name: String,
    pub region: String,
    pub rpc_address: String,
    pub rpc_host_address: String,
    // Toxi Server is only used in network traffic originated from Lake Indexer
    // to simulate high load and slowness etc. in Lake Indexer
    // Child process is used for proxy host (local node) to container
    pub toxi_server_process: Child,
    // Container toxi server is used for proxy container to container
    pub toxi_server_container: Container,
}

impl LakeIndexer {
    pub const CONTAINER_RPC_PORT: u16 = 3030;

    pub const S3_PORT_PROXIED: u16 = 4566;
    pub const S3_ADDRESS_PROXIED: &'static str = "127.0.0.1:4566";
    pub const TOXI_SERVER_PROCESS_PORT: u16 = 8474;
    pub const TOXI_SERVER_EXPOSE_PORT: u16 = 8475;
    pub const TOXI_SERVER_PROCESS_ADDRESS: &'static str = "http://127.0.0.1:8474";
    pub const TOXI_SERVER_EXPOSE_ADDRESS: &'static str = "http://127.0.0.1:8475";

    async fn spin_up_toxi_server_process() -> anyhow::Result<Child> {
        let toxi_server = async_process::Command::new("toxiproxy-server")
            .kill_on_drop(true)
            .spawn()
            .with_context(|| "failed to run toxiproxy-server")?;
        utils::ping_until_ok(
            &format!("{}/version", Self::TOXI_SERVER_PROCESS_ADDRESS),
            10,
        )
        .await?;
        Ok(toxi_server)
    }

    async fn spin_up_toxi_server_container(network: &str) -> anyhow::Result<Container> {
        let container = GenericImage::new("ghcr.io/shopify/toxiproxy", "2.9.0")
            .with_exposed_port(Self::CONTAINER_RPC_PORT.tcp())
            .with_network(network)
            .with_mapped_port(
                Self::TOXI_SERVER_EXPOSE_PORT,
                Self::TOXI_SERVER_PROCESS_PORT.tcp(),
            )
            .start()
            .await
            .unwrap();

        container.exec(ExecCommand::new(
            format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::TOXI_SERVER_PROCESS_PORT)
                .split_whitespace()
        )
        .with_container_ready_conditions(vec![WaitFor::message_on_stdout("version")])
        ).await.unwrap();

        Ok(container)
    }

    fn remove_protocol(address: &str) -> &str {
        if let Some(pos) = address.find("://") {
            &address[pos + 3..]
        } else {
            address
        }
    }

    // Populate a new proxy in toxi proxy server. It proxies all traffic originated from `listen`
    // to `upstream`. The proxy can be configured later (adding latency etc.) given the `name`
    // `listen` and `upstream` must in format `host:port` since toxiproxy operates on tcp level
    // host = true, proxy between a host client request host/container server
    // host = false, proxy between a container client to a container server
    // With current docker setup, container client cannot request host server
    pub async fn populate_proxy(
        name: &str,
        host: bool,
        listen: &str,
        upstream: &str,
    ) -> anyhow::Result<()> {
        let toxiproxy_client = reqwest::Client::default();
        let listen = Self::remove_protocol(listen);
        let upstream = Self::remove_protocol(upstream);
        let proxies = json!([{
            "name": name,
            "listen": listen,
            "upstream": upstream
        }]);
        let proxies_json = serde_json::to_string(&proxies).unwrap();
        toxiproxy_client
            .post(format!(
                "{}/populate",
                if host {
                    Self::TOXI_SERVER_PROCESS_ADDRESS
                } else {
                    Self::TOXI_SERVER_EXPOSE_ADDRESS
                }
            ))
            .header("Content-Type", "application/json")
            .body(proxies_json)
            .send()
            .await?;
        Ok(())
    }

    pub async fn run(
        spawner: &ClusterSpawner,
        s3_address: &str,
        bucket_name: &str,
        region: &str,
    ) -> LakeIndexer {
        tracing::info!("initializing toxi proxy servers");
        let toxi_server_process = Self::spin_up_toxi_server_process().await.unwrap();
        let toxi_server_container = Self::spin_up_toxi_server_container(&spawner.network)
            .await
            .unwrap();
        let toxi_server_container_address = spawner
            .docker
            .get_network_ip_address(&toxi_server_container, &spawner.network)
            .await
            .unwrap();
        let s3_address_proxied = format!(
            "{}:{}",
            &toxi_server_container_address,
            Self::S3_PORT_PROXIED
        );
        tracing::info!(
            s3_address,
            s3_address_proxied,
            "Proxy S3 access from Lake Indexer"
        );
        Self::populate_proxy("lake-s3", false, &s3_address_proxied, s3_address)
            .await
            .unwrap();

        tracing::info!(
            network = %spawner.network,
            s3_address_proxied,
            bucket_name,
            region,
            "running NEAR Lake Indexer container..."
        );

        let container = GenericImage::new("ghcr.io/near/near-lake-indexer", "node-2.3.0")
            .with_wait_for(WaitFor::message_on_stderr("Starting Streamer"))
            .with_exposed_port(Self::CONTAINER_RPC_PORT.tcp())
            .with_env_var("AWS_ACCESS_KEY_ID", "FAKE_LOCALSTACK_KEY_ID")
            .with_env_var("AWS_SECRET_ACCESS_KEY", "FAKE_LOCALSTACK_ACCESS_KEY")
            .with_network(&spawner.network)
            .with_cmd(vec![
                "--endpoint".to_string(),
                format!("http://{}", s3_address_proxied),
                "--bucket".to_string(),
                bucket_name.to_string(),
                "--region".to_string(),
                region.to_string(),
                "--stream-while-syncing".to_string(),
                "sync-from-latest".to_string(),
            ])
            .start()
            .await
            .unwrap();

        let address = spawner
            .docker
            .get_network_ip_address(&container, &spawner.network)
            .await
            .unwrap();
        let rpc_address = format!("http://{}:{}", address, Self::CONTAINER_RPC_PORT);
        let rpc_host_port = container
            .get_host_port_ipv4(Self::CONTAINER_RPC_PORT)
            .await
            .unwrap();
        let rpc_host_address = format!("http://127.0.0.1:{rpc_host_port}");

        tracing::info!(
            bucket_name,
            region,
            rpc_address,
            rpc_host_address,
            "NEAR Lake Indexer container is running"
        );
        LakeIndexer {
            container,
            bucket_name: bucket_name.to_string(),
            region: region.to_string(),
            rpc_address,
            rpc_host_address,
            toxi_server_process,
            toxi_server_container,
        }
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
        for mine_idx in &participant_ids {
            for _ in 0..(cfg.protocol.triple.min_triples * mul) {
                num_triples += 1;
                let triple_id = rand::random();
                for (participant, triple) in participant_ids
                    .iter()
                    .zip(shares_to_triples(triple_id, &public, &shares))
                {
                    let mine = participant == mine_idx;
                    storage
                        .get(participant)
                        .unwrap()
                        .insert(triple, mine, false)
                        .await
                        .unwrap();
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
