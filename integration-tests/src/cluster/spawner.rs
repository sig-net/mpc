use mpc_contract::config::ProtocolConfig;
use near_workspaces::network::Sandbox;
use near_workspaces::{Account, Worker};

use std::future::{Future, IntoFuture};

use crate::containers::DockerClient;
use crate::{NodeConfig, Nodes};

use crate::cluster::Cluster;

const DOCKER_NETWORK: &str = "mpc_it_network";

pub struct ClusterSpawner {
    pub docker: DockerClient,
    pub release: bool,
    pub network: String,
    pub accounts: Vec<Account>,

    pub cfg: NodeConfig,
    pub wait_for_running: bool,
    pub pregenerate_triples: bool,
    pub pregenerate_presigs: bool,
}

impl Default for ClusterSpawner {
    fn default() -> Self {
        let cfg = NodeConfig {
            nodes: 3,
            threshold: 2,
            ..Default::default()
        };
        Self {
            docker: DockerClient::default(),
            release: true,
            network: DOCKER_NETWORK.to_string(),
            accounts: Vec::with_capacity(cfg.nodes),

            cfg,
            wait_for_running: false,
            pregenerate_triples: true,
            pregenerate_presigs: true,
        }
    }
}

impl ClusterSpawner {
    pub async fn init_network(self) -> anyhow::Result<Self> {
        self.docker.create_network(&self.network).await?;
        Ok(self)
    }

    pub fn nodes(mut self, nodes: usize) -> Self {
        self.cfg.nodes = nodes;
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.cfg.threshold = threshold;
        self
    }

    pub fn protocol(mut self, protocol: ProtocolConfig) -> Self {
        self.cfg.protocol = protocol;
        self
    }

    pub fn config(mut self, cfg: NodeConfig) -> Self {
        self.cfg = cfg;
        self
    }

    pub fn with_config(mut self, call: impl FnOnce(&mut NodeConfig)) -> Self {
        call(&mut self.cfg);
        self
    }

    pub fn wait_for_running(mut self) -> Self {
        self.wait_for_running = true;
        self
    }

    pub fn disable_pregenerate_triples(mut self) -> Self {
        self.pregenerate_triples = false;
        self
    }

    pub fn disable_pregenerate_presigs(mut self) -> Self {
        self.pregenerate_presigs = false;
        self
    }

    pub fn network(mut self, network: &str) -> Self {
        self.network = network.to_string();
        self
    }

    pub fn debug_node(&mut self) -> &mut Self {
        self.release = false;
        self
    }

    /// Create accounts for the nodes:
    pub async fn create_accounts(&mut self, worker: &Worker<Sandbox>) {
        let accounts =
            futures::future::join_all((0..self.cfg.nodes).map(|_| worker.dev_create_account()))
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        self.accounts.extend(accounts);
    }

    pub async fn run(&mut self) -> anyhow::Result<Nodes> {
        crate::run(self).await
    }

    pub async fn dry_run(&mut self) -> anyhow::Result<crate::Context> {
        crate::dry_run(self).await
    }
}

impl IntoFuture for ClusterSpawner {
    type Output = anyhow::Result<Cluster>;
    type IntoFuture = std::pin::Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(mut self) -> Self::IntoFuture {
        Box::pin(async move {
            self = self.init_network().await?;

            let nodes = self.run().await?;
            let connector = near_jsonrpc_client::JsonRpcClient::new_client();
            let jsonrpc_client = connector.connect(&nodes.ctx().lake_indexer.rpc_host_address);
            let rpc_client = near_fetch::Client::from_client(jsonrpc_client);

            let cluster = Cluster {
                cfg: self.cfg,
                rpc_client,
                http_client: reqwest::Client::default(),
                docker_client: self.docker,
                nodes,
            };

            if self.wait_for_running {
                cluster.wait().running().nodes_running().await?;
            }

            Ok(cluster)
        })
    }
}
