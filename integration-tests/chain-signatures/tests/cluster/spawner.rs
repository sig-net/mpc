use crate::cluster::Cluster;

use std::future::{Future, IntoFuture};

use integration_tests_chain_signatures::containers::{DockerClient, RedisLoad};
use integration_tests_chain_signatures::run;
use integration_tests_chain_signatures::types::NodeConfig;
use mpc_contract::config::ProtocolConfig;
use near_workspaces::Account;

pub struct ClusterSpawner {
    pub(crate) accounts: Option<Vec<Account>>,
    pub(crate) wait_for_running: bool,
    pub(crate) cfg: NodeConfig,
}

impl ClusterSpawner {
    pub fn accounts(mut self, accounts: Vec<Account>) -> Self {
        self.accounts = Some(accounts);
        self
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

    pub fn load(mut self, load: RedisLoad) -> Self {
        self.cfg.load = load;
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
}

impl IntoFuture for ClusterSpawner {
    type Output = anyhow::Result<Cluster>;
    type IntoFuture = std::pin::Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let docker_client = DockerClient::default();
            let nodes = run(&self.cfg, &docker_client, self.accounts).await?;
            let connector = near_jsonrpc_client::JsonRpcClient::new_client();
            let jsonrpc_client = connector.connect(&nodes.ctx().lake_indexer.rpc_host_address);
            let rpc_client = near_fetch::Client::from_client(jsonrpc_client);

            let cluster = Cluster {
                cfg: self.cfg,
                rpc_client,
                http_client: reqwest::Client::default(),
                docker_client,
                nodes,
            };

            if self.wait_for_running {
                cluster.wait().running().await?;
            }

            Ok(cluster)
        })
    }
}
