use mpc_contract::config::ProtocolConfig;

use std::future::{Future, IntoFuture};

use integration_tests_chain_signatures::containers::DockerClient;
use integration_tests_chain_signatures::{run, MultichainConfig};

// use crate::actions::wait_for;
use crate::cluster::Cluster;

pub struct ClusterSpawner {
    pub(crate) cfg: MultichainConfig,
    pub(crate) wait_for_running: bool,
}

impl ClusterSpawner {
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

    pub fn with_config(mut self, call: impl FnOnce(&mut MultichainConfig)) -> Self {
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
            let nodes = run(self.cfg.clone(), &docker_client).await?;
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
