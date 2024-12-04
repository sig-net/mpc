use anyhow::Context;
use backon::{ExponentialBuilder, Retryable};
use mpc_contract::config::ProtocolConfig;
use mpc_contract::{ProtocolContractState, RunningContractState};
use mpc_node::web::StateView;

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
                running_mpc(&cluster, Some(0)).await?;
            }

            Ok(cluster)
        })
    }
}

pub async fn running_mpc(
    nodes: &Cluster,
    epoch: Option<u64>,
) -> anyhow::Result<RunningContractState> {
    let is_running = || async {
        match nodes.contract_state().await? {
            ProtocolContractState::Running(running) => match epoch {
                None => Ok(running),
                Some(expected_epoch) if running.epoch >= expected_epoch => Ok(running),
                Some(_) => {
                    anyhow::bail!("running with an older epoch: {}", running.epoch)
                }
            },
            _ => anyhow::bail!("not running"),
        }
    };
    let err_msg = format!(
        "mpc did not reach {} in time",
        if epoch.is_some() {
            "expected epoch"
        } else {
            "running state"
        }
    );
    is_running
        .retry(&ExponentialBuilder::default().with_max_times(6))
        .await
        .with_context(|| err_msg)
}

pub async fn require_mine_presignatures(
    nodes: &Cluster,
    expected: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough = || async {
        let state_views = nodes.fetch_states().await?;
        let enough = state_views
            .iter()
            .filter(|state| match state {
                StateView::Running {
                    presignature_mine_count,
                    ..
                } => *presignature_mine_count >= expected,
                _ => {
                    tracing::warn!("state=NotRunning while checking mine presignatures");
                    false
                }
            })
            .count();
        if enough >= nodes.len() {
            Ok(state_views)
        } else {
            anyhow::bail!("not enough nodes with mine presignatures")
        }
    };

    let state_views = is_enough
        .retry(&ExponentialBuilder::default().with_max_times(15))
        .await
        .with_context(|| {
            format!(
                "mpc nodes failed to generate {} presignatures before deadline",
                expected
            )
        })?;

    Ok(state_views)
}

pub async fn require_mine_triples(
    nodes: &Cluster,
    expected: usize,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough = || async {
        let state_views = nodes.fetch_states().await?;
        let enough = state_views
            .iter()
            .filter(|state| match state {
                StateView::Running {
                    triple_mine_count, ..
                } => *triple_mine_count >= expected,
                _ => {
                    tracing::warn!("state=NotRunning while checking mine triples");
                    false
                }
            })
            .count();
        if enough >= nodes.len() {
            Ok(state_views)
        } else {
            anyhow::bail!("not enough nodes with mine triples")
        }
    };
    let state_views = is_enough
        .retry(&ExponentialBuilder::default().with_max_times(12))
        .await
        .with_context(|| {
            format!(
                "mpc nodes failed to generate {} triples before deadline",
                expected
            )
        })?;

    Ok(state_views)
}
