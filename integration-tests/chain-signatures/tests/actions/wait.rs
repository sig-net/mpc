use std::future::{Future, IntoFuture};

use anyhow::Context;
use backon::{ConstantBuilder, Retryable};
use mpc_contract::{ProtocolContractState, RunningContractState};
use mpc_node::web::StateView;

use crate::cluster::Cluster;

type Epoch = u64;

enum WaitActions {
    Running(Epoch),
    MinTriples(usize),
    MinMineTriples(usize),
    MinPresignatures(usize),
    MinMinePresignatures(usize),
    Signable(usize),
}

pub struct WaitAction<'a, R> {
    nodes: &'a Cluster,
    actions: Vec<WaitActions>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'a> WaitAction<'a, ()> {
    pub fn new(nodes: &'a Cluster) -> Self {
        Self {
            nodes,
            actions: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, R> WaitAction<'a, R> {
    pub fn running(self) -> WaitAction<'a, RunningContractState> {
        self.running_on_epoch(0)
    }

    pub fn running_on_epoch(mut self, epoch: Epoch) -> WaitAction<'a, RunningContractState> {
        self.actions.push(WaitActions::Running(epoch));
        WaitAction {
            nodes: self.nodes,
            actions: self.actions,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn min_triples(mut self, min_triples: usize) -> Self {
        self.actions.push(WaitActions::MinTriples(min_triples));
        self
    }

    pub fn min_mine_triples(mut self, min_mine_triples: usize) -> Self {
        self.actions
            .push(WaitActions::MinMineTriples(min_mine_triples));
        self
    }

    pub fn min_presignatures(mut self, min_presignatures: usize) -> Self {
        self.actions
            .push(WaitActions::MinPresignatures(min_presignatures));
        self
    }

    pub fn min_mine_presignatures(mut self, min_mine_presignatures: usize) -> Self {
        self.actions
            .push(WaitActions::MinMinePresignatures(min_mine_presignatures));
        self
    }

    pub fn signable(mut self) -> Self {
        self.actions.push(WaitActions::Signable(1));
        self
    }

    pub fn signable_many(mut self, count: usize) -> Self {
        self.actions.push(WaitActions::Signable(count));
        self
    }

    async fn execute(self) -> anyhow::Result<&'a Cluster> {
        for action in self.actions {
            match action {
                WaitActions::Running(epoch) => {
                    running_mpc(self.nodes, Some(epoch)).await?;
                }
                WaitActions::MinTriples(expected) => {
                    require_triples(self.nodes, expected, false).await?;
                }
                WaitActions::MinMineTriples(expected) => {
                    require_triples(self.nodes, expected, true).await?;
                }
                WaitActions::MinPresignatures(expected) => {
                    require_presignatures(self.nodes, expected, false).await?;
                }
                WaitActions::MinMinePresignatures(expected) => {
                    require_presignatures(self.nodes, expected, true).await?;
                }
                WaitActions::Signable(count) => {
                    require_presignatures(self.nodes, count, true).await?;
                }
            }
        }

        Ok(self.nodes)
    }
}

impl<'a> IntoFuture for WaitAction<'a, ()> {
    type Output = anyhow::Result<()>;
    type IntoFuture = std::pin::Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            self.execute().await?;
            Ok(())
        })
    }
}

impl<'a> IntoFuture for WaitAction<'a, RunningContractState> {
    type Output = anyhow::Result<RunningContractState>;
    type IntoFuture = std::pin::Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.execute().await?.expect_running().await })
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

    let strategy = ConstantBuilder::default()
        .with_delay(std::time::Duration::from_secs(5))
        .with_max_times(100);

    is_running.retry(&strategy).await.with_context(|| {
        format!(
            "mpc did not reach {} in time",
            if epoch.is_some() {
                "expected epoch"
            } else {
                "running state"
            }
        )
    })
}

pub async fn require_presignatures(
    nodes: &Cluster,
    expected: usize,
    mine: bool,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough = || async {
        let state_views = nodes.fetch_states().await?;
        let enough = state_views
            .iter()
            .filter(|state| match state {
                StateView::Running {
                    presignature_mine_count,
                    presignature_count,
                    ..
                } => {
                    if mine {
                        *presignature_mine_count >= expected
                    } else {
                        *presignature_count >= expected
                    }
                }
                _ => {
                    tracing::warn!("state=NotRunning while checking presignatures");
                    false
                }
            })
            .count();
        if enough >= nodes.len() {
            Ok(state_views)
        } else {
            anyhow::bail!("not enough nodes with presignatures")
        }
    };

    let strategy = ConstantBuilder::default()
        .with_delay(std::time::Duration::from_secs(5))
        .with_max_times(expected * 100);

    let state_views = is_enough.retry(&strategy).await.with_context(|| {
        format!(
            "mpc nodes failed to generate {} presignatures before deadline",
            expected
        )
    })?;

    Ok(state_views)
}

pub async fn require_triples(
    nodes: &Cluster,
    expected: usize,
    mine: bool,
) -> anyhow::Result<Vec<StateView>> {
    let is_enough = || async {
        let state_views = nodes.fetch_states().await?;
        let enough = state_views
            .iter()
            .filter(|state| match state {
                StateView::Running {
                    triple_mine_count,
                    triple_count,
                    ..
                } => {
                    if mine {
                        *triple_mine_count >= expected
                    } else {
                        *triple_count >= expected
                    }
                }
                _ => {
                    tracing::warn!("state=NotRunning while checking triples");
                    false
                }
            })
            .count();
        if enough >= nodes.len() {
            Ok(state_views)
        } else {
            anyhow::bail!("not enough nodes with triples")
        }
    };

    let strategy = ConstantBuilder::default()
        .with_delay(std::time::Duration::from_secs(5))
        .with_max_times(expected * 100);

    let state_views = is_enough.retry(&strategy).await.with_context(|| {
        format!(
            "mpc nodes failed to generate {} triples before deadline",
            expected
        )
    })?;

    Ok(state_views)
}