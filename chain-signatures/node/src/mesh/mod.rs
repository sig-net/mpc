use std::time::Duration;

use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use cait_sith::protocol::Participant;
use connection::{ConnectionWatcher, NodeStatusUpdate};
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod connection;

#[derive(Debug, Clone, clap::Parser)]
#[group(id = "mesh_options")]
pub struct Options {
    /// The interval in milliseconds between pings to participants to check their aliveness
    /// within the MPC network. 1s is normally good enough.
    #[clap(long, env("MPC_MESH_PING_INTERVAL"), default_value = "1000")]
    pub ping_interval: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        vec![
            "--ping-interval".to_string(),
            self.ping_interval.to_string(),
        ]
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MeshState {
    /// Participants that are active in the network; as in they respond when pinged.
    pub active: Participants,

    /// Participants that are stable in the network; as in they have met certain criterias such
    /// as indexing the latest blocks.
    pub stable: Vec<Participant>,
}

/// Set of connections to participants in the network. Each participant is pinged at regular
/// intervals to check their aliveness. The connections can be dropped and reconnected at any time.
pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    connections: connection::Pool,
    state: Arc<RwLock<MeshState>>,
    ping_interval: Duration,
    conn_change: ConnectionWatcher,
}

impl Mesh {
    pub fn new(client: &NodeClient, options: Options) -> Self {
        let ping_interval = Duration::from_millis(options.ping_interval);
        let connections = connection::Pool::new(client, ping_interval);
        let conn_change = connections.watcher();
        Self {
            connections,
            state: Arc::new(RwLock::new(MeshState::default())),
            ping_interval,
            conn_change,
        }
    }

    pub fn state(&self) -> &Arc<RwLock<MeshState>> {
        &self.state
    }

    pub async fn run(mut self, contract_state: Arc<RwLock<Option<ProtocolState>>>) {
        let mut contract_change_interval = tokio::time::interval(self.ping_interval / 2);
        loop {
            tokio::select! {
                _ = contract_change_interval.tick() => {
                    if let Some(contract) = &*contract_state.read().await {
                        self.connections.connect(contract).await;
                    }
                }
                Some((p, status)) = self.conn_change.next() => {
                    self.update_mesh(p, status).await;
                }
            }
        }
    }

    async fn update_mesh(&self, participant: Participant, status: NodeStatusUpdate) {
        update(&self.state, participant, status).await;
    }
}

async fn update(
    state: &Arc<RwLock<MeshState>>,
    participant: Participant,
    status: NodeStatusUpdate,
) {
    let mut state = state.write().await;
    match status {
        NodeStatusUpdate::Active(is_stable, info) => {
            state.active.insert(&participant, info);
            if is_stable {
                state.stable.push(participant);
            }
        }
        NodeStatusUpdate::Offline => {
            state.active.remove(&participant);
            state.stable.retain(|p| p != &participant);
        }
    }
}
