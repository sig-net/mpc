use std::time::Duration;

use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use cait_sith::protocol::Participant;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

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

    /// Participants that are currently out-of-sync, they will become active
    /// once we finished synchronization.
    pub need_sync: Vec<Participant>,

    /// Participants that can be selected for a new protocol invocation.
    pub stable: Vec<Participant>,
}

/// Set of connections to participants in the network. Each participant is pinged at regular
/// intervals to check their aliveness. The connections can be dropped and reconnected at any time.
pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    connections: connection::Pool,
    state: Arc<RwLock<MeshState>>,
    ping_interval: Duration,
    synced_peer_rx: mpsc::Receiver<Participant>,
}

impl Mesh {
    pub fn new(
        client: &NodeClient,
        options: Options,
        synced_peer_rx: mpsc::Receiver<Participant>,
    ) -> Self {
        let ping_interval = Duration::from_millis(options.ping_interval);
        Self {
            connections: connection::Pool::new(client, ping_interval),
            state: Arc::new(RwLock::new(MeshState::default())),
            ping_interval,
            synced_peer_rx,
        }
    }

    pub fn state(&self) -> &Arc<RwLock<MeshState>> {
        &self.state
    }

    pub async fn run(mut self, contract_state: Arc<RwLock<Option<ProtocolState>>>) {
        let mut interval = tokio::time::interval(self.ping_interval / 2);
        loop {
            tokio::select! {
                _ = interval.tick() => {

                    if let Some(contract) = &*contract_state.read().await {
                        self.connections.connect(contract).await;
                        let new_state = self.connections.status().await;
                        let mut state = self.state.write().await;
                        *state = new_state;
                    }
                }
                Some(participant) = self.synced_peer_rx.recv() => {
                    self.connections.report_node_synced(participant).await;
                    let mut state = self.state.write().await;

                    if let Some(pos) = state.need_sync.iter().position(|p| *p == participant) {
                        state.need_sync.remove(pos);
                        state.stable.push(participant);
                    }
                }
            }
        }
    }
}
