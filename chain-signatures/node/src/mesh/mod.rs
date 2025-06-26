use std::time::Duration;

use crate::protocol::contract::primitives::Participants;
use crate::{node_client::NodeClient, rpc::ContractStateWatcher};
use cait_sith::protocol::Participant;
use tokio::sync::{mpsc, watch};

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
    pub need_sync: Participants,

    /// Participants that can be selected for a new protocol invocation.
    pub stable: Vec<Participant>,
}

/// Set of connections to participants in the network. Each participant is pinged at regular
/// intervals to check their aliveness. The connections can be dropped and reconnected at any time.
pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    connections: connection::Pool,
    state_tx: watch::Sender<MeshState>,
    state_rx: watch::Receiver<MeshState>,
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
        let (state_tx, state_rx) = watch::channel(MeshState::default());
        Self {
            connections: connection::Pool::new(client, ping_interval),
            state_tx,
            state_rx,
            ping_interval,
            synced_peer_rx,
        }
    }

    pub fn watch(&self) -> watch::Receiver<MeshState> {
        self.state_rx.clone()
    }

    pub async fn run(mut self, mut contract: ContractStateWatcher) {
        let mut interval = tokio::time::interval(self.ping_interval / 2);
        loop {
            tokio::select! {
                // TODO: this will be removed once we have reactive connection changes coming in:
                // but for now, we will need to poll for changes in the connection pool when nodes
                // go offline or come online again.
                _ = interval.tick() => {
                    let new_state = self.connections.status().await;
                    let _ = self.state_tx.send(new_state);
                }
                Some(contract) = contract.next_state() => {
                    tracing::info!(?contract, "new contract state received");
                    self.connections.connect(contract).await;
                    let new_state = self.connections.status().await;
                    let _ = self.state_tx.send(new_state);
                }
                Some(participant) = self.synced_peer_rx.recv() => {
                    self.connections.report_node_synced(participant).await;
                    self.state_tx.send_if_modified(|state| {
                        if let Some(info) = state.need_sync.remove(&participant) {
                            state.active.insert(&participant, info);
                            state.stable.push(participant);
                            true
                        } else {
                            false
                        }
                    });
                }
            }
        }
    }
}
