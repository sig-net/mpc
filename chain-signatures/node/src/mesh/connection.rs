use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use cait_sith::protocol::Participant;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::{ParticipantInfo, ProtocolState};
use crate::web::StateView;

use super::MeshState;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum NodeStatus {
    /// The connected node responds and is actively participating in the MPC
    /// network.
    Active,
    /// The node responds but is in an inactive NodeState, hence it is not ready
    /// for participating in any MPC protocols, yet.
    Inactive,
    /// The node can't be reached at the moment.
    Offline,
}

/// A connection that runs in the background, constantly polling nodes for their
/// active status.
struct NodeConnection {
    info: ParticipantInfo,
    status: Arc<RwLock<NodeStatus>>,
    task: JoinHandle<()>,
}

impl NodeConnection {
    fn spawn(
        client: &NodeClient,
        participant: &Participant,
        info: &ParticipantInfo,
        ping_interval: Duration,
    ) -> Self {
        let status = Arc::new(RwLock::new(NodeStatus::Offline));
        let task = tokio::spawn(Self::run(
            client.clone(),
            status.clone(),
            *participant,
            info.url.clone(),
            ping_interval,
        ));
        Self {
            info: info.clone(),
            status,
            task,
        }
    }

    async fn status(&self) -> NodeStatus {
        *self.status.read().await
    }

    async fn run(
        client: NodeClient,
        status: Arc<RwLock<NodeStatus>>,
        participant: Participant,
        url: String,
        ping_interval: Duration,
    ) {
        let node = (participant, &url);
        tracing::info!(?node, "starting connection task");
        let url = url.to_string();
        let mut interval = tokio::time::interval(ping_interval);
        loop {
            interval.tick().await;
            if let Err(err) = client.msg_empty(&url).await {
                tracing::warn!(?node, ?err, "checking /msg (empty) failed");
                *status.write().await = NodeStatus::Offline;
                continue;
            }

            match client.state(&url).await {
                Ok(state) => {
                    let new_status = match state {
                        StateView::Running { .. } | StateView::Resharing { .. } => {
                            NodeStatus::Active
                        }
                        StateView::Joining { .. } | StateView::NotRunning => NodeStatus::Inactive,
                    };
                    let mut status = status.write().await;
                    if *status != new_status {
                        tracing::info!(?node, ?new_status, "updated with new status");
                        *status = new_status;
                    }
                }
                Err(err) => {
                    tracing::warn!(?node, ?err, "checking /state failed");
                    *status.write().await = NodeStatus::Offline;
                }
            }
        }
    }
}

impl Drop for NodeConnection {
    fn drop(&mut self) {
        tracing::info!(info = ?self.info, "connection dropped");
        self.task.abort();
    }
}

/// Pool that manages connections to nodes in the network. It is responsible for
/// connecting to nodes, checking their status, and dropping connections that are
/// no longer within the network.
pub struct Pool {
    client: NodeClient,

    /// The interval between checking the status of the nodes' connection status.
    ping_interval: Duration,

    /// All connections in the network, even including the potential ones that are going
    /// to join the network within the next epoch.
    connections: HashMap<Participant, NodeConnection>,
}

impl Pool {
    pub fn new(client: &NodeClient, ping_interval: Duration) -> Self {
        tracing::info!("creating new connection pool");
        Self {
            client: client.clone(),
            ping_interval,
            connections: HashMap::new(),
        }
    }

    pub async fn connect(&mut self, contract: &ProtocolState) {
        let mut seen = HashSet::new();
        match contract {
            ProtocolState::Initializing(init) => {
                let participants: Participants = init.candidates.clone().into();
                self.connect_nodes(&participants, &mut seen).await;
            }
            ProtocolState::Running(running) => {
                self.connect_nodes(&running.participants, &mut seen).await;
            }
            ProtocolState::Resharing(resharing) => {
                // NOTE: do NOT connect with old participants since only the new ones are
                // operating under the new epoch and talking to each other. In the case of
                // a resharing revert, we will go back to running state from the contract,
                // and then the old participants would be connected again.
                self.connect_nodes(&resharing.new_participants, &mut seen)
                    .await;
            }
        }

        // drop the connections that are not in the seen list
        self.drop_connections(seen);
    }

    async fn connect_nodes(
        &mut self,
        participants: &Participants,
        seen: &mut HashSet<Participant>,
    ) {
        for (participant, info) in participants.iter() {
            seen.insert(*participant);

            let node = (*participant, &info.url);
            match self.connections.entry(*participant) {
                Entry::Occupied(mut conn) => {
                    if &conn.get().info != info {
                        tracing::info!(?node, "node connection updating");
                        conn.insert(NodeConnection::spawn(
                            &self.client,
                            participant,
                            info,
                            self.ping_interval,
                        ));
                    }
                }
                Entry::Vacant(conn) => {
                    tracing::info!(?node, "node connection created");
                    conn.insert(NodeConnection::spawn(
                        &self.client,
                        participant,
                        info,
                        self.ping_interval,
                    ));
                }
            }
        }
    }

    /// Drop connections that are not in the active connections list. Dropped connections
    /// are no longer polled for their status.
    fn drop_connections(&mut self, active_conn: HashSet<Participant>) {
        let mut remove = Vec::new();
        for participant in self.connections.keys() {
            if !active_conn.contains(participant) {
                remove.push(*participant);
            }
        }

        for participant in remove {
            self.connections.remove(&participant);
        }
    }

    pub async fn status(&self) -> MeshState {
        let mut stable = Vec::new();
        let mut active = Participants::default();
        for (participant, conn) in self.connections.iter() {
            match conn.status().await {
                NodeStatus::Active => {
                    active.insert(participant, conn.info.clone());
                    stable.push(*participant);
                }
                NodeStatus::Inactive => {
                    // TODO: should we really insert inactive nodes to the active list here?
                    // For now, in the refactoring PR, I just keep the exact same behavior.
                    // We can delete this line when in the next PR.
                    active.insert(participant, conn.info.clone());
                }
                NodeStatus::Offline => (),
            }
        }

        MeshState { active, stable }
    }
}
