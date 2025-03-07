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

type IsStable = bool;

#[derive(Copy, Clone, Debug)]
enum NodeStatus {
    Active(IsStable),
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
        tracing::info!(target: "net[conn]", to = ?(participant, &url), "starting connection task");
        let url = url.to_string();
        let mut interval = tokio::time::interval(ping_interval);
        loop {
            interval.tick().await;
            if let Err(err) = client.msg_empty(&url).await {
                tracing::warn!(
                    target: "net[conn]",
                    to = ?(participant, &url),
                    ?err,
                    "call /msg empty failed",
                );
                *status.write().await = NodeStatus::Offline;
                continue;
            }

            match client.state(&url).await {
                Ok(state) => {
                    *status.write().await = match state {
                        StateView::Running { is_stable, .. }
                        | StateView::Resharing { is_stable, .. } => NodeStatus::Active(is_stable),
                        StateView::Joining { .. } | StateView::NotRunning { .. } => {
                            NodeStatus::Active(false)
                        }
                    };
                }
                Err(err) => {
                    tracing::warn!(
                        target: "net[conn]",
                        to = ?(participant, &url),
                        ?err,
                        "call /state failed",
                    );
                    *status.write().await = NodeStatus::Offline;
                }
            }
        }
    }
}

impl Drop for NodeConnection {
    fn drop(&mut self) {
        tracing::info!(target: "net[conn]", info = ?self.info, "dropping connection");
        self.task.abort();
    }
}

// TODO: this is a basic connection pool and does not do most of the work yet. This is
//       mostly here just to facilitate offline node handling for now.
// TODO/NOTE: we can use libp2p to facilitate most the of low level TCP connection work.
pub struct Pool {
    client: NodeClient,
    ping_interval: Duration,

    /// All connections in the network, even including the potential ones that are going
    /// to join the network within the next epoch.
    connections: HashMap<Participant, NodeConnection>,

    /// This is a list of potential participants that are not yet in the network. This is
    /// useful for distinguishing which connections are active participants and which are
    /// potential ones.
    potential: HashSet<Participant>,
}

impl Pool {
    pub fn new(client: &NodeClient, ping_interval: Duration) -> Self {
        tracing::info!(target: "net[pool]", "creating new connection pool");
        Self {
            client: client.clone(),
            ping_interval,
            connections: HashMap::new(),
            potential: HashSet::new(),
        }
    }

    pub async fn connect(&mut self, contract_state: &ProtocolState) {
        let mut seen = HashSet::new();
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                let participants: Participants = contract_state.candidates.clone().into();
                self.connect_nodes(&participants, false, &mut seen).await;
            }
            ProtocolState::Running(contract_state) => {
                self.connect_nodes(&contract_state.participants, false, &mut seen)
                    .await;
            }
            ProtocolState::Resharing(contract_state) => {
                self.connect_nodes(&contract_state.old_participants, false, &mut seen)
                    .await;
                self.connect_nodes(&contract_state.new_participants, true, &mut seen)
                    .await;
            }
        }

        // drop the connections that are not in the seen list
        self.drop_connections(seen);
    }

    async fn connect_nodes(
        &mut self,
        participants: &Participants,
        potential: bool,
        seen: &mut HashSet<Participant>,
    ) {
        if potential {
            // clear the potential list if we are connecting new set of potential participants
            self.potential.clear();
        }

        for (participant, info) in participants.iter() {
            seen.insert(*participant);
            if potential {
                self.potential.insert(*participant);
            }

            let potential = potential.then(|| true);
            match self.connections.entry(*participant) {
                Entry::Occupied(mut conn) => {
                    if &conn.get().info != info {
                        tracing::info!(target: "net[pool]", potential, ?info, "updating participant info");
                        conn.insert(NodeConnection::spawn(
                            &self.client,
                            participant,
                            info,
                            self.ping_interval,
                        ));
                    }
                }
                Entry::Vacant(conn) => {
                    tracing::info!(target: "net[pool]", potential, ?info, "adding participant");
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
            tracing::info!(target: "net[pool]", ?participant, "dropping connected node");
            self.connections.remove(&participant);
        }
    }

    /// Get active participants that have a stable connection. This is useful for arbitrary metrics to
    /// say whether or not a node is stable, such as a node being on track with the latest block height.
    pub async fn stable_participants(&self) -> Vec<Participant> {
        let mut active = Vec::new();
        for (participant, conn) in self.connections.iter() {
            if self.potential.contains(participant) {
                continue;
            }

            if matches!(conn.status().await, NodeStatus::Active(true)) {
                active.push(*participant);
            }
        }
        active
    }

    /// Active participants that may or may not be stable.
    pub async fn active_participants(&self) -> Vec<Participant> {
        let mut active = Vec::new();
        for (participant, conn) in self.connections.iter() {
            if self.potential.contains(participant) {
                continue;
            }

            if matches!(conn.status().await, NodeStatus::Active(_)) {
                active.push(*participant);
            }
        }
        active
    }

    pub async fn status(&self) -> MeshState {
        let mut stable = Vec::new();
        let mut active = Vec::new();
        let mut active_potential = Vec::new();
        let mut active_all = Participants::default();

        for (participant, conn) in self.connections.iter() {
            if let NodeStatus::Active(is_stable) = conn.status().await {
                let is_potential = self.potential.contains(participant);
                if is_stable && !is_potential {
                    stable.push(*participant);
                }

                active_all.insert(participant, conn.info.clone());
                if is_potential {
                    active_potential.push(*participant);
                } else {
                    active.push(*participant);
                }
            }
        }

        MeshState {
            active,
            active_potential,
            active_all,
            stable,
        }
    }
}
