use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use cait_sith::protocol::Participant;
use tokio::sync::watch;
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
    /// State sync is running for node in this state.
    ///
    /// State sync needs to run once for every connection when a node starts.
    /// Additionally, whenever we temporarily lose the connection, we have to
    /// run it again before we can reliably use the peer node in a protocol.
    ///
    /// Note: There are two directions of "being in sync" between two nodes. But
    /// each node only tracks it one directional.
    ///
    /// Example: Node A only cares about IDs it owns. Hence, a peer node B is
    /// considered stable after A sent SyncUpdate and B responded with a
    /// SyncView. This is all node A needs to know to make decisions about
    /// protocols it initiates.
    ///
    /// The mirrored synchronization, with IDs owned by node B, should also
    /// happen. But this is irrelevant for what node A does. Hence, only node B
    /// tracks it.
    Syncing,
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
    status_tx: watch::Sender<NodeStatus>,
    status_rx: watch::Receiver<NodeStatus>,
    task: JoinHandle<()>,
}

impl NodeConnection {
    fn spawn(
        client: &NodeClient,
        participant: &Participant,
        info: &ParticipantInfo,
        ping_interval: Duration,
    ) -> Self {
        let (status_tx, status_rx) = watch::channel(NodeStatus::Offline);
        let task = tokio::spawn(Self::run(
            client.clone(),
            status_tx.clone(),
            *participant,
            info.url.clone(),
            ping_interval,
        ));
        Self {
            info: info.clone(),
            status_tx,
            status_rx,
            task,
        }
    }

    fn status(&self) -> NodeStatus {
        *self.status_rx.borrow()
    }

    async fn run(
        client: NodeClient,
        status: watch::Sender<NodeStatus>,
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
                let _ = status.send(NodeStatus::Offline);
                continue;
            }

            match client.state(&url).await {
                Ok(state) => {
                    let mut new_status = match state {
                        StateView::Running { .. } => NodeStatus::Active,
                        StateView::Resharing { .. }
                        | StateView::Joining { .. }
                        | StateView::NotRunning => NodeStatus::Inactive,
                    };
                    let old_status = *status.borrow();
                    if old_status == NodeStatus::Inactive && new_status == NodeStatus::Active {
                        // Sync when we want to enter an active state
                        //
                        // The peer is running. But before we can reliably
                        // use the connected node in protocols we initiate,
                        // we need to ensure the peer has the up-to-date
                        // data about out owned IDs.
                        new_status = NodeStatus::Syncing;
                    }
                    if old_status != new_status {
                        tracing::info!(?node, ?new_status, "updated with new status");
                        let _ = status.send(new_status);
                    }
                }
                Err(err) => {
                    tracing::warn!(?node, ?err, "checking /state failed");
                    let _ = status.send(NodeStatus::Offline);
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

    pub async fn connect(&mut self, contract: ProtocolState) {
        let mut seen = HashSet::new();
        match contract {
            ProtocolState::Initializing(init) => {
                let participants: Participants = init.candidates.into();
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

    pub fn status(&self) -> MeshState {
        let mut stable = Vec::new();
        let mut active = Participants::default();
        let mut need_sync = Participants::default();
        for (participant, conn) in self.connections.iter() {
            match conn.status() {
                NodeStatus::Active => {
                    active.insert(participant, conn.info.clone());
                    stable.push(*participant);
                }
                NodeStatus::Syncing => {
                    need_sync.insert(participant, conn.info.clone());
                }
                NodeStatus::Inactive => {
                    // TODO: Adding inactive nodes to the active connections
                    // list is confusing. But the way keygen works now, it is
                    // still required.
                    active.insert(participant, conn.info.clone());
                }
                NodeStatus::Offline => (),
            }
        }

        MeshState {
            active,
            need_sync,
            stable,
        }
    }

    /// Update the node state after synchronization was successful.
    pub async fn report_node_synced(&self, participant: Participant) {
        if let Some(conn) = self.connections.get(&participant) {
            if let NodeStatus::Syncing = conn.status() {
                let _ = conn.status_tx.send(NodeStatus::Active);
            }
        }
    }
}
