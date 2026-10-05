use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use cait_sith::protocol::Participant;
use near_account_id::AccountId;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::state::NodeStatus as OtherNodeStatus;
use crate::protocol::{ParticipantInfo, ProtocolState};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
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
    /// considered active after A sent SyncUpdate and B responded with a
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
/// active status. Status changes are written straight into the shared
/// [`MeshState`].
struct NodeConnection {
    info_tx: watch::Sender<ParticipantInfo>,
    task: JoinHandle<()>,
}

impl NodeConnection {
    fn spawn(
        client: &NodeClient,
        participant: Participant,
        info: &ParticipantInfo,
        ping_interval: Duration,
        state_tx: watch::Sender<MeshState>,
    ) -> Self {
        let (info_tx, info_rx) = watch::channel(info.clone());
        let task = tokio::spawn(Self::run(
            client.clone(),
            state_tx,
            info_rx,
            participant,
            ping_interval,
        ));
        Self { info_tx, task }
    }

    fn update(&mut self, info: &ParticipantInfo) {
        tracing::info!(?info, "updating connection with new info");
        if self.info_tx.send(info.clone()).is_err() {
            tracing::warn!("unable to update connection");
        }
    }

    async fn run(
        client: NodeClient,
        state_tx: watch::Sender<MeshState>,
        mut info_rx: watch::Receiver<ParticipantInfo>,
        participant: Participant,
        ping_interval: Duration,
    ) {
        let mut info = info_rx.borrow().clone();
        let mut node = (participant, info.url.clone());
        tracing::info!(?node, "starting connection task");
        // The mesh state only knows Active and Syncing; this keeps the
        // Inactive/Offline distinction for an unlisted peer.
        let mut status = NodeStatus::Offline;
        let mut interval = tokio::time::interval(ping_interval);
        loop {
            tokio::select! {
                Ok(()) = info_rx.changed() => {
                    info = info_rx.borrow_and_update().clone();
                    node = (participant, info.url.clone());
                    state_tx.send_if_modified(|state| match state.status(participant) {
                        Some(listed) => state.update(participant, listed, info.clone()),
                        None => false,
                    });
                }
                _ = interval.tick() => {
                    let resp = match client.status(&info.url).await {
                        Ok(status) => status,
                        Err(err) => {
                            tracing::warn!(?node, ?err, "checking /status failed");
                            status = NodeStatus::Offline;
                            state_tx.send_if_modified(|state| state.remove(participant));
                            continue;
                        }
                    };

                    if resp.protocol_version != crate::PROTOCOL_VERSION {
                        tracing::warn!(
                            ?node,
                            our_version = crate::PROTOCOL_VERSION,
                            peer_version = resp.protocol_version,
                            "protocol version mismatch"
                        );
                        status = NodeStatus::Offline;
                        state_tx.send_if_modified(|state| state.remove(participant));
                        continue;
                    }

                    // Sync reports flip a peer between Active and Syncing behind
                    // our back, so the mesh state is the source of truth for those.
                    let old_status = match state_tx.borrow().status(participant) {
                        Some(listed) => listed,
                        None if matches!(status, NodeStatus::Inactive | NodeStatus::Offline) => status,
                        None => NodeStatus::Offline,
                    };
                    let mut new_status = match resp.status {
                        OtherNodeStatus::Running { .. } => NodeStatus::Active,
                        OtherNodeStatus::Resharing { .. }
                        | OtherNodeStatus::Generating { .. }
                        | OtherNodeStatus::Joining { .. }
                        | OtherNodeStatus::Starting
                        | OtherNodeStatus::Started
                        | OtherNodeStatus::WaitingForConsensus { .. } => NodeStatus::Inactive,
                    };
                    if matches!(old_status, NodeStatus::Inactive | NodeStatus::Offline | NodeStatus::Syncing)
                        && new_status == NodeStatus::Active {
                        // Sync when we want to enter an active state
                        //
                        // The peer is running. But before we can reliably
                        // use the connected node in protocols we initiate,
                        // we need to ensure the peer has the up-to-date
                        // data about out owned IDs.
                        new_status = NodeStatus::Syncing;
                    }
                    if old_status != new_status {
                        tracing::info!(?node, ?old_status, ?new_status, "updated with new status");
                        state_tx.send_if_modified(|state| {
                            state.update(participant, new_status, info.clone())
                        });
                    }
                    status = new_status;
                }
            }
        }
    }

    pub fn info(&self) -> watch::Ref<'_, ParticipantInfo> {
        self.info_tx.borrow()
    }
}

impl Drop for NodeConnection {
    fn drop(&mut self) {
        tracing::info!(info = ?*self.info_tx.borrow(), "connection dropped");
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

    /// Account id of this node. Used to avoid creating self connections.
    node_account_id: AccountId,

    /// Shared mesh state that every connection writes its status into.
    state_tx: watch::Sender<MeshState>,
}

impl Pool {
    pub fn new(
        client: &NodeClient,
        node_account_id: &AccountId,
        ping_interval: Duration,
        state_tx: watch::Sender<MeshState>,
    ) -> Self {
        tracing::info!("creating new connection pool");
        Self {
            client: client.clone(),
            ping_interval,
            connections: HashMap::new(),
            node_account_id: node_account_id.clone(),
            state_tx,
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

    pub fn disconnect_all(&mut self) {
        self.drop_connections(HashSet::new());
    }

    pub(crate) async fn connect_nodes(
        &mut self,
        participants: &Participants,
        seen: &mut HashSet<Participant>,
    ) {
        for (&participant, info) in participants.iter() {
            if info.account_id == self.node_account_id {
                tracing::debug!(?participant, "skipping self connection");
                if self.connections.remove(&participant).is_some() {
                    self.state_tx
                        .send_if_modified(|state| state.remove(participant));
                }
                continue;
            }

            seen.insert(participant);

            let node = (participant, &info.url);
            match self.connections.entry(participant) {
                Entry::Occupied(mut conn) => {
                    if &*conn.get().info() != info {
                        tracing::info!(?node, "node connection updating");
                        conn.get_mut().update(info);
                    }
                }
                Entry::Vacant(conn) => {
                    tracing::info!(?node, "node connection created");
                    conn.insert(NodeConnection::spawn(
                        &self.client,
                        participant,
                        info,
                        self.ping_interval,
                        self.state_tx.clone(),
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
            if self.connections.remove(&participant).is_some() {
                self.state_tx
                    .send_if_modified(|state| state.remove(participant));
            }
        }
    }

    /// Mark an active node as out-of-sync, so it is re-synced before we use it
    /// in protocols we initiate. Called when we learn our record of what that
    /// peer stores is wrong, e.g. it rejects a posit for an artifact we list
    /// it as holding.
    pub fn report_node_desynced(&self, participant: Participant) {
        self.transition(participant, NodeStatus::Active, NodeStatus::Syncing);
    }

    /// Update the node state after synchronization was successful.
    pub fn report_node_synced(&self, participant: Participant) {
        self.transition(participant, NodeStatus::Syncing, NodeStatus::Active);
    }

    /// Move `participant` from `from` to `to` in the mesh state, if it is
    /// currently listed as `from`. Anything else is a no-op that does not
    /// wake the mesh watchers.
    fn transition(&self, participant: Participant, from: NodeStatus, to: NodeStatus) {
        let Some(conn) = self.connections.get(&participant) else {
            return;
        };
        let info = conn.info().clone();
        self.state_tx.send_if_modified(|state| {
            if state.status(participant) != Some(from) {
                return false;
            }
            tracing::info!(?participant, ?from, ?to, "reporting node status");
            state.update(participant, to, info)
        });
    }
}
