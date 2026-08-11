use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use cait_sith::protocol::Participant;
use near_account_id::AccountId;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::{StreamExt, StreamMap};

use crate::metrics::mesh as metrics;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::state::NodeStatus as OtherNodeStatus;
use crate::protocol::{ParticipantInfo, ProtocolState};

/// Status of a single connection, as seen by this node.
///
/// See the [module docs](crate::mesh) for how these map onto the two
/// [`MeshState`](crate::mesh::MeshState) sets and what drives each transition.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    /// The connected node responds and is actively participating in the MPC
    /// network.
    ///
    /// Reachable only via [`Pool::report_node_synced`]; no ping sets this.
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
/// active status.
struct NodeConnection {
    info_tx: watch::Sender<ParticipantInfo>,
    status_rx: watch::Receiver<(NodeStatus, ParticipantInfo)>,
    status_tx: watch::Sender<(NodeStatus, ParticipantInfo)>,
    task: JoinHandle<()>,
}

impl NodeConnection {
    fn spawn(
        client: &NodeClient,
        participant: Participant,
        info: &ParticipantInfo,
        ping_interval: Duration,
    ) -> Self {
        let (status_tx, status_rx) = watch::channel((NodeStatus::Offline, info.clone()));
        let (info_tx, info_rx) = watch::channel(info.clone());
        let task = tokio::spawn(Self::run(
            client.clone(),
            status_tx.clone(),
            info_rx,
            participant,
            ping_interval,
        ));
        Self {
            info_tx,
            status_rx,
            status_tx,
            task,
        }
    }

    fn update(&mut self, info: &ParticipantInfo) {
        tracing::info!(?info, "updating connection with new info");
        if self.info_tx.send(info.clone()).is_err() {
            tracing::warn!("unable to update connection");
        }
    }

    async fn run(
        client: NodeClient,
        status_tx: watch::Sender<(NodeStatus, ParticipantInfo)>,
        mut info_rx: watch::Receiver<ParticipantInfo>,
        participant: Participant,
        ping_interval: Duration,
    ) {
        let mut url = info_rx.borrow().url.clone();
        let mut node = (participant, &url);
        tracing::info!(?node, "starting connection task");
        let mut interval = tokio::time::interval(ping_interval);
        loop {
            tokio::select! {
                Ok(()) = info_rx.changed() => {
                    let new_info = info_rx.borrow_and_update().clone();
                    url = new_info.url.clone();
                    node = (participant, &url);
                    status_tx.send_modify(|(_, info)| {
                        *info = new_info;
                    });
                }
                _ = interval.tick() => {
                    let resp = match client.status(&url).await {
                        Ok(status) => status,
                        Err(err) => {
                            tracing::warn!(?node, ?err, "checking /status failed");
                            if status_tx.send_if_modified(|(status, _)| {
                                std::mem::replace(status, NodeStatus::Offline) != NodeStatus::Offline
                            }) {
                                metrics::MESH_PEER_OFFLINE
                                    .with_label_values(&[metrics::OFFLINE_UNREACHABLE])
                                    .inc();
                            }
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
                        if status_tx.send_if_modified(|(status, _)| {
                            std::mem::replace(status, NodeStatus::Offline) != NodeStatus::Offline
                        }) {
                            metrics::MESH_PEER_OFFLINE
                                .with_label_values(&[metrics::OFFLINE_VERSION_MISMATCH])
                                .inc();
                        }
                        continue;
                    }

                    let old_status = status_tx.borrow().0;
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
                        status_tx.send_modify(|(status, _)| {
                            *status = new_status;
                        });
                    }
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

/// Snapshot of the pool's current connections, keyed by participant.
///
/// Published as a whole rather than as a stream of add/remove events. The set is
/// state, not a sequence: a watcher only ever needs the latest version of it, and
/// publishing the set means a slow watcher converges on the truth instead of
/// missing an event and diverging from it permanently.
type ConnectionSet = Arc<HashMap<Participant, watch::Receiver<(NodeStatus, ParticipantInfo)>>>;

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

    conns_tx: watch::Sender<ConnectionSet>,
}

impl Pool {
    pub fn new(client: &NodeClient, node_account_id: &AccountId, ping_interval: Duration) -> Self {
        tracing::info!("creating new connection pool");
        let (conns_tx, _) = watch::channel(Arc::new(HashMap::new()));
        Self {
            client: client.clone(),
            ping_interval,
            connections: HashMap::new(),
            node_account_id: node_account_id.clone(),
            conns_tx,
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

    pub fn disconnect_all(&mut self) {
        self.drop_connections(HashSet::new());
    }

    pub(crate) async fn connect_nodes(
        &mut self,
        participants: &Participants,
        seen: &mut HashSet<Participant>,
    ) {
        let mut changed = false;
        for (&participant, info) in participants.iter() {
            if info.account_id == self.node_account_id {
                tracing::debug!(?participant, "skipping self connection");
                changed |= self.connections.remove(&participant).is_some();
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
                    ));
                    changed = true;
                }
            }
        }

        if changed {
            self.publish();
        }
    }

    /// Drop connections that are not in the active connections list. Dropped connections
    /// are no longer polled for their status.
    fn drop_connections(&mut self, active_conn: HashSet<Participant>) {
        let before = self.connections.len();
        self.connections
            .retain(|participant, _| active_conn.contains(participant));
        if self.connections.len() != before {
            self.publish();
        }
    }

    /// Publish the current connection set to all watchers.
    fn publish(&self) {
        let set: ConnectionSet = Arc::new(
            self.connections
                .iter()
                .map(|(p, conn)| (*p, conn.status_rx.clone()))
                .collect(),
        );
        // No receivers is normal: the mesh may not be watching yet.
        let _ = self.conns_tx.send(set);
    }

    /// Update the node state after synchronization was successful.
    pub fn report_node_synced(&self, participant: Participant) {
        if let Some(conn) = self.connections.get(&participant) {
            tracing::info!(?participant, "reporting node synced");
            conn.status_tx.send_if_modified(|(status, _)| {
                if *status == NodeStatus::Syncing {
                    *status = NodeStatus::Active;
                    true
                } else {
                    false
                }
            });
        }
    }

    pub fn watch(&self) -> ConnectionWatcher {
        ConnectionWatcher::new(self.conns_tx.subscribe())
    }
}

/// A change observed by a [`ConnectionWatcher`].
pub enum MeshUpdate {
    /// A connection reported a new status.
    Status(Participant, NodeStatus, ParticipantInfo),
    /// The participant left the connection set and is no longer polled.
    ///
    /// Carries no [`ParticipantInfo`]: there is none to report, and inventing a
    /// placeholder only works for as long as every consumer happens to ignore it.
    Dropped(Participant),
}

pub struct ConnectionWatcher {
    /// Latest connection set published by the pool.
    conns: watch::Receiver<ConnectionSet>,
    /// Per-connection status streams, kept in step with `conns`.
    watchers: StreamMap<Participant, WatchStream<(NodeStatus, ParticipantInfo)>>,
    /// Drops found by the last reconcile, still to be reported.
    dropped: Vec<Participant>,
}

impl ConnectionWatcher {
    fn new(conns: watch::Receiver<ConnectionSet>) -> Self {
        Self {
            conns,
            watchers: StreamMap::new(),
            dropped: Vec::new(),
        }
    }

    /// Next change, or `None` once the pool is gone and no further updates can
    /// arrive. Callers must treat `None` as terminal: continuing to use the last
    /// mesh state would be acting on a snapshot that can no longer be corrected.
    pub async fn next(&mut self) -> Option<MeshUpdate> {
        loop {
            if let Some(participant) = self.dropped.pop() {
                return Some(MeshUpdate::Dropped(participant));
            }

            tokio::select! {
                // Both branches are cancel-safe, and `changed()` erroring is the
                // only way out, so this select can never end up with every branch
                // disabled.
                changed = self.conns.changed() => {
                    if changed.is_err() {
                        tracing::warn!("connection pool dropped; connection watcher stopping");
                        return None;
                    }
                    self.reconcile();
                }
                // `watchers.next()` yields `None` while the map is empty, which
                // just disables this branch until the set changes.
                Some((p, (status, info))) = self.watchers.next() => {
                    return Some(MeshUpdate::Status(p, status, info));
                }
            }
        }
    }

    /// Bring the status streams in line with the latest published set.
    ///
    /// Re-inserted connections re-emit their current status, because
    /// `WatchStream` yields the present value on creation. That is what makes a
    /// missed intermediate state self-correcting rather than permanent.
    fn reconcile(&mut self) {
        let set = self.conns.borrow_and_update().clone();

        let gone: Vec<Participant> = self
            .watchers
            .keys()
            .filter(|p| !set.contains_key(p))
            .copied()
            .collect();
        for participant in gone {
            tracing::debug!(?participant, "dropping watcher");
            self.watchers.remove(&participant);
            self.dropped.push(participant);
        }

        for (participant, rx) in set.iter() {
            if !self.watchers.contains_key(participant) {
                tracing::debug!(?participant, "adding new watcher");
                self.watchers
                    .insert(*participant, WatchStream::new(rx.clone()));
            }
        }
    }
}
