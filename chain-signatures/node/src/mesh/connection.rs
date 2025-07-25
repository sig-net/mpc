use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use cait_sith::protocol::Participant;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::{StreamExt, StreamMap};

use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::{ParticipantInfo, ProtocolState};
use crate::web::StateView;

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
        let task = tokio::spawn(Self::run(
            client.clone(),
            status_tx.clone(),
            participant,
            info.clone(),
            ping_interval,
        ));
        Self {
            info: info.clone(),
            status_rx,
            status_tx,
            task,
        }
    }

    fn update(&mut self, client: &NodeClient, info: &ParticipantInfo, ping_interval: Duration) {
        tracing::info!(?self.info, "updating connection");
        self.task.abort();
        self.task = tokio::spawn(Self::run(
            client.clone(),
            self.status_tx.clone(),
            Participant::from(self.info.id),
            info.clone(),
            ping_interval,
        ));
    }

    async fn run(
        client: NodeClient,
        status_tx: watch::Sender<(NodeStatus, ParticipantInfo)>,
        participant: Participant,
        info: ParticipantInfo,
        ping_interval: Duration,
    ) {
        let node = (participant, &info.url);
        tracing::info!(?node, "starting connection task");
        let url = info.url.clone();
        let mut interval = tokio::time::interval(ping_interval);
        loop {
            interval.tick().await;
            if let Err(err) = client.msg_empty(&url).await {
                tracing::warn!(?node, ?err, "checking /msg (empty) failed");
                status_tx.send_if_modified(|(status, _)| {
                    std::mem::replace(status, NodeStatus::Offline) != NodeStatus::Offline
                });
                continue;
            }

            match client.state(&url).await {
                Ok(state) => {
                    // note: borrowing and sending later on `status_tx` can potentially deadlock,
                    // but since we are copying the status, this is not the case. Change this carefully.
                    let old_status = status_tx.borrow().0;
                    let mut new_status = match state {
                        StateView::Running { .. } => NodeStatus::Active,
                        StateView::Resharing { .. }
                        | StateView::Joining { .. }
                        | StateView::NotRunning => NodeStatus::Inactive,
                    };
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
                        status_tx.send_modify(|(status, _)| {
                            *status = new_status;
                        });
                    }
                }
                Err(err) => {
                    tracing::warn!(?node, ?err, "checking /state failed");
                    status_tx.send_if_modified(|(status, _)| {
                        std::mem::replace(status, NodeStatus::Offline) != NodeStatus::Offline
                    });
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

    conn_update_tx: broadcast::Sender<ConnectionUpdate>,
    conn_update_rx: broadcast::Receiver<ConnectionUpdate>,
}

impl Pool {
    pub fn new(client: &NodeClient, ping_interval: Duration) -> Self {
        tracing::info!("creating new connection pool");
        let (conn_update_tx, conn_update_rx) = broadcast::channel(256);
        Self {
            client: client.clone(),
            ping_interval,
            connections: HashMap::new(),

            conn_update_tx,
            conn_update_rx,
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

    pub(crate) async fn connect_nodes(
        &mut self,
        participants: &Participants,
        seen: &mut HashSet<Participant>,
    ) {
        for (&participant, info) in participants.iter() {
            seen.insert(participant);

            let node = (participant, &info.url);
            match self.connections.entry(participant) {
                Entry::Occupied(mut conn) => {
                    if &conn.get().info != info {
                        tracing::info!(?node, "node connection updating");
                        conn.get_mut()
                            .update(&self.client, info, self.ping_interval);
                    }
                }
                Entry::Vacant(conn) => {
                    tracing::info!(?node, "node connection created");
                    let conn = conn.insert(NodeConnection::spawn(
                        &self.client,
                        participant,
                        info,
                        self.ping_interval,
                    ));

                    let watcher = conn.status_rx.clone();
                    if self
                        .conn_update_tx
                        .send(ConnectionUpdate::New(participant, watcher))
                        .is_err()
                    {
                        tracing::warn!(?node, "failed to send new connection");
                    }
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
            let removed = self.connections.remove(&participant).is_some();
            if removed
                && self
                    .conn_update_tx
                    .send(ConnectionUpdate::Drop(participant))
                    .is_err()
            {
                tracing::warn!(?participant, "unable to send update for drop participant");
            }
        }
    }

    /// Update the node state after synchronization was successful.
    pub async fn report_node_synced(&self, participant: Participant) {
        if let Some(conn) = self.connections.get(&participant) {
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
        ConnectionWatcher::new(self.conn_update_rx.resubscribe())
    }
}

#[derive(Clone)]
pub enum ConnectionUpdate {
    New(Participant, watch::Receiver<(NodeStatus, ParticipantInfo)>),
    Drop(Participant),
}

pub struct ConnectionWatcher {
    /// Watch for new connections and dropped connections from the pool. This
    /// is so that we can update our watchers when the pool changes.
    // NOTE: this is a broadcast channel so that we can get a series of updates, and
    // not just the latest entry with watcher channel.
    conn_update: broadcast::Receiver<ConnectionUpdate>,
    /// Set of active connections that we are watching.
    watchers: StreamMap<Participant, WatchStream<(NodeStatus, ParticipantInfo)>>,
}

impl ConnectionWatcher {
    fn new(conn_update: broadcast::Receiver<ConnectionUpdate>) -> Self {
        Self {
            conn_update,
            watchers: StreamMap::new(),
        }
    }

    pub async fn next(&mut self) -> (Participant, NodeStatus, ParticipantInfo) {
        loop {
            tokio::select! {
                // Update our watchers if the connections changed.
                Ok(update) = self.conn_update.recv() => {
                    match update {
                        ConnectionUpdate::New(participant, rx) => {
                            tracing::debug!(?participant, "adding new watcher");
                            self.watchers.insert(participant, WatchStream::new(rx));
                        }
                        ConnectionUpdate::Drop(participant) => {
                            tracing::debug!(?participant, "dropping watcher");
                            self.watchers.remove(&participant);
                            return (participant, NodeStatus::Offline, ParticipantInfo::new(u32::MAX));
                        }
                    }
                }
                // NOTE: if watchers.next() return None, it means that the connection is dropped
                // or that the StreamMap is empty. In that case, we should just continue
                Some((p, (status, info))) = self.watchers.next() => {
                    return (p, status, info);
                }
            }
        }
    }
}
