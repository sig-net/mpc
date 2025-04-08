use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use cait_sith::protocol::Participant;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::{StreamExt as _, StreamMap};

use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::{ParticipantInfo, ProtocolState};
use crate::web::StateView;

type IsStable = bool;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeStatusUpdate {
    Active(IsStable, ParticipantInfo),
    Offline,
}

/// Enum representing the connection status of a node. Only used internally
/// to track the status of the connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum NodeStatus {
    Active(IsStable),
    Offline,
}

impl NodeStatus {
    fn with_info(self, info: &ParticipantInfo) -> NodeStatusUpdate {
        match self {
            NodeStatus::Active(is_stable) => NodeStatusUpdate::Active(is_stable, info.clone()),
            NodeStatus::Offline => NodeStatusUpdate::Offline,
        }
    }
}

/// A connection that runs in the background, constantly polling nodes for their
/// active status.
struct NodeConnection {
    info: ParticipantInfo,
    status_rx: watch::Receiver<NodeStatusUpdate>,
    status_tx: watch::Sender<NodeStatusUpdate>,
    task: JoinHandle<()>,
}

impl NodeConnection {
    fn spawn(
        client: &NodeClient,
        participant: Participant,
        info: &ParticipantInfo,
        ping_interval: Duration,
    ) -> Self {
        let (status_tx, status_rx) = watch::channel(NodeStatusUpdate::Offline);
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
        status: watch::Sender<NodeStatusUpdate>,
        participant: Participant,
        info: ParticipantInfo,
        ping_interval: Duration,
    ) {
        let node = (participant, &info.url);
        tracing::info!(?node, "starting connection task");
        let mut interval = tokio::time::interval(ping_interval);

        let mut current_status = NodeStatus::Offline;
        loop {
            interval.tick().await;
            if let Err(err) = client.msg_empty(&info.url).await {
                tracing::warn!(?node, ?err, "checking /msg (empty) failed");
                if let Err(err) = status.send(NodeStatusUpdate::Offline) {
                    tracing::warn!(?node, ?err, "failed to make status offline on err /msg");
                } else {
                    current_status = NodeStatus::Offline;
                }
                continue;
            }

            match client.state(&info.url).await {
                Ok(state) => {
                    let new_status = match state {
                        StateView::Running { is_stable, .. }
                        | StateView::Resharing { is_stable, .. } => NodeStatus::Active(is_stable),
                        StateView::Joining { .. } | StateView::NotRunning => {
                            NodeStatus::Active(false)
                        }
                    };
                    if current_status != new_status {
                        tracing::info!(?node, ?new_status, "updated with new status");
                        if let Err(err) = status.send(new_status.with_info(&info)) {
                            tracing::warn!(?node, ?err, "failed to update status for watcher");
                        } else {
                            current_status = new_status;
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(?node, ?err, "checking /state failed");
                    if let Err(err) = status.send(NodeStatusUpdate::Offline) {
                        tracing::warn!(?node, ?err, "failed to make status offline on err /state");
                    } else {
                        current_status = NodeStatus::Offline;
                    }
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
        let (conn_update_tx, conn_update_rx) = broadcast::channel(32);
        Self {
            client: client.clone(),
            ping_interval,
            connections: HashMap::new(),
            conn_update_tx,
            conn_update_rx,
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
            };
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

    pub fn watcher(&self) -> ConnectionWatcher {
        ConnectionWatcher::new(self.conn_update_rx.resubscribe())
    }
}

#[derive(Clone)]
enum ConnectionUpdate {
    New(Participant, watch::Receiver<NodeStatusUpdate>),
    Drop(Participant),
}

pub struct ConnectionWatcher {
    /// Watch for new connections and dropped connections from the pool. This
    /// is so that we can update our watchers when the pool changes.
    // NOTE: this is a broadcast channel so that we can get a series of updates, and
    // not just the latest entry with watcher channel.
    conn_update: broadcast::Receiver<ConnectionUpdate>,
    /// Set of active connections that we are watching.
    watchers: StreamMap<Participant, WatchStream<NodeStatusUpdate>>,
}

impl ConnectionWatcher {
    fn new(conn_update: broadcast::Receiver<ConnectionUpdate>) -> Self {
        Self {
            conn_update,
            watchers: StreamMap::new(),
        }
    }

    pub async fn next(&mut self) -> (Participant, NodeStatusUpdate) {
        loop {
            tokio::select! {
                // Update our watchers if the connections changed.
                Ok(update) = self.conn_update.recv() => {
                    match update {
                        ConnectionUpdate::New(participant, rx) => {
                            self.watchers.insert(participant, WatchStream::new(rx));
                        }
                        ConnectionUpdate::Drop(participant) => {
                            tracing::debug!(?participant, "dropping watcher");
                            self.watchers.remove(&participant);
                            return (participant, NodeStatusUpdate::Offline);
                        }
                    }
                }
                // NOTE: if watchers.next() return None, it means that the connection is dropped
                // or that the StreamMap is empty. In that case, we should just continue
                Some(item) = self.watchers.next() => {
                    return item;
                }
            }
        }
    }
}
