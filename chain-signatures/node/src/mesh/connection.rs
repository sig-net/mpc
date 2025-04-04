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
            status_tx,
            participant,
            info.clone(),
            ping_interval,
        ));
        Self {
            info: info.clone(),
            status_rx,
            task,
        }
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

    conn_change_tx: broadcast::Sender<ConnectionUpdate>,
    conn_change_rx: broadcast::Receiver<ConnectionUpdate>,
}

impl Pool {
    pub fn new(client: &NodeClient, ping_interval: Duration) -> Self {
        tracing::info!("creating new connection pool");
        let (conn_change_tx, conn_change_rx) = broadcast::channel(32);
        Self {
            client: client.clone(),
            ping_interval,
            connections: HashMap::new(),
            conn_change_tx,
            conn_change_rx,
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
        for (&participant, info) in participants.iter() {
            seen.insert(participant);

            let node = (participant, &info.url);
            match self.connections.entry(participant) {
                Entry::Occupied(mut conn) => {
                    if &conn.get().info != info {
                        tracing::info!(?node, "node connection updating");
                        let conn = conn.insert(NodeConnection::spawn(
                            &self.client,
                            participant,
                            info,
                            self.ping_interval,
                        ));

                        if let Err(_) = self
                            .conn_change_tx
                            .send(ConnectionUpdate::New(participant, conn.status_rx.clone()))
                        {
                            tracing::warn!(?node, "failed to send new connection");
                        }
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

                    if let Err(_) = self
                        .conn_change_tx
                        .send(ConnectionUpdate::New(participant, conn.status_rx.clone()))
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
            self.connections.remove(&participant);
            if let Err(err) = self
                .conn_change_tx
                .send(ConnectionUpdate::Drop(participant))
            {
                tracing::warn!(?participant, "unable to send change for drop participant");
            }
        }
    }

    // pub async fn status(&self) -> MeshState {
    //     let mut stable = Vec::new();
    //     let mut active = Participants::default();
    //     for (participant, conn) in self.connections.iter() {
    //         if let NodeStatus::Active(is_stable) = conn.status().await {
    //             active.insert(participant, conn.info.clone());
    //             if is_stable {
    //                 stable.push(*participant);
    //             }
    //         }
    //     }

    //     MeshState { active, stable }
    // }

    pub fn watcher(&self) -> ConnectionWatcher {
        // ConnectionWatcher {
        //     watchers: self
        //         .connections
        //         .iter()
        //         .map(|(&p, conn)| (p, conn.status_rx.clone()))
        //         .collect(),
        // }

        // ConnectionWatcher::new(
        //     self.connections
        //         .iter()
        //         .map(|(&p, conn)| (p, conn.status_rx.clone())),
        // )

        ConnectionWatcher::new(self.conn_change_rx.resubscribe())
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
    conn_update: broadcast::Receiver<ConnectionUpdate>,
    /// Set of active connections that we are watching.
    watchers: StreamMap<Participant, WatchStream<NodeStatusUpdate>>,
}

impl ConnectionWatcher {
    fn new(
        conn_update: broadcast::Receiver<ConnectionUpdate>,
        // conn: impl IntoIterator<Item = (Participant, watch::Receiver<NodeStatus>)>,
    ) -> Self {
        // let mut watchers = StreamMap::new();
        // for (id, receiver) in conn {
        //     watchers.insert(id, WatchStream::new(receiver));
        // }
        // Self { watchers }

        Self {
            conn_update,
            watchers: StreamMap::new(),
        }
    }

    pub async fn next(&mut self) -> Option<(Participant, NodeStatusUpdate)> {
        loop {
            tokio::select! {
                // Update our watchers if the connections changed.
                Ok(update) = self.conn_update.recv() => {
                    match update {
                        ConnectionUpdate::New(participant, rx) => {
                            self.watchers.insert(participant, WatchStream::new(rx));
                        }
                        ConnectionUpdate::Drop(participant) => {
                            self.watchers.remove(&participant);
                        }
                    }
                }
                // NOTE: if watchers.next() return None, it means that the connection is dropped
                Some(item) = self.watchers.next() => {
                    return Some(item);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mockito::ServerGuard;
    use tokio::sync::RwLock;

    use crate::mesh::MeshState;
    use test_log::test;

    use super::*;

    struct Server {
        id: u32,
        server: ServerGuard,
    }

    impl Server {
        async fn new(id: u32) -> Self {
            let mut server = mockito::Server::new_async().await;
            server
                .mock("GET", "/state")
                .with_status(201)
                .with_header("content-type", "text/plain")
                .with_body(
                    serde_json::to_vec(&StateView::Running {
                        participants: vec![Participant::from(0)],
                        triple_count: 0,
                        triple_mine_count: 0,
                        triple_potential_count: 0,
                        presignature_count: 0,
                        presignature_mine_count: 0,
                        presignature_potential_count: 0,
                        latest_block_height: 0,
                        is_stable: true,
                    })
                    .unwrap(),
                )
                .create_async()
                .await;

            server
                .mock("POST", "/msg")
                .with_status(201)
                .with_header("content-type", "application/json")
                .with_body("{}")
                .create_async()
                .await;

            Self { id, server }
        }

        fn client(&self) -> NodeClient {
            NodeClient::new(&crate::node_client::Options::default())
        }

        fn info(&self) -> ParticipantInfo {
            ParticipantInfo {
                id: self.id,
                account_id: format!("p{}.test", self.id).parse().unwrap(),
                url: self.server.url(),
                cipher_pk: mpc_keys::hpke::PublicKey::from_bytes(&[0; 32]),
                sign_pk: near_crypto::PublicKey::empty(near_crypto::KeyType::ED25519),
            }
        }
    }

    struct Servers {
        servers: Vec<Server>,
    }

    // TODO: make this async spawn
    impl Servers {
        async fn new(num_nodes: u32) -> Self {
            let mut servers = Vec::new();
            for i in 0..num_nodes {
                servers.push(Server::new(i).await);
            }
            Self { servers }
        }

        fn participants(&self) -> Participants {
            let mut participants = Participants::default();
            for server in &self.servers {
                participants.insert(&Participant::from(server.id), server.info().clone());
            }
            participants
        }
    }

    #[test(tokio::test)]
    async fn test_connection_update() {
        let num_nodes = 3;
        // let state = Arc::new(RwLock::new(MeshState::default()));
        let ping_interval = Duration::from_millis(1000);
        let servers = Servers::new(num_nodes).await;
        let participants = servers.participants();
        let mut pool = Pool::new(&servers.servers[0].client(), ping_interval);
        let mut watcher = pool.watcher();
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        // sleep a bit before trying to get the status.
        tokio::time::sleep(ping_interval + Duration::from_millis(100)).await;

        for i in 0..num_nodes {
            match tokio::time::timeout(Duration::from_millis(100), watcher.next()).await {
                Ok(Some((participant, status))) => {
                    tracing::info!(?participant, ?status, "got connection update");
                    assert!(matches!(status, NodeStatusUpdate::Active(true, _)));
                }
                Ok(None) => {
                    panic!("{i}: failed to get connection update");
                }
                Err(_) => {
                    panic!("{i}: timeout waiting for connection update");
                }
            }
        }

        // crate::mesh::update(
        //     &state,
        //     Participant::from(0),
        //     NodeStatusUpdate::Active(true, servers.servers[0].info()),
        // )
        // .await;
    }
}
