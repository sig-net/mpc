use std::time::Duration;

use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use cait_sith::protocol::Participant;
use connection::{ConnectionWatcher, NodeStatusUpdate};
use std::sync::Arc;
use tokio::sync::RwLock;

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

    /// Participants that are stable in the network; as in they have met certain criterias such
    /// as indexing the latest blocks.
    pub stable: Vec<Participant>,
}

impl MeshState {
    pub fn update(&mut self, participant: Participant, status: NodeStatusUpdate) {
        match status {
            NodeStatusUpdate::Active(is_stable, info) => {
                self.active.insert(&participant, info);
                if is_stable {
                    self.stable.push(participant);
                }
            }
            NodeStatusUpdate::Offline => {
                self.active.remove(&participant);
                self.stable.retain(|p| p != &participant);
            }
        }
    }
}

/// Set of connections to participants in the network. Each participant is pinged at regular
/// intervals to check their aliveness. The connections can be dropped and reconnected at any time.
pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    connections: connection::Pool,
    state: Arc<RwLock<MeshState>>,
    ping_interval: Duration,
    conn_update: ConnectionWatcher,
}

impl Mesh {
    pub fn new(client: &NodeClient, options: Options) -> Self {
        let ping_interval = Duration::from_millis(options.ping_interval);
        let connections = connection::Pool::new(client, ping_interval);
        let conn_update = connections.watcher();
        Self {
            connections,
            state: Arc::new(RwLock::new(MeshState::default())),
            ping_interval,
            conn_update,
        }
    }

    pub fn state(&self) -> &Arc<RwLock<MeshState>> {
        &self.state
    }

    pub async fn run(mut self, contract_state: Arc<RwLock<Option<ProtocolState>>>) {
        let mut contract_change_interval = tokio::time::interval(self.ping_interval / 2);
        tokio::spawn(async move {
            loop {
                let (p, status) = self.conn_update.next().await;
                tracing::info!(?p, ?status, "mesh connection status changed");
                let mut state = self.state.write().await;
                state.update(p, status);
            }
        });

        loop {
            contract_change_interval.tick().await;
            if let Some(contract) = &*contract_state.read().await {
                self.connections.connect(contract).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::mesh::connection::Pool;
    use crate::protocol::contract::RunningContractState;
    use crate::protocol::ParticipantInfo;
    use crate::web::StateView;

    use mockito::ServerGuard;
    use test_log::test;

    struct MockServer {
        id: u32,
        server: ServerGuard,
    }

    impl MockServer {
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

    struct MockCluster {
        servers: Vec<MockServer>,
    }

    // TODO: make this async spawn
    impl MockCluster {
        async fn new(num_nodes: u32) -> Self {
            let mut servers = Vec::new();
            for i in 0..num_nodes {
                servers.push(MockServer::new(i).await);
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
    async fn test_pool_update() {
        let num_nodes = 3;
        let ping_interval = Duration::from_millis(1000);
        let servers = MockCluster::new(num_nodes).await;
        let participants = servers.participants();
        let mut pool = Pool::new(&servers.servers[0].client(), ping_interval);
        let mut watcher = pool.watcher();
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        // sleep a bit before trying to get the status.
        tokio::time::sleep(ping_interval + Duration::from_millis(100)).await;

        for i in 0..num_nodes {
            match tokio::time::timeout(Duration::from_millis(100), watcher.next()).await {
                Ok((participant, status)) => {
                    tracing::info!(?participant, ?status, "got connection update");
                    assert!(matches!(status, NodeStatusUpdate::Active(true, _)));
                }
                Err(_) => {
                    panic!("{i}: timeout waiting for connection update");
                }
            }
        }
    }

    #[test(tokio::test)]
    async fn test_mesh_update() {
        let threshold = 2;
        let num_nodes = 3;
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk = sk.public_key();
        let ping_interval = Duration::from_millis(1000);
        let servers = MockCluster::new(num_nodes).await;
        let participants = servers.participants();
        let client = servers.servers[0].client();

        let contract = Arc::new(RwLock::new(Some(ProtocolState::Running(
            RunningContractState {
                epoch: 0,
                public_key: *pk.as_affine(),
                participants: participants.clone(),
                candidates: Default::default(),
                join_votes: Default::default(),
                leave_votes: Default::default(),
                threshold,
            },
        ))));

        let mesh = Mesh::new(
            &client,
            Options {
                ping_interval: ping_interval.as_millis() as u64,
            },
        );

        let state = mesh.state().clone();
        let mesh_task = tokio::spawn(mesh.run(contract));

        // give the mesh some time to run and update the connections.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // check that the mesh state is updated.
        let state = state.read().await;
        assert_eq!(state.active.len(), num_nodes as usize);
        assert_eq!(state.active, participants);

        mesh_task.abort();
    }
}
