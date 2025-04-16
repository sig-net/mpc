pub mod connection;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use connection::{ConnectionWatcher, NodeStatusUpdate};

use cait_sith::protocol::Participant;
use tokio::sync::RwLock;

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

    /// Participants that can be selected for a new protocol invocation.
    pub stable: BTreeSet<Participant>,
}

impl MeshState {
    pub fn update(&mut self, participant: Participant, status: NodeStatusUpdate) {
        match status {
            NodeStatusUpdate::Active(info) => {
                self.active.insert(&participant, info);
                self.stable.insert(participant);
            }
            NodeStatusUpdate::Inactive(info) => {
                self.active.insert(&participant, info);
            }
            NodeStatusUpdate::Offline => {
                self.active.remove(&participant);
                self.stable.remove(&participant);
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

    pub fn watcher(&self) -> ConnectionWatcher {
        self.connections.watcher()
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
    use crate::web::mock::MockServers;

    use test_log::test;

    #[test(tokio::test)]
    async fn test_pool_update() {
        let num_nodes = 3;
        let ping_interval = Duration::from_millis(300);
        let servers = MockServers::new(num_nodes).await;
        let participants = servers.participants();

        let mut pool = Pool::new(&servers.client(), ping_interval);
        let mut watcher = pool.watcher();
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        // sleep a bit before trying to get the status.
        tokio::time::sleep(ping_interval).await;

        for i in 0..num_nodes {
            match tokio::time::timeout(Duration::from_millis(100), watcher.next()).await {
                Ok((participant, status)) => {
                    tracing::info!(?participant, ?status, "got connection update");
                    assert!(matches!(status, NodeStatusUpdate::Active(_)));
                }
                Err(_) => {
                    panic!("{i}: timeout waiting for connection update");
                }
            }
        }
    }

    #[test(tokio::test)]
    async fn test_mesh_update() {
        let num_nodes = 3;
        let threshold = 2;
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let ping_interval = Duration::from_millis(300);

        let mut servers = MockServers::new(num_nodes).await;
        let contract = Arc::new(RwLock::new(Some(ProtocolState::Running(
            RunningContractState {
                epoch: 0,
                public_key: *sk.public_key().as_affine(),
                participants: servers.participants(),
                candidates: Default::default(),
                join_votes: Default::default(),
                leave_votes: Default::default(),
                threshold,
            },
        ))));

        let mesh = Mesh::new(
            &servers.client(),
            Options {
                ping_interval: ping_interval.as_millis() as u64,
            },
        );

        let state = mesh.state().clone();
        let mesh_task = tokio::spawn(mesh.run(contract.clone()));

        // check that the mesh state is updated.
        {
            // give the mesh some time to run and update the connections.
            tokio::time::sleep(ping_interval).await;
            let state = state.read().await;
            assert_eq!(state.active.len(), num_nodes);
            assert_eq!(state.active, servers.participants());
        }

        // check that the mesh state is updated when a participant goes offline
        {
            servers[0].make_offline().await;
            tokio::time::sleep(Duration::from_millis(2000)).await;

            let state = state.read().await;
            assert_eq!(state.active.len(), num_nodes - 1);
            assert!(state.active.contains_key(&servers[1].id()));
            assert!(state.active.contains_key(&servers[2].id()));
            assert!(state.stable.contains(&servers[1].id()));
            assert!(state.stable.contains(&servers[2].id()));
        }

        // check that the mesh state is updated when a participant goes back online.
        {
            servers[0].make_online().await;
            tokio::time::sleep(Duration::from_millis(2000)).await;

            let state = state.read().await;
            assert_eq!(state.active.len(), num_nodes);
        }

        mesh_task.abort();
    }

    #[test(tokio::test)]
    async fn test_mesh_contract_update() {
        let mut num_nodes = 3;
        let threshold = 2;
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk = sk.public_key();
        let ping_interval = Duration::from_millis(300);
        let mut servers = MockServers::new(num_nodes).await;
        let participants = servers.participants();
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
            &servers.client(),
            Options {
                ping_interval: ping_interval.as_millis() as u64,
            },
        );
        let state = mesh.state().clone();
        let mesh_task = tokio::spawn(mesh.run(contract.clone()));

        // check on node creation with contract change.
        {
            num_nodes += 1;
            servers.push_next().await;

            let mut contract = contract.write().await;
            match contract.as_mut().unwrap() {
                ProtocolState::Running(RunningContractState { participants, .. }) => {
                    *participants = servers.participants();
                }
                _ => panic!("expected running contract"),
            }
            // need to drop our write lock of the contract so mesh can read from it.
            drop(contract);

            tokio::time::sleep(ping_interval).await;
            let state = state.read().await;
            assert_eq!(state.active.len(), num_nodes);
            assert_eq!(state.active, servers.participants());
            assert_eq!(state.stable.len(), num_nodes);
            assert_eq!(
                state.stable,
                servers
                    .participants()
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
            );
        }

        // check on node deletion with contract change.
        {
            num_nodes -= 1;
            servers.swap_remove_front().await;

            let mut contract = contract.write().await;
            match contract.as_mut().unwrap() {
                ProtocolState::Running(RunningContractState { participants, .. }) => {
                    *participants = servers.participants();
                }
                _ => panic!("expected running contract"),
            }
            // need to drop our write lock of the contract so mesh can read from it.
            drop(contract);

            tokio::time::sleep(ping_interval).await;
            let state = state.read().await;
            assert_eq!(state.active.len(), num_nodes);
            assert_eq!(state.active, servers.participants());
            assert_eq!(state.stable.len(), num_nodes);
            assert_eq!(
                state.stable,
                servers
                    .participants()
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
            );
        }

        mesh_task.abort();
    }
}
