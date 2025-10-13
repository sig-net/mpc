use std::collections::BTreeSet;
use std::time::Duration;

use crate::mesh::connection::NodeStatus;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ParticipantInfo;
use crate::rpc::ContractStateWatcher;
use cait_sith::protocol::Participant;
use tokio::sync::{mpsc, watch};

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

    /// Participants that are currently out-of-sync, they will become active
    /// once we finished synchronization.
    pub need_sync: Participants,

    /// Participants that can be selected for a new protocol invocation.
    pub stable: BTreeSet<Participant>,
}

impl MeshState {
    pub fn update(&mut self, participant: Participant, status: NodeStatus, info: ParticipantInfo) {
        match status {
            NodeStatus::Active => {
                self.active.insert(&participant, info);
                self.need_sync.remove(&participant);
                self.stable.insert(participant);
            }
            NodeStatus::Syncing => {
                self.need_sync.insert(&participant, info);
            }
            NodeStatus::Inactive | NodeStatus::Offline => {
                self.active.remove(&participant);
                self.need_sync.remove(&participant);
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
    state_tx: watch::Sender<MeshState>,
    state_rx: watch::Receiver<MeshState>,
    synced_peer_rx: mpsc::Receiver<Participant>,
}

impl Mesh {
    pub fn new(
        client: &NodeClient,
        options: Options,
        synced_peer_rx: mpsc::Receiver<Participant>,
    ) -> Self {
        let ping_interval = Duration::from_millis(options.ping_interval);
        let (state_tx, state_rx) = watch::channel(MeshState::default());
        let connections = connection::Pool::new(client, ping_interval);
        Self {
            connections,
            state_tx,
            state_rx,
            synced_peer_rx,
        }
    }

    pub fn watch(&self) -> watch::Receiver<MeshState> {
        self.state_rx.clone()
    }

    pub async fn run(mut self, mut contract: ContractStateWatcher) {
        let state_tx = self.state_tx.clone();
        let mut conn_update = self.connections.watch();
        tokio::spawn(async move {
            loop {
                let (p, status, info) = conn_update.next().await;
                tracing::info!(?p, ?status, "mesh connection status changed");
                state_tx.send_modify(|state| {
                    state.update(p, status, info);
                });
            }
        });

        loop {
            tokio::select! {
                Some(contract) = contract.next_state() => {
                    tracing::info!(?contract, "new contract state received");
                    self.connections.connect(contract).await;
                }
                Some(participant) = self.synced_peer_rx.recv() => {
                    self.connections.report_node_synced(participant).await;
                }
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
    use crate::protocol::ProtocolState;
    use crate::util::NearPublicKeyExt as _;
    use crate::web::mock::MockServers;

    use test_log::test;

    const PING_INTERVAL: Duration = Duration::from_millis(10);

    #[test(tokio::test)]
    async fn test_pool_update() {
        let num_nodes = 3;
        let servers = MockServers::new(num_nodes).await;
        let participants = servers.participants();

        let mut pool = Pool::new(&servers.client(), PING_INTERVAL);
        let mut watcher = pool.watch();
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        tokio::time::sleep(PING_INTERVAL * 3).await;
        let mut syncing = HashSet::new();
        for i in 0..num_nodes {
            match tokio::time::timeout(Duration::from_millis(100), watcher.next()).await {
                Ok((participant, status, _info)) => {
                    tracing::info!(?participant, ?status, "got connection update for syncing");
                    if matches!(status, NodeStatus::Syncing) {
                        syncing.insert(participant);
                    }
                }
                Err(_) => {
                    panic!("timed out waiting for syncing nodes idx={i}");
                }
            }
        }

        for i in 0..num_nodes {
            pool.report_node_synced(servers[i].id()).await;
        }

        tokio::time::sleep(PING_INTERVAL * 3).await;
        for i in 0..num_nodes {
            match tokio::time::timeout(Duration::from_millis(100), watcher.next()).await {
                Ok((participant, status, _info)) => {
                    tracing::info!(?participant, ?status, "got connection update for active");
                    if matches!(status, NodeStatus::Active) {
                        syncing.insert(participant);
                    }
                }
                Err(_) => {
                    panic!("timed out waiting for active nodes idx={i}");
                }
            }
        }
    }

    #[test(tokio::test)]
    async fn test_mesh_update() {
        let node_id = "node0.testnet".parse().unwrap();
        let root_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, "root");
        let num_nodes = 3;

        let mut servers = MockServers::new(num_nodes).await;

        let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
            &node_id,
            root_sk.public_key().into_affine_point(),
            2,
            servers.participants().clone(),
        );

        let (sync_tx, sync_rx) = mpsc::channel(16);
        let mesh = Mesh::new(
            &servers.client(),
            Options {
                ping_interval: PING_INTERVAL.as_millis() as u64,
            },
            sync_rx,
        );

        let mut mesh_state = mesh.watch();
        let mesh_task = tokio::spawn(mesh.run(contract_watcher));

        // check that the mesh state is updated.
        {
            let expected_participants = servers.participants();
            tokio::time::sleep(PING_INTERVAL * 3).await;

            sync_tx.send(servers[0].id()).await.unwrap();
            sync_tx.send(servers[1].id()).await.unwrap();
            sync_tx.send(servers[2].id()).await.unwrap();
            tokio::time::sleep(PING_INTERVAL * 3).await;

            let state = mesh_state.borrow();
            assert_eq!(state.active.len(), num_nodes);
            assert_eq!(state.active, expected_participants);
            assert!(state.need_sync.is_empty());
            assert!(state.active.contains_key(&servers[0].id()));
            assert!(state.active.contains_key(&servers[1].id()));
            assert!(state.active.contains_key(&servers[2].id()));
        }

        // check that the mesh state is updated when a participant goes offline
        {
            servers[0].make_offline().await;
            tokio::time::sleep(PING_INTERVAL * 3).await;

            let state = mesh_state.borrow();
            assert_eq!(state.active.len(), num_nodes - 1);
            assert!(state.active.contains_key(&servers[1].id()));
            assert!(state.active.contains_key(&servers[2].id()));
            assert!(state.stable.contains(&servers[1].id()));
            assert!(state.stable.contains(&servers[2].id()));
        }

        // check that the mesh state is updated when a participant goes back online.
        {
            servers[0].make_online().await;
            tokio::time::sleep(PING_INTERVAL * 3).await;

            let state = mesh_state.borrow_and_update().clone();
            // We're still in syncing, make sure we report node 0 and mark it as synced.
            assert_eq!(state.active.len(), num_nodes - 1);
            sync_tx.send(servers[0].id()).await.unwrap();
            tokio::time::sleep(PING_INTERVAL).await;

            let state = mesh_state.borrow_and_update().clone();
            assert_eq!(state.active.len(), num_nodes);
            assert!(state.need_sync.is_empty());
            assert!(state.active.contains_key(&servers[0].id()));
            assert!(state.active.contains_key(&servers[1].id()));
            assert!(state.active.contains_key(&servers[2].id()));
            assert!(state.stable.contains(&servers[0].id()));
            assert!(state.stable.contains(&servers[1].id()));
            assert!(state.stable.contains(&servers[2].id()));
        }

        mesh_task.abort();
    }

    #[test(tokio::test)]
    async fn test_mesh_contract_update() {
        let node_id = "node0.testnet".parse().unwrap();
        let root_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, "root");
        let mut num_nodes = 3;
        let mut servers = MockServers::new(num_nodes).await;

        let (contract_watcher, contract_tx) = ContractStateWatcher::with_running(
            &node_id,
            root_sk.public_key().into_affine_point(),
            2,
            servers.participants(),
        );

        let (sync_tx, synced_peer_rx) = mpsc::channel(100);
        let mesh = Mesh::new(
            &servers.client(),
            Options {
                ping_interval: PING_INTERVAL.as_millis() as u64,
            },
            synced_peer_rx,
        );
        let mesh_state = mesh.watch();
        let mesh_task = tokio::spawn(mesh.run(contract_watcher));

        // check on node creation with contract change.
        {
            num_nodes += 1;
            servers.push_next().await;
            // update the contract with the newest participant.
            contract_tx.send_modify(|contract| {
                match contract.as_mut().unwrap() {
                    ProtocolState::Running(RunningContractState { participants, .. }) => {
                        *participants = servers.participants().clone();
                    }
                    _ => tracing::warn!("expected running contract"),
                }
                tracing::info!(?contract, "updating contract with new participant");
            });

            // Wait for the mesh to process the contract update and connect the new participant
            let expected_participants = servers.participants();
            let expected_stable: BTreeSet<_> = expected_participants.keys().copied().collect();

            tokio::time::sleep(PING_INTERVAL * 3).await;
            for i in 0..num_nodes {
                sync_tx.send(servers[i].id()).await.unwrap();
            }

            tokio::time::sleep(PING_INTERVAL * 3).await;
            let state = mesh_state.borrow();

            assert!(state.active.len() == num_nodes);
            assert!(state.need_sync.is_empty());
            for i in 0..num_nodes {
                assert!(
                    state.active.contains_key(&servers[i].id()),
                    "missing {:?}",
                    servers[i].id(),
                );
            }
            assert_eq!(state.stable, expected_stable);
        }

        // check on node deletion with contract change.
        {
            num_nodes -= 1;
            servers.swap_remove_front().await;
            // update the contract after removing the participant.
            contract_tx.send_modify(|contract| match contract.as_mut().unwrap() {
                ProtocolState::Running(RunningContractState { participants, .. }) => {
                    *participants = servers.participants().clone();
                }
                _ => tracing::warn!("expected running contract"),
            });

            // Wait for the mesh to process the contract update and remove the participant
            let expected_participants = servers.participants();
            let expected_stable: BTreeSet<_> = expected_participants.keys().copied().collect();

            tokio::time::sleep(PING_INTERVAL * 3).await;
            let state = mesh_state.borrow();

            assert!(state.need_sync.is_empty());
            assert!(state.active.len() == num_nodes);
            for i in 0..num_nodes {
                assert!(
                    state.active.contains_key(&servers[i].id()),
                    "missing {:?}",
                    servers[i].id(),
                );
            }
            assert_eq!(state.stable, expected_stable);
        }

        mesh_task.abort();
    }
}
