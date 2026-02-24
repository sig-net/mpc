use std::collections::BTreeSet;
use std::time::Duration;

use crate::mesh::connection::NodeStatus;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ParticipantInfo;
use crate::protocol::ProtocolState;
use crate::rpc::ContractStateWatcher;
use cait_sith::protocol::Participant;
use near_account_id::AccountId;
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
    my_id: AccountId,
    me: Option<Participant>,
}

impl Mesh {
    pub fn new(
        client: &NodeClient,
        options: Options,
        my_id: &AccountId,
        synced_peer_rx: mpsc::Receiver<Participant>,
    ) -> Self {
        let ping_interval = Duration::from_millis(options.ping_interval);
        let (state_tx, state_rx) = watch::channel(MeshState::default());
        let connections = connection::Pool::new(client, my_id, ping_interval);
        Self {
            connections,
            state_tx,
            state_rx,
            synced_peer_rx,
            my_id: my_id.clone(),
            me: None,
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
                    let my_info = self.find_myself(&contract);
                    let previous_me = self.me.take();
                    self.me = my_info.as_ref().map(|(participant, _)| *participant);

                    // Check that we are indeed part of the contract participants.
                    if let Some((participant, info)) = my_info {
                        let new_status = match &contract {
                            ProtocolState::Initializing(_) | ProtocolState::Resharing(_) => NodeStatus::Inactive,
                            ProtocolState::Running(_) => NodeStatus::Active,
                        };
                        self.connections.connect(contract).await;
                        self.state_tx.send_modify(|state| {
                            // if the previous me is different from the current me, remove the
                            // previous me from the MeshState.
                            if let Some(previous_me) = previous_me.filter(|old| *old != participant) {
                                state.active.remove(&previous_me);
                                state.need_sync.remove(&previous_me);
                                state.stable.remove(&previous_me);
                            }
                            state.update(participant, new_status, info);
                        });
                    } else {
                        tracing::warn!(?previous_me, ?contract, "we are no longer part of the MPC network");
                        self.connections.disconnect_all();
                        self.state_tx.send_modify(|state| {
                            state.active.clear();
                            state.need_sync.clear();
                            state.stable.clear();
                        });
                    }
                }
                Some(participant) = self.synced_peer_rx.recv() => {
                    if self.me == Some(participant) {
                        tracing::warn!(?participant, "ignoring self sync report");
                        continue;
                    }
                    self.connections.report_node_synced(participant).await;
                }
            }
        }
    }

    fn find_myself(&self, contract: &ProtocolState) -> Option<(Participant, ParticipantInfo)> {
        match contract {
            ProtocolState::Initializing(init) => {
                let participants: Participants = init.candidates.clone().into();
                participants
                    .find(&self.my_id)
                    .map(|(p, info)| (*p, info.clone()))
            }
            ProtocolState::Running(running) => running
                .participants
                .find(&self.my_id)
                .map(|(p, info)| (*p, info.clone())),
            ProtocolState::Resharing(resharing) => resharing
                .new_participants
                .find(&self.my_id)
                .map(|(p, info)| (*p, info.clone())),
        }
    }
}

pub async fn wait_threshold_active(mesh_state: &mut watch::Receiver<MeshState>, threshold: usize) {
    loop {
        if mesh_state.borrow().active.len() >= threshold {
            return;
        }
        let _ = mesh_state.changed().await;
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

    async fn expect_status(
        watcher: &mut connection::ConnectionWatcher,
        participant: Participant,
        expected: NodeStatus,
    ) {
        for _ in 0..20 {
            if let Ok((p, status, _info)) =
                tokio::time::timeout(Duration::from_millis(500), watcher.next()).await
            {
                if p == participant && status == expected {
                    return;
                }
            }
        }
        panic!("timed out waiting for {participant:?} to become {expected:?}");
    }

    #[test(tokio::test)]
    async fn test_pool_update() {
        let num_nodes = 3;
        let servers = MockServers::run(num_nodes).await;
        let participants = servers.participants();
        let my_id = servers[0].account_id().clone();

        let mut pool = Pool::new(&servers.client(), &my_id, PING_INTERVAL);
        let mut watcher = pool.watch();
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        // We do not sync with ourselves, so only expect 1..num_nodes
        tokio::time::sleep(PING_INTERVAL * 3).await;
        let mut syncing = HashSet::new();
        for i in 1..num_nodes {
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
        for i in 1..num_nodes {
            pool.report_node_synced(servers[i].id()).await;
        }

        // Same with active. We only expect 1..num_nodes for new statuses
        tokio::time::sleep(PING_INTERVAL * 3).await;
        for i in 1..num_nodes {
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
        let root_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, "root");
        let num_nodes = 3;

        let mut servers = MockServers::run(num_nodes).await;

        let participants = servers.participants();
        let me = servers[0].id();
        let node_id = servers[0].account_id().clone();
        let expected_participants = participants.clone();

        let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
            &node_id,
            root_sk.public_key().into_affine_point(),
            2,
            participants.clone(),
        );

        let (sync_tx, sync_rx) = mpsc::channel(16);
        let mesh = Mesh::new(
            &servers.client(),
            Options {
                ping_interval: PING_INTERVAL.as_millis() as u64,
            },
            &node_id,
            sync_rx,
        );

        let mut mesh_state = mesh.watch();
        let mesh_task = tokio::spawn(mesh.run(contract_watcher));

        // check that the mesh state is updated.
        {
            tokio::time::sleep(PING_INTERVAL * 3).await;
            let state = mesh_state.borrow();
            assert!(state.active.contains_key(&me));
            assert!(state.stable.contains(&me));
            drop(state);

            for idx in 0..num_nodes {
                sync_tx.send(servers[idx].id()).await.unwrap();
            }
            tokio::time::sleep(PING_INTERVAL * 3).await;

            let state = mesh_state.borrow();
            assert_eq!(state.active.len(), num_nodes);
            assert_eq!(state.active, expected_participants);
            assert!(state.need_sync.is_empty());
            for idx in 0..num_nodes {
                assert!(state.active.contains_key(&servers[idx].id()));
            }
            assert!(state.active.contains_key(&me));
        }

        // check that the mesh state is updated when a participant goes offline
        {
            servers[1].make_offline().await;
            tokio::time::sleep(PING_INTERVAL * 3).await;

            let state = mesh_state.borrow();
            assert_eq!(state.active.len(), num_nodes - 1);
            assert!(state.active.contains_key(&me));
            assert!(state.active.contains_key(&servers[0].id()));
            assert!(!state.active.contains_key(&servers[1].id()));
            assert!(state.active.contains_key(&servers[2].id()));
        }

        // check that the mesh state is updated when a participant goes back online.
        {
            servers[1].make_online().await;
            tokio::time::sleep(PING_INTERVAL * 3).await;

            let state = mesh_state.borrow_and_update().clone();
            assert_eq!(state.active.len(), num_nodes - 1);
            sync_tx.send(servers[1].id()).await.unwrap();
            tokio::time::sleep(PING_INTERVAL).await;

            let state = mesh_state.borrow_and_update().clone();
            assert_eq!(state.active.len(), num_nodes);
            assert!(state.need_sync.is_empty());
            for idx in 0..num_nodes {
                assert!(state.active.contains_key(&servers[idx].id()));
                assert!(state.stable.contains(&servers[idx].id()));
            }
            assert!(state.active.contains_key(&me));
            assert!(state.stable.contains(&me));
        }

        mesh_task.abort();
    }

    #[test(tokio::test)]
    async fn test_mesh_contract_update() {
        let root_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, "root");
        let mut num_nodes = 3;
        let mut servers = MockServers::run(num_nodes).await;
        let node_id = servers[0].account_id().clone();

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
            &node_id,
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
            servers.remove_back();
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

    #[test(tokio::test)]
    async fn test_protocol_version_mismatch_marks_offline() {
        let mut servers = MockServers::run(2).await;
        let participants = servers.participants();
        let my_id = servers[0].account_id().clone();

        let mut pool = Pool::new(&servers.client(), &my_id, PING_INTERVAL);
        let mut watcher = pool.watch();
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        let remote_id = servers[1].id();

        expect_status(&mut watcher, remote_id, NodeStatus::Syncing).await;
        pool.report_node_synced(remote_id).await;
        expect_status(&mut watcher, remote_id, NodeStatus::Active).await;

        servers[1].set_protocol_version(None).await;
        expect_status(&mut watcher, remote_id, NodeStatus::Offline).await;

        servers[1].make_online().await;
        expect_status(&mut watcher, remote_id, NodeStatus::Syncing).await;
        pool.report_node_synced(remote_id).await;
        expect_status(&mut watcher, remote_id, NodeStatus::Active).await;

        servers[1].set_protocol_version(Some(0)).await;
        expect_status(&mut watcher, remote_id, NodeStatus::Offline).await;
    }
}
