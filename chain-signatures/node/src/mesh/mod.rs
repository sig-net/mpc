use std::time::Duration;

use crate::mesh::connection::NodeStatus;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::sync::{SyncKind, SyncReportReceiver};
use crate::protocol::ParticipantInfo;
use crate::protocol::ProtocolState;
use crate::rpc::ContractStateWatcher;
use cait_sith::protocol::Participant;
use near_account_id::AccountId;
use tokio::sync::watch;

pub mod connection;
mod state;
pub use state::MeshState;

#[derive(Debug, Clone, clap::Parser)]
#[group(id = "mesh_options")]
pub struct Options {
    /// The interval in milliseconds between pings to participants to check their aliveness
    /// within the MPC network. 1s is normally good enough.
    #[arg(long, env("MPC_MESH_PING_INTERVAL"), default_value = "1000")]
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

/// Set of connections to participants in the network. Each participant is pinged at regular
/// intervals to check their aliveness. The connections can be dropped and reconnected at any time.
pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    connections: connection::Pool,
    state_tx: watch::Sender<MeshState>,
    state_rx: watch::Receiver<MeshState>,
    sync_report_rx: SyncReportReceiver,
    my_id: AccountId,
    me: Option<Participant>,
}

impl Mesh {
    pub fn new(
        client: &NodeClient,
        options: Options,
        my_id: &AccountId,
        sync_report_rx: SyncReportReceiver,
    ) -> Self {
        let ping_interval = Duration::from_millis(options.ping_interval);
        let (state_tx, state_rx) = watch::channel(MeshState::default());
        let connections = connection::Pool::new(client, my_id, ping_interval, state_tx.clone());
        Self {
            connections,
            state_tx,
            state_rx,
            sync_report_rx,
            my_id: my_id.clone(),
            me: None,
        }
    }

    pub fn watch(&self) -> watch::Receiver<MeshState> {
        self.state_rx.clone()
    }

    pub async fn run(mut self, mut contract: ContractStateWatcher) {
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
                                state.remove(previous_me);
                            }
                            state.update(participant, new_status, info);
                        });
                    } else {
                        tracing::warn!(?previous_me, ?contract, "we are no longer part of the MPC network");
                        self.connections.disconnect_all();
                        self.state_tx.send_modify(|state| {
                            state.clear();
                        });
                    }
                }
                Some((participant, kind)) = self.sync_report_rx.recv() => {
                    if self.me == Some(participant) {
                        tracing::warn!(?participant, ?kind, "ignoring self sync report");
                        continue;
                    }
                    match kind {
                        SyncKind::Synced => self.connections.report_node_synced(participant),
                        SyncKind::Desynced => self.connections.report_node_desynced(participant),
                    }
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
        if mesh_state.borrow().active().len() >= threshold {
            return;
        }
        if mesh_state.changed().await.is_err() {
            // The mesh task is gone and nothing will change any more.
            std::future::pending::<()>().await;
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
    use tokio::sync::mpsc;

    use test_log::test;

    const PING_INTERVAL: Duration = Duration::from_millis(10);

    /// Wait for the mesh state to satisfy `f`. Sleeping a fixed span instead
    /// races the connection tasks, which have to complete a real `/status`
    /// round trip before any of our reports can take effect.
    async fn wait_for_state(
        mesh_state: &mut watch::Receiver<MeshState>,
        what: &str,
        f: impl Fn(&MeshState) -> bool,
    ) {
        let wait = async {
            loop {
                if f(&mesh_state.borrow_and_update()) {
                    return;
                }
                mesh_state.changed().await.unwrap();
            }
        };
        if tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .is_err()
        {
            panic!("timed out waiting for mesh state: {what}");
        }
    }

    #[test(tokio::test)]
    async fn test_pool_update() {
        let num_nodes = 3;
        let servers = MockServers::run(num_nodes).await;
        let participants = servers.participants();
        let my_id = servers[0].account_id().clone();

        let (state_tx, mut state_rx) = watch::channel(MeshState::default());
        let mut pool = Pool::new(&servers.client(), &my_id, PING_INTERVAL, state_tx);
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        // We do not sync with ourselves, so only expect 1..num_nodes
        wait_for_state(&mut state_rx, "peers syncing", |state| {
            (1..num_nodes).all(|i| state.need_sync().contains_key(&servers[i].id()))
        })
        .await;
        assert!(state_rx.borrow().active().is_empty());

        for i in 1..num_nodes {
            pool.report_node_synced(servers[i].id());
        }
        wait_for_state(&mut state_rx, "peers active", |state| {
            (1..num_nodes).all(|i| state.active().contains_key(&servers[i].id()))
        })
        .await;
        assert!(state_rx.borrow().need_sync().is_empty());
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
            assert!(state.active().contains_key(&me));
            drop(state);

            for idx in 0..num_nodes {
                sync_tx
                    .send((servers[idx].id(), SyncKind::Synced))
                    .await
                    .unwrap();
            }
            tokio::time::sleep(PING_INTERVAL * 3).await;

            let state = mesh_state.borrow();
            assert_eq!(state.active().len(), num_nodes);
            assert_eq!(state.active(), &expected_participants);
            assert!(state.need_sync().is_empty());
            for idx in 0..num_nodes {
                assert!(state.active().contains_key(&servers[idx].id()));
            }
            assert!(state.active().contains_key(&me));
        }

        // check that the mesh state is updated when a participant goes offline
        {
            servers[1].make_offline().await;
            tokio::time::sleep(PING_INTERVAL * 3).await;

            let state = mesh_state.borrow();
            assert_eq!(state.active().len(), num_nodes - 1);
            assert!(state.active().contains_key(&me));
            assert!(state.active().contains_key(&servers[0].id()));
            assert!(!state.active().contains_key(&servers[1].id()));
            assert!(state.active().contains_key(&servers[2].id()));
        }

        // check that the mesh state is updated when a participant goes back online.
        {
            servers[1].make_online().await;
            tokio::time::sleep(PING_INTERVAL * 3).await;

            // Node is now syncing: should be in need_sync but not in active yet.
            let state = mesh_state.borrow_and_update().clone();
            assert_eq!(state.active().len(), num_nodes - 1);
            assert!(!state.active().contains_key(&servers[1].id()));
            assert!(state.need_sync().contains_key(&servers[1].id()));

            sync_tx
                .send((servers[1].id(), SyncKind::Synced))
                .await
                .unwrap();
            tokio::time::sleep(PING_INTERVAL).await;

            let state = mesh_state.borrow_and_update().clone();
            assert_eq!(state.active().len(), num_nodes);
            assert!(state.need_sync().is_empty());
            for idx in 0..num_nodes {
                assert!(state.active().contains_key(&servers[idx].id()));
            }
            assert!(state.active().contains_key(&me));
        }

        // check that a desync report takes a peer back out of active, and that
        // a later sync report restores it.
        {
            let desynced = servers[1].id();
            sync_tx.send((desynced, SyncKind::Desynced)).await.unwrap();
            wait_for_state(&mut mesh_state, "peer desynced", |state| {
                state.need_sync().contains_key(&desynced)
            })
            .await;
            assert!(!mesh_state.borrow().active().contains_key(&desynced));

            sync_tx.send((desynced, SyncKind::Synced)).await.unwrap();
            wait_for_state(&mut mesh_state, "peer restored", |state| {
                state.active().contains_key(&desynced)
            })
            .await;
            assert!(mesh_state.borrow().need_sync().is_empty());
        }

        mesh_task.abort();
    }

    /// `report_node_desynced` only acts on a peer that is currently active.
    /// Concurrent sign tasks all reporting the same lagging peer must collapse
    /// into the one transition rather than waking the mesh once per report.
    #[test(tokio::test)]
    async fn test_pool_redundant_desync_report_is_a_noop() {
        let num_nodes = 2;
        let servers = MockServers::run(num_nodes).await;
        let participants = servers.participants();
        let my_id = servers[0].account_id().clone();
        let peer = servers[1].id();

        // A long ping interval so the statuses we observe are only the ones
        // our reports drive: the connection task ticks once, then sleeps.
        let (state_tx, mut state_rx) = watch::channel(MeshState::default());
        let mut pool = Pool::new(&servers.client(), &my_id, Duration::from_secs(60), state_tx);
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        // A fresh connection syncs before it is usable.
        wait_for_state(&mut state_rx, "peer syncing", |state| {
            state.status(peer) == Some(NodeStatus::Syncing)
        })
        .await;
        pool.report_node_synced(peer);
        wait_for_state(&mut state_rx, "peer active", |state| {
            state.status(peer) == Some(NodeStatus::Active)
        })
        .await;

        pool.report_node_desynced(peer);
        wait_for_state(&mut state_rx, "peer desynced", |state| {
            state.status(peer) == Some(NodeStatus::Syncing)
        })
        .await;

        // Already syncing, so this one must not touch the mesh state at all.
        pool.report_node_desynced(peer);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), state_rx.changed())
                .await
                .is_err(),
            "a repeated desync report must not notify the mesh again"
        );
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

        let (sync_tx, sync_rx) = mpsc::channel(100);
        let mesh = Mesh::new(
            &servers.client(),
            Options {
                ping_interval: PING_INTERVAL.as_millis() as u64,
            },
            &node_id,
            sync_rx,
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
            tokio::time::sleep(PING_INTERVAL * 3).await;
            for i in 0..num_nodes {
                sync_tx
                    .send((servers[i].id(), SyncKind::Synced))
                    .await
                    .unwrap();
            }

            tokio::time::sleep(PING_INTERVAL * 3).await;
            let state = mesh_state.borrow();

            assert!(state.active().len() == num_nodes);
            assert!(state.need_sync().is_empty());
            for i in 0..num_nodes {
                assert!(
                    state.active().contains_key(&servers[i].id()),
                    "missing {:?}",
                    servers[i].id(),
                );
            }
            assert_eq!(state.active(), &expected_participants);
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
            tokio::time::sleep(PING_INTERVAL * 3).await;
            let state = mesh_state.borrow();

            assert!(state.need_sync().is_empty());
            assert!(state.active().len() == num_nodes);
            for i in 0..num_nodes {
                assert!(
                    state.active().contains_key(&servers[i].id()),
                    "missing {:?}",
                    servers[i].id(),
                );
            }
            assert_eq!(state.active(), &expected_participants);
        }

        mesh_task.abort();
    }

    #[test(tokio::test)]
    async fn test_protocol_version_mismatch_marks_offline() {
        let mut servers = MockServers::run(2).await;
        let participants = servers.participants();
        let my_id = servers[0].account_id().clone();

        let (state_tx, mut state_rx) = watch::channel(MeshState::default());
        let mut pool = Pool::new(&servers.client(), &my_id, PING_INTERVAL, state_tx);
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        let remote_id = servers[1].id();
        let syncing = |state: &MeshState| state.status(remote_id) == Some(NodeStatus::Syncing);
        let active = |state: &MeshState| state.status(remote_id) == Some(NodeStatus::Active);
        let offline = |state: &MeshState| state.status(remote_id).is_none();

        wait_for_state(&mut state_rx, "peer syncing", syncing).await;
        pool.report_node_synced(remote_id);
        wait_for_state(&mut state_rx, "peer active", active).await;

        servers[1].set_protocol_version(None).await;
        wait_for_state(&mut state_rx, "peer offline", offline).await;

        servers[1].make_online().await;
        wait_for_state(&mut state_rx, "peer syncing again", syncing).await;
        pool.report_node_synced(remote_id);
        wait_for_state(&mut state_rx, "peer active again", active).await;

        servers[1].set_protocol_version(Some(0)).await;
        wait_for_state(&mut state_rx, "peer offline again", offline).await;
    }
}
