use std::collections::BTreeSet;
use std::time::Duration;

use crate::mesh::connection::NodeStatus;
use crate::metrics::mesh as metrics;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::ParticipantInfo;
use crate::protocol::ProtocolState;
use crate::rpc::ContractStateWatcher;
use cait_sith::protocol::Participant;
use near_account_id::AccountId;
use tokio::sync::{mpsc, watch};

pub mod connection;
mod state;
pub use state::MeshState;

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
        // Deliberately not detached-and-forgotten: if this loop ever ends, the
        // mesh state freezes at its last value while the node keeps reporting
        // healthy, and every `wait_threshold_active` downstream would go on
        // succeeding against a stale snapshot. Say so loudly.
        let mut updater = tokio::spawn(async move {
            while let Some(update) = conn_update.next().await {
                match update {
                    connection::MeshUpdate::Status(p, status, info) => {
                        tracing::info!(?p, ?status, "mesh connection status changed");
                        metrics::MESH_STATUS_TRANSITIONS
                            .with_label_values(&[status_label(status)])
                            .inc();
                        state_tx.send_modify(|state| state.update(p, status, info));
                    }
                    connection::MeshUpdate::Dropped(p) => {
                        tracing::info!(?p, "mesh connection dropped");
                        metrics::MESH_STATUS_TRANSITIONS
                            .with_label_values(&["dropped"])
                            .inc();
                        state_tx.send_modify(|state| state.remove(p));
                    }
                }
                let state = state_tx.borrow();
                metrics::MESH_PARTICIPANTS
                    .with_label_values(&["active"])
                    .set(state.active().len() as i64);
                metrics::MESH_PARTICIPANTS
                    .with_label_values(&["need_sync"])
                    .set(state.need_sync().len() as i64);
            }
            tracing::error!("mesh connection watcher stopped; mesh state is now frozen");
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
                        self.connections.connect(&contract).await;
                        // The contract is the authority on membership, so take
                        // the participant set from it rather than waiting for a
                        // drop to arrive per departed peer.
                        let members = Self::members(&contract);
                        self.state_tx.send_modify(|state| {
                            state.retain(|p| members.contains(p) || *p == participant);
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
                Some(participant) = self.synced_peer_rx.recv() => {
                    if self.me == Some(participant) {
                        tracing::warn!(?participant, "ignoring self sync report");
                        continue;
                    }
                    self.connections.report_node_synced(participant);
                }
                // The updater outlives the pool it watches, so reaching this arm
                // means it panicked or the pool was torn down. Either way the mesh
                // state can no longer be corrected; stop rather than serve a
                // snapshot that will silently go stale.
                result = &mut updater => {
                    tracing::error!(?result, "mesh connection updater exited; stopping mesh");
                    return;
                }
            }
        }
    }

    /// Participants the contract currently recognizes for this node's epoch.
    fn members(contract: &ProtocolState) -> BTreeSet<Participant> {
        match contract {
            ProtocolState::Initializing(init) => {
                let participants: Participants = init.candidates.clone().into();
                participants.keys().copied().collect()
            }
            ProtocolState::Running(running) => running.participants.keys().copied().collect(),
            // Matches `Pool::connect`: only the new set operates under the new epoch.
            ProtocolState::Resharing(resharing) => {
                resharing.new_participants.keys().copied().collect()
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

const fn status_label(status: NodeStatus) -> &'static str {
    match status {
        NodeStatus::Active => "active",
        NodeStatus::Syncing => "syncing",
        NodeStatus::Inactive => "inactive",
        NodeStatus::Offline => "offline",
    }
}

pub async fn wait_threshold_active(mesh_state: &mut watch::Receiver<MeshState>, threshold: usize) {
    loop {
        if mesh_state.borrow().active().len() >= threshold {
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
    /// Generous on purpose: these tests assert what the mesh converges to, not
    /// how fast. A wall-clock bound only needs to be long enough that a loaded
    /// machine does not read as a failure.
    const SETTLE_TIMEOUT: Duration = Duration::from_secs(10);

    /// Poll until `cond` holds, instead of sleeping for a fixed multiple of the
    /// ping interval and hoping the mesh got there.
    async fn wait_until(
        state: &watch::Receiver<MeshState>,
        what: &str,
        cond: impl Fn(&MeshState) -> bool,
    ) {
        let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
        loop {
            {
                let current = state.borrow();
                if cond(&current) {
                    return;
                }
                if tokio::time::Instant::now() >= deadline {
                    panic!(
                        "timed out waiting for {what}; active={:?} need_sync={:?}",
                        current.active().keys_vec(),
                        current.need_sync().keys_vec(),
                    );
                }
            }
            tokio::time::sleep(PING_INTERVAL).await;
        }
    }

    async fn expect_status(
        watcher: &mut connection::ConnectionWatcher,
        participant: Participant,
        expected: NodeStatus,
    ) {
        for _ in 0..20 {
            match tokio::time::timeout(Duration::from_millis(500), watcher.next()).await {
                Ok(Some(connection::MeshUpdate::Status(p, status, _info)))
                    if p == participant && status == expected =>
                {
                    return
                }
                Ok(None) => panic!("connection watcher ended while waiting for {participant:?}"),
                _ => continue,
            }
        }
        panic!("timed out waiting for {participant:?} to become {expected:?}");
    }

    /// Collect statuses from the watcher until every peer in `expect` has
    /// reported `status`, so the test asserts the set it cares about rather than
    /// a fixed number of arbitrary updates.
    async fn expect_all(
        watcher: &mut connection::ConnectionWatcher,
        mut expect: HashSet<Participant>,
        status: NodeStatus,
    ) {
        let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
        while !expect.is_empty() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for {status:?} from {expect:?}"
            );
            match tokio::time::timeout(remaining, watcher.next()).await {
                Ok(Some(connection::MeshUpdate::Status(p, got, _))) if got == status => {
                    expect.remove(&p);
                }
                Ok(Some(_)) => continue,
                Ok(None) => panic!("connection watcher ended waiting for {status:?}"),
                Err(_) => panic!("timed out waiting for {status:?} from {expect:?}"),
            }
        }
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

        // We never connect to ourselves, so servers[0] is not expected here.
        let peers: HashSet<Participant> = (1..num_nodes).map(|i| servers[i].id()).collect();

        expect_all(&mut watcher, peers.clone(), NodeStatus::Syncing).await;
        for &peer in &peers {
            pool.report_node_synced(peer);
        }
        expect_all(&mut watcher, peers, NodeStatus::Active).await;
    }

    /// A peer leaving the connection set must reach the watcher as a drop even
    /// though it never reports a status again.
    #[test(tokio::test)]
    async fn test_pool_reports_dropped_connections() {
        let num_nodes = 2;
        let servers = MockServers::run(num_nodes).await;
        let my_id = servers[0].account_id().clone();

        let mut pool = Pool::new(&servers.client(), &my_id, PING_INTERVAL);
        let mut watcher = pool.watch();
        pool.connect_nodes(&servers.participants(), &mut HashSet::new())
            .await;

        let peer = servers[1].id();
        expect_status(&mut watcher, peer, NodeStatus::Syncing).await;

        pool.disconnect_all();

        let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for drop of {peer:?}"
            );
            match tokio::time::timeout(remaining, watcher.next()).await {
                Ok(Some(connection::MeshUpdate::Dropped(p))) => {
                    assert_eq!(p, peer);
                    return;
                }
                Ok(Some(_)) => continue,
                Ok(None) => panic!("connection watcher ended before reporting the drop"),
                Err(_) => panic!("timed out waiting for drop of {peer:?}"),
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

        let mesh_state = mesh.watch();
        let mesh_task = tokio::spawn(mesh.run(contract_watcher));

        // check that the mesh state is updated.
        {
            wait_until(&mesh_state, "self to be active", |state| {
                state.active().contains_key(&me)
            })
            .await;

            for idx in 0..num_nodes {
                sync_tx.send(servers[idx].id()).await.unwrap();
            }
            wait_until(&mesh_state, "all nodes to be active", |state| {
                state.active().len() == num_nodes && state.need_sync().is_empty()
            })
            .await;

            let state = mesh_state.borrow();
            assert_eq!(state.active(), &expected_participants);
            for idx in 0..num_nodes {
                assert!(state.active().contains_key(&servers[idx].id()));
            }
        }

        // check that the mesh state is updated when a participant goes offline
        {
            servers[1].make_offline().await;
            wait_until(&mesh_state, "offline node to leave active", |state| {
                !state.active().contains_key(&servers[1].id())
            })
            .await;

            let state = mesh_state.borrow();
            assert_eq!(state.active().len(), num_nodes - 1);
            assert!(state.active().contains_key(&me));
            assert!(state.active().contains_key(&servers[0].id()));
            assert!(state.active().contains_key(&servers[2].id()));
        }

        // check that the mesh state is updated when a participant goes back online.
        {
            servers[1].make_online().await;
            // Node is now syncing: should be in need_sync but not in active yet.
            wait_until(&mesh_state, "returning node to need sync", |state| {
                state.need_sync().contains_key(&servers[1].id())
            })
            .await;
            assert!(!mesh_state.borrow().active().contains_key(&servers[1].id()));

            sync_tx.send(servers[1].id()).await.unwrap();
            wait_until(&mesh_state, "synced node to become active", |state| {
                state.active().len() == num_nodes && state.need_sync().is_empty()
            })
            .await;

            let state = mesh_state.borrow();
            for idx in 0..num_nodes {
                assert!(state.active().contains_key(&servers[idx].id()));
            }
            assert!(state.active().contains_key(&me));
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
            wait_until(&mesh_state, "new participant to be tracked", |state| {
                state.active().len() + state.need_sync().len() == num_nodes
            })
            .await;
            for i in 0..num_nodes {
                sync_tx.send(servers[i].id()).await.unwrap();
            }

            wait_until(&mesh_state, "new participant to become active", |state| {
                state.active().len() == num_nodes && state.need_sync().is_empty()
            })
            .await;
            let state = mesh_state.borrow();

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
            wait_until(&mesh_state, "removed participant to be dropped", |state| {
                state.active().len() == num_nodes && state.need_sync().is_empty()
            })
            .await;
            let state = mesh_state.borrow();

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

        let mut pool = Pool::new(&servers.client(), &my_id, PING_INTERVAL);
        let mut watcher = pool.watch();
        pool.connect_nodes(&participants, &mut HashSet::new()).await;

        let remote_id = servers[1].id();

        expect_status(&mut watcher, remote_id, NodeStatus::Syncing).await;
        pool.report_node_synced(remote_id);
        expect_status(&mut watcher, remote_id, NodeStatus::Active).await;

        servers[1].set_protocol_version(None).await;
        expect_status(&mut watcher, remote_id, NodeStatus::Offline).await;

        servers[1].make_online().await;
        expect_status(&mut watcher, remote_id, NodeStatus::Syncing).await;
        pool.report_node_synced(remote_id);
        expect_status(&mut watcher, remote_id, NodeStatus::Active).await;

        servers[1].set_protocol_version(Some(0)).await;
        expect_status(&mut watcher, remote_id, NodeStatus::Offline).await;
    }
}
