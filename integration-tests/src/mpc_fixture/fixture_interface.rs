//! Types used by tests directly to control a running MPC network fixture, feed
//! it with controlled inputs, and assert on outputs.

use crate::containers::Redis;
use crate::mpc_fixture::message_collector::{CollectMessages, MessagePrinter};
use cait_sith::protocol::Participant;
use mpc_node::backlog::Backlog;
use mpc_node::config::Config;
use mpc_node::mesh::MeshState;
use mpc_node::protocol::state::NodeStateWatcher;
use mpc_node::protocol::sync::SyncChannel;
use mpc_node::protocol::{MessageChannel, ProtocolState, Sign};
use mpc_node::storage::{PresignatureStorage, TripleStorage};
use near_sdk::AccountId;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::{watch, Mutex};

pub struct MpcFixture {
    pub nodes: Vec<MpcFixtureNode>,
    pub redis_container: Redis,
    pub shared_contract_state: watch::Sender<Option<ProtocolState>>,
    pub output: SharedOutput,
}

pub struct MpcFixtureNode {
    pub me: Participant,
    pub state: NodeStateWatcher,
    pub mesh: watch::Sender<MeshState>,
    pub config: watch::Sender<Config>,

    pub sign_tx: mpsc::Sender<Sign>,
    pub msg_channel: MessageChannel,

    pub triple_storage: TripleStorage,
    pub presignature_storage: PresignatureStorage,
    pub backlog: Backlog,

    pub web_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Logs for reading outputs after a test run for assertions and debugging.
pub struct SharedOutput {
    pub msg_log: Arc<Mutex<dyn CollectMessages + Send>>,
    pub rpc_actions: Arc<Mutex<HashSet<String>>>,
}

impl MpcFixture {
    pub async fn wait_for_triples(&self, threshold_per_node: usize) {
        for node in &self.nodes {
            node.wait_for_triples(threshold_per_node).await;
        }
    }

    pub async fn wait_for_presignatures(&self, threshold_per_node: usize) {
        for node in &self.nodes {
            node.wait_for_presignatures(threshold_per_node).await;
        }
    }

    pub async fn wait_for_actions(&self, threshold: usize) -> HashSet<String> {
        let interval = Duration::from_millis(100);

        loop {
            let actions = self.output.rpc_actions.lock().await;

            if actions.len() >= threshold {
                return actions.clone();
            }

            drop(actions);
            tokio::time::sleep(interval).await;
        }
    }

    pub async fn assert_triples(&self, threshold_per_node: usize, timeout: Duration) {
        let result = tokio::time::timeout(timeout, self.wait_for_triples(threshold_per_node)).await;
        if result.is_err() {
            self.print_triples().await;
        }
        result.expect("should have enough triples")
    }

    pub async fn assert_presignatures(&self, threshold_per_node: usize, timeout: Duration) {
        let result =
            tokio::time::timeout(timeout, self.wait_for_presignatures(threshold_per_node)).await;
        if result.is_err() {
            self.print_presignatures().await;
        }
        result.expect("should have enough presignatures")
    }

    pub async fn assert_actions(
        &self,
        threshold_per_node: usize,
        timeout: Duration,
    ) -> HashSet<String> {
        let result = tokio::time::timeout(timeout, self.wait_for_actions(threshold_per_node)).await;
        if result.is_err() {
            self.print_actions().await;
        }
        result.expect("should produce enough signatures")
    }

    pub async fn print_triples(&self) {
        for node in &self.nodes {
            let id = node.me;
            let num = node.triple_storage.len_by_owner(id).await;
            tracing::info!("Node {id:?} has {num} Ts");
        }
    }

    pub async fn print_presignatures(&self) {
        for node in &self.nodes {
            let id = node.me;
            let num = node.presignature_storage.len_by_owner(id).await;
            tracing::info!("Node {id:?} has {num} Ps");
        }
    }

    pub async fn print_actions(&self) {
        let actions: tokio::sync::MutexGuard<'_, HashSet<String>> =
            self.output.rpc_actions.lock().await;

        tracing::info!("All published RPC actions:");
        for action in actions.iter() {
            tracing::info!("{action}");
        }
    }
}

impl MpcFixtureNode {
    pub async fn wait_for_triples(&self, threshold_per_node: usize) {
        loop {
            let count = self.triple_storage.len_by_owner(self.me).await;
            if count >= threshold_per_node {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    pub async fn wait_for_presignatures(&self, threshold_per_node: usize) {
        loop {
            let count = self.presignature_storage.len_by_owner(self.me).await;
            if count >= threshold_per_node {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    pub fn start_web_interface(&mut self, account_id: AccountId) {
        let task = mpc_node::web::run(
            8200 + u32::from(self.me) as u16,
            self.msg_channel.clone(),
            self.state.clone(),
            self.triple_storage.clone(),
            self.presignature_storage.clone(),
            // unused but needed to call the web interface
            SyncChannel::new().1,
            account_id,
            self.backlog.clone(),
        );
        self.web_handle = Some(tokio::spawn(task));
    }
}

impl std::ops::Index<usize> for MpcFixture {
    type Output = MpcFixtureNode;

    fn index(&self, index: usize) -> &MpcFixtureNode {
        &self.nodes[index]
    }
}

impl std::ops::IndexMut<usize> for MpcFixture {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.nodes[index]
    }
}

impl SharedOutput {
    pub fn new<M: CollectMessages + Default + Send + 'static>() -> Self {
        Self {
            msg_log: Arc::new(Mutex::new(M::default())),
            rpc_actions: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

impl Default for SharedOutput {
    fn default() -> Self {
        Self {
            msg_log: Arc::new(Mutex::new(MessagePrinter)),
            rpc_actions: Default::default(),
        }
    }
}
