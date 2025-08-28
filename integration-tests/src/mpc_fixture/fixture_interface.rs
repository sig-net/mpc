//! Types used by tests directly to control a running MPC network fixture, feed
//! it with controlled inputs, and assert on outputs.

use crate::containers::Redis;
use cait_sith::protocol::Participant;
use mpc_keys::hpke::Ciphered;
use mpc_node::config::Config;
use mpc_node::mesh::MeshState;
use mpc_node::protocol::state::NodeStateWatcher;
use mpc_node::protocol::{IndexedSignRequest, ProtocolState};
use mpc_node::storage::{PresignatureStorage, TripleStorage};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
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

    pub sign_tx: Sender<IndexedSignRequest>,
    pub msg_tx: Sender<Ciphered>,

    pub triple_storage: TripleStorage,
    pub presignature_storage: PresignatureStorage,
}

/// Logs for reading outputs after a test run for assertions and debugging.
#[derive(Default)]
pub struct SharedOutput {
    pub msg_log: Arc<Mutex<Vec<String>>>,
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
