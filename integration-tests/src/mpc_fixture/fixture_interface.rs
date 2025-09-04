//! Types used by tests directly to control a running MPC network fixture, feed
//! it with controlled inputs, and assert on outputs.

use crate::containers::Redis;
use crate::mpc_fixture::mock_indexers::MockIndexer;
use cait_sith::protocol::Participant;
use mpc_keys::hpke::Ciphered;
use mpc_node::checkpoint::CheckpointManager;
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
    pub checkpoint_manager: Option<CheckpointManager>,
    pub ethereum_indexer: Option<MockIndexer>,
    pub solana_indexer: Option<MockIndexer>,
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

    /// Start the mock indexers if they are available
    pub async fn start_mock_indexers(
        &mut self,
    ) -> Option<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
        if let (Some(checkpoint_manager), Some(ethereum_indexer), Some(solana_indexer)) = (
            &self.checkpoint_manager,
            &self.ethereum_indexer,
            &self.solana_indexer,
        ) {
            let eth_handle = MockIndexer::start(
                ethereum_indexer.chain(),
                Arc::new(checkpoint_manager.clone()),
                ethereum_indexer.sign_request_tx(),
            );

            let sol_handle = MockIndexer::start(
                solana_indexer.chain(),
                Arc::new(checkpoint_manager.clone()),
                solana_indexer.sign_request_tx(),
            );

            Some((eth_handle, sol_handle))
        } else {
            None
        }
    }

    /// Add a mock transaction to be tracked by the Ethereum indexer
    pub async fn add_mock_ethereum_transaction(
        &mut self,
        sign_id: mpc_primitives::SignId,
    ) -> Option<mpc_node::sign_respond_tx::SignRespondTxId> {
        if let Some(ref mut ethereum_indexer) = &mut self.ethereum_indexer {
            Some(ethereum_indexer.add_mock_transaction(sign_id).await)
        } else {
            None
        }
    }

    /// Add a mock transaction to be tracked by the Solana indexer
    pub async fn add_mock_solana_transaction(
        &mut self,
        sign_id: mpc_primitives::SignId,
    ) -> Option<mpc_node::sign_respond_tx::SignRespondTxId> {
        if let Some(ref mut solana_indexer) = &mut self.solana_indexer {
            Some(solana_indexer.add_mock_transaction(sign_id).await)
        } else {
            None
        }
    }

    /// Get the checkpoint manager if available
    pub fn checkpoint_manager(&self) -> Option<&CheckpointManager> {
        self.checkpoint_manager.as_ref()
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
