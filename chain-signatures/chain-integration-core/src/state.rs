use std::collections::HashMap;
use std::sync::Arc;

use mpc_primitives::{BidirectionalTx, BidirectionalTxId, Chain, SignId};
use tokio::sync::RwLock;

/// Interface for the Indexer to query and update state.
/// Currently implemented by the Backlog
#[async_trait::async_trait]
pub trait StateManager: Send + Sync + Clone + 'static {
    /// Get the processed block height for a specific chain
    async fn get_processed_block(&self, chain: Chain) -> Option<u64>;

    /// Get the set of bidirectional transactions currently awaiting execution on the
    /// specified destination chain.
    async fn get_execution_watchers(
        &self,
        chain: Chain,
    ) -> HashMap<BidirectionalTxId, (SignId, Arc<BidirectionalTx>)>;

    /// All `Executing` backlog entries targeting `chain`, from every source
    /// chain. A superset of [`StateManager::get_execution_watchers`]: entries
    /// whose watch a duplicate destination id displaced are included.
    async fn get_pending_executions(&self, chain: Chain) -> Vec<(SignId, Arc<BidirectionalTx>)>;

    /// Registers under `tx.id`, replacing any previous watch.
    async fn watch_execution(&self, chain: Chain, tx: Arc<BidirectionalTx>);

    /// Set the processed block height for a specific chain.
    async fn set_processed_block(&self, chain: Chain, height: u64);
}

/// Type alias to make clippy happy
type Watchers =
    Arc<RwLock<HashMap<Chain, HashMap<BidirectionalTxId, (SignId, Arc<BidirectionalTx>)>>>>;

/// In-memory mock implementation of [`StateManager`] intended for use in tests.
///
/// This is shared across chain integration crates so that indexer tests can rely
/// on a common state manager mock instead of pulling in the full `Backlog`.
#[derive(Clone, Default)]
pub struct MockStateManager {
    processed_blocks: Arc<RwLock<HashMap<Chain, u64>>>,
    watchers: Watchers,
    pending: Arc<RwLock<Vec<Arc<BidirectionalTx>>>>,
}

#[async_trait::async_trait]
impl StateManager for MockStateManager {
    async fn get_processed_block(&self, chain: Chain) -> Option<u64> {
        self.processed_blocks.read().await.get(&chain).cloned()
    }

    async fn get_execution_watchers(
        &self,
        chain: Chain,
    ) -> HashMap<BidirectionalTxId, (SignId, Arc<BidirectionalTx>)> {
        self.watchers
            .read()
            .await
            .get(&chain)
            .cloned()
            .unwrap_or_default()
    }

    async fn get_pending_executions(&self, chain: Chain) -> Vec<(SignId, Arc<BidirectionalTx>)> {
        self.pending
            .read()
            .await
            .iter()
            .filter(|tx| tx.target_chain == chain)
            .map(|tx| (tx.sign_id(), Arc::clone(tx)))
            .collect()
    }

    async fn set_processed_block(&self, chain: Chain, height: u64) {
        self.processed_blocks.write().await.insert(chain, height);
    }

    async fn watch_execution(&self, chain: Chain, tx: Arc<BidirectionalTx>) {
        let sign_id = tx.sign_id();
        self.watchers
            .write()
            .await
            .entry(chain)
            .or_default()
            .insert(tx.id, (sign_id, tx));
    }
}

impl MockStateManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Watch under an explicit sign_id — displacement tests pair one
    /// the tx does not derive.
    pub async fn watch_execution_as(
        &self,
        chain: Chain,
        sign_id: SignId,
        tx: Arc<BidirectionalTx>,
    ) {
        self.watchers
            .write()
            .await
            .entry(chain)
            .or_default()
            .insert(tx.id, (sign_id, tx));
    }

    /// Register an `Executing` backlog entry targeting `tx.target_chain`.
    /// Independent of [`StateManager::watch_execution`]: an entry can be
    /// pending with no watch.
    pub async fn add_pending_execution(&self, tx: Arc<BidirectionalTx>) {
        self.pending.write().await.push(tx);
    }

    /// Removes the entry — what the node's confirmation handling does.
    pub async fn remove_pending_execution(&self, sign_id: SignId) {
        self.pending
            .write()
            .await
            .retain(|tx| tx.sign_id() != sign_id);
    }
}
