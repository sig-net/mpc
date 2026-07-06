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
    ) -> HashMap<BidirectionalTxId, (SignId, BidirectionalTx)>;

    /// Set the processed block height for a specific chain.
    async fn set_processed_block(&self, chain: Chain, height: u64);
}

/// Type alias to make clippy happy
type Watchers = Arc<RwLock<HashMap<Chain, HashMap<BidirectionalTxId, (SignId, BidirectionalTx)>>>>;

/// In-memory mock implementation of [`StateManager`] intended for use in tests.
///
/// This is shared across chain integration crates so that indexer tests can rely
/// on a common state manager mock instead of pulling in the full `Backlog`.
#[derive(Clone, Default)]
pub struct MockStateManager {
    processed_blocks: Arc<RwLock<HashMap<Chain, u64>>>,
    watchers: Watchers,
}

#[async_trait::async_trait]
impl StateManager for MockStateManager {
    async fn get_processed_block(&self, chain: Chain) -> Option<u64> {
        self.processed_blocks.read().await.get(&chain).cloned()
    }

    async fn get_execution_watchers(
        &self,
        chain: Chain,
    ) -> HashMap<BidirectionalTxId, (SignId, BidirectionalTx)> {
        self.watchers
            .read()
            .await
            .get(&chain)
            .cloned()
            .unwrap_or_default()
    }

    async fn set_processed_block(&self, chain: Chain, height: u64) {
        self.processed_blocks.write().await.insert(chain, height);
    }
}

impl MockStateManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a bidirectional transaction awaiting execution on `chain`.
    pub async fn watch_execution(&self, chain: Chain, sign_id: SignId, tx: BidirectionalTx) {
        self.watchers
            .write()
            .await
            .entry(chain)
            .or_default()
            .insert(tx.id, (sign_id, tx));
    }
}
