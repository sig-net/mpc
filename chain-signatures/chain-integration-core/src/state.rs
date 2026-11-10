use std::collections::HashMap;
use std::sync::Arc;

use mpc_primitives::{BidirectionalTx, BidirectionalTxId, Chain, SignId};
use tokio::sync::RwLock;

/// One watched execution: the entry's sign id and its transaction.
pub type WatchedExecution = (SignId, Arc<BidirectionalTx>);

/// Interface for the Indexer to query and update state.
/// Currently implemented by the Backlog
#[async_trait::async_trait]
pub trait StateManager: Send + Sync + Clone + 'static {
    /// Get the processed block height for a specific chain
    async fn get_processed_block(&self, chain: Chain) -> Option<u64>;

    /// Get the bidirectional transactions awaiting execution on `chain`,
    /// keyed by flat id — duplicate ids carry one watch per entry.
    async fn get_execution_watchers(
        &self,
        chain: Chain,
    ) -> HashMap<BidirectionalTxId, Vec<WatchedExecution>>;

    /// All `Executing` backlog entries targeting `chain`, from every
    /// source chain — the authoritative set; the watch map is its
    /// derived index (the mock keeps the two independent).
    async fn get_pending_executions(&self, chain: Chain) -> Vec<(SignId, Arc<BidirectionalTx>)>;

    /// Registers or refreshes the entry's own watch under `tx.id`;
    /// sibling watches under the same flat id survive.
    async fn watch_execution(&self, chain: Chain, tx: Arc<BidirectionalTx>);

    /// Set the processed block height for a specific chain.
    async fn set_processed_block(&self, chain: Chain, height: u64);
}

/// Type alias to make clippy happy
type Watchers = Arc<RwLock<HashMap<Chain, HashMap<BidirectionalTxId, Vec<WatchedExecution>>>>>;

/// In-memory mock implementation of [`StateManager`] intended for use in tests.
///
/// This is shared across chain integration crates so that indexer tests can rely
/// on a common state manager mock instead of pulling in the full `Backlog`.
#[derive(Clone, Default)]
pub struct MockStateManager {
    processed_blocks: Arc<RwLock<HashMap<Chain, u64>>>,
    // TODO: extract the watch map into a dedicated type to avoid divergence with the backlog.
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
    ) -> HashMap<BidirectionalTxId, Vec<WatchedExecution>> {
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
        self.upsert_watch(chain, sign_id, tx).await;
    }
}

impl MockStateManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Watch under an explicit sign_id — tests pair one the tx does
    /// not derive.
    pub async fn watch_execution_as(
        &self,
        chain: Chain,
        sign_id: SignId,
        tx: Arc<BidirectionalTx>,
    ) {
        self.upsert_watch(chain, sign_id, tx).await;
    }

    async fn upsert_watch(&self, chain: Chain, sign_id: SignId, tx: Arc<BidirectionalTx>) {
        let mut watchers = self.watchers.write().await;
        let watches = watchers.entry(chain).or_default().entry(tx.id).or_default();
        watches.retain(|(id, watched)| {
            *id != sign_id || watched.source_chain != tx.source_chain
        });
        watches.push((sign_id, tx));
    }

    /// Register an `Executing` backlog entry targeting `tx.target_chain`.
    /// Independent of [`StateManager::watch_execution`]: an entry can be
    /// pending with no watch.
    pub async fn add_pending_execution(&self, tx: Arc<BidirectionalTx>) {
        self.pending.write().await.push(tx);
    }

    /// Removes the entry by its `(source_chain, sign_id)` key.
    pub async fn remove_pending_execution(&self, source_chain: Chain, sign_id: SignId) {
        self.pending
            .write()
            .await
            .retain(|tx| tx.source_chain != source_chain || tx.sign_id() != sign_id);
    }

    /// Removes one entry's watch; sibling watches stay.
    pub async fn remove_execution_watch(
        &self,
        chain: Chain,
        tx_id: &BidirectionalTxId,
        source_chain: Chain,
        sign_id: SignId,
    ) {
        let mut watchers = self.watchers.write().await;
        let Some(watches) = watchers.get_mut(&chain) else {
            return;
        };
        if let Some(members) = watches.get_mut(tx_id) {
            members.retain(|(id, tx)| *id != sign_id || tx.source_chain != source_chain);
            if members.is_empty() {
                watches.remove(tx_id);
            }
        }
    }
}
