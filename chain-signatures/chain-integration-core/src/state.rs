use std::collections::HashMap;
use std::sync::Arc;

use mpc_primitives::{BidirectionalTx, BidirectionalTxId, Chain, SignId};
use tokio::sync::RwLock;

/// One watched execution: the entry's sign id and its transaction.
pub type WatchedExecution = (SignId, Arc<BidirectionalTx>);

/// Watch key for an execution: identifies the flat id, source chain, and sign id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WatchKey {
    pub flat_id: BidirectionalTxId,
    pub source: Chain,
    pub sign_id: SignId,
}

impl WatchKey {
    pub fn of(tx: &BidirectionalTx) -> Self {
        Self {
            flat_id: tx.id,
            source: tx.source_chain,
            sign_id: tx.sign_id(),
        }
    }
}

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
type Watchers = Arc<RwLock<HashMap<Chain, HashMap<WatchKey, Arc<BidirectionalTx>>>>>;

/// In-memory mock implementation of [`StateManager`] intended for use in tests.
///
/// This is shared across chain integration crates so that indexer tests can rely
/// on a common state manager mock instead of pulling in the full `Backlog`.
#[derive(Clone, Default)]
pub struct MockStateManager {
    processed_blocks: Arc<RwLock<HashMap<Chain, u64>>>,
    // TODO: extract the watch map into a dedicated type to avoid
    // divergence with the backlog — the identity is shared (`WatchKey`),
    // the map shape is not.
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
        let watches = self
            .watchers
            .read()
            .await
            .get(&chain)
            .cloned()
            .unwrap_or_default();
        let mut grouped: HashMap<BidirectionalTxId, Vec<WatchedExecution>> = HashMap::new();
        for (key, tx) in watches {
            grouped
                .entry(key.flat_id)
                .or_default()
                .push((key.sign_id, tx));
        }
        grouped
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
        let mut watchers = self.watchers.write().await;
        watchers
            .entry(chain)
            .or_default()
            .insert(WatchKey::of(&tx), tx);
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
        self.watchers
            .write()
            .await
            .entry(chain)
            .or_default()
            .insert(
                WatchKey {
                    flat_id: tx.id,
                    source: tx.source_chain,
                    sign_id,
                },
                tx,
            );
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
        self.watchers
            .write()
            .await
            .entry(chain)
            .or_default()
            .remove(&WatchKey {
                flat_id: *tx_id,
                source: source_chain,
                sign_id,
            });
    }
}
