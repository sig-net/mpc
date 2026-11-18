use std::collections::HashMap;
use std::sync::Arc;

use enum_map::EnumMap;
use mpc_primitives::{BidirectionalTx, BidirectionalTxId, Chain, SignId};
use tokio::sync::RwLock;

/// One watched execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedExecution {
    pub sign_id: SignId,
    pub tx: Arc<BidirectionalTx>,
}

impl WatchedExecution {
    /// The execution of `tx`, sign id derived from it. For pending
    /// enumerations; watch rows carry the key's sign id instead
    /// ([`ExecutionWatchIndex::all`]).
    pub fn of(tx: Arc<BidirectionalTx>) -> Self {
        Self {
            sign_id: tx.sign_id(),
            tx,
        }
    }
}

/// Watch key: flat id, source, sign id, and target chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WatchKey {
    pub flat_id: BidirectionalTxId,
    pub source: Chain,
    pub sign_id: SignId,
    pub target: Chain,
}

impl WatchKey {
    pub fn of(tx: &BidirectionalTx) -> Self {
        Self {
            flat_id: tx.id,
            source: tx.source_chain,
            sign_id: tx.sign_id(),
            target: tx.target_chain,
        }
    }
}

/// The transactions a node watches for execution, one per watch key —
/// the index the backlog rebuilds from its `Executing` entries and the
/// test mock keeps independent of its pending entries.
#[derive(Debug, Clone, Default)]
pub struct ExecutionWatchIndex {
    watches: HashMap<WatchKey, Arc<BidirectionalTx>>,
}

impl ExecutionWatchIndex {
    pub fn insert(&mut self, tx: Arc<BidirectionalTx>) {
        self.insert_at(WatchKey::of(&tx), tx);
    }

    /// Under an explicit key — for a sign id the tx does not derive.
    pub fn insert_at(&mut self, key: WatchKey, tx: Arc<BidirectionalTx>) {
        self.watches.insert(key, tx);
    }

    /// Replaces `source`'s watches with `entries`.
    pub fn rebuild(
        &mut self,
        source: Chain,
        entries: impl IntoIterator<Item = Arc<BidirectionalTx>>,
    ) {
        self.watches.retain(|key, _| key.source != source);
        self.watches
            .extend(entries.into_iter().map(|tx| (WatchKey::of(&tx), tx)));
    }

    pub fn remove(&mut self, key: &WatchKey) -> Option<Arc<BidirectionalTx>> {
        self.watches.remove(key)
    }

    pub fn contains(&self, key: &WatchKey) -> bool {
        self.watches.contains_key(key)
    }

    pub fn all(&self) -> HashMap<BidirectionalTxId, Vec<WatchedExecution>> {
        let mut grouped: HashMap<BidirectionalTxId, Vec<WatchedExecution>> = HashMap::new();
        for (key, tx) in &self.watches {
            grouped
                .entry(key.flat_id)
                .or_default()
                .push(WatchedExecution {
                    sign_id: key.sign_id,
                    tx: Arc::clone(tx),
                });
        }
        grouped
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
    async fn get_pending_executions(&self, chain: Chain) -> Vec<WatchedExecution>;

    /// Registers or refreshes the entry's own watch, keyed by its flat
    /// id and sign id on `tx`'s target chain; sibling watches under the
    /// same flat id survive.
    async fn watch_execution(&self, tx: Arc<BidirectionalTx>);

    /// Set the processed block height for a specific chain.
    async fn set_processed_block(&self, chain: Chain, height: u64);
}

/// In-memory mock implementation of [`StateManager`] intended for use in tests.
///
/// This is shared across chain integration crates so that indexer tests can rely
/// on a common state manager mock instead of pulling in the full `Backlog`.
#[derive(Clone, Default)]
pub struct MockStateManager {
    processed_blocks: Arc<RwLock<HashMap<Chain, u64>>>,
    watchers: Arc<EnumMap<Chain, RwLock<ExecutionWatchIndex>>>,
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
        self.watchers[chain].read().await.all()
    }

    async fn get_pending_executions(&self, chain: Chain) -> Vec<WatchedExecution> {
        self.pending
            .read()
            .await
            .iter()
            .filter(|tx| tx.target_chain == chain)
            .map(|tx| WatchedExecution::of(Arc::clone(tx)))
            .collect()
    }

    async fn set_processed_block(&self, chain: Chain, height: u64) {
        self.processed_blocks.write().await.insert(chain, height);
    }

    async fn watch_execution(&self, tx: Arc<BidirectionalTx>) {
        self.watchers[tx.target_chain].write().await.insert(tx);
    }
}

impl MockStateManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Watch under an explicit sign_id — tests pair one the tx does
    /// not derive.
    pub async fn watch_execution_as(&self, sign_id: SignId, tx: Arc<BidirectionalTx>) {
        self.watchers[tx.target_chain].write().await.insert_at(
            WatchKey {
                sign_id,
                ..WatchKey::of(&tx)
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

    /// Removes one entry's watch, routed to its target chain;
    /// sibling watches stay.
    pub async fn remove_execution_watch(&self, key: WatchKey) {
        self.watchers[key.target].write().await.remove(&key);
    }
}
