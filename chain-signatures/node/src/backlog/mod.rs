mod checkpoints;
pub mod consensus;
mod local;
pub(crate) mod migration;
#[cfg(any(test, feature = "test-feature"))]
pub mod mock;
pub mod request;

pub use request::{
    AnyProgress, Bidirectional, Executing, ExecutionWatch, Final, Generating, Initial, Publishing,
    Sign, SignEntry,
};

use crate::sign_bidirectional::{
    BidirectionalProgress, NonceSlot, SignBidirectionalEventExt as _, SignProgress, SignStatus,
};
use crate::storage::checkpoint_storage::CheckpointStorage;
pub use checkpoints::{Checkpoint, CheckpointEntry, CheckpointError, Checkpoints};
pub use local::LocalRecord;

use enum_map::EnumMap;
use mpc_chain_integration_core::StateManager;
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, IndexedSignRequest, PublicKey,
    SignBidirectionalEvent, SignId, SignKind,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Max pending (unconfirmed) checkpoints per chain before stalling.
pub const MAX_PENDING_CHECKPOINTS: usize = 32;

#[derive(Debug, Clone)]
pub struct PendingRequests {
    requests: HashMap<SignId, BacklogEntry>,
    /// The highest block height that has been processed for this chain
    processed_block_height: Option<u64>,
    /// The last block replayed while catching up, when the processed height stands still.
    replayed_block_height: Option<u64>,
    /// This node's records of requests admitted after the checkpoint it recovered from, which
    /// replay admits again.
    unclaimed: HashMap<SignId, LocalRecord>,
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingRequests {
    /// Creates a new empty PendingRequests container
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
            processed_block_height: None,
            replayed_block_height: None,
            unclaimed: HashMap::new(),
        }
    }

    /// Inserts a sign-respond transaction into the pending requests map
    /// Returns Some(old_value) if the key was already present
    pub(super) fn insert(&mut self, id: SignId, entry: BacklogEntry) -> Option<BacklogEntry> {
        self.requests.insert(id, entry)
    }

    /// Removes a sign-respond transaction from the pending requests map
    /// Returns Some(value) if the key was present
    fn remove(&mut self, id: &SignId) -> Option<BacklogEntry> {
        self.requests.remove(id)
    }

    /// Gets a ref of a backlog entry from the pending requests map
    /// Returns Some(value) if the key is present
    fn get(&self, id: &SignId) -> Option<&BacklogEntry> {
        self.requests.get(id)
    }

    /// Returns the number of pending requests
    fn len(&self) -> usize {
        self.requests.len()
    }

    /// A watch for every transaction of every entry that awaits its outcome.
    fn execution_watches(&self) -> Vec<ExecutionWatch> {
        self.requests
            .values()
            .filter(|entry| entry.awaits_execution())
            .flat_map(|entry| entry.watched_txs())
            .map(|tx| ExecutionWatch::new(tx, None))
            .collect()
    }

    /// Get the processed block height for this chain
    fn processed_block_height(&self) -> Option<u64> {
        self.processed_block_height
    }

    /// Set the processed block height for this chain
    pub(super) fn set_processed_block(&mut self, height: u64) {
        self.processed_block_height = Some(height);
    }

    /// The height a record written now is stamped with: the last block whose events were
    /// processed, caught up or not.
    fn record_height(&self) -> u64 {
        self.replayed_block_height
            .max(self.processed_block_height)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default)]
struct ExecutionWatchers {
    watchers: HashMap<BidirectionalTxId, ExecutionWatch>,
}

impl ExecutionWatchers {
    fn insert(&mut self, watch: ExecutionWatch) -> Option<ExecutionWatch> {
        self.watchers.insert(watch.tx.id, watch)
    }

    fn remove(&mut self, tx_id: &BidirectionalTxId) -> Option<ExecutionWatch> {
        self.watchers.remove(tx_id)
    }

    /// Watch `txs`, keeping a request's existing watch (and its observation time); a
    /// transaction id another request shares goes to the latest, as `insert` does.
    fn insert_all(&mut self, txs: impl IntoIterator<Item = Arc<BidirectionalTx>>) {
        for tx in txs {
            let same = self.watchers.get(&tx.id).map(|watch| watch.tx.sign_id());
            if same != Some(tx.sign_id()) {
                self.watchers.insert(tx.id, ExecutionWatch::new(tx, None));
            }
        }
    }

    fn all(&self) -> HashMap<BidirectionalTxId, (SignId, Arc<BidirectionalTx>)> {
        self.watchers
            .iter()
            .map(|(id, watch)| (*id, (watch.tx.sign_id(), Arc::clone(&watch.tx))))
            .collect()
    }
}

/// Backlog manages pending sign-respond requests across multiple chains.
/// Each chain has its own isolated set of pending requests with their own
/// publish queues.
#[derive(Debug, Clone)]
pub struct Backlog {
    checkpoints: Checkpoints,
    /// Pending requests indexed by chain
    requests: Arc<EnumMap<Chain, RwLock<PendingRequests>>>,
    /// Execution watchers indexed by chain
    execution_watchers: Arc<EnumMap<Chain, RwLock<ExecutionWatchers>>>,
    /// Total number of pending requests across all chains, wrapped in Arc to make clonable
    total_pending: Arc<AtomicUsize>,
    /// Whether each chain's stream has caught up, read across streams
    caught_up: Arc<EnumMap<Chain, AtomicBool>>,
}

impl Default for Backlog {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocks between checkpoints: the chain's production cadence, or in test
/// builds the mock one so checkpoint tests finish in seconds.
pub fn checkpoint_interval(chain: Chain) -> Option<u64> {
    #[cfg(feature = "test-feature")]
    return mock_checkpoint_interval(chain);
    #[cfg(not(feature = "test-feature"))]
    mpc_primitives::ChainConfig::checkpoint_interval(&chain)
}

/// Short cadence for test networks. Mirrors `ChainConfig::checkpoint_interval`
/// in which chains have one.
#[cfg(any(test, feature = "test-feature"))]
fn mock_checkpoint_interval(chain: Chain) -> Option<u64> {
    match chain {
        Chain::NEAR | Chain::Bitcoin | Chain::Tron => None,
        Chain::Ethereum => Some(2),
        Chain::Solana | Chain::Hydration | Chain::Canton | Chain::Midnight => Some(5),
    }
}

impl Backlog {
    pub fn new() -> Self {
        Self::persisted(CheckpointStorage::in_memory())
    }

    /// Initialize the backlog with storage for all chains
    pub fn persisted(storage: CheckpointStorage) -> Self {
        Self {
            checkpoints: Checkpoints::new(storage),
            requests: Arc::default(),
            execution_watchers: Arc::default(),
            total_pending: Arc::new(AtomicUsize::new(0)),
            caught_up: Arc::default(),
        }
    }

    /// Whether `chain`'s stream has caught up.
    pub(crate) fn is_caught_up(&self, chain: Chain) -> bool {
        self.caught_up[chain].load(Ordering::SeqCst)
    }

    pub(crate) fn set_caught_up(&self, chain: Chain, caught_up: bool) {
        self.caught_up[chain].store(caught_up, Ordering::SeqCst);
    }

    /// Get the pending requests for a specific chain.
    #[inline]
    pub(crate) fn pending(&self, chain: &Chain) -> &RwLock<PendingRequests> {
        &self.requests[*chain]
    }

    /// Get the execution watchers for a specific chain.
    #[inline]
    fn watchers(&self, chain: &Chain) -> &RwLock<ExecutionWatchers> {
        &self.execution_watchers[*chain]
    }

    /// Insert a new Sign request into the backlog for the specified chain.
    /// Returns the [`SignEntry<Generating>`] handle and whether to sign it: `false` when the
    /// request is already present, or when replay reattached a record that is past signing.
    /// A request that is already present keeps the state its entry has reached:
    /// overwriting would reset an executing entry and sign it a second time.
    pub async fn insert(&self, request: Arc<IndexedSignRequest>) -> (SignEntry<Generating>, bool) {
        let chain = request.chain;
        let id = request.id;
        let (len, to_sign, handle) = {
            let mut pending = self.pending(&chain).write().await;
            if pending.get(&id).is_some() {
                return (SignEntry::generating(request, self), false);
            }
            let mut entry = BacklogEntry::new(Arc::clone(&request));
            // Replay admits again a request this node had already signed or answered.
            if let Some(record) = pending.unclaimed.remove(&id) {
                entry.status = record.status;
            }
            let to_sign = entry.status.is_pending_generation();
            // A reattached answer signs its response, not the first leg.
            let handle = SignEntry::generating(Arc::clone(entry.request()), self);
            pending.insert(id, entry);
            (pending.len(), to_sign, handle)
        };

        self.total_pending.fetch_add(1, Ordering::Relaxed);
        self.observe_backlog_size(chain, len);
        (handle, to_sign)
    }

    /// Remove a Sign request from the backlog for the specified chain.
    /// Returns `true` if an entry was removed, `false` otherwise.
    pub async fn remove(&self, chain: Chain, id: &SignId) -> bool {
        let (removed, len) = {
            let mut pending = self.pending(&chain).write().await;
            let rem = pending.remove(id);
            (rem, pending.len())
        };
        let removed = match removed {
            Some(entry) => {
                // A removed request's transactions are never answered, executed or not.
                for tx in entry.watched_txs() {
                    self.watchers(&tx.target_chain).write().await.remove(&tx.id);
                }
                self.forget_local(chain, &[*id]).await;
                true
            }
            None => false,
        };

        // Only decrement total pending if an entry was actually removed
        if removed {
            self.total_pending.fetch_sub(1, Ordering::Relaxed);
        }

        self.observe_backlog_size(chain, len);
        removed
    }

    /// Get an in-flight sign request entry from the backlog for the specified chain.
    /// The entry for `id` as stored, with its transactions.
    pub(crate) async fn entry(&self, chain: Chain, id: &SignId) -> Option<BacklogEntry> {
        self.pending(&chain).read().await.get(id).cloned()
    }

    pub async fn get(&self, chain: Chain, id: &SignId) -> Option<SignEntry> {
        let entry = self.pending(&chain).read().await.get(id).cloned()?;
        Some(SignEntry {
            chain,
            request: Arc::clone(entry.request()),
            state: entry.status,
            backlog: self.clone(),
        })
    }

    /// Returns the number of pending requests in total
    pub fn len(&self) -> usize {
        self.total_pending.load(Ordering::Relaxed)
    }

    /// Returns true if there are no pending requests
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Observe the backlog size for a specific chain and update metrics accordingly
    fn observe_backlog_size(&self, chain: Chain, len: usize) {
        crate::metrics::requests::BACKLOG_SIZE
            .with_label_values(&[chain.as_str()])
            .set(len as i64);
    }

    /// Requests pending on a chain in any state — for admission checks that
    /// must consider everything not yet final (duplicate destination ids).
    pub async fn pending_requests(&self, chain: Chain) -> Vec<Arc<IndexedSignRequest>> {
        self.pending(&chain)
            .read()
            .await
            .requests
            .values()
            .map(|entry| Arc::clone(&entry.request))
            .collect()
    }

    /// Returns backlog requests for a chain that are still eligible to be
    /// enqueued for processing after catchup completes.
    pub async fn requeueable_requests(&self, chain: Chain) -> Vec<SignEntry<Generating>> {
        let pending = self.pending(&chain).read().await;

        let mut requeueable: Vec<_> = pending
            .requests
            .values()
            .filter(|entry| entry.status().is_pending_generation())
            .map(|entry| SignEntry {
                chain,
                request: Arc::clone(entry.request()),
                state: Generating,
                backlog: self.clone(),
            })
            .collect();

        requeueable.sort_by(|left, right| {
            left.request()
                .unix_timestamp_indexed
                .cmp(&right.request().unix_timestamp_indexed)
                .then_with(|| left.request_id().cmp(&right.request_id()))
        });

        requeueable
    }

    /// Returns backlog requests for a chain that are ready to be published, each
    /// with whether this node already dispatched a publish for it.
    /// Sorted by indexed timestamp and request id.
    pub async fn publishable_requests(&self, chain: Chain) -> Vec<SignEntry<Publishing>> {
        // Read-only scan; the publish failover sweep calls this on every block, so a
        // write lock here would serialize against the signing hot path for nothing.
        let pending = self.pending(&chain).read().await;

        let mut publishable: Vec<_> = pending
            .requests
            .values()
            .filter_map(|entry| {
                let publish = entry.status.publishing()?;
                Some(SignEntry {
                    chain,
                    request: Arc::clone(entry.request()),
                    state: publish.clone(),
                    backlog: self.clone(),
                })
            })
            .collect();

        publishable.sort_by(|left, right| {
            left.request()
                .unix_timestamp_indexed
                .cmp(&right.request().unix_timestamp_indexed)
                .then_with(|| left.request_id().cmp(&right.request_id()))
        });

        publishable
    }

    /// Returns the number of pending requests for a specific chain
    pub async fn len_by_chain(&self, chain: Chain) -> usize {
        self.pending(&chain).read().await.len()
    }

    /// Begin watching for execution of a bidirectional transaction on the destination chain.
    pub async fn watch_execution(&self, entry: &SignEntry<Bidirectional<Executing>>) {
        let tx = entry.execution_tx();
        let target_chain = tx.target_chain;
        let mut watchers = self.watchers(&target_chain).write().await;

        watchers.insert(entry.execution_watch());
    }

    /// Watch these transactions, keeping any watch already in place.
    pub(crate) async fn watch_txs(&self, txs: impl IntoIterator<Item = Arc<BidirectionalTx>>) {
        let mut by_target: HashMap<Chain, Vec<Arc<BidirectionalTx>>> = HashMap::new();
        for tx in txs {
            by_target.entry(tx.target_chain).or_default().push(tx);
        }
        for (target, txs) in by_target {
            self.watchers(&target).write().await.insert_all(txs);
        }
    }

    pub(crate) async fn unwatch_txs(&self, txs: Vec<Arc<BidirectionalTx>>) {
        for tx in txs {
            self.watchers(&tx.target_chain).write().await.remove(&tx.id);
        }
    }

    /// Stop watching the entry whose transaction `tx_id` was found on `chain`, under every one
    /// of its transactions, and return it as executing under that one.
    pub async fn unwatch_execution(
        &self,
        chain: Chain,
        tx_id: &BidirectionalTxId,
    ) -> Option<SignEntry<Bidirectional<Executing>>> {
        let watch = self.watchers(&chain).write().await.remove(tx_id)?;
        let source_chain = watch.tx.source_chain;
        let entry = self.entry(source_chain, &watch.tx.sign_id()).await?;
        if !entry.awaits_execution() {
            return None;
        }
        let mut watchers = self.watchers(&chain).write().await;
        for tx in entry.watched_txs() {
            watchers.remove(&tx.id);
        }
        drop(watchers);
        Some(SignEntry {
            chain: source_chain,
            request: entry.request,
            state: Bidirectional(Executing(watch)),
            backlog: self.clone(),
        })
    }

    /// Record a published signature's transaction for an entry that already left Initial.
    pub(crate) async fn add_published_tx(&self, tx: Arc<BidirectionalTx>) {
        let chain = tx.source_chain;
        let watch = {
            let mut pending = self.pending(&chain).write().await;
            let Some(entry) = pending.requests.get_mut(&tx.sign_id()) else {
                return;
            };
            if !entry.add_tx(Arc::clone(&tx)) {
                return;
            }
            entry.awaits_execution()
        };
        if watch {
            self.watch_txs([tx]).await;
        }
    }

    /// Take the entries that `taker`, executed, leaves unexecutable (M4): same account and
    /// nonce, other bytes, no outcome yet, signed or not.
    pub async fn take_nonce_siblings(
        &self,
        chain: Chain,
        taker: &SignBidirectionalEvent,
        root_pk: PublicKey,
    ) -> Vec<SignEntry<Bidirectional<Executing>>> {
        let slot = match NonceSlot::of_request(taker) {
            Ok(Some(slot)) => slot,
            Ok(None) => return Vec::new(),
            Err(err) => {
                tracing::warn!(?err, "cannot derive the nonce of an executed tx");
                return Vec::new();
            }
        };
        let siblings =
            |entry: &BacklogEntry| entry.awaits_execution() && entry.is_nonce_sibling(&slot);
        self.take_where([chain], siblings, root_pk).await
    }

    /// Record that a Response at `height` used `slot` up, on every request it leaves
    /// unexecutable (#1430). A source-chain fact, so set whatever this node's progress.
    pub(crate) async fn mark_unviable(&self, chain: Chain, slot: &NonceSlot, height: u64) {
        let mut pending = self.pending(&chain).write().await;
        for entry in pending.requests.values_mut() {
            if entry.unviable_at.is_none() && entry.is_nonce_sibling(slot) {
                tracing::info!(sign_id = ?entry.sign_id(), height, "nonce used up by a Response");
                entry.unviable_at = Some(height);
            }
        }
    }

    /// Take the entries a Response left unexecutable at `height` on `target` that this node
    /// has not answered yet.
    pub(crate) async fn take_unviable(
        &self,
        target: Chain,
        height: u64,
        root_pk: PublicKey,
    ) -> Vec<SignEntry<Bidirectional<Executing>>> {
        let unviable = |entry: &BacklogEntry| entry.awaits_unviable_answer(target) == Some(height);
        self.take_where(Chain::iter(), unviable, root_pk).await
    }

    /// Take the entries on `chains` that `pick` selects, to answer them: unwatched, each
    /// executing under its first transaction or, unsigned, under its request's id. One no
    /// transaction can be built for cannot be answered, and is parked instead.
    async fn take_where(
        &self,
        chains: impl IntoIterator<Item = Chain>,
        pick: impl Fn(&BacklogEntry) -> bool,
        root_pk: PublicKey,
    ) -> Vec<SignEntry<Bidirectional<Executing>>> {
        let mut taken = Vec::new();
        for chain in chains {
            let picked: Vec<BacklogEntry> = {
                let pending = self.pending(&chain).read().await;
                pending
                    .requests
                    .values()
                    .filter(|entry| pick(entry))
                    .cloned()
                    .collect()
            };
            for entry in picked {
                let unsigned = BidirectionalTxId(entry.request.id.request_id);
                let tx = entry.watched_txs().into_iter().next();
                let Some(tx) = tx.or_else(|| entry.rebuild_txs(&[unsigned], root_pk).pop()) else {
                    // Logged by `rebuild_txs`; parked so that nothing asks for it again.
                    let parked = SignStatus::Bidirectional(BidirectionalProgress::Parked);
                    if let Err(err) = self.set_local_status(chain, entry.sign_id(), parked).await {
                        tracing::error!(sign_id = ?entry.sign_id(), ?err, "failed to park a request");
                    }
                    continue;
                };
                self.unwatch_txs(entry.watched_txs()).await;
                taken.push(SignEntry {
                    chain,
                    request: entry.request,
                    state: Bidirectional(Executing(ExecutionWatch::new(tx, None))),
                    backlog: self.clone(),
                });
            }
        }
        taken
    }

    /// Note a block replayed while catching up, so that records written from here on carry
    /// its height; the processed height, which paces checkpoints, stays.
    pub async fn note_replayed_block(&self, chain: Chain, height: u64) {
        self.pending(&chain).write().await.replayed_block_height = Some(height);
    }

    /// Set the processed block height for a specific chain.
    /// Returns Some(Checkpoint) if a checkpoint should be created and submitted at this block height.
    pub async fn set_processed_block(&self, chain: Chain, height: u64) -> Option<Checkpoint> {
        let interval = checkpoint_interval(chain)?;
        self.set_processed_block_interval(chain, height, interval)
            .await
    }

    /// Set the processed block height for a specific chain and checkpoint on interval.
    pub async fn set_processed_block_interval(
        &self,
        chain: Chain,
        height: u64,
        interval: u64,
    ) -> Option<Checkpoint> {
        let mut pending = self.pending(&chain).write().await;
        let prev = pending.processed_block_height().unwrap_or(0);
        pending.set_processed_block(height);

        tracing::trace!(
            ?chain,
            height,
            ?interval,
            "backlog updated processed block height"
        );

        if interval == 0 {
            return None;
        }

        // Create a checkpoint when crossing an interval boundary, not only
        // when landing exactly on an interval multiple. This matters for chains
        // like Solana where the indexer only observes slots containing
        // program-relevant transactions; sparse traffic may jump from slot 119
        // to 500 and never observe slot 120 exactly.
        //
        // Caveat: this does not checkpoint every sparse request immediately. If
        // the last processed height and the new height are in the same interval
        // bucket, the request waits until the next observed height crosses a
        // boundary. On restart/recovery, the node still resumes from the latest
        // confirmed checkpoint and replays only the post-checkpoint same-bucket
        // tail.
        if height / interval <= prev / interval {
            return None;
        }

        drop(pending);
        match self.checkpoint(chain).await {
            Ok(checkpoint) => {
                tracing::info!(
                    ?chain,
                    height,
                    tx_count = checkpoint.len(),
                    ?checkpoint,
                    "creating checkpoint"
                );
                Some(checkpoint)
            }
            Err(CheckpointError::PendingCap { tx_count, .. }) => {
                tracing::warn!(
                    ?chain,
                    height,
                    tx_count,
                    "checkpoint creation stalled (pending cap reached)"
                );
                None
            }
            Err(err @ CheckpointError::Storage { .. }) => {
                tracing::error!(?chain, %err, "failed to create checkpoint");
                None
            }
        }
    }

    /// Create a checkpoint of the current backlog state for a specific chain.
    pub async fn checkpoint(&self, chain: Chain) -> Result<Checkpoint, CheckpointError> {
        let checkpoint = {
            let requests = self.pending(&chain).read().await;
            Checkpoints::snapshot(&requests, chain)
        };
        self.checkpoints.persist_pending(&checkpoint).await?;
        Ok(checkpoint)
    }

    /// Recovers local backlog state from the latest durable checkpoint if one exists.
    pub async fn recover_local(
        &self,
        chain: Chain,
        root_pk: PublicKey,
    ) -> Result<Option<Checkpoint>, CheckpointError> {
        let Some(checkpoint) = self.checkpoints.latest(chain).await? else {
            // Without a checkpoint nothing says which records are stale, and a chain that
            // re-indexes from its start may admit every one of them again.
            self.pending(&chain).write().await.unclaimed = self.load_local(chain).await?;
            return Ok(None);
        };
        self.recover_by_checkpoint(&checkpoint, root_pk).await?;
        Ok(Some(checkpoint))
    }

    /// Replace the local backlog with a consensus checkpoint after divergence:
    /// resets durable storage to consensus, zeroes pending counts, and restores in-memory state.
    pub async fn regress(
        &self,
        checkpoint: &Checkpoint,
        root_pk: PublicKey,
    ) -> Result<(), CheckpointError> {
        // Loaded first: a failed load leaves storage and memory as they were.
        let local = self.load_local(checkpoint.chain).await?;
        self.checkpoints.regress(checkpoint).await?;
        self.restore(checkpoint, local, root_pk).await;
        Ok(())
    }

    /// Access the checkpoint subsystem.
    pub fn checkpoints(&self) -> &Checkpoints {
        &self.checkpoints
    }

    /// Recover backlog state from a checkpoint into memory.
    /// This is called when a node restarts (via `hydrate`) or regresses to consensus (via `regress`).
    pub async fn recover_by_checkpoint(
        &self,
        checkpoint: &Checkpoint,
        root_pk: PublicKey,
    ) -> Result<(), CheckpointError> {
        let local = self.load_local(checkpoint.chain).await?;
        self.restore(checkpoint, local, root_pk).await;
        Ok(())
    }

    async fn restore(
        &self,
        checkpoint: &Checkpoint,
        mut local: HashMap<SignId, LocalRecord>,
        root_pk: PublicKey,
    ) {
        let chain = checkpoint.chain;
        let requests = checkpoint
            .pending_requests
            .iter()
            .map(|entry| {
                let record = local.remove(&entry.sign_id());
                (
                    entry.sign_id(),
                    BacklogEntry::recover(entry, record, root_pk),
                )
            })
            .collect();
        // A record written at height `at` is of a request admitted by `at + 1`: below the
        // checkpoint and missing from it, it was answered; from there on, replay admits it again.
        let (unclaimed, answered): (HashMap<_, _>, HashMap<_, _>) = local
            .into_iter()
            .partition(|(_, record)| record.at >= checkpoint.block_height);
        let answered: Vec<SignId> = answered.into_keys().collect();
        self.forget_local(chain, &answered).await;
        let restored = PendingRequests {
            requests,
            processed_block_height: Some(checkpoint.block_height),
            replayed_block_height: None,
            unclaimed,
        };
        let checkpoint_height = checkpoint.block_height;
        tracing::info!(
            ?chain,
            height = checkpoint_height,
            num_pending = checkpoint.len(),
            "recovering backlog to checkpoint"
        );

        let execution_to_watch = {
            let mut pending = self.pending(&checkpoint.chain).write().await;
            let previous_height = pending.processed_block_height().unwrap_or(0);

            // Execution watchers are ephemeral, we need to get all the execution watchers here
            let cleared = pending.len();
            let restored_len = restored.len();
            *pending = restored;
            // Otherwise the gauge shows nothing until the chain's next request.
            self.observe_backlog_size(chain, restored_len);

            // Update total pending count based on the difference between cleared and restored requests
            if restored_len > cleared {
                self.total_pending
                    .fetch_add(restored_len - cleared, Ordering::Relaxed);
            } else if cleared > restored_len {
                self.total_pending
                    .fetch_sub(cleared - restored_len, Ordering::Relaxed);
            }

            tracing::info!(
                ?chain,
                old_block = previous_height,
                new_block = checkpoint_height,
                cleared_requests = cleared,
                restored_requests = restored_len,
                "successfully recovered from checkpoint"
            );
            pending.execution_watches()
        };

        // Replace this chain's watches, retaining wait start times for executions
        // that are still being awaited.
        for destination_chain in Chain::iter() {
            let mut watchers = self.watchers(&destination_chain).write().await;
            let mut observed = HashMap::new();
            watchers.watchers.retain(|id, watch| {
                if watch.tx.source_chain != chain {
                    return true;
                }
                observed.insert(*id, watch.respond_observed_at);
                false
            });
            for watch in &execution_to_watch {
                let mut watch = watch.clone();
                if watch.tx.target_chain == destination_chain {
                    watch.respond_observed_at = observed.remove(&watch.tx.id).flatten();
                    watchers.insert(watch);
                }
            }
        }
    }
}

/// Implement the StateManager trait for Backlog to provide access to processed block height and execution watchers for indexers
#[async_trait::async_trait]
impl StateManager for Backlog {
    async fn get_processed_block(&self, chain: Chain) -> Option<u64> {
        self.pending(&chain).read().await.processed_block_height()
    }

    async fn set_processed_block(&self, chain: Chain, height: u64) {
        self.pending(&chain)
            .write()
            .await
            .set_processed_block(height);
    }

    async fn get_execution_watchers(
        &self,
        chain: Chain,
    ) -> HashMap<BidirectionalTxId, (SignId, Arc<BidirectionalTx>)> {
        self.watchers(&chain).read().await.all()
    }

    async fn get_block_hash_lookups(&self, chain: Chain) -> Vec<u64> {
        let mut heights = Vec::new();
        for source in Chain::iter() {
            let pending = self.pending(&source).read().await;
            heights.extend(
                pending
                    .requests
                    .values()
                    .filter_map(|entry| entry.awaits_unviable_answer(chain)),
            );
        }
        heights.sort_unstable();
        heights.dedup();
        heights
    }
}

/// Errors that can occur when working with Backlog
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BacklogError {
    #[error("request not found for chain {chain:?} with id {id:?}")]
    NotFound { chain: Chain, id: SignId },
    #[error("failed to reconstruct signature")]
    InvalidSignature,
    #[error("cannot mark publishing: status must be pending generation")]
    InvalidPublishTransition,
    #[error("{id:?} on {chain:?} moved on while its record was stored")]
    Superseded { chain: Chain, id: SignId },
    #[error("failed to store the local record of {id:?} on {chain:?}: {reason}")]
    Storage {
        chain: Chain,
        id: SignId,
        reason: String,
    },
}

/// What a node holds for a request: the source chain's facts, which go into checkpoints, and
/// its own progress, which does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacklogEntry {
    pub request: Arc<IndexedSignRequest>,
    pub status: SignStatus,
    /// The transactions of the request's published signatures, in id order.
    pub txs: Vec<Arc<BidirectionalTx>>,
    /// The height another request's Response attests, which left this one unexecutable (M4).
    pub unviable_at: Option<u64>,
}

impl BacklogEntry {
    pub fn new(request: Arc<IndexedSignRequest>) -> Self {
        let status = match &request.kind {
            SignKind::Sign => SignStatus::Sign(SignProgress::Generating),
            SignKind::SignBidirectional(_) => {
                SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Generating))
            }
            SignKind::RespondBidirectional(_) => {
                SignStatus::Bidirectional(BidirectionalProgress::Final {
                    respond_request: Arc::clone(&request),
                    progress: SignProgress::Generating,
                })
            }
        };
        Self::with_status(request, status)
    }

    pub fn with_status(request: Arc<IndexedSignRequest>, status: SignStatus) -> Self {
        Self {
            request,
            status,
            txs: Vec::new(),
            unviable_at: None,
        }
    }

    /// Rebuild an entry from a checkpoint and this node's record of it.
    fn recover(entry: &CheckpointEntry, record: Option<LocalRecord>, root_pk: PublicKey) -> Self {
        let mut recovered = Self::new(Arc::clone(&entry.request));
        recovered.unviable_at = entry.unviable_at;
        recovered.txs = recovered.rebuild_txs(&entry.tx_ids, root_pk);
        if let Some(record) = record {
            recovered.status = record.status;
        }
        let first_leg_done = matches!(
            recovered.status,
            SignStatus::Bidirectional(BidirectionalProgress::Initial(_))
        ) && !recovered.txs.is_empty();
        if first_leg_done {
            recovered.status = SignStatus::Bidirectional(BidirectionalProgress::Executing);
        }
        recovered
    }

    fn rebuild_txs(
        &self,
        ids: &[BidirectionalTxId],
        root_pk: PublicKey,
    ) -> Vec<Arc<BidirectionalTx>> {
        let SignKind::SignBidirectional(event) = &self.request.kind else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|id| {
                event
                    .bidirectional_tx(self.request.id.request_id, *id, root_pk)
                    .inspect_err(|err| {
                        tracing::error!(sign_id = ?self.sign_id(), ?id, ?err, "cannot rebuild a transaction");
                    })
                    .ok()
                    .map(Arc::new)
            })
            .collect()
    }

    pub fn sign_id(&self) -> SignId {
        self.request.id
    }

    /// The request actively being signed or published.
    /// In Phase 2 this yields the `respond_request`, while `self.request` retains
    /// the original `SignBidirectional` provenance.
    pub fn request(&self) -> &Arc<IndexedSignRequest> {
        match &self.status {
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request, ..
            }) => respond_request,
            _ => &self.request,
        }
    }

    /// Get the status of this transaction
    pub fn status(&self) -> SignStatus {
        self.status.clone()
    }

    /// Whether this node still looks for the request's execution.
    pub fn awaits_execution(&self) -> bool {
        matches!(
            self.status,
            SignStatus::Bidirectional(
                BidirectionalProgress::Initial(_) | BidirectionalProgress::Executing
            )
        )
    }

    /// The transactions of the request's published signatures, which the node looks for.
    pub fn watched_txs(&self) -> Vec<Arc<BidirectionalTx>> {
        self.txs.clone()
    }

    /// Whether this request waits on `slot` with other bytes (M4).
    fn is_nonce_sibling(&self, slot: &NonceSlot) -> bool {
        match &self.request.kind {
            SignKind::SignBidirectional(event) => slot.is_sibling(event),
            _ => false,
        }
    }

    /// The height a Response left this request unexecutable at on `target`, while this node
    /// has not answered it.
    fn awaits_unviable_answer(&self, target: Chain) -> Option<u64> {
        let height = self.unviable_at.filter(|_| self.awaits_execution())?;
        let SignKind::SignBidirectional(event) = &self.request.kind else {
            return None;
        };
        (event.target_chain().ok() == Some(target)).then_some(height)
    }

    /// Add a published signature's transaction; false if it was known.
    pub(crate) fn add_tx(&mut self, tx: Arc<BidirectionalTx>) -> bool {
        match self.txs.binary_search_by_key(&tx.id.0, |known| known.id.0) {
            Ok(_) => false,
            Err(at) => {
                self.txs.insert(at, tx);
                true
            }
        }
    }

    pub(crate) fn checkpoint_entry(&self) -> CheckpointEntry {
        CheckpointEntry {
            request: Arc::clone(&self.request),
            tx_ids: self.txs.iter().map(|tx| tx.id).collect(),
            unviable_at: self.unviable_at,
            legacy_tag: None,
        }
    }
}

#[cfg(test)]
mod tests;
