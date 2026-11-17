mod checkpoints;
pub mod consensus;
pub(crate) mod migration;
#[cfg(any(test, feature = "test-feature"))]
pub mod mock;
pub mod request;

pub use request::{
    AnyProgress, Bidirectional, Executing, ExecutionWatch, Final, Generating, Initial, Publishing,
    Sign, SignEntry,
};

use crate::sign_bidirectional::{
    transaction_nonce, BidirectionalProgress, SignBidirectionalEventExt as _, SignProgress,
    SignStatus,
};
use crate::storage::checkpoint_storage::CheckpointStorage;
pub use checkpoints::{Checkpoint, CheckpointError, Checkpoints};

use crate::util::cadence::Cadence;
use enum_map::EnumMap;
use mpc_chain_integration_core::{StateManager, WatchKey, WatchedExecution};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, IndexedSignRequest, PublicKey, SignId, SignKind,
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

    /// A watch for every transaction of every entry that awaits its execution.
    fn execution_watches(&self) -> Vec<ExecutionWatch> {
        self.requests
            .values()
            .flat_map(|entry| entry.watched_txs())
            .map(|tx| ExecutionWatch::new(tx, None))
            .collect()
    }

    fn executing_targeting(&self, target: Chain) -> Vec<WatchedExecution> {
        self.requests
            .values()
            .filter_map(|entry| {
                entry
                    .execution_tx()
                    .filter(|tx| tx.target_chain == target)
                    .map(|tx| WatchedExecution {
                        sign_id: entry.sign_id(),
                        tx: Arc::clone(tx),
                    })
            })
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

    fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        let requests = checkpoint
            .pending_requests
            .iter()
            .map(|entry| (entry.sign_id(), entry.clone()))
            .collect();
        Self {
            requests,
            processed_block_height: Some(checkpoint.block_height),
        }
    }
}

// TODO: move wait starts out of this polling index into their own
// table — the map then holds only `WatchKey` → tx, and the carry and
// rebuild arms go away. Do it together with the extraction (state.rs
// TODO).
#[derive(Debug, Clone, Default)]
struct ExecutionWatchers {
    watches: HashMap<WatchKey, ExecutionWatch>,
}

impl ExecutionWatchers {
    /// Registers `watch`, keeping the resident's wait start.
    fn insert(&mut self, mut watch: ExecutionWatch) {
        let key = WatchKey::of(&watch.tx);
        watch.respond_observed_at = watch.respond_observed_at.or_else(|| {
            self.watches
                .get(&key)
                .and_then(|resident| resident.respond_observed_at)
        });
        self.watches.insert(key, watch);
    }

    /// Replaces `source`'s watches with `entries`, keeping a returning
    /// member's wait start.
    fn rebuild(&mut self, source: Chain, entries: impl IntoIterator<Item = ExecutionWatch>) {
        let fresh: HashMap<WatchKey, ExecutionWatch> = entries
            .into_iter()
            .map(|watch| (WatchKey::of(&watch.tx), watch))
            .collect();
        self.watches
            .retain(|key, _| key.source != source || fresh.contains_key(key));
        for (_, watch) in fresh {
            self.insert(watch);
        }
    }

    fn remove(&mut self, key: &WatchKey) -> Option<ExecutionWatch> {
        self.watches.remove(key)
    }

    fn all(&self) -> HashMap<BidirectionalTxId, Vec<WatchedExecution>> {
        let mut grouped: HashMap<BidirectionalTxId, Vec<WatchedExecution>> = HashMap::new();
        for watch in self.watches.values() {
            grouped
                .entry(watch.tx.id)
                .or_default()
                .push(WatchedExecution::of(Arc::clone(&watch.tx)));
        }
        grouped
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
    /// Shared cadence. Read-only after startup, so every backlog clone holds the same `Arc`.
    cadence: Arc<Cadence>,
}

impl Default for Backlog {
    fn default() -> Self {
        Self::new(Cadence::default())
    }
}

impl Backlog {
    pub fn new(cadence: impl Into<Arc<Cadence>>) -> Self {
        Self::persisted(CheckpointStorage::in_memory(), cadence)
    }

    /// Initialize the backlog with storage for all chains
    pub fn persisted(storage: CheckpointStorage, cadence: impl Into<Arc<Cadence>>) -> Self {
        Self {
            checkpoints: Checkpoints::new(storage),
            requests: Arc::default(),
            execution_watchers: Arc::default(),
            total_pending: Arc::new(AtomicUsize::new(0)),
            caught_up: Arc::default(),
            cadence: cadence.into(),
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
    /// Returns the initial [`SignEntry<Generating>`] handle and a boolean indicating
    /// whether the request was newly inserted (`true`) or was already present (`false`).
    /// A request that is already present keeps the state its entry has reached:
    /// overwriting would reset an executing entry and sign it a second time.
    pub async fn insert(&self, request: Arc<IndexedSignRequest>) -> (SignEntry<Generating>, bool) {
        let chain = request.chain;
        let id = request.id;
        let len = {
            let mut pending = self.pending(&chain).write().await;
            if pending.get(&id).is_some() {
                return (SignEntry::generating(request, self), false);
            }
            pending.insert(id, BacklogEntry::new(Arc::clone(&request)));
            pending.len()
        };

        self.total_pending.fetch_add(1, Ordering::Relaxed);
        self.observe_backlog_size(chain, len);
        (SignEntry::generating(request, self), true)
    }

    /// Remove a Sign request from the backlog for the specified chain.
    /// Returns `true` if an entry was removed, `false` otherwise.
    pub async fn remove(&self, chain: Chain, id: &SignId) -> bool {
        let (removed, len) = {
            let mut pending = self.pending(&chain).write().await;
            let rem = pending.remove(id);
            (rem.is_some(), pending.len())
        };

        // Only decrement total pending if an entry was actually removed
        if removed {
            self.total_pending.fetch_sub(1, Ordering::Relaxed);
            // Only a restart reads the record, so it goes in the background; catching up deletes
            // any this misses.
            let (storage, id) = (self.checkpoints.storage().clone(), *id);
            tokio::spawn(async move {
                if let Err(err) = storage.remove_local(chain, &[id]).await {
                    tracing::warn!(?chain, ?id, ?err, "failed to remove a local record");
                }
            });
        }

        self.observe_backlog_size(chain, len);
        removed
    }

    /// Delete the records of requests no longer in the backlog, which a rebase past their
    /// `Response` or a failed delete leaves. Call it once caught up.
    pub(crate) async fn forget_stale_local(&self, chain: Chain) {
        let storage = self.checkpoints.storage();
        let stale: Vec<SignId> = match storage.load_local(chain).await {
            Ok(records) => {
                let pending = self.pending(&chain).read().await;
                let gone = |id: &SignId| pending.get(id).is_none();
                records.into_iter().map(|(id, _)| id).filter(gone).collect()
            }
            Err(err) => {
                tracing::warn!(?chain, ?err, "failed to load local records");
                return;
            }
        };
        if let Err(err) = storage.remove_local(chain, &stale).await {
            tracing::warn!(?chain, ?err, "failed to remove local records");
        }
    }

    /// Get an in-flight sign request entry from the backlog for the specified chain.
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
            .filter(|entry| entry.signs_at_catchup())
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

    /// `Executing` entries targeting `target`, from every owning chain.
    async fn pending_executions_targeting(&self, target: Chain) -> Vec<WatchedExecution> {
        let mut targeting = Vec::new();
        for pending in self.requests.values() {
            targeting.extend(pending.read().await.executing_targeting(target));
        }
        targeting
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

    /// Stops watching and retrieves the entry, keyed by flat id plus
    /// the entry's own source and sign id; sibling watches stay.
    pub async fn unwatch_execution(
        &self,
        chain: Chain,
        tx_id: &BidirectionalTxId,
        source_chain: Chain,
        sign_id: &SignId,
    ) -> Option<SignEntry<Bidirectional<Executing>>> {
        let key = WatchKey {
            flat_id: *tx_id,
            source: source_chain,
            sign_id: *sign_id,
        };
        let watch = self.watchers(&chain).write().await.remove(&key)?;

        // The status names one transaction and no observation time; the watch that fired has both.
        let entry = self
            .get_by::<Bidirectional<Executing>>(watch.tx.source_chain, &watch.tx.sign_id())
            .await?;
        // Its other transactions can no longer execute, whoever published their signatures.
        let pending = self.pending(&watch.tx.source_chain).read().await;
        let others = pending
            .get(&watch.tx.sign_id())
            .map(BacklogEntry::watched_txs)
            .unwrap_or_default();
        // Under the pending lock, as `add_published_tx` inserts: no watch outlives the entry.
        let mut watchers = self.watchers(&chain).write().await;
        for other in others {
            watchers.remove(&WatchKey::of(&other));
        }
        drop(watchers);
        drop(pending);
        Some(entry.with_execution_watch(watch))
    }

    /// The entry of `id`, whatever leg it is on.
    pub(crate) async fn entry(&self, chain: Chain, id: &SignId) -> Option<BacklogEntry> {
        self.pending(&chain).read().await.get(id).cloned()
    }

    /// Record a published signature's transaction for an entry that already left Initial.
    pub(crate) async fn add_published_tx(&self, tx: Arc<BidirectionalTx>) {
        let mut pending = self.pending(&tx.source_chain).write().await;
        let Some(entry) = pending.requests.get_mut(&tx.sign_id()) else {
            return;
        };
        if !entry.add_tx_id(tx.id) {
            return;
        }
        let Some(status_tx) = entry.execution_tx() else {
            return;
        };
        let mut watchers = self.watchers(&tx.target_chain).write().await;
        let observed_at = watchers
            .watches
            .get(&WatchKey::of(status_tx))
            .and_then(|watch| watch.respond_observed_at);
        watchers.insert(ExecutionWatch::new(tx, observed_at));
    }

    /// Unwatch and return the entries of `chain` that `taker`, executed, leaves unexecutable (M4),
    /// signed or not, that this node has not answered.
    pub(crate) async fn unwatch_nonce_siblings(
        &self,
        chain: Chain,
        taker: &BidirectionalTx,
        root_pk: PublicKey,
    ) -> Vec<SignEntry<Bidirectional<Executing>>> {
        let siblings =
            |entry: &BacklogEntry| entry.awaits_execution() && entry.is_nonce_sibling(taker);
        self.unwatch_where(chain, siblings, root_pk).await
    }

    /// Record that a Response at `height` reports `taker` included, on every request of `chain`
    /// it leaves unexecutable. A source-chain fact, so set whatever this node's progress.
    pub(crate) async fn mark_unviable(&self, chain: Chain, taker: &BidirectionalTx, height: u64) {
        let mut pending = self.pending(&chain).write().await;
        for entry in pending.requests.values_mut() {
            if entry.unviable_at.is_none() && entry.is_nonce_sibling(taker) {
                tracing::info!(sign_id = ?entry.sign_id(), height, "nonce used up by a Response");
                entry.unviable_at = Some(height);
            }
        }
    }

    /// Unwatch and return the entries of `chain` a Response left unexecutable that this node has
    /// not answered.
    pub(crate) async fn unwatch_unviable(
        &self,
        chain: Chain,
        root_pk: PublicKey,
    ) -> Vec<SignEntry<Bidirectional<Executing>>> {
        let unviable =
            |entry: &BacklogEntry| entry.unviable_at.is_some() && entry.awaits_execution();
        self.unwatch_where(chain, unviable, root_pk).await
    }

    /// Unwatch and return the entries on `chain` that `pick` selects, to answer them. They stay in
    /// the backlog, each named by its request's id, since nodes may know different transactions.
    async fn unwatch_where(
        &self,
        chain: Chain,
        pick: impl Fn(&BacklogEntry) -> bool,
        root_pk: PublicKey,
    ) -> Vec<SignEntry<Bidirectional<Executing>>> {
        let picked: Vec<BacklogEntry> = {
            let pending = self.pending(&chain).read().await;
            pending
                .requests
                .values()
                .filter(|entry| pick(entry))
                .cloned()
                .collect()
        };
        let mut unwatched = Vec::new();
        for entry in picked {
            let Some(tx) = entry.named_tx(root_pk) else {
                tracing::error!(sign_id = ?entry.sign_id(), "cannot build a transaction to answer");
                continue;
            };
            let mut observed_at = None;
            for watched in entry.watched_txs() {
                let removed = self
                    .watchers(&watched.target_chain)
                    .write()
                    .await
                    .remove(&WatchKey::of(&watched));
                observed_at = observed_at.or(removed.and_then(|watch| watch.respond_observed_at));
            }
            unwatched.push(SignEntry {
                chain,
                request: entry.request,
                state: Bidirectional(Executing(ExecutionWatch::new(tx, observed_at))),
                backlog: self.clone(),
            });
        }
        unwatched
    }

    /// Parks the entry by key — the confirmation error path, whose
    /// `advance` consumed the handle.
    pub async fn park_execution(
        &self,
        chain: Chain,
        sign_id: &SignId,
        tx: &Arc<BidirectionalTx>,
    ) -> Result<(), BacklogError> {
        let mut pending = self.pending(&chain).write().await;
        let entry = pending
            .requests
            .get_mut(sign_id)
            .ok_or(BacklogError::NotFound {
                chain,
                id: *sign_id,
            })?;
        entry.status = SignStatus::Bidirectional(BidirectionalProgress::Parked(Arc::clone(tx)));
        Ok(())
    }

    /// The executing entry a confirmation attests: by the entry's own
    /// watch, or by source and sign id from the backlog.
    pub async fn executing_entry_for(
        &self,
        target_chain: Chain,
        tx_id: &BidirectionalTxId,
        source_chain: Chain,
        sign_id: &SignId,
    ) -> Option<SignEntry<Bidirectional<Executing>>> {
        if let Some(entry) = self
            .unwatch_execution(target_chain, tx_id, source_chain, sign_id)
            .await
        {
            return Some(entry);
        }
        self.get_by::<Bidirectional<Executing>>(source_chain, sign_id)
            .await
    }

    /// Set the processed block height for a specific chain.
    /// Returns Some(Checkpoint) if a checkpoint should be created and submitted at this block height.
    pub async fn set_processed_block(&self, chain: Chain, height: u64) -> Option<Checkpoint> {
        let interval = self.cadence.checkpoint_interval(chain)?;
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

    /// Hydrate the backlog from storage: initializes the pending checkpoint counter
    /// and recovers local backlog state from the latest durable checkpoint if one exists.
    pub async fn hydrate(
        &self,
        chain: Chain,
        root_pk: PublicKey,
    ) -> Result<Option<Checkpoint>, CheckpointError> {
        self.checkpoints.hydrate(chain).await?;
        self.recover_local(chain, root_pk).await
    }

    /// Give each entry its stored records, once replay has rebuilt the backlog.
    pub(crate) async fn claim_local(&self, chain: Chain, records: Vec<(SignId, SignStatus)>) {
        let mut pending = self.pending(&chain).write().await;
        for (id, record) in records {
            if let Some(entry) = pending.requests.get_mut(&id) {
                entry.apply_record(record);
            }
        }
    }

    /// Recovers local backlog state from the latest durable checkpoint if one exists.
    /// A body from an earlier version may be one adopted as sent, so its progress is rebuilt.
    pub async fn recover_local(
        &self,
        chain: Chain,
        root_pk: PublicKey,
    ) -> Result<Option<Checkpoint>, CheckpointError> {
        let Some(checkpoint) = self.checkpoints.latest(chain).await? else {
            return Ok(None);
        };
        if checkpoint.legacy_digest.is_some() {
            self.recover_by_checkpoint(&checkpoint.without_progress(root_pk))
                .await;
        } else {
            self.recover_by_checkpoint(&checkpoint).await;
        }
        Ok(Some(checkpoint))
    }

    /// Replace the local backlog with a consensus checkpoint after divergence:
    /// resets durable storage to consensus, zeroes pending counts, and restores in-memory state.
    /// A peer's body is only vouched for by the digest, which leaves out each entry's progress,
    /// so that is rebuilt here. A body from an earlier version hashes each entry's phase, so one
    /// whose rebuild changes a phase is stored as sent.
    pub async fn regress(
        &self,
        checkpoint: &Checkpoint,
        root_pk: PublicKey,
    ) -> Result<(), CheckpointError> {
        let adopted = checkpoint.without_progress(root_pk);
        let durable = if adopted.digest() == checkpoint.digest() {
            &adopted
        } else {
            checkpoint
        };
        self.checkpoints.regress(durable).await?;
        self.recover_by_checkpoint(&adopted).await;
        Ok(())
    }

    /// Access the checkpoint subsystem.
    pub fn checkpoints(&self) -> &Checkpoints {
        &self.checkpoints
    }

    /// Recover backlog state from a checkpoint into memory.
    /// This is called when a node restarts (via `hydrate`) or regresses to consensus (via `regress`).
    pub async fn recover_by_checkpoint(&self, checkpoint: &Checkpoint) {
        let restored = PendingRequests::from_checkpoint(checkpoint);
        let chain = checkpoint.chain;
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

        // Replace this chain's watches, retaining wait start times for
        // executions that are still being awaited.
        let mut by_target: HashMap<Chain, Vec<ExecutionWatch>> = HashMap::new();
        for watch in execution_to_watch {
            by_target
                .entry(watch.tx.target_chain)
                .or_default()
                .push(watch);
        }
        for destination_chain in Chain::iter() {
            let empty = Vec::new();
            let entries = by_target.get(&destination_chain).unwrap_or(&empty);
            self.watchers(&destination_chain)
                .write()
                .await
                .rebuild(chain, entries.iter().cloned());
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
    ) -> HashMap<BidirectionalTxId, Vec<WatchedExecution>> {
        self.watchers(&chain).read().await.all()
    }

    async fn get_pending_executions(&self, chain: Chain) -> Vec<WatchedExecution> {
        self.pending_executions_targeting(chain).await
    }

    async fn watch_execution(&self, chain: Chain, tx: Arc<BidirectionalTx>) {
        self.watchers(&chain)
            .write()
            .await
            .insert(ExecutionWatch::new(tx, None));
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
    #[error("request was already answered")]
    AlreadyAnswered,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(from = "migration::MigratableBacklogEntry")]
pub struct BacklogEntry {
    pub request: Arc<IndexedSignRequest>,
    pub status: SignStatus,
    /// The transactions the request's published signatures give, in id order.
    pub tx_ids: Vec<BidirectionalTxId>,
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
        Self {
            request,
            status,
            tx_ids: Vec::new(),
            unviable_at: None,
        }
    }

    pub fn with_status(request: Arc<IndexedSignRequest>, status: SignStatus) -> Self {
        let mut entry = Self::new(request);
        entry.tx_ids.extend(migration::legacy_tx_id(&status));
        entry.status = status;
        entry
    }

    /// Whether catchup queues this entry for signing. The first leg is not signed again once a
    /// signature of it is published, which a failed rebuild can leave beside `Initial`. An
    /// unanswered marked entry is answered Unviable instead; one already answered still needs
    /// its response signed.
    fn signs_at_catchup(&self) -> bool {
        let signed_first_leg = !self.tx_ids.is_empty()
            && matches!(
                self.status,
                SignStatus::Bidirectional(BidirectionalProgress::Initial(_))
            );
        let unanswered_mark = self.unviable_at.is_some() && self.awaits_execution();
        self.status.is_pending_generation() && !signed_first_leg && !unanswered_mark
    }

    /// The source-chain facts the digest covers; indexing times are node-local.
    fn digest_bytes(&self) -> Vec<u8> {
        let request = &self.request;
        let fields = (
            request.id,
            &request.args,
            request.chain,
            &request.kind,
            &self.tx_ids,
            self.unviable_at,
        );
        let mut bytes = Vec::new();
        ciborium::into_writer(&fields, &mut bytes).expect("encoding into memory cannot fail");
        bytes
    }

    /// Whether this node still has to answer the request.
    pub(crate) fn awaits_execution(&self) -> bool {
        matches!(
            self.status,
            SignStatus::Bidirectional(
                BidirectionalProgress::Initial(_) | BidirectionalProgress::Executing(_)
            )
        )
    }

    /// The request's transaction, named by the request's id: it answers for the request
    /// whatever signatures of it a node knows.
    pub(crate) fn named_tx(&self, root_pk: PublicKey) -> Option<Arc<BidirectionalTx>> {
        let SignKind::SignBidirectional(event) = &self.request.kind else {
            return None;
        };
        let request_id = self.request.id.request_id;
        event
            .bidirectional_tx(request_id, BidirectionalTxId(request_id), root_pk)
            .ok()
            .map(Arc::new)
    }

    /// Whether `taker`, executed, leaves this request unexecutable (M4): same account and nonce,
    /// other bytes. The source chain, sender, path and key version fix the account. A Tron
    /// transaction ID executes once whatever else runs; expiry answers the rest (M6).
    pub(crate) fn is_nonce_sibling(&self, taker: &BidirectionalTx) -> bool {
        let SignKind::SignBidirectional(event) = &self.request.kind else {
            return false;
        };
        taker.target_chain == Chain::Ethereum
            && event.caip2_id == taker.caip2_id
            && event.chain == taker.source_chain
            && event.sender == taker.sender
            && event.path == taker.path
            && event.key_version == taker.key_version
            && event.serialized_transaction != taker.serialized_transaction
            && transaction_nonce(taker.target_chain, &event.serialized_transaction)
                .is_ok_and(|nonce| nonce == taker.nonce)
    }

    /// Add a published signature's transaction; false if it was known.
    pub(crate) fn add_tx_id(&mut self, id: BidirectionalTxId) -> bool {
        match self.tx_ids.binary_search_by_key(&id.0, |known| known.0) {
            Ok(_) => false,
            Err(at) => {
                self.tx_ids.insert(at, id);
                true
            }
        }
    }

    /// The transactions this node looks for: all that signatures of the request give, while it
    /// awaits their execution.
    pub(crate) fn watched_txs(&self) -> Vec<Arc<BidirectionalTx>> {
        let Some(tx) = self.status.execution_tx() else {
            return Vec::new();
        };
        self.tx_ids
            .iter()
            .map(|id| {
                Arc::new(BidirectionalTx {
                    id: *id,
                    ..(**tx).clone()
                })
            })
            .collect()
    }

    /// This entry with only what the source chain says of it: progress as if just indexed,
    /// or awaiting execution where a signature of it is published.
    pub(crate) fn without_progress(&self, root_pk: PublicKey) -> Self {
        let mut bare = Self::new(Arc::clone(&self.request));
        bare.tx_ids = self.tx_ids.clone();
        bare.unviable_at = self.unviable_at;
        let (SignKind::SignBidirectional(event), Some(id)) =
            (&self.request.kind, self.tx_ids.first())
        else {
            return bare;
        };
        match event.bidirectional_tx(self.request.id.request_id, *id, root_pk) {
            Ok(tx) => {
                bare.status =
                    SignStatus::Bidirectional(BidirectionalProgress::Executing(Arc::new(tx)));
            }
            Err(err) => {
                tracing::error!(sign_id = ?self.sign_id(), ?err, "cannot rebuild a transaction")
            }
        }
        bare
    }

    /// Take a stored status unless the entry has moved past it. A record is written only on
    /// publishing, so a first leg's stays behind once the request executes.
    fn apply_record(&mut self, record: SignStatus) {
        use BidirectionalProgress::{Executing, Final, Initial};
        use SignStatus::{Bidirectional, Sign};
        let applies = match (&record, &self.status) {
            (Sign(_), Sign(progress))
            | (Bidirectional(Initial(_)), Bidirectional(Initial(progress)))
            | (Bidirectional(Final { .. }), Bidirectional(Final { progress, .. })) => {
                progress.is_generating()
            }
            (Bidirectional(Final { .. }), Bidirectional(Initial(_) | Executing(_))) => true,
            _ => false,
        };
        if applies {
            self.status = record;
        }
    }

    pub fn sign_id(&self) -> SignId {
        self.request.id
    }

    /// The request actively being signed or published.
    /// In Phase 2 this yields the `respond_request`, while `self.request` retains
    /// the original `SignBidirectional` provenance.
    pub fn request(&self) -> &Arc<IndexedSignRequest> {
        match &self.status {
            SignStatus::Sign(_)
            | SignStatus::Bidirectional(
                BidirectionalProgress::Initial(_)
                | BidirectionalProgress::Executing(_)
                | BidirectionalProgress::Parked(_),
            ) => &self.request,
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request, ..
            }) => respond_request,
        }
    }

    /// Get the status of this transaction
    pub fn status(&self) -> SignStatus {
        self.status.clone()
    }

    pub fn execution_tx(&self) -> Option<&Arc<BidirectionalTx>> {
        self.status.execution_tx()
    }
}

#[cfg(test)]
mod tests;
