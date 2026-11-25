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
pub use checkpoints::{
    Checkpoint, CheckpointError, CheckpointFacts, Checkpoints, Confirmation, EntryFacts,
};

use enum_map::EnumMap;
use mpc_chain_integration_core::{ExecutionWatchIndex, StateManager, WatchKey, WatchedExecution};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, IndexedSignRequest, PublicKey, SignId, SignKind,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Max pending (unconfirmed) checkpoints per chain before stalling.
pub const MAX_PENDING_CHECKPOINTS: usize = 32;

/// Base delay before storing a checkpoint is retried; doubles up to `MAX_PERSIST_RETRY_DELAY`.
const PERSIST_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Upper bound of the checkpoint persist retry backoff.
const MAX_PERSIST_RETRY_DELAY: Duration = Duration::from_secs(30);

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

    /// Every transaction of every entry that awaits its execution.
    fn execution_watches(&self) -> Vec<Arc<BidirectionalTx>> {
        self.requests
            .values()
            .flat_map(|entry| entry.watched_txs())
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

/// The watches for one target chain and their wait starts, under one
/// lock: registering or resolving an execution touches both atomically.
#[derive(Debug, Clone, Default)]
struct ExecutionWatches {
    index: ExecutionWatchIndex,
    wait_starts: HashMap<WatchKey, Instant>,
}

impl ExecutionWatches {
    /// `None` keeps a resident clock — a re-registration goes on
    /// waiting from its first observation.
    fn register(&mut self, tx: Arc<BidirectionalTx>, observed_at: Option<Instant>) {
        if let Some(observed_at) = observed_at {
            self.wait_starts.insert(WatchKey::of(&tx), observed_at);
        }
        self.index.insert(tx);
    }

    fn clock_of(&self, key: &WatchKey) -> Option<Instant> {
        self.wait_starts.get(key).copied()
    }

    fn remove(&mut self, key: &WatchKey) -> Option<(Arc<BidirectionalTx>, Option<Instant>)> {
        let tx = self.index.remove(key)?;
        Some((tx, self.wait_starts.remove(key)))
    }

    /// Replaces `source`'s watches with `entries`; a returning execution
    /// keeps its first observation.
    fn rebuild(&mut self, source: Chain, entries: &[Arc<BidirectionalTx>]) {
        self.index.rebuild(source, entries.iter().cloned());
        self.wait_starts.retain(|key, _| self.index.contains(key));
    }

    fn all(&self) -> HashMap<BidirectionalTxId, Vec<WatchedExecution>> {
        self.index.all()
    }
}

/// Backlog manages pending sign-respond requests across multiple chains.
/// Each chain has its own isolated set of pending requests with their own
/// publish queues.
#[derive(Clone)]
pub struct Backlog {
    checkpoints: Checkpoints,
    /// Pending requests indexed by chain
    requests: Arc<EnumMap<Chain, RwLock<PendingRequests>>>,
    /// Execution watchers indexed by chain, each with its wait starts
    execution_watchers: Arc<EnumMap<Chain, RwLock<ExecutionWatches>>>,
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

/// Shows how many requests are pending. Each `SignEntry` keeps a handle to the whole
/// backlog, so every logged entry includes this count.
impl std::fmt::Debug for Backlog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backlog")
            .field("total_pending", &self.total_pending.load(Ordering::Relaxed))
            .finish_non_exhaustive()
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
    fn watchers(&self, chain: Chain) -> &RwLock<ExecutionWatches> {
        &self.execution_watchers[chain]
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
        let watch = entry.execution_watch();
        self.watchers(watch.tx.target_chain)
            .write()
            .await
            .register(Arc::clone(&watch.tx), watch.respond_observed_at);
    }

    /// Stops watching and retrieves the entry; sibling watches stay.
    pub async fn unwatch_execution(
        &self,
        key: WatchKey,
    ) -> Option<SignEntry<Bidirectional<Executing>>> {
        let (tx, observed_at) = self.watchers(key.target).write().await.remove(&key)?;

        // The status names one transaction and no observation time; the watch that fired has both.
        let entry = self
            .get_by::<Bidirectional<Executing>>(tx.source_chain, &tx.sign_id())
            .await?;
        // Its other transactions can no longer execute, whoever published their signatures.
        let pending = self.pending(&tx.source_chain).read().await;
        let others = pending
            .get(&tx.sign_id())
            .map(BacklogEntry::watched_txs)
            .unwrap_or_default();
        // Under the pending lock, as `add_published_tx` inserts: the
        // sweep sees every tx the entry holds when it runs.
        let mut watchers = self.watchers(key.target).write().await;
        for other in others {
            watchers.remove(&WatchKey::of(&other));
        }
        drop((watchers, pending));
        Some(entry.with_execution_watch(ExecutionWatch::new(tx, observed_at)))
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
        let status_key = WatchKey::of(status_tx);
        let mut watchers = self.watchers(tx.target_chain).write().await;
        let observed_at = watchers.clock_of(&status_key);
        watchers.register(tx, observed_at);
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
                let key = WatchKey::of(&watched);
                let clock = self
                    .watchers(key.target)
                    .write()
                    .await
                    .remove(&key)
                    .and_then(|(_, clock)| clock);
                observed_at = observed_at.or(clock);
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
        key: WatchKey,
    ) -> Option<SignEntry<Bidirectional<Executing>>> {
        if let Some(entry) = self.unwatch_execution(key).await {
            return Some(entry);
        }
        self.get_by::<Bidirectional<Executing>>(key.source, &key.sign_id)
            .await
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
        let checkpoint = self.snapshot(chain).await;
        // A boundary passed without a stored checkpoint is never voted for,
        // so storing it is retried until it succeeds.
        let mut retry_delay = PERSIST_RETRY_DELAY;
        loop {
            match self.checkpoints.persist_pending(&checkpoint).await {
                Ok(()) => break,
                Err(CheckpointError::PendingCap { tx_count, .. }) => {
                    tracing::warn!(
                        ?chain,
                        height,
                        tx_count,
                        "checkpoint creation stalled (pending cap reached)"
                    );
                    return None;
                }
                // The stored one keeps its vote (doc/checkpoints.md, Section 4).
                Err(err @ CheckpointError::Conflict { .. }) => {
                    tracing::error!(
                        ?chain,
                        height,
                        %err,
                        "keeping the stored checkpoint; a different one at its height is a bug"
                    );
                    return None;
                }
                Err(err @ CheckpointError::Storage { .. }) => {
                    tracing::error!(
                        ?chain,
                        height,
                        %err,
                        ?retry_delay,
                        "failed to persist checkpoint; retrying"
                    );
                }
            }
            tokio::time::sleep(retry_delay).await;
            retry_delay = (retry_delay * 2).min(MAX_PERSIST_RETRY_DELAY);
        }
        tracing::info!(
            ?chain,
            height,
            tx_count = checkpoint.len(),
            "creating checkpoint"
        );
        Some(checkpoint)
    }

    /// Captures the current backlog state of `chain` as a checkpoint.
    async fn snapshot(&self, chain: Chain) -> Checkpoint {
        let requests = self.pending(&chain).read().await;
        Checkpoints::snapshot(&requests, chain)
    }

    /// Create a checkpoint of the current backlog state for a specific chain.
    pub async fn checkpoint(&self, chain: Chain) -> Result<Checkpoint, CheckpointError> {
        let checkpoint = self.snapshot(chain).await;
        self.checkpoints.persist_pending(&checkpoint).await?;
        Ok(checkpoint)
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

    /// Seeds the in-memory backlog from the confirmed base only.
    /// The seed is whatever `load_latest` returns — the durable confirmed base — and nothing
    /// else. Pending and orphan checkpoints are never used here: they remain durable, servable,
    /// and promotable, but after a restart they must not seed the backlog we index or vote from.
    /// A body from an earlier version may be one adopted as sent, so its progress is rebuilt.
    pub async fn hydrate(
        &self,
        chain: Chain,
        root_pk: PublicKey,
    ) -> Result<Option<Checkpoint>, CheckpointError> {
        let Some(checkpoint) = self
            .checkpoints
            .storage()
            .load_latest(chain)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?
        else {
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

        let mut pending = self.pending(&chain).write().await;
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

        let mut by_target: EnumMap<Chain, Vec<Arc<BidirectionalTx>>> = EnumMap::default();
        for tx in pending.execution_watches() {
            by_target[tx.target_chain].push(tx);
        }
        for destination_chain in Chain::iter() {
            self.watchers(destination_chain)
                .write()
                .await
                .rebuild(chain, &by_target[destination_chain]);
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
        self.watchers(chain).read().await.all()
    }

    async fn get_pending_executions(&self, chain: Chain) -> Vec<WatchedExecution> {
        self.pending_executions_targeting(chain).await
    }

    async fn watch_execution(&self, tx: Arc<BidirectionalTx>) {
        self.watchers(tx.target_chain)
            .write()
            .await
            .register(tx, None);
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

impl From<EntryFacts> for BacklogEntry {
    fn from(facts: EntryFacts) -> Self {
        let mut entry = Self::new(Arc::new(IndexedSignRequest {
            id: facts.id,
            args: facts.args,
            chain: facts.chain,
            unix_timestamp_indexed: None,
            kind: facts.kind,
        }));
        entry.tx_ids = facts.tx_ids;
        entry.unviable_at = facts.unviable_at;
        entry
    }
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
    pub(crate) fn facts(&self) -> EntryFacts {
        let request = &self.request;
        EntryFacts {
            id: request.id,
            args: request.args.clone(),
            chain: request.chain,
            kind: request.kind.clone(),
            tx_ids: self.tx_ids.clone(),
            unviable_at: self.unviable_at,
        }
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
