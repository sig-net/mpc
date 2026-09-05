mod checkpoints;
pub mod consensus;
#[cfg(any(test, feature = "test-feature"))]
pub mod mock;
pub mod request;

pub use request::{
    AnyProgress, Bidirectional, Executing, Final, Generating, Initial, Publishing, Sign, SignEntry,
};

use crate::sign_bidirectional::{BidirectionalProgress, SignProgress, SignStatus};
use crate::storage::checkpoint_storage::CheckpointStorage;
pub(crate) use checkpoints::CheckpointError;
use checkpoints::Checkpoints;

use enum_map::EnumMap;
use mpc_chain_integration_core::StateManager;
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainConfig as _, IndexedSignRequest, SignId,
    SignKind,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

pub use checkpoints::Checkpoint;

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

    fn pending_executions(
        &self,
        chain: Chain,
        backlog: &Backlog,
    ) -> Vec<SignEntry<Bidirectional<Executing>>> {
        self.requests
            .values()
            .filter_map(|entry| match &entry.status {
                SignStatus::Bidirectional(BidirectionalProgress::Executing(tx)) => {
                    Some(SignEntry {
                        chain,
                        request: Arc::clone(entry.request()),
                        state: Bidirectional(Executing(Arc::clone(tx))),
                        backlog: backlog.clone(),
                    })
                }
                _ => None,
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
        let mut requests = HashMap::new();
        for entry in &checkpoint.pending_requests {
            requests.insert(entry.sign_id(), entry.clone());
        }
        Self {
            requests,
            processed_block_height: Some(checkpoint.block_height),
        }
    }
}

#[derive(Debug, Clone)]
struct ExecutionWatcher {
    sign_id: SignId,
    tx: Arc<BidirectionalTx>,
}

#[derive(Debug, Clone, Default)]
struct ExecutionWatchers {
    watchers: HashMap<BidirectionalTxId, ExecutionWatcher>,
}

impl ExecutionWatchers {
    fn insert(
        &mut self,
        tx_id: BidirectionalTxId,
        watcher: ExecutionWatcher,
    ) -> Option<ExecutionWatcher> {
        self.watchers.insert(tx_id, watcher)
    }

    fn remove(&mut self, tx_id: &BidirectionalTxId) -> Option<ExecutionWatcher> {
        self.watchers.remove(tx_id)
    }

    fn all(&self) -> HashMap<BidirectionalTxId, (SignId, Arc<BidirectionalTx>)> {
        self.watchers
            .iter()
            .map(|(id, watcher)| (*id, (watcher.sign_id, Arc::clone(&watcher.tx))))
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
}

impl Default for Backlog {
    fn default() -> Self {
        Self::new()
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
        }
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
    pub async fn insert(&self, request: Arc<IndexedSignRequest>) -> (SignEntry<Generating>, bool) {
        let chain = request.chain;
        let id = request.id;
        let entry = BacklogEntry::new(Arc::clone(&request));
        let (prev, len) = {
            let mut pending = self.pending(&chain).write().await;
            let p = pending.insert(id, entry);
            (p, pending.len())
        };

        let is_new = prev.is_none();
        // Only increment total pending if this is a new entry
        if is_new {
            self.total_pending.fetch_add(1, Ordering::Relaxed);
        }

        self.observe_backlog_size(chain, len);
        (SignEntry::generating(request, self), is_new)
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
        }

        self.observe_backlog_size(chain, len);
        removed
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

    /// Returns backlog requests for a chain that are ready to be published.
    /// Sorted by indexed timestamp and request id.
    pub async fn publishable_requests(&self, chain: Chain) -> Vec<SignEntry<Publishing>> {
        // Read-only scan; the backup sweep calls this every second per chain, so a
        // write lock here would serialize against the signing hot path for nothing.
        let pending = self.pending(&chain).read().await;

        let mut publishable: Vec<_> = pending
            .requests
            .values()
            .filter_map(|entry| {
                let publish = entry.status.publish_state()?;
                Some(SignEntry {
                    chain,
                    request: Arc::clone(entry.request()),
                    state: Publishing(Arc::clone(publish)),
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

    /// Returns all backlog entries currently in destination-chain execution for a specific chain.
    pub async fn pending_executions(
        &self,
        chain: Chain,
    ) -> Vec<SignEntry<Bidirectional<Executing>>> {
        let pending = self.pending(&chain).read().await;
        pending.pending_executions(chain, self)
    }

    /// Returns the number of pending requests for a specific chain
    pub async fn len_by_chain(&self, chain: Chain) -> usize {
        self.pending(&chain).read().await.len()
    }

    /// Begin watching for execution of a bidirectional transaction on the destination chain.
    pub async fn watch_execution(
        &self,
        entry: &SignEntry<Bidirectional<Executing>>,
    ) -> Option<(SignId, Arc<BidirectionalTx>)> {
        let tx = entry.execution_tx();
        let target_chain = tx.target_chain;
        let sign_id = entry.sign_id();
        let mut watchers = self.watchers(&target_chain).write().await;

        watchers
            .insert(
                tx.id,
                ExecutionWatcher {
                    sign_id,
                    tx: Arc::clone(tx),
                },
            )
            .map(|previous| (previous.sign_id, previous.tx))
    }

    /// Stop watching for execution of a bidirectional transaction on the destination chain.
    pub async fn unwatch_execution(
        &self,
        chain: Chain,
        tx_id: &BidirectionalTxId,
    ) -> Option<(SignId, Arc<BidirectionalTx>)> {
        let mut entry = self.watchers(&chain).write().await;

        entry
            .remove(tx_id)
            .map(|watcher| (watcher.sign_id, watcher.tx))
    }

    /// Set the processed block height for a specific chain.
    /// Returns Some(Checkpoint) if a checkpoint should be created and submitted at this block height.
    pub async fn set_processed_block(&self, chain: Chain, height: u64) -> Option<Checkpoint> {
        let interval = chain.checkpoint_interval()?;
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
        if height / interval > prev / interval {
            let tx_count = pending.len();
            drop(pending);
            match self.checkpoint(chain).await {
                Ok(checkpoint) => {
                    tracing::info!(?chain, height, tx_count, ?checkpoint, "creating checkpoint");
                    Some(checkpoint)
                }
                Err(CheckpointError::PendingCap { .. }) => {
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
        } else {
            None
        }
    }

    /// Create a checkpoint of the current backlog state for a specific chain.
    ///
    pub async fn checkpoint(&self, chain: Chain) -> Result<Checkpoint, CheckpointError> {
        let checkpoint = {
            let requests = self.pending(&chain).read().await;
            Checkpoint::snapshot(&requests, chain)
        };
        self.checkpoints.persist_pending(&checkpoint).await?;
        Ok(checkpoint)
    }

    /// Confirm a locally available checkpoint against an on-chain consensus digest.
    ///
    /// Returns `Ok(true)` when the digest matched a local checkpoint and it was
    /// promoted, `Ok(false)` when no local checkpoint matches, and an error when
    /// storage was unavailable.
    pub async fn confirm_consensus(
        &self,
        chain: Chain,
        digest: [u8; 32],
    ) -> Result<bool, CheckpointError> {
        self.checkpoints.confirm(chain, digest).await
    }

    /// Load the durable checkpoint state and return the newest checkpoint.
    pub async fn load_local(&self, chain: Chain) -> anyhow::Result<Option<Checkpoint>> {
        self.checkpoints.load_local(chain).await
    }

    /// Replace the local backlog with a consensus checkpoint after divergence.
    async fn regress(&self, checkpoint: Checkpoint) -> anyhow::Result<()> {
        // Decode the checkpoint before the durable write so a malformed peer
        // checkpoint cannot leave storage regressed while memory stays put.
        let restored = PendingRequests::from_checkpoint(&checkpoint);
        self.checkpoints.regress(&checkpoint).await?;
        self.apply_checkpoint(checkpoint, restored).await;
        Ok(())
    }

    /// Get the latest checkpoint for a specific chain.
    pub async fn latest_checkpoint(&self, chain: Chain) -> Option<Checkpoint> {
        self.checkpoints.latest(chain).await
    }

    /// Check if the chain backlog has an available checkpoint slot.
    pub async fn has_checkpoint_slot(&self, chain: Chain) -> bool {
        self.checkpoints.has_slot(chain).await
    }

    /// Number of pending checkpoints for a chain.
    pub async fn pending_checkpoint_count(&self, chain: Chain) -> usize {
        self.checkpoints.count(chain).await
    }

    #[cfg(test)]
    pub(crate) fn checkpoint_storage(&self) -> &CheckpointStorage {
        self.checkpoints.storage()
    }

    /// Find a checkpoint by its consensus digest.
    pub async fn find_checkpoint_by_digest(
        &self,
        chain: Chain,
        digest: [u8; 32],
    ) -> Option<Checkpoint> {
        self.checkpoints.find(chain, digest).await
    }

    /// Recover backlog state from a checkpoint.
    /// This is called when a node restarts or when it needs to align/regress to consensus.
    pub async fn recover_by_checkpoint(&self, checkpoint: Checkpoint) {
        let restored = PendingRequests::from_checkpoint(&checkpoint);
        self.apply_checkpoint(checkpoint, restored).await;
    }

    /// Apply an already-decoded checkpoint to the backlog.
    async fn apply_checkpoint(&self, checkpoint: Checkpoint, restored: PendingRequests) {
        let chain = checkpoint.chain;
        let checkpoint_height = checkpoint.block_height;
        tracing::info!(
            ?chain,
            height = checkpoint_height,
            num_pending = checkpoint.pending_requests.len(),
            "recovering backlog to checkpoint"
        );

        let execution_to_watch = {
            let mut pending = self.pending(&checkpoint.chain).write().await;
            let previous_height = pending.processed_block_height().unwrap_or(0);

            // Execution watchers are ephemeral, we need to get all the execution watchers here
            let cleared = pending.len();
            let restored_len = restored.len();
            *pending = restored;

            // Update total pending count based on the difference between cleared and restored requests
            self.total_pending.fetch_sub(cleared, Ordering::Relaxed);
            self.total_pending
                .fetch_add(restored_len, Ordering::Relaxed);

            tracing::info!(
                ?chain,
                old_block = previous_height,
                new_block = checkpoint_height,
                cleared_requests = cleared,
                restored_requests = restored_len,
                "successfully recovered from checkpoint"
            );
            pending.pending_executions(chain, self)
        };

        // Clear execution watchers whose source chain is the recovered chain
        for destination_chain in Chain::iter() {
            let mut watchers = self.watchers(&destination_chain).write().await;
            watchers
                .watchers
                .retain(|_, watcher| watcher.tx.source_chain != chain);
        }

        // now repopulate our execution watchers
        for entry in execution_to_watch {
            self.watch_execution(&entry).await;
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
}

/// Errors that can occur when working with Backlog
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BacklogError {
    #[error("request not found for chain {chain:?} with id {id:?}")]
    NotFound { chain: Chain, id: SignId },
    #[error("failed to reconstruct signature")]
    InvalidSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BacklogEntry {
    pub request: Arc<IndexedSignRequest>,
    pub status: SignStatus,
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
        Self { request, status }
    }

    pub fn with_status(request: Arc<IndexedSignRequest>, status: SignStatus) -> Self {
        Self { request, status }
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
                BidirectionalProgress::Initial(_) | BidirectionalProgress::Executing(_),
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
