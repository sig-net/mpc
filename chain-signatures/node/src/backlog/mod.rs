mod checkpoints;
pub mod consensus;

use crate::sign_bidirectional::{PublishState, SignBidirectionalEventExt, SignStatus};
use crate::storage::checkpoint_storage::CheckpointStorage;
pub use checkpoints::{Checkpoint, CheckpointError, Checkpoints};

use anyhow::Context as _;
use enum_map::EnumMap;
use mpc_chain_integration_core::StateManager;
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainConfig as _, IndexedSignRequest, PublicKey,
    SignId, SignKind, Signature,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    fn insert(&mut self, id: SignId, entry: BacklogEntry) -> Option<BacklogEntry> {
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

    fn pending_generations(&self) -> HashMap<SignId, BacklogEntry> {
        self.requests
            .iter()
            .filter(|(_, entry)| entry.status() == SignStatus::PendingGeneration)
            .map(|(id, entry)| (*id, entry.clone()))
            .collect()
    }

    fn pending_generation_bidirectionals(&self) -> HashMap<SignId, BacklogEntry> {
        self.requests
            .iter()
            .filter(|(_, entry)| entry.status() == SignStatus::PendingGenerationBidirectional)
            .map(|(id, entry)| (*id, entry.clone()))
            .collect()
    }

    fn pending_execution(&self, id: &SignId) -> Option<&BacklogEntry> {
        self.requests
            .get(id)
            .filter(|entry| entry.status().is_pending_execution())
    }

    fn pending_executions(&self) -> Vec<(SignId, BacklogEntry)> {
        self.requests
            .iter()
            .filter(|(_, entry)| entry.status().is_pending_execution())
            .map(|(&id, entry)| (id, entry.clone()))
            .collect()
    }

    /// Get the processed block height for this chain
    fn processed_block_height(&self) -> Option<u64> {
        self.processed_block_height
    }

    /// Set the processed block height for this chain
    fn set_processed_block(&mut self, height: u64) {
        self.processed_block_height = Some(height);
    }

    #[cfg(test)]
    fn checkpoint(&self, chain: Chain) -> Checkpoint {
        Checkpoints::snapshot(self, chain)
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
    fn pending(&self, chain: &Chain) -> &RwLock<PendingRequests> {
        &self.requests[*chain]
    }

    /// Get the execution watchers for a specific chain.
    #[inline]
    fn watchers(&self, chain: &Chain) -> &RwLock<ExecutionWatchers> {
        &self.execution_watchers[*chain]
    }

    /// Insert a new Sign request into the backlog for the specified chain.
    pub async fn insert(&self, request: Arc<IndexedSignRequest>) -> Option<BacklogEntry> {
        let chain = request.chain;
        let id = request.id;
        let entry = BacklogEntry::new(request);
        let (prev, len) = {
            let mut pending = self.pending(&chain).write().await;
            let p = pending.insert(id, entry);
            (p, pending.len())
        };

        // Only increment total pending if this is a new entry
        if prev.is_none() {
            self.total_pending.fetch_add(1, Ordering::Relaxed);
        }

        self.observe_backlog_size(chain, len);
        prev
    }

    /// Remove a Sign request from the backlog for the specified chain.
    pub async fn remove(&self, chain: Chain, id: &SignId) -> Option<BacklogEntry> {
        let (removed, len) = {
            let mut pending = self.pending(&chain).write().await;
            let rem = pending.remove(id);
            (rem, pending.len())
        };

        // Only decrement total pending if an entry was actually removed
        if removed.is_some() {
            self.total_pending.fetch_sub(1, Ordering::Relaxed);
        }

        self.observe_backlog_size(chain, len);
        removed
    }

    /// Get a Sign request from the backlog for the specified chain.
    pub async fn get(&self, chain: Chain, id: &SignId) -> Option<BacklogEntry> {
        self.pending(&chain).read().await.get(id).cloned()
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
    pub async fn take_requeueable_requests(&self, chain: Chain) -> Vec<Arc<IndexedSignRequest>> {
        let pending = self.pending(&chain).write().await;

        let mut requeueable: Vec<_> = pending
            .requests
            .values()
            .filter(|entry| entry.status().is_pending_generation())
            .map(|entry| Arc::clone(&entry.request))
            .collect();

        requeueable.sort_by(|left, right| {
            left.unix_timestamp_indexed
                .cmp(&right.unix_timestamp_indexed)
                .then_with(|| left.id.request_id.cmp(&right.id.request_id))
        });

        requeueable
    }

    /// Returns backlog requests for a chain that are ready to be published, each
    /// with whether this node already dispatched a publish for it.
    /// Sorted by indexed timestamp and request id.
    pub async fn publishable_requests(
        &self,
        chain: Chain,
    ) -> Vec<(Arc<IndexedSignRequest>, Arc<PublishState>, bool)> {
        // Read-only scan; the publish failover sweep calls this on every block, so a
        // write lock here would serialize against the signing hot path for nothing.
        let pending = self.pending(&chain).read().await;

        let mut publishable: Vec<_> = pending
            .requests
            .values()
            .filter_map(|entry| match &entry.status {
                SignStatus::PendingPublish { publish }
                | SignStatus::PendingPublishBidirectional { publish } => Some((
                    Arc::clone(&entry.request),
                    Arc::clone(publish),
                    entry.publish_dispatched,
                )),
                _ => None,
            })
            .collect();

        publishable.sort_by(|left, right| {
            left.0
                .unix_timestamp_indexed
                .cmp(&right.0.unix_timestamp_indexed)
                .then_with(|| left.0.id.request_id.cmp(&right.0.id.request_id))
        });

        publishable
    }

    /// Returns backlog requests for a chain that are still pending generation
    pub async fn pending_generations(&self, chain: Chain) -> HashMap<SignId, BacklogEntry> {
        self.pending(&chain).read().await.pending_generations()
    }

    /// Returns backlog requests for a chain that are still pending generation for bidirectional transactions
    pub async fn pending_generation_bidirectionals(
        &self,
        chain: Chain,
    ) -> HashMap<SignId, BacklogEntry> {
        self.pending(&chain)
            .read()
            .await
            .pending_generation_bidirectionals()
    }

    /// Returns backlog entries that are pending execution for a given chain and request id
    pub async fn pending_execution(&self, chain: Chain, id: &SignId) -> Option<BacklogEntry> {
        self.pending(&chain)
            .read()
            .await
            .pending_execution(id)
            .cloned()
    }

    /// Returns the number of pending requests for a specific chain
    pub async fn len_by_chain(&self, chain: Chain) -> usize {
        self.pending(&chain).read().await.len()
    }

    /// Marks a request as publishing for a specific chain and request id, with the given publish state.
    pub async fn mark_publishing(
        &self,
        chain: Chain,
        id: &SignId,
        publish: Arc<PublishState>,
    ) -> Result<(), BacklogError> {
        let mut pending = self.pending(&chain).write().await;

        let Some(entry) = pending.requests.get_mut(id) else {
            return Err(BacklogError::NotFound { chain, id: *id });
        };

        entry.mark_publishing(publish)
    }

    /// Record that this node dispatched a publish for `id`'s current
    /// pending-publish episode, returning `false` if one was already dispatched or
    /// the entry is gone.
    pub async fn mark_publish_dispatched(&self, chain: Chain, id: &SignId) -> bool {
        let mut pending = self.pending(&chain).write().await;

        pending
            .requests
            .get_mut(id)
            .is_some_and(BacklogEntry::mark_publish_dispatched)
    }

    // TODO: the backlog is a bit bloated with transition functions, so we need to do a proper cleanup
    // where we can have proper typestate on a set of types. With these types, we can easily guide
    // ourselves into the right transitions. For now, this is used to set the request in
    // `execution_confirmed` to transition from PendingExecution to PendingGenerationBidirectional.
    //
    // Test-only: production transitions go through the checked helpers above, which keep
    // request kind and status paired. `test-feature` is what exposes this to
    // `integration-tests`; a bare `cfg(test)` would not.
    #[cfg(any(test, feature = "test-feature"))]
    pub async fn set_request(
        &self,
        chain: Chain,
        id: &SignId,
        request: Arc<IndexedSignRequest>,
    ) -> Result<(), BacklogError> {
        let mut pending = self.pending(&chain).write().await;

        let Some(entry) = pending.requests.get_mut(id) else {
            return Err(BacklogError::NotFound { chain, id: *id });
        };
        entry.set_request(request);
        Ok(())
    }

    /// Atomically move a completed target-chain execution into final response signing.
    pub async fn transition_to_bidirectional_response(
        &self,
        chain: Chain,
        id: &SignId,
        request: Arc<IndexedSignRequest>,
    ) -> Result<BacklogEntry, BacklogError> {
        let mut pending = self.pending(&chain).write().await;

        let entry = pending
            .requests
            .get_mut(id)
            .ok_or(BacklogError::NotFound { chain, id: *id })?;
        entry.transition_to_bidirectional_response(request)?;
        Ok(entry.clone())
    }

    /// Begin watching for execution of a bidirectional transaction on the destination chain.
    ///
    /// The watcher's `sign_id` and `tx.request_id` are expected to agree: on
    /// confirmation the final-response request is rebuilt from `tx.request_id` while
    /// the backlog entry is looked up by `sign_id`, and
    /// `BacklogEntry::transition_to_bidirectional_response` rejects the pair when they
    /// disagree. Warn here, where the divergence originates, rather than leaving only
    /// a stalled request at confirmation time.
    pub async fn watch_execution(
        &self,
        chain: Chain,
        sign_id: SignId,
        tx: Arc<BidirectionalTx>,
    ) -> Option<(SignId, Arc<BidirectionalTx>)> {
        if sign_id != SignId::new(tx.request_id) {
            tracing::warn!(
                ?chain,
                ?sign_id,
                request_id = ?SignId::new(tx.request_id),
                tx_id = ?tx.id,
                "execution watcher sign_id disagrees with tx request_id; the final \
                 response transition will be rejected for this request"
            );
        }

        let mut entry = self.watchers(&chain).write().await;

        entry
            .insert(tx.id, ExecutionWatcher { sign_id, tx })
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

    /// Update the status of a tracked bidirectional transaction on the source chain.
    ///
    /// Test-only; see the note on [`Backlog::set_request`].
    #[cfg(any(test, feature = "test-feature"))]
    pub async fn set_status(
        &self,
        chain: Chain,
        id: &SignId,
        status: SignStatus,
    ) -> Option<BacklogEntry> {
        let mut pending = self.pending(&chain).write().await;

        let Some(entry) = pending.requests.get_mut(id) else {
            tracing::warn!(
                ?chain,
                ?id,
                ?status,
                "set_status: tx id not found in chain pending requests"
            );
            return None;
        };
        tracing::info!(?chain, ?id, before = ?entry.status(), after = ?status, "set_status: updating");
        entry.set_status(status);
        Some(entry.clone())
    }

    /// Advances a `Sign` transaction to its execution phase and register execution watcher.
    /// This is called after the protocol generates the signature for a SignBidirectional request.
    pub async fn advance(
        &self,
        chain: Chain,
        sign_id: SignId,
        bidirectional_tx: Arc<BidirectionalTx>,
    ) -> Result<(), BacklogError> {
        // Update the transaction in the backlog from Sign to Bidirectional
        let mut pending = self.pending(&chain).write().await;

        let entry = pending
            .requests
            .get_mut(&sign_id)
            .ok_or(BacklogError::NotFound { chain, id: sign_id })?;

        entry.advance_to_execution(Arc::clone(&bidirectional_tx))?;

        // Registration successful, now register the execution watcher on the target chain
        let target_chain = bidirectional_tx.target_chain;
        drop(pending);
        self.watch_execution(target_chain, sign_id, bidirectional_tx)
            .await;
        Ok(())
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
    pub async fn hydrate(&self, chain: Chain) -> Result<Option<Checkpoint>, CheckpointError> {
        self.checkpoints.hydrate(chain).await?;
        self.recover_local(chain).await
    }

    /// Recovers local backlog state from the latest durable checkpoint if one exists.
    pub async fn recover_local(&self, chain: Chain) -> Result<Option<Checkpoint>, CheckpointError> {
        let Some(checkpoint) = self.checkpoints.latest(chain).await? else {
            return Ok(None);
        };
        self.recover_by_checkpoint(&checkpoint).await;
        Ok(Some(checkpoint))
    }

    /// Replace the local backlog with a consensus checkpoint after divergence:
    /// resets durable storage to consensus, zeroes pending counts, and restores in-memory state.
    pub async fn regress(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointError> {
        self.checkpoints.regress(checkpoint).await?;
        self.recover_by_checkpoint(checkpoint).await;
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
            pending.pending_executions()
        };

        // Clear execution watchers whose source chain is the recovered chain
        for destination_chain in Chain::iter() {
            let mut watchers = self.watchers(&destination_chain).write().await;
            watchers
                .watchers
                .retain(|_, watcher| watcher.tx.source_chain != chain);
        }

        // Repopulate our execution watchers
        for (sign_id, entry) in execution_to_watch {
            // Only restore execution watchers for bidirectional transactions
            if let Some(tx) = entry.execution_tx().cloned() {
                self.watch_execution(tx.target_chain, sign_id, tx).await;
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
}

/// Errors that can occur when working with Backlog
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BacklogError {
    #[error("request not found for chain {chain:?} with id {id:?}")]
    NotFound { chain: Chain, id: SignId },
    #[error("chain not initialized: {chain:?}")]
    ChainNotInitialized { chain: Chain },
    #[error("transaction not found")]
    TransactionNotFound,
    #[error("cannot advance sign request: status must be pending generation or publishing")]
    InvalidAdvanceTransition,
    #[error("cannot mark publishing: status must be pending generation")]
    InvalidPublishingTransition,
    #[error("cannot transition to bidirectional response: id must match and request must be RespondBidirectional")]
    InvalidBidirectionalResponseTransition,
}

#[derive(Debug, Clone, Eq, serde::Serialize, serde::Deserialize)]
pub struct BacklogEntry {
    pub request: Arc<IndexedSignRequest>,
    pub status: SignStatus,
    /// Whether this node has dispatched a publish for this entry. Node-local, so it
    /// is not serialized, and checkpoint recovery resets it.
    #[serde(skip)]
    publish_dispatched: bool,
}

/// Node-local state is not part of an entry's identity to avoid divergence.
impl PartialEq for BacklogEntry {
    fn eq(&self, other: &Self) -> bool {
        self.request == other.request && self.status == other.status
    }
}

impl BacklogEntry {
    pub fn new(request: Arc<IndexedSignRequest>) -> Self {
        Self::with_status(request, SignStatus::PendingGeneration)
    }

    pub fn with_status(request: Arc<IndexedSignRequest>, status: SignStatus) -> Self {
        Self {
            request,
            status,
            publish_dispatched: false,
        }
    }

    pub fn pending_execution(request: Arc<IndexedSignRequest>, tx: Arc<BidirectionalTx>) -> Self {
        Self::with_status(request, SignStatus::PendingExecution { tx })
    }

    pub fn sign_id(&self) -> SignId {
        self.request.id
    }

    /// Check that a respond event's signature is the one this entry asked for.
    pub fn verify_signature(
        &self,
        root_public_key: PublicKey,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        mpc_crypto::verify_signature(
            root_public_key,
            self.request.args.epsilon,
            self.request.args.payload,
            signature,
        )
        .with_context(|| {
            format!(
                "respond event carried invalid signature for sign id {:?}",
                self.sign_id()
            )
        })
    }

    /// Get the request ID for this transaction
    pub fn request_id(&self) -> [u8; 32] {
        self.request.id.request_id
    }

    /// Get the source chain for this transaction
    pub fn source_chain(&self) -> Chain {
        self.request.chain
    }

    /// Get the status of this transaction
    pub fn status(&self) -> SignStatus {
        self.status.clone()
    }

    /// The single place a status is assigned. Every transition ends the current
    /// pending-publish episode, so no dispatch flag may survive one.
    fn enter_status(&mut self, status: SignStatus) {
        self.status = status;
        self.publish_dispatched = false;
    }

    /// Record that this node dispatched a publish for the current episode,
    /// returning `false` if one was already dispatched.
    fn mark_publish_dispatched(&mut self) -> bool {
        !std::mem::replace(&mut self.publish_dispatched, true)
    }

    /// Set the status of this transaction
    ///
    /// Test-only; see the note on [`Backlog::set_request`].
    #[cfg(any(test, feature = "test-feature"))]
    pub fn set_status(&mut self, status: SignStatus) {
        self.enter_status(status);
    }

    /// Test-only; see the note on [`Backlog::set_request`].
    #[cfg(any(test, feature = "test-feature"))]
    pub fn set_request(&mut self, request: Arc<IndexedSignRequest>) {
        self.request = request;
    }

    /// Rewrite this entry into the final-response request produced by a confirmed
    /// target-chain execution.
    ///
    /// Rejects a request whose id differs from this entry's. Callers look the entry
    /// up by `SignId`, so accepting a mismatch would leave `request.id` disagreeing
    /// with the key it is stored under, and `checkpoint` commits to the key while
    /// diagnostics report the id. `Backlog::watch_execution` warns when the two
    /// identifiers diverge, which is the only way to reach this rejection.
    fn transition_to_bidirectional_response(
        &mut self,
        request: Arc<IndexedSignRequest>,
    ) -> Result<(), BacklogError> {
        if self.request.id != request.id
            || !matches!(&request.kind, SignKind::RespondBidirectional(_))
        {
            return Err(BacklogError::InvalidBidirectionalResponseTransition);
        }

        self.request = request;
        self.enter_status(SignStatus::PendingGenerationBidirectional);
        Ok(())
    }

    pub fn mark_publishing(&mut self, publish: Arc<PublishState>) -> Result<(), BacklogError> {
        match (&self.request.kind, &self.status) {
            (SignKind::Sign | SignKind::SignBidirectional(_), SignStatus::PendingGeneration) => {
                self.enter_status(SignStatus::PendingPublish { publish });
                Ok(())
            }
            (SignKind::RespondBidirectional(_), SignStatus::PendingGenerationBidirectional) => {
                self.enter_status(SignStatus::PendingPublishBidirectional { publish });
                Ok(())
            }
            _ => Err(BacklogError::InvalidPublishingTransition),
        }
    }

    pub fn advance_to_execution(
        &mut self,
        bidirectional_tx: Arc<BidirectionalTx>,
    ) -> Result<(), BacklogError> {
        match (&self.request.kind, self.status.clone()) {
            (
                SignKind::SignBidirectional(_),
                SignStatus::PendingGeneration | SignStatus::PendingPublish { .. },
            ) => {
                self.enter_status(SignStatus::PendingExecution {
                    tx: bidirectional_tx,
                });
                Ok(())
            }
            _ => Err(BacklogError::InvalidAdvanceTransition),
        }
    }

    /// Get target chain if this is a bidirectional transaction
    // TODO: looks a bit weird having two different ways to get target_chain in the match
    pub fn target_chain(&self) -> Option<Chain> {
        match &self.request.kind {
            SignKind::Sign => None,
            SignKind::SignBidirectional(event) => self
                .execution_tx()
                .map(|tx| tx.target_chain)
                .or_else(|| event.target_chain().ok()),
            SignKind::RespondBidirectional(_) => None,
        }
    }

    /// Check if this is a bidirectional transaction
    pub fn is_bidirectional(&self) -> bool {
        matches!(self.request.kind, SignKind::SignBidirectional(_))
    }

    pub fn execution_tx(&self) -> Option<&Arc<BidirectionalTx>> {
        self.status.execution_tx()
    }

    pub fn typename(&self) -> &'static str {
        match (&self.request.kind, &self.status) {
            (SignKind::Sign, _) => "Sign",
            (SignKind::SignBidirectional(_), SignStatus::PendingExecution { .. }) => {
                "BidirectionalExecution"
            }
            (SignKind::SignBidirectional(_), SignStatus::PendingGeneration) => {
                "BidirectionalPending"
            }
            (SignKind::SignBidirectional(_), _) => "BidirectionalPending",
            (SignKind::RespondBidirectional(_), SignStatus::PendingGenerationBidirectional) => {
                "BidirectionalRespondPending"
            }
            (SignKind::RespondBidirectional(_), _) => "RespondBidirectional",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_bidirectional::{PublishState, SignStatus};
    use alloy::primitives::{Address, B256};
    use cait_sith::protocol::Participant;
    use k256::{AffinePoint, Scalar};
    use mpc_chain_solana::Pubkey;
    use mpc_primitives::{
        BidirectionalTx, BidirectionalTxId, RespondBidirectionalTx, SignArgs,
        SignBidirectionalEvent, SignId, SignKind,
    };
    use std::convert::TryInto;

    fn digest_hex(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str)
            .unwrap()
            .try_into()
            .expect("digest hex must be 32 bytes")
    }

    fn test_signature() -> mpc_primitives::Signature {
        mpc_primitives::Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0)
    }

    fn test_publish_state(is_proposer: bool) -> Arc<PublishState> {
        Arc::new(PublishState::new(
            test_signature(),
            vec![Participant::from(0u32), Participant::from(1u32)],
            is_proposer,
        ))
    }

    fn pending_execution_status(tx: &BidirectionalTx) -> SignStatus {
        SignStatus::PendingExecution {
            tx: Arc::new(tx.clone()),
        }
    }

    fn create_test_tx(id: u8) -> BidirectionalTx {
        BidirectionalTx {
            id: BidirectionalTxId(B256::from([id; 32]).0),
            sender: [0u8; 32],
            serialized_transaction: vec![1, 2, 3],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 1,
            deposit: 1000,
            path: "test_path".to_string(),
            algo: "ECDSA".to_string(),
            dest: "0x1234567890123456789012345678901234567890".to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: [id; 32],
            from_address: **Address::ZERO,
            nonce: 0,
        }
    }

    fn create_test_event(dest: &str) -> SignBidirectionalEvent {
        let mut program_id = [0u8; 32];
        let prefix_len = dest.len().min(program_id.len());
        program_id[..prefix_len].copy_from_slice(&dest.as_bytes()[..prefix_len]);

        SignBidirectionalEvent {
            sender: Default::default(),
            serialized_transaction: vec![],
            dest: dest.to_string(),
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 0,
            deposit: 0,
            path: "".to_string(),
            algo: "".to_string(),
            params: "".to_string(),
            chain: Chain::Solana,
            chain_ctx: Some(program_id.to_vec()),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        }
    }

    fn create_test_args(id: u8) -> SignArgs {
        SignArgs {
            entropy: [id; 32],
            epsilon: k256::Scalar::from(1u64),
            payload: k256::Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        }
    }

    fn create_indexed_request(
        sign_id: SignId,
        chain: Chain,
        args: SignArgs,
        kind: SignKind,
        unix_timestamp_indexed: u64,
    ) -> Arc<IndexedSignRequest> {
        Arc::new(IndexedSignRequest::new(
            sign_id,
            args,
            chain,
            unix_timestamp_indexed,
            kind,
        ))
    }

    fn create_bidirectional_request(
        sign_id: SignId,
        chain: Chain,
        dest: &str,
        unix_timestamp_indexed: u64,
    ) -> Arc<IndexedSignRequest> {
        Arc::new(IndexedSignRequest::sign_bidirectional(
            sign_id,
            create_test_args(sign_id.request_id[0]),
            chain,
            unix_timestamp_indexed,
            create_test_event(dest),
        ))
    }

    fn create_execution_entry(
        tx: BidirectionalTx,
        chain: Chain,
        status: SignStatus,
        dest: &str,
    ) -> BacklogEntry {
        create_execution_entry_with_timestamp(tx, chain, status, dest, 0)
    }

    fn create_execution_entry_with_timestamp(
        tx: BidirectionalTx,
        chain: Chain,
        status: SignStatus,
        dest: &str,
        unix_timestamp_indexed: u64,
    ) -> BacklogEntry {
        let sign_id = SignId::new(tx.request_id);
        let request = Arc::new(IndexedSignRequest::new(
            sign_id,
            create_test_args(tx.request_id[0]),
            chain,
            unix_timestamp_indexed,
            SignKind::SignBidirectional(create_test_event(dest)),
        ));

        match status {
            SignStatus::PendingExecution { .. } => {
                BacklogEntry::pending_execution(request, Arc::new(tx))
            }
            status => BacklogEntry::with_status(request, status),
        }
    }

    /// Builds a checkpoint for a chain with exactly one backlog entry at height 100.
    fn single_entry_checkpoint(entry: BacklogEntry) -> Checkpoint {
        let mut pending = PendingRequests::new();
        pending.insert(entry.sign_id(), entry);
        pending.set_processed_block(100);
        pending.checkpoint(Chain::Ethereum)
    }

    async fn insert_bidirectional_with_status(
        backlog: &Backlog,
        chain: Chain,
        tx: BidirectionalTx,
        status: SignStatus,
        dest: &str,
    ) {
        let sign_id = SignId::new(tx.request_id);
        backlog
            .insert(create_bidirectional_request(sign_id, chain, dest, 0))
            .await;

        match status {
            SignStatus::PendingGeneration => {}
            SignStatus::PendingGenerationBidirectional => {
                let completion_request = IndexedSignRequest::respond_bidirectional(
                    sign_id,
                    create_test_args(sign_id.request_id[0]),
                    chain,
                    0,
                    RespondBidirectionalTx {
                        tx_id: tx.id,
                        output: vec![],
                        chain_ctx: None,
                    },
                );
                backlog
                    .set_request(chain, &sign_id, Arc::new(completion_request))
                    .await
                    .unwrap();
                backlog
                    .set_status(chain, &sign_id, SignStatus::PendingGenerationBidirectional)
                    .await;
            }
            SignStatus::PendingPublish { .. } => {
                backlog.set_status(chain, &sign_id, status).await;
            }
            SignStatus::PendingExecution { .. } => {
                backlog
                    .set_status(
                        chain,
                        &sign_id,
                        SignStatus::PendingPublish {
                            publish: test_publish_state(true),
                        },
                    )
                    .await;
                backlog.advance(chain, sign_id, Arc::new(tx)).await.unwrap();
            }
            SignStatus::PendingPublishBidirectional { .. } => {
                let completion_request = IndexedSignRequest::respond_bidirectional(
                    sign_id,
                    create_test_args(sign_id.request_id[0]),
                    chain,
                    0,
                    RespondBidirectionalTx {
                        tx_id: tx.id,
                        output: vec![],
                        chain_ctx: None,
                    },
                );
                backlog
                    .set_request(chain, &sign_id, Arc::new(completion_request))
                    .await
                    .unwrap();
                backlog.set_status(chain, &sign_id, status).await;
            }
        }
    }

    #[tokio::test]
    async fn test_backlog_chain_isolation() {
        let backlog = Backlog::new();

        let tx_eth = create_test_tx(1);
        let tx_sol = create_test_tx(2);
        let tx_near = create_test_tx(3);

        let sign_id_eth = SignId::new(tx_eth.request_id);
        let sign_id_sol = SignId::new(tx_sol.request_id);
        let sign_id_near = SignId::new(tx_near.request_id);

        // Insert into different chains
        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx_eth.clone(),
            SignStatus::PendingGeneration,
            "ethereum",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::Solana,
            tx_sol.clone(),
            SignStatus::PendingGeneration,
            "solana",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::NEAR,
            tx_near.clone(),
            SignStatus::PendingGeneration,
            "near",
        )
        .await;

        // Verify correct transactions in each chain
        assert!(backlog.get(Chain::Ethereum, &sign_id_eth).await.is_some());
        assert!(backlog.get(Chain::Ethereum, &sign_id_sol).await.is_none());
        assert!(backlog.get(Chain::Solana, &sign_id_sol).await.is_some());
        assert!(backlog.get(Chain::Solana, &sign_id_eth).await.is_none());
        assert!(backlog.get(Chain::NEAR, &sign_id_near).await.is_some());
        assert!(backlog.get(Chain::NEAR, &sign_id_eth).await.is_none());
    }

    #[tokio::test]
    async fn test_backlog_filter_by_status() {
        let backlog = Backlog::new();

        // Add transactions with different statuses to Ethereum
        let tx0 = create_test_tx(0);
        let tx1 = create_test_tx(1);
        let tx2 = create_test_tx(2);
        let tx3 = create_test_tx(3);

        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx1,
            SignStatus::PendingGeneration,
            "ethereum",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx2,
            SignStatus::PendingGenerationBidirectional,
            "ethereum",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx3.clone(),
            pending_execution_status(&tx3),
            "ethereum",
        )
        .await;

        // Add transactions to Solana
        let tx4 = create_test_tx(4);
        insert_bidirectional_with_status(
            &backlog,
            Chain::Solana,
            tx4.clone(),
            pending_execution_status(&tx4),
            "solana",
        )
        .await;

        // Filter Ethereum by Pending
        let eth_pending = backlog
            .pending_execution(Chain::Ethereum, &SignId::new(tx3.request_id))
            .await;
        assert!(eth_pending.is_some());

        let eth_awaiting = backlog.pending_generations(Chain::Ethereum).await;
        assert_eq!(eth_awaiting.len(), 1);

        // Filter Ethereum by bidirectional completion awaiting final respond
        let eth_completion = backlog
            .pending_generation_bidirectionals(Chain::Ethereum)
            .await;
        assert_eq!(eth_completion.len(), 1);

        // Filter Solana by Pending
        let sol_pending = backlog
            .pending_execution(Chain::Solana, &SignId::new(tx4.request_id))
            .await;
        assert!(sol_pending.is_some());

        // Filter non-existent chain returns empty
        let near_pending = backlog
            .pending_execution(Chain::NEAR, &SignId::new(tx0.request_id))
            .await;
        assert!(near_pending.is_none());
    }

    #[tokio::test]
    async fn test_backlog_concurrent_access() {
        let backlog = Backlog::new();
        let mut handles = vec![];

        // Spawn multiple tasks that insert concurrently to different chains
        for i in 0..5 {
            let backlog = backlog.clone();
            let handle = tokio::spawn(async move {
                let tx = create_test_tx(i);
                insert_bidirectional_with_status(
                    &backlog,
                    Chain::Ethereum,
                    tx,
                    SignStatus::PendingGeneration,
                    "ethereum",
                )
                .await;
            });
            handles.push(handle);
        }

        for i in 5..10 {
            let backlog = backlog.clone();
            let handle = tokio::spawn(async move {
                let tx = create_test_tx(i);
                insert_bidirectional_with_status(
                    &backlog,
                    Chain::Solana,
                    tx,
                    SignStatus::PendingGeneration,
                    "solana",
                )
                .await;
            });
            handles.push(handle);
        }

        // Wait for all insertions and verify all were inserted
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(backlog.len_by_chain(Chain::Ethereum).await, 5);
        assert_eq!(backlog.len_by_chain(Chain::Solana).await, 5);

        // Spawn multiple tasks that remove concurrently
        let mut handles = vec![];
        for i in 0..5 {
            let backlog = backlog.clone();
            let handle = tokio::spawn(async move {
                let id = SignId::new([i; 32]);
                backlog.remove(Chain::Ethereum, &id).await
            });
            handles.push(handle);
        }

        // Wait for all removals
        for handle in handles {
            let removed = handle.await.unwrap();
            assert!(removed.is_some());
        }

        // Verify Ethereum chain is now empty, but Solana still has data
        assert_eq!(backlog.len_by_chain(Chain::Ethereum).await, 0);
        assert_eq!(backlog.len_by_chain(Chain::Solana).await, 5);
    }

    #[tokio::test]
    async fn test_checkpoint_creation() {
        let backlog = Backlog::new();

        // Add some transactions
        let tx1 = create_test_tx(1);
        let tx2 = create_test_tx(2);

        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx1.clone(),
            pending_execution_status(&tx1),
            "ethereum",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx2.clone(),
            SignStatus::PendingGenerationBidirectional,
            "ethereum",
        )
        .await;

        backlog
            .set_processed_block(Chain::Ethereum, 100)
            .await
            .unwrap();

        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();
        assert_eq!(checkpoint.block_height, 100);
        assert_eq!(checkpoint.chain, Chain::Ethereum);
        assert_eq!(checkpoint.pending_requests.len(), 2);
        // Guard the checkpoint digest wire format; update only for intentional changes.
        assert_eq!(
            checkpoint.digest(),
            digest_hex("884b11ef5550724b788b7e29e9a07e7a6fd46f94d604e6d38bae71a36816b65e")
        );
    }

    #[tokio::test]
    async fn test_checkpoint_equality() {
        let tx1 = create_test_tx(1);
        let tx2 = create_test_tx(2);
        let mut pending1 = PendingRequests::new();
        pending1.insert(
            SignId::new(tx1.request_id),
            create_execution_entry(
                tx1.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            ),
        );
        pending1.insert(
            SignId::new(tx2.request_id),
            create_execution_entry(
                tx2.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            ),
        );
        pending1.set_processed_block(100);

        let mut pending2 = PendingRequests::new();
        pending2.insert(
            SignId::new(tx1.request_id),
            create_execution_entry(
                tx1.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            ),
        );
        pending2.insert(
            SignId::new(tx2.request_id),
            create_execution_entry(
                tx2.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            ),
        );
        pending2.set_processed_block(100);

        let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
        let checkpoint2 = pending2.checkpoint(Chain::Ethereum);
        // Same data should be equal
        assert_eq!(checkpoint1, checkpoint2);
        assert_eq!(checkpoint1.digest(), checkpoint2.digest());

        // Different block height should not be equal
        let mut checkpoint3 = pending2.checkpoint(Chain::Ethereum);
        checkpoint3.block_height = 101;
        assert_ne!(checkpoint1, checkpoint3);
    }

    #[test]
    fn test_checkpoint_consensus_projection() {
        let tx = create_test_tx(60);
        let sign_id = SignId::new(tx.request_id);

        // The digest commits only to the consensus projection of each entry's
        // status (sorted by sign_id), not to the request or publish content.

        // Initial source-chain phase: generation, and publishing by any proposer,
        // all collapse to a single digest.
        let generation = single_entry_checkpoint(create_execution_entry(
            tx.clone(),
            Chain::Ethereum,
            SignStatus::PendingGeneration,
            "ethereum",
        ));
        let publish = single_entry_checkpoint(create_execution_entry(
            tx.clone(),
            Chain::Ethereum,
            SignStatus::PendingPublish {
                publish: test_publish_state(true),
            },
            "ethereum",
        ));
        let publish_other = single_entry_checkpoint(create_execution_entry(
            tx.clone(),
            Chain::Ethereum,
            SignStatus::PendingPublish {
                publish: test_publish_state(false),
            },
            "ethereum",
        ));
        assert_eq!(generation.digest(), publish.digest());
        assert_eq!(generation.digest(), publish_other.digest());

        // Plain `Sign` requests follow the same initial-phase projection.
        let plain = create_indexed_request(
            sign_id,
            Chain::Ethereum,
            create_test_args(60),
            SignKind::Sign,
            0,
        );
        let plain_generation = single_entry_checkpoint(BacklogEntry::new(Arc::clone(&plain)));
        let plain_publish = single_entry_checkpoint(BacklogEntry::with_status(
            plain,
            SignStatus::PendingPublish {
                publish: test_publish_state(true),
            },
        ));
        assert_eq!(plain_generation.digest(), plain_publish.digest());

        // Post-initial phase: awaiting target-chain execution and the final
        // response generation/publish states are not observable at the
        // source-chain checkpoint height, so they share the checkpoint digest.
        let execution = single_entry_checkpoint(create_execution_entry(
            tx.clone(),
            Chain::Ethereum,
            pending_execution_status(&tx),
            "ethereum",
        ));
        let response_request = IndexedSignRequest::respond_bidirectional(
            sign_id,
            create_test_args(sign_id.request_id[0]),
            Chain::Ethereum,
            0,
            RespondBidirectionalTx {
                tx_id: tx.id,
                output: vec![],
                chain_ctx: None,
            },
        );
        let gen_bidirectional = single_entry_checkpoint(BacklogEntry::with_status(
            Arc::new(response_request.clone()),
            SignStatus::PendingGenerationBidirectional,
        ));
        let pub_bidirectional = single_entry_checkpoint(BacklogEntry::with_status(
            Arc::new(response_request),
            SignStatus::PendingPublishBidirectional {
                publish: test_publish_state(true),
            },
        ));
        assert_eq!(
            execution.digest(),
            gen_bidirectional.digest(),
            "PendingExecution must yield the same checkpoint digest as the final response generation state"
        );
        assert_eq!(
            execution.digest(),
            pub_bidirectional.digest(),
            "PendingExecution must yield the same checkpoint digest as the final response publish state"
        );

        // The initial source-chain phase is observable at this height and must
        // still differ from the post-initial phase.
        assert_ne!(
            generation.digest(),
            execution.digest(),
            "the initial source-chain phase must remain distinct in the checkpoint"
        );
    }

    #[test]
    fn test_transition_to_bidirectional_response_updates_entry_atomically() {
        let tx = create_test_tx(23);
        let sign_id = SignId::new(tx.request_id);
        let mut entry = create_execution_entry(
            tx.clone(),
            Chain::Ethereum,
            pending_execution_status(&tx),
            "ethereum",
        );
        let response_request = IndexedSignRequest::respond_bidirectional(
            sign_id,
            create_test_args(23),
            Chain::Ethereum,
            0,
            RespondBidirectionalTx {
                tx_id: tx.id,
                output: vec![],
                chain_ctx: None,
            },
        );

        entry
            .transition_to_bidirectional_response(Arc::new(response_request))
            .unwrap();

        assert!(matches!(
            entry.request.kind,
            SignKind::RespondBidirectional(_)
        ));
        assert_eq!(entry.status(), SignStatus::PendingGenerationBidirectional);
    }

    #[test]
    fn test_transition_to_bidirectional_response_rejects_mismatched_request_id() {
        let tx = create_test_tx(24);
        let original_sign_id = SignId::new(tx.request_id);
        let mut entry = create_execution_entry(
            tx.clone(),
            Chain::Ethereum,
            pending_execution_status(&tx),
            "ethereum",
        );
        let response_request = IndexedSignRequest::respond_bidirectional(
            SignId::new([25; 32]),
            create_test_args(25),
            Chain::Ethereum,
            0,
            RespondBidirectionalTx {
                tx_id: tx.id,
                output: vec![],
                chain_ctx: None,
            },
        );

        let err = entry
            .transition_to_bidirectional_response(Arc::new(response_request))
            .unwrap_err();

        assert!(matches!(
            err,
            BacklogError::InvalidBidirectionalResponseTransition
        ));
        assert_eq!(entry.sign_id(), original_sign_id);
        assert!(matches!(
            entry.status(),
            SignStatus::PendingExecution { .. }
        ));
    }

    #[tokio::test]
    async fn test_checkpoint_digest_ignores_timestamp() {
        let tx = create_test_tx(8);

        let entry1 = create_execution_entry_with_timestamp(
            tx.clone(),
            Chain::Ethereum,
            SignStatus::PendingGeneration,
            "ethereum",
            1000,
        );
        let entry2 = create_execution_entry_with_timestamp(
            tx.clone(),
            Chain::Ethereum,
            SignStatus::PendingGeneration,
            "ethereum",
            9999,
        );

        let mut pending1 = PendingRequests::new();
        pending1.insert(SignId::new(tx.request_id), entry1);
        pending1.set_processed_block(200);

        let mut pending2 = PendingRequests::new();
        pending2.insert(SignId::new(tx.request_id), entry2);
        pending2.set_processed_block(200);

        let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
        let checkpoint2 = pending2.checkpoint(Chain::Ethereum);

        assert_eq!(checkpoint1.digest(), checkpoint2.digest());
    }

    #[tokio::test]
    async fn test_checkpoint_digest_differs_for_different_requests() {
        let tx1 = create_test_tx(10);
        let tx2 = create_test_tx(11);

        let mut pending1 = PendingRequests::new();
        pending1.insert(
            SignId::new(tx1.request_id),
            create_execution_entry(
                tx1.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            ),
        );
        pending1.set_processed_block(100);

        let mut pending2 = PendingRequests::new();
        pending2.insert(
            SignId::new(tx2.request_id),
            create_execution_entry(
                tx2.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            ),
        );
        pending2.set_processed_block(100);

        let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
        let checkpoint2 = pending2.checkpoint(Chain::Ethereum);

        assert_ne!(checkpoint1.digest(), checkpoint2.digest());
        assert_eq!(
            checkpoint1.digest(),
            digest_hex("a31e0d66f5b4fb860cc62e809cc29918b9138550b5cd62e1c752fc40ce6c2779")
        );
    }

    #[tokio::test]
    async fn test_checkpoint_serialization() {
        let tx1 = create_test_tx(1);

        let mut pending = PendingRequests::new();
        pending.insert(
            SignId::new(tx1.request_id),
            create_execution_entry(
                tx1.clone(),
                Chain::Ethereum,
                pending_execution_status(&tx1),
                "ethereum",
            ),
        );
        pending.set_processed_block(100);
        let checkpoint = pending.checkpoint(Chain::Ethereum);

        // Test JSON serialization
        let json = serde_json::to_string(&checkpoint).unwrap();
        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(checkpoint, deserialized);
        // Guard the checkpoint digest wire format; update only for intentional changes.
        assert_eq!(
            checkpoint.digest(),
            digest_hex("12f5bc5c4f0fea1debafceb8879644ea545309775b3e2cc266335cd3247d5394")
        );
        assert_eq!(checkpoint.digest(), deserialized.digest());

        let restored_entry = &deserialized.pending_requests[0];
        assert_eq!(restored_entry.sign_id(), SignId::new(tx1.request_id));
        let SignKind::SignBidirectional(ref event) = restored_entry.request.kind else {
            panic!("Expected SignBidirectional kind");
        };
        assert_eq!(event.dest, "ethereum");
        assert_eq!(restored_entry.status, pending_execution_status(&tx1));
    }

    #[tokio::test]
    async fn test_recover_restores_execution_watchers() {
        let backlog = Backlog::new();
        let tx = create_test_tx(6);
        let sign_id = SignId::new(tx.request_id);

        insert_bidirectional_with_status(
            &backlog,
            Chain::Solana,
            tx.clone(),
            pending_execution_status(&tx),
            "ethereum",
        )
        .await;
        backlog.set_processed_block(Chain::Solana, 10).await;

        let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

        let recovered = Backlog::new();
        recovered.recover_by_checkpoint(&checkpoint).await;

        let entry = recovered
            .get(Chain::Solana, &sign_id)
            .await
            .expect("entry should exist");
        assert_eq!(entry.sign_id(), sign_id);
        assert_eq!(entry.status(), pending_execution_status(&tx));

        let watchers = recovered.get_execution_watchers(Chain::Ethereum).await;
        assert_eq!(watchers.len(), 1);
        assert!(watchers.contains_key(&tx.id));
    }

    #[tokio::test]
    async fn test_recovery_makes_checkpoint_visible_as_latest() {
        let backlog = Backlog::new();
        let tx = create_test_tx(16);

        insert_bidirectional_with_status(
            &backlog,
            Chain::Solana,
            tx.clone(),
            pending_execution_status(&tx),
            "ethereum",
        )
        .await;
        backlog.set_processed_block(Chain::Solana, 10).await;

        let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

        let recovered = Backlog::new();
        recovered
            .checkpoints()
            .storage()
            .persist(&checkpoint)
            .await
            .unwrap();
        recovered.recover_by_checkpoint(&checkpoint).await;

        assert_eq!(
            recovered.checkpoints().latest(Chain::Solana).await.unwrap(),
            Some(checkpoint),
            "recovered checkpoint should be visible via latest for /checkpoint"
        );
    }

    #[tokio::test]
    async fn test_recover_preserves_sign_kind() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([42u8; 32]);
        let args = SignArgs {
            entropy: [1u8; 32],
            epsilon: k256::Scalar::from(1u64),
            payload: k256::Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        let program_id = Pubkey::new_unique();
        let sign_kind = SignKind::SignBidirectional(SignBidirectionalEvent {
            sender: Default::default(),
            serialized_transaction: vec![1, 2, 3],
            dest: "ethereum".to_string(),
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 1,
            deposit: 10,
            path: "m/0".to_string(),
            algo: "ECDSA".to_string(),
            params: "{}".to_string(),
            chain: Chain::Solana,
            chain_ctx: Some(program_id.to_bytes().to_vec()),
            output_deserialization_schema: vec![9],
            respond_serialization_schema: vec![8],
        });

        backlog
            .insert(create_indexed_request(
                sign_id,
                Chain::Solana,
                args,
                sign_kind,
                0,
            ))
            .await;
        backlog.set_processed_block(Chain::Solana, 10).await;

        let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

        let recovered = Backlog::new();
        recovered.recover_by_checkpoint(&checkpoint).await;

        let recovered_entry = recovered
            .get(Chain::Solana, &sign_id)
            .await
            .expect("missing recovered entry");

        assert!(matches!(
            recovered_entry.request.kind,
            SignKind::SignBidirectional(_)
        ));
    }

    #[tokio::test]
    async fn test_recovered_completed_bidirectional_requests_are_requeued_for_final_respond() {
        let status = SignStatus::PendingGenerationBidirectional;
        for offset in 0..2 {
            let backlog = Backlog::new();
            let tx = create_test_tx(8 + offset as u8);
            let sign_id = SignId::new(tx.request_id);

            insert_bidirectional_with_status(
                &backlog,
                Chain::Solana,
                tx.clone(),
                status.clone(),
                "ethereum",
            )
            .await;
            backlog.set_processed_block(Chain::Solana, 10).await;

            let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

            let recovered = Backlog::new();
            recovered.recover_by_checkpoint(&checkpoint).await;

            let completion_request = IndexedSignRequest::respond_bidirectional(
                sign_id,
                create_test_args(sign_id.request_id[0]),
                Chain::Solana,
                0,
                RespondBidirectionalTx {
                    tx_id: tx.id,
                    output: vec![],
                    chain_ctx: None,
                },
            );
            recovered
                .set_request(Chain::Solana, &sign_id, Arc::new(completion_request))
                .await
                .expect("failed to store completion request");
            recovered
                .set_status(
                    Chain::Solana,
                    &sign_id,
                    SignStatus::PendingGenerationBidirectional,
                )
                .await;

            let requeued = recovered.take_requeueable_requests(Chain::Solana).await;
            assert_eq!(
                requeued.len(),
                1,
                "completed bidirectional request should be requeued for final respond"
            );
            assert!(matches!(
                requeued[0].kind,
                SignKind::RespondBidirectional(_)
            ));
        }
    }

    #[tokio::test]
    async fn test_awaiting_response_bidirectional_requeues() {
        let backlog = Backlog::new();
        let tx = create_test_tx(42);
        let sign_id = SignId::new(tx.request_id);

        let completion_request = IndexedSignRequest::respond_bidirectional(
            sign_id,
            create_test_args(sign_id.request_id[0]),
            Chain::Solana,
            0,
            RespondBidirectionalTx {
                tx_id: tx.id,
                output: vec![1, 2, 3],
                chain_ctx: None,
            },
        );

        backlog.insert(Arc::new(completion_request)).await;
        backlog
            .set_status(
                Chain::Solana,
                &sign_id,
                SignStatus::PendingGenerationBidirectional,
            )
            .await;

        let requeued = backlog.take_requeueable_requests(Chain::Solana).await;
        assert_eq!(requeued.len(), 1);
        assert!(matches!(
            requeued[0].kind,
            SignKind::RespondBidirectional(_)
        ));
    }

    #[tokio::test]
    async fn test_mark_publishing_accepts_bidirectional_pending_generation() {
        let backlog = Backlog::new();
        let tx = create_test_tx(43);
        let sign_id = SignId::new(tx.request_id);

        backlog
            .insert(create_bidirectional_request(
                sign_id,
                Chain::Solana,
                "ethereum",
                0,
            ))
            .await;

        backlog
            .mark_publishing(Chain::Solana, &sign_id, test_publish_state(true))
            .await
            .expect("pending generation should transition to pending publish");

        let entry = backlog
            .get(Chain::Solana, &sign_id)
            .await
            .expect("entry should remain in backlog");
        assert!(matches!(entry.status(), SignStatus::PendingPublish { .. }));
    }

    /// The flag keeps the per-block sweep to one publish per pending-publish
    /// episode. Entering pending-publish again, as the second bidirectional leg
    /// does, starts a new one.
    #[tokio::test]
    async fn test_mark_publish_dispatched_is_once_per_episode() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([45u8; 32]);

        assert!(
            !backlog
                .mark_publish_dispatched(Chain::Solana, &sign_id)
                .await,
            "an entry that is not in the backlog cannot be dispatched"
        );

        backlog
            .insert(create_bidirectional_request(
                sign_id,
                Chain::Solana,
                "ethereum",
                0,
            ))
            .await;
        backlog
            .mark_publishing(Chain::Solana, &sign_id, test_publish_state(false))
            .await
            .expect("pending generation should transition to pending publish");

        let dispatched = |backlog: Backlog| async move {
            let publishable = backlog.publishable_requests(Chain::Solana).await;
            assert_eq!(publishable.len(), 1, "the entry stays in the scan");
            publishable[0].2
        };

        assert!(!dispatched(backlog.clone()).await);
        assert!(
            backlog
                .mark_publish_dispatched(Chain::Solana, &sign_id)
                .await
        );
        assert!(
            !backlog
                .mark_publish_dispatched(Chain::Solana, &sign_id)
                .await,
            "the second dispatch is refused"
        );
        assert!(
            dispatched(backlog.clone()).await,
            "the scan reports it, so the sweep skips it and the resume still sees it"
        );

        backlog
            .set_status(Chain::Solana, &sign_id, SignStatus::PendingGeneration)
            .await;
        backlog
            .mark_publishing(Chain::Solana, &sign_id, test_publish_state(false))
            .await
            .expect("re-entering pending publish starts a new episode");
        assert!(
            !dispatched(backlog.clone()).await,
            "a new episode is scheduled afresh"
        );
    }

    #[tokio::test]
    async fn test_mark_publishing_accepts_final_respond_generation() {
        let backlog = Backlog::new();
        let tx = create_test_tx(44);
        let sign_id = SignId::new(tx.request_id);

        let completion_request = IndexedSignRequest::respond_bidirectional(
            sign_id,
            create_test_args(sign_id.request_id[0]),
            Chain::Solana,
            0,
            RespondBidirectionalTx {
                tx_id: tx.id,
                output: vec![],
                chain_ctx: None,
            },
        );

        backlog.insert(Arc::new(completion_request)).await;
        backlog
            .set_status(
                Chain::Solana,
                &sign_id,
                SignStatus::PendingGenerationBidirectional,
            )
            .await;

        backlog
            .mark_publishing(Chain::Solana, &sign_id, test_publish_state(true))
            .await
            .expect("pending generation bidirectional should transition to pending publish bidirectional");

        let entry = backlog
            .get(Chain::Solana, &sign_id)
            .await
            .expect("entry should remain in backlog");
        assert!(matches!(
            entry.status(),
            SignStatus::PendingPublishBidirectional { .. }
        ));
    }

    #[tokio::test]
    async fn test_watch_unwatch_and_set_status() {
        use k256::Scalar;
        let backlog = Backlog::new();
        let tx = create_test_tx(7);
        let sign_id = SignId::new(tx.request_id);

        // Insert a pending Sign request on the source chain
        let args = SignArgs {
            entropy: [1u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
        let unix_timestamp_indexed = 0;
        backlog
            .insert(create_indexed_request(
                sign_id,
                tx.source_chain,
                args.clone(),
                SignKind::Sign,
                unix_timestamp_indexed,
            ))
            .await;

        // Watch execution on the target chain
        backlog
            .watch_execution(tx.target_chain, sign_id, Arc::new(tx.clone()))
            .await;

        // Unwatch should return the watcher
        let maybe = backlog.unwatch_execution(tx.target_chain, &tx.id).await;
        assert!(maybe.is_some());
        let (s, watched_tx) = maybe.unwrap();
        assert_eq!(s, sign_id);
        assert_eq!(watched_tx.id, tx.id);

        // set_status should update the sign request status
        backlog
            .set_status(
                tx.source_chain,
                &sign_id,
                SignStatus::PendingGenerationBidirectional,
            )
            .await;
        let successes = backlog
            .pending_generation_bidirectionals(tx.source_chain)
            .await;
        assert!(successes.contains_key(&sign_id));
    }

    #[tokio::test]
    async fn test_automatic_checkpoint_on_interval() {
        let backlog = Backlog::new();

        // Add some transactions
        let tx1 = create_test_tx(1);
        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx1.clone(),
            pending_execution_status(&tx1),
            "ethereum",
        )
        .await;

        let interval = Chain::Ethereum.checkpoint_interval().unwrap();

        // First few blocks shouldn't create checkpoints
        for i in 1..interval {
            let checkpoint = backlog.set_processed_block(Chain::Ethereum, i).await;
            assert!(checkpoint.is_none(), "Block {i} should not make checkpoint");
        }

        // At block interval, should create checkpoint
        let checkpoint = backlog.set_processed_block(Chain::Ethereum, interval).await;
        assert!(checkpoint.is_some());
        let checkpoint = checkpoint.unwrap();
        assert_eq!(checkpoint.block_height, interval);
        assert_eq!(checkpoint.chain, Chain::Ethereum);
        assert_eq!(checkpoint.pending_requests.len(), 1);

        let checkpoint = backlog
            .set_processed_block(Chain::Ethereum, interval + 1)
            .await;
        assert!(checkpoint.is_none());

        let checkpoint = backlog
            .set_processed_block(Chain::Ethereum, 2 * interval)
            .await;
        assert!(checkpoint.is_some());
        let checkpoint = checkpoint.unwrap();
        assert_eq!(checkpoint.block_height, 2 * interval);
    }

    #[tokio::test]
    async fn test_automatic_checkpoint_solana_interval() {
        let backlog = Backlog::new();
        let interval = Chain::Solana.checkpoint_interval().unwrap();

        // Add transaction
        let tx1 = create_test_tx(1);
        insert_bidirectional_with_status(
            &backlog,
            Chain::Solana,
            tx1.clone(),
            pending_execution_status(&tx1),
            "solana",
        )
        .await;

        // Solana interval is 10 blocks
        for i in 1..interval {
            let checkpoint = backlog.set_processed_block(Chain::Solana, i).await;
            assert!(checkpoint.is_none(), "Block {i} should not make checkpoint");
        }

        // At block interval, should create checkpoint
        let checkpoint = backlog.set_processed_block(Chain::Solana, interval).await;
        assert!(checkpoint.is_some());
        let checkpoint = checkpoint.unwrap();
        assert_eq!(checkpoint.block_height, interval);
        assert_eq!(checkpoint.chain, Chain::Solana);
    }

    async fn seed_pending_solana_request(backlog: &Backlog) {
        let tx = create_test_tx(1);
        insert_bidirectional_with_status(
            backlog,
            Chain::Solana,
            tx.clone(),
            pending_execution_status(&tx),
            "solana",
        )
        .await;
    }

    #[tokio::test]
    async fn test_boundary_crossing_sparse_request_waits_until_next_bucket() {
        let backlog = Backlog::new();
        seed_pending_solana_request(&backlog).await;

        // This documents the main caveat of boundary-crossing checkpointing:
        // sparse requests still wait if the next observed slot remains in the
        // same interval bucket.
        //
        // 480 -> 500: same bucket (both / 120 == 4), no checkpoint.
        backlog
            .set_processed_block_interval(Chain::Solana, 480, 120)
            .await;
        let cp = backlog
            .set_processed_block_interval(Chain::Solana, 500, 120)
            .await;
        assert!(cp.is_none());

        // 500 -> 600: crosses from bucket 4 to bucket 5
        let cp = backlog
            .set_processed_block_interval(Chain::Solana, 600, 120)
            .await;
        assert!(cp.is_some());
        let cp = cp.unwrap();
        assert_eq!(cp.block_height, 600);
        assert_eq!(cp.pending_requests.len(), 1);
    }

    #[tokio::test]
    async fn test_boundary_crossing_same_bucket_no_checkpoint() {
        let backlog = Backlog::new();
        seed_pending_solana_request(&backlog).await;

        // 121 crosses from bucket 0 to bucket 1
        let cp = backlog
            .set_processed_block_interval(Chain::Solana, 121, 120)
            .await;
        assert!(cp.is_some());

        // 130 stays in bucket 1; no new boundary crossed
        let cp = backlog
            .set_processed_block_interval(Chain::Solana, 130, 120)
            .await;
        assert!(cp.is_none());
    }

    #[tokio::test]
    async fn test_boundary_crossing_within_first_bucket_no_checkpoint() {
        let backlog = Backlog::new();
        seed_pending_solana_request(&backlog).await;

        // First observed slot 50 is still in bucket 0 (50 / 120 == 0 == prev default 0)
        let cp = backlog
            .set_processed_block_interval(Chain::Solana, 50, 120)
            .await;
        assert!(cp.is_none());
    }

    #[tokio::test]
    async fn test_boundary_crossing_exact_multiple_still_checkpoints() {
        let backlog = Backlog::new();
        seed_pending_solana_request(&backlog).await;

        let cp = backlog
            .set_processed_block_interval(Chain::Solana, 119, 120)
            .await;
        assert!(cp.is_none());

        // Exact multiple still works; it crosses from bucket 0 to bucket 1
        let cp = backlog
            .set_processed_block_interval(Chain::Solana, 120, 120)
            .await;
        assert!(cp.is_some());
        assert_eq!(cp.unwrap().block_height, 120);
    }

    #[tokio::test]
    async fn test_boundary_crossing_first_observed_height_above_interval() {
        let backlog = Backlog::new();
        seed_pending_solana_request(&backlog).await;

        // First ever processed block is 500 (prev defaults to 0)
        // 500 / 120 = 4 > 0, so a boundary was crossed.
        let cp = backlog
            .set_processed_block_interval(Chain::Solana, 500, 120)
            .await
            .unwrap();
        assert_eq!(cp.block_height, 500);
        assert_eq!(cp.pending_requests.len(), 1);
    }

    #[tokio::test]
    async fn test_advance_rejects_plain_sign_entries() {
        let backlog = Backlog::new();
        let tx = create_test_tx(8);
        let sign_id = SignId::new(tx.request_id);

        let args = SignArgs {
            entropy: [1u8; 32],
            epsilon: k256::Scalar::from(1u64),
            payload: k256::Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        backlog
            .insert(create_indexed_request(
                sign_id,
                tx.source_chain,
                args,
                SignKind::Sign,
                0,
            ))
            .await;

        let err = backlog
            .advance(tx.source_chain, sign_id, Arc::new(tx))
            .await
            .expect_err("advance should fail for plain Sign requests");

        assert!(matches!(err, BacklogError::InvalidAdvanceTransition));
    }

    #[tokio::test]
    async fn test_advance_accepts_pending_generation_bidirectional() {
        let backlog = Backlog::new();
        let tx = create_test_tx(9);
        let sign_id = SignId::new(tx.request_id);

        backlog
            .insert(create_bidirectional_request(
                sign_id,
                tx.source_chain,
                "ethereum",
                0,
            ))
            .await;

        backlog
            .advance(tx.source_chain, sign_id, Arc::new(tx.clone()))
            .await
            .expect("advance should accept catchup advancement from PendingGeneration");

        let entry = backlog
            .get(tx.source_chain, &sign_id)
            .await
            .expect("entry should remain in backlog");
        assert_eq!(entry.status(), pending_execution_status(&tx));
    }

    #[tokio::test]
    async fn test_advance_accepts_pending_publish_bidirectional() {
        let backlog = Backlog::new();
        let tx = create_test_tx(10);
        let sign_id = SignId::new(tx.request_id);

        backlog
            .insert(create_bidirectional_request(
                sign_id,
                tx.source_chain,
                "ethereum",
                0,
            ))
            .await;
        backlog
            .set_status(
                tx.source_chain,
                &sign_id,
                SignStatus::PendingPublish {
                    publish: test_publish_state(true),
                },
            )
            .await;

        backlog
            .advance(tx.source_chain, sign_id, Arc::new(tx.clone()))
            .await
            .expect("advance should succeed once respond() is confirmed from PendingPublish");

        let entry = backlog
            .get(tx.source_chain, &sign_id)
            .await
            .expect("entry should remain in backlog");
        assert_eq!(entry.status(), pending_execution_status(&tx));
        assert_eq!(
            entry.execution_tx().map(|execution| execution.id),
            Some(tx.id)
        );
    }

    #[tokio::test]
    async fn test_total_pending_increments_on_insert() {
        let backlog = Backlog::new();
        let tx = create_test_tx(1);

        backlog
            .insert(create_indexed_request(
                SignId::new(tx.request_id),
                Chain::Ethereum,
                create_test_args(1),
                SignKind::Sign,
                0,
            ))
            .await;

        assert_eq!(backlog.len(), 1);
        assert!(!backlog.is_empty());
    }

    #[tokio::test]
    async fn test_total_pending_ignores_duplicate_inserts() {
        let backlog = Backlog::new();
        let tx = create_test_tx(1);
        let request = create_indexed_request(
            SignId::new(tx.request_id),
            Chain::Ethereum,
            create_test_args(1),
            SignKind::Sign,
            0,
        );

        // Insert first time
        backlog.insert(Arc::clone(&request)).await;
        assert_eq!(backlog.len(), 1);

        // Insert exactly the same ID again (overwrites)
        backlog.insert(request).await;
        assert_eq!(
            backlog.len(),
            1,
            "Duplicate insert should not increment total"
        );
    }

    #[tokio::test]
    async fn test_total_pending_counts_across_chains() {
        let backlog = Backlog::new();

        backlog
            .insert(create_indexed_request(
                SignId::new(create_test_tx(1).request_id),
                Chain::Ethereum,
                create_test_args(1),
                SignKind::Sign,
                0,
            ))
            .await;

        backlog
            .insert(create_indexed_request(
                SignId::new(create_test_tx(2).request_id),
                Chain::Solana,
                create_test_args(2),
                SignKind::Sign,
                0,
            ))
            .await;

        assert_eq!(backlog.len(), 2);
    }

    #[tokio::test]
    async fn test_total_pending_decrements_on_remove() {
        let backlog = Backlog::new();
        let sign_id = SignId::new(create_test_tx(1).request_id);

        backlog
            .insert(create_indexed_request(
                sign_id,
                Chain::Ethereum,
                create_test_args(1),
                SignKind::Sign,
                0,
            ))
            .await;
        assert_eq!(backlog.len(), 1);

        backlog.remove(Chain::Ethereum, &sign_id).await;
        assert_eq!(backlog.len(), 0);
        assert!(backlog.is_empty());
    }

    #[tokio::test]
    async fn test_total_pending_ignores_invalid_removes() {
        let backlog = Backlog::new();
        let sign_id1 = SignId::new(create_test_tx(1).request_id);
        let sign_id2 = SignId::new(create_test_tx(2).request_id); // Not inserted

        backlog
            .insert(create_indexed_request(
                sign_id1,
                Chain::Ethereum,
                create_test_args(1),
                SignKind::Sign,
                0,
            ))
            .await;

        backlog.remove(Chain::Ethereum, &sign_id2).await;
        assert_eq!(
            backlog.len(),
            1,
            "Removing non-existent ID should not decrement total"
        );
    }

    #[tokio::test]
    async fn test_total_pending_updates_on_clean_recovery() {
        let backlog = Backlog::new();

        // Populate 3 requests and create a checkpoint
        for i in 1..=3 {
            backlog
                .insert(create_indexed_request(
                    SignId::new(create_test_tx(i).request_id),
                    Chain::Ethereum,
                    create_test_args(i),
                    SignKind::Sign,
                    0,
                ))
                .await;
        }
        backlog.set_processed_block(Chain::Ethereum, 10).await;
        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();

        // Clean backlog recovers the checkpoint
        let recovered = Backlog::new();
        assert_eq!(recovered.len(), 0);

        recovered.recover_by_checkpoint(&checkpoint).await;

        assert_eq!(recovered.len(), 3);
    }

    #[tokio::test]
    async fn test_total_pending_updates_on_dirty_recovery() {
        let backlog = Backlog::new();

        // Populate 3 requests and create a checkpoint
        for i in 1..=3 {
            backlog
                .insert(create_indexed_request(
                    SignId::new(create_test_tx(i).request_id),
                    Chain::Ethereum,
                    create_test_args(i),
                    SignKind::Sign,
                    0,
                ))
                .await;
        }
        backlog.set_processed_block(Chain::Ethereum, 10).await;
        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();

        // Dirty backlog has 1 entirely different request before recovery
        let dirty_backlog = Backlog::new();
        dirty_backlog
            .insert(create_indexed_request(
                SignId::new([99u8; 32]),
                Chain::Ethereum,
                create_test_args(99),
                SignKind::Sign,
                0,
            ))
            .await;

        assert_eq!(dirty_backlog.len(), 1);

        // Recover from checkpoint (should overwrite the dirty state)
        dirty_backlog.recover_by_checkpoint(&checkpoint).await;

        assert_eq!(
            dirty_backlog.len(),
            3,
            "Total should reflect exactly the restored checkpoint size, ignoring the overwritten dirty state"
        );
    }

    #[tokio::test]
    async fn test_recovery_keeps_pending_checkpoints() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let interval = chain.checkpoint_interval().unwrap();

        backlog.set_processed_block(chain, interval).await.unwrap();
        backlog
            .set_processed_block(chain, 2 * interval)
            .await
            .unwrap();

        assert_eq!(
            backlog.checkpoints().count(chain),
            2,
            "two checkpoints should be pending"
        );

        // Recover the request backlog without discarding checkpoints that may
        // still be needed to match an on-chain consensus digest.
        let fresh = Backlog::new();
        let recovery_cp = fresh.set_processed_block(chain, interval / 2).await;
        // interval/2 is not a multiple of interval → no auto-checkpoint
        assert!(recovery_cp.is_none());
        // Force create a checkpoint at that height
        let fresh_cp = fresh.checkpoint(chain).await.unwrap();
        assert_eq!(fresh_cp.block_height, interval / 2);

        backlog.recover_by_checkpoint(&fresh_cp).await;
        assert_eq!(
            backlog.checkpoints().count(chain),
            2,
            "pending checkpoints should remain available for consensus matching"
        );
    }

    #[tokio::test]
    async fn test_hydrate_initializes_pending_and_recovers_backlog() {
        let storage = CheckpointStorage::in_memory();
        let backlog = Backlog::persisted(storage.clone());
        let chain = Chain::Ethereum;
        let interval = chain.checkpoint_interval().unwrap();

        // Create pending checkpoints
        backlog.set_processed_block(chain, interval).await.unwrap();
        backlog
            .set_processed_block(chain, 2 * interval)
            .await
            .unwrap();
        assert_eq!(backlog.checkpoints().count(chain), 2);

        // A new Backlog instance sharing storage starts with 0 count and None processed block
        let restarted = Backlog::persisted(storage);
        assert_eq!(restarted.checkpoints().count(chain), 0);
        assert_eq!(restarted.get_processed_block(chain).await, None);

        // Hydrate initializes the counter and recovers from the latest checkpoint
        let hydrated = restarted.hydrate(chain).await.unwrap();
        assert!(hydrated.is_some());
        assert_eq!(hydrated.unwrap().block_height, 2 * interval);
        assert_eq!(restarted.checkpoints().count(chain), 2);
        assert_eq!(
            restarted.get_processed_block(chain).await,
            Some(2 * interval)
        );
    }
}
