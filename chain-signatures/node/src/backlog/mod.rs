mod checkpoints;
pub mod consensus;
pub mod request;
#[cfg(any(test, feature = "test-feature"))]
pub mod mock;

pub use request::{
    AnyProgress, Bidirectional, Executing, Final, Generating, Initial, Publishing, Sign, SignEntry,
};

use crate::sign_bidirectional::{BidirectionalProgress, PublishState, SignProgress, SignStatus};
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

    fn from_checkpoint(checkpoint: &Checkpoint) -> anyhow::Result<Self> {
        let mut requests = HashMap::new();
        for entry in &checkpoint.pending_requests {
            requests.insert(entry.sign_id(), entry.clone());
        }
        Ok(Self {
            requests,
            processed_block_height: Some(checkpoint.block_height),
        })
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
            .map(|entry| Arc::clone(entry.request()))
            .collect();

        requeueable.sort_by(|left, right| {
            left.unix_timestamp_indexed
                .cmp(&right.unix_timestamp_indexed)
                .then_with(|| left.id.request_id.cmp(&right.id.request_id))
        });

        requeueable
    }

    /// Returns backlog requests for a chain that are ready to be published.
    /// Sorted by indexed timestamp and request id.
    pub async fn publishable_requests(
        &self,
        chain: Chain,
    ) -> Vec<(Arc<IndexedSignRequest>, Arc<PublishState>)> {
        // Read-only scan; the backup sweep calls this every second per chain, so a
        // write lock here would serialize against the signing hot path for nothing.
        let pending = self.pending(&chain).read().await;

        let mut publishable: Vec<_> = pending
            .requests
            .values()
            .filter_map(|entry| {
                let publish = entry.status.publish_state()?;
                Some((Arc::clone(entry.request()), Arc::clone(publish)))
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

    /// Returns the number of pending requests for a specific chain
    pub async fn len_by_chain(&self, chain: Chain) -> usize {
        self.pending(&chain).read().await.len()
    }

    /// Marks a request as publishing for a specific chain and request id, with the given publish state.
    pub async fn publish(
        &self,
        chain: Chain,
        id: &SignId,
        publish: Arc<PublishState>,
    ) -> Result<(), BacklogError> {
        let mut pending = self.pending(&chain).write().await;

        let Some(entry) = pending.requests.get_mut(id) else {
            return Err(BacklogError::NotFound { chain, id: *id });
        };

        entry.publish(publish)
    }

    /// Atomically move a completed target-chain execution into final response signing.
    pub async fn respond(
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
        entry.respond(request)?;
        Ok(entry.clone())
    }

    /// Begin watching for execution of a bidirectional transaction on the destination chain.
    ///
    /// The watcher's `sign_id` and `tx.request_id` are expected to agree: on
    /// confirmation the final-response request is rebuilt from `tx.request_id` while
    /// the backlog entry is looked up by `sign_id`, and
    /// `BacklogEntry::respond` rejects the pair when they
    /// disagree. Warn here, where the divergence originates, rather than leaving only
    /// a stalled request at confirmation time.
    pub async fn watch_execution(
        &self,
        chain: Chain,
        sign_id: SignId,
        tx: Arc<BidirectionalTx>,
    ) -> Option<(SignId, Arc<BidirectionalTx>)> {
        if sign_id != tx.sign_id() {
            tracing::warn!(
                ?chain,
                ?sign_id,
                request_id = ?tx.sign_id(),
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

        entry.advance(Arc::clone(&bidirectional_tx))?;

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
            Checkpoints::snapshot(&requests, chain)
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
        let restored = PendingRequests::from_checkpoint(&checkpoint)?;
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
    pub async fn recover_by_checkpoint(&self, checkpoint: Checkpoint) -> anyhow::Result<()> {
        let restored = PendingRequests::from_checkpoint(&checkpoint)?;
        self.apply_checkpoint(checkpoint, restored).await;
        Ok(())
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
            pending.pending_executions()
        };

        // Clear execution watchers whose source chain is the recovered chain
        for destination_chain in Chain::iter() {
            let mut watchers = self.watchers(&destination_chain).write().await;
            watchers
                .watchers
                .retain(|_, watcher| watcher.tx.source_chain != chain);
        }

        // now repopulate our execution watchers
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

    pub fn pending_execution(request: Arc<IndexedSignRequest>, tx: Arc<BidirectionalTx>) -> Self {
        Self::with_status(
            request,
            SignStatus::Bidirectional(BidirectionalProgress::Executing(tx)),
        )
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

    /// Move this entry into the final-response request produced by a confirmed
    /// target-chain execution.
    ///
    /// Rejects a request whose id differs from this entry's. Callers look the entry
    /// up by `SignId`, so accepting a mismatch would leave `request.id` disagreeing
    /// with the key it is stored under, and `checkpoint` commits to the key while
    /// diagnostics report the id. `Backlog::watch_execution` warns when the two
    /// identifiers diverge, which is the only way to reach this rejection.
    pub fn respond(&mut self, request: Arc<IndexedSignRequest>) -> Result<(), BacklogError> {
        if self.request.id != request.id
            || !matches!(&request.kind, SignKind::RespondBidirectional(_))
        {
            return Err(BacklogError::InvalidBidirectionalResponseTransition);
        }

        self.status = SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: request,
            progress: SignProgress::Generating,
        });
        Ok(())
    }

    pub fn publish(&mut self, publish: Arc<PublishState>) -> Result<(), BacklogError> {
        match &mut self.status {
            SignStatus::Sign(progress) => progress.publish(publish),
            SignStatus::Bidirectional(BidirectionalProgress::Initial(progress)) => {
                progress.publish(publish)
            }
            SignStatus::Bidirectional(BidirectionalProgress::Final { progress, .. }) => {
                progress.publish(publish)
            }
            SignStatus::Bidirectional(BidirectionalProgress::Executing(_)) => {
                Err(BacklogError::InvalidPublishingTransition)
            }
        }
    }

    pub fn advance(&mut self, tx: Arc<BidirectionalTx>) -> Result<(), BacklogError> {
        match &mut self.status {
            SignStatus::Bidirectional(progress @ BidirectionalProgress::Initial(_)) => {
                *progress = BidirectionalProgress::Executing(tx);
                Ok(())
            }
            _ => Err(BacklogError::InvalidAdvanceTransition),
        }
    }

    pub fn execution_tx(&self) -> Option<&Arc<BidirectionalTx>> {
        self.status.execution_tx()
    }
}

#[cfg(test)]
mod tests {
    use crate::backlog::checkpoints::Checkpoint;
    use crate::backlog::mock::{
        bidi_initial_status, mock_bidi_request, mock_bidi_response_request, mock_execution_entry,
        mock_execution_entry_with_timestamp, mock_publish_state, mock_sign_request, mock_tx,
        pending_execution_status, BacklogTestExt,
    };
    use crate::backlog::{
        Backlog, BacklogEntry, BacklogError, Bidirectional, Executing, Final, Generating, Initial,
        PendingRequests, Publishing,
    };
    use crate::sign_bidirectional::{
        BidirectionalProgress, SignProgress, SignStatus,
    };
    use mpc_chain_integration_core::StateManager;
    use mpc_chain_solana::Pubkey;
    use mpc_primitives::{
        Chain, ChainConfig as _, IndexedSignRequest, SignArgs, SignBidirectionalEvent, SignId,
        SignKind,
    };
    use std::convert::TryInto;
    use std::sync::Arc;

    fn digest_hex(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str)
            .unwrap()
            .try_into()
            .expect("digest hex must be 32 bytes")
    }

    /// Builds a checkpoint for a chain with exactly one backlog entry at height 100.
    fn single_entry_checkpoint(entry: BacklogEntry) -> Checkpoint {
        let mut pending = PendingRequests::new();
        pending.insert(entry.sign_id(), entry);
        pending.set_processed_block(100);
        pending.checkpoint(Chain::Ethereum)
    }

    #[tokio::test]
    async fn test_backlog_chain_isolation() {
        let backlog = Backlog::new();

        let sign_id_eth = SignId::from_u8(1);
        let sign_id_sol = SignId::from_u8(2);
        let sign_id_near = SignId::from_u8(3);

        backlog
            .insert_mock_bidirectional(sign_id_eth, Chain::Ethereum)
            .await;
        backlog
            .insert_mock_bidirectional(sign_id_sol, Chain::Solana)
            .await;
        backlog
            .insert_mock_bidirectional(sign_id_near, Chain::NEAR)
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
        let tx0 = mock_tx(0);
        let tx1 = mock_tx(1);
        let tx2 = mock_tx(2);
        let tx3 = mock_tx(3);

        let sign_id1 = tx1.sign_id();
        let sign_id2 = tx2.sign_id();
        let sign_id3 = tx3.sign_id();

        backlog
            .insert_mock_bidirectional(sign_id1, Chain::Ethereum)
            .await;

        let completion_request = mock_bidi_response_request(sign_id2, tx2.id, Chain::Ethereum);

        backlog
            .insert_mock_bidirectional(sign_id2, Chain::Ethereum)
            .await
            .advance(mock_publish_state(true))
            .await
            .unwrap()
            .advance(Arc::new(tx2.clone()))
            .await
            .unwrap()
            .advance(completion_request)
            .await
            .unwrap();

        backlog
            .insert_mock_bidirectional(sign_id3, Chain::Ethereum)
            .await
            .advance(mock_publish_state(true))
            .await
            .unwrap()
            .advance(Arc::new(tx3.clone()))
            .await
            .unwrap();

        // Add transactions to Solana
        let tx4 = mock_tx(4);
        let sign_id4 = tx4.sign_id();
        backlog
            .insert_mock_bidirectional(sign_id4, Chain::Solana)
            .await
            .advance(mock_publish_state(true))
            .await
            .unwrap()
            .advance(Arc::new(tx4.clone()))
            .await
            .unwrap();

        // Filter Ethereum by Pending execution
        let eth_pending = backlog
            .get_by::<Bidirectional<Executing>>(Chain::Ethereum, &sign_id3)
            .await;
        assert!(eth_pending.is_some());

        // Filter Ethereum by Initial Generating
        let eth_awaiting = backlog
            .get_by::<Bidirectional<Initial<Generating>>>(Chain::Ethereum, &sign_id1)
            .await;
        assert!(eth_awaiting.is_some());

        // Filter Ethereum by bidirectional completion awaiting final respond
        let eth_completion = backlog
            .get_by::<Bidirectional<Final<Generating>>>(Chain::Ethereum, &sign_id2)
            .await;
        assert!(eth_completion.is_some());

        // Filter Solana by Pending execution
        let sol_pending = backlog
            .get_by::<Bidirectional<Executing>>(Chain::Solana, &sign_id4)
            .await;
        assert!(sol_pending.is_some());

        // Filter non-existent chain returns empty
        let near_pending = backlog
            .get_by::<Bidirectional<Executing>>(Chain::NEAR, &tx0.sign_id())
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
                backlog
                    .insert_mock_bidirectional(SignId::from_u8(i), Chain::Ethereum)
                    .await;
            });
            handles.push(handle);
        }

        for i in 5..10 {
            let backlog = backlog.clone();
            let handle = tokio::spawn(async move {
                backlog
                    .insert_mock_bidirectional(SignId::from_u8(i), Chain::Solana)
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
                let id = SignId::from_u8(i);
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
        let tx1 = mock_tx(1);
        let tx2 = mock_tx(2);

        let sign_id1 = tx1.sign_id();
        let sign_id2 = tx2.sign_id();

        backlog
            .insert_mock_bidirectional(sign_id1, Chain::Ethereum)
            .await
            .advance(mock_publish_state(true))
            .await
            .unwrap()
            .advance(Arc::new(tx1.clone()))
            .await
            .unwrap();

        let completion_request = mock_bidi_response_request(sign_id2, tx2.id, Chain::Ethereum);

        backlog
            .insert_mock_bidirectional(sign_id2, Chain::Ethereum)
            .await
            .advance(mock_publish_state(true))
            .await
            .unwrap()
            .advance(Arc::new(tx2.clone()))
            .await
            .unwrap()
            .advance(completion_request)
            .await
            .unwrap();

        backlog
            .set_processed_block(Chain::Ethereum, 100)
            .await;

        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();

        assert_eq!(checkpoint.block_height, 100);
        assert_eq!(checkpoint.pending_requests.len(), 2);
        // Guard the checkpoint digest wire format; update only for intentional changes.
        assert_eq!(
            checkpoint.digest(),
            digest_hex("884b11ef5550724b788b7e29e9a07e7a6fd46f94d604e6d38bae71a36816b65e")
        );
    }

    #[tokio::test]
    async fn test_checkpoint_equality() {
        let tx1 = mock_tx(1);
        let tx2 = mock_tx(2);

        let mut pending1 = PendingRequests::new();
        pending1.insert(
            tx1.sign_id(),
            mock_execution_entry(&tx1, Chain::Ethereum, bidi_initial_status()),
        );
        pending1.insert(
            tx2.sign_id(),
            mock_execution_entry(&tx2, Chain::Ethereum, bidi_initial_status()),
        );
        pending1.set_processed_block(100);

        let mut pending2 = PendingRequests::new();
        pending2.insert(
            tx1.sign_id(),
            mock_execution_entry(&tx1, Chain::Ethereum, bidi_initial_status()),
        );
        pending2.insert(
            tx2.sign_id(),
            mock_execution_entry(&tx2, Chain::Ethereum, bidi_initial_status()),
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
        let tx = mock_tx(60);
        let sign_id = tx.sign_id();

        // The digest commits only to the consensus projection of each entry's
        // status (sorted by sign_id), not to the request or publish content.

        // Initial source-chain phase: generation, and publishing by any proposer,
        // all collapse to a single digest.
        let generation = single_entry_checkpoint(mock_execution_entry(
            &tx,
            Chain::Ethereum,
            bidi_initial_status(),
        ));
        let publish = single_entry_checkpoint(mock_execution_entry(
            &tx,
            Chain::Ethereum,
            SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Publishing(
                mock_publish_state(true),
            ))),
        ));
        let publish_other = single_entry_checkpoint(mock_execution_entry(
            &tx,
            Chain::Ethereum,
            SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Publishing(
                mock_publish_state(false),
            ))),
        ));
        assert_eq!(generation.digest(), publish.digest());
        assert_eq!(generation.digest(), publish_other.digest());

        // Plain `Sign` requests follow the same initial-phase projection.
        let plain = mock_sign_request(sign_id, Chain::Ethereum);
        let plain_generation = single_entry_checkpoint(BacklogEntry::new(Arc::clone(&plain)));
        let plain_publish = single_entry_checkpoint(BacklogEntry::with_status(
            plain,
            SignStatus::Sign(SignProgress::Publishing(mock_publish_state(true))),
        ));
        assert_eq!(plain_generation.digest(), plain_publish.digest());

        // Post-initial phase: awaiting target-chain execution and the final
        // response generation/publish states are not observable at the
        // source-chain checkpoint height, so they share the checkpoint digest.
        let execution = single_entry_checkpoint(mock_execution_entry(
            &tx,
            Chain::Ethereum,
            pending_execution_status(&tx),
        ));
        let response_request = mock_bidi_response_request(sign_id, tx.id, Chain::Ethereum);
        let origin_request = mock_bidi_request(sign_id, Chain::Ethereum);
        let gen_bidirectional = single_entry_checkpoint(BacklogEntry::with_status(
            Arc::clone(&origin_request),
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request: Arc::clone(&response_request),
                progress: SignProgress::Generating,
            }),
        ));
        let pub_bidirectional = single_entry_checkpoint(BacklogEntry::with_status(
            origin_request,
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request: response_request,
                progress: SignProgress::Publishing(mock_publish_state(true)),
            }),
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
    fn test_respond_updates_entry_atomically() {
        let tx = mock_tx(23);
        let sign_id = tx.sign_id();
        let mut entry = mock_execution_entry(
            &tx,
            Chain::Ethereum,
            pending_execution_status(&tx),
        );
        let response_request = mock_bidi_response_request(sign_id, tx.id, Chain::Ethereum);

        entry.respond(response_request).unwrap();

        assert_matches!(entry.request().kind, SignKind::RespondBidirectional(_));
        assert_matches!(
            entry.status(),
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                progress: SignProgress::Generating,
                ..
            })
        );
    }

    #[test]
    fn test_respond_rejects_mismatched_request_id() {
        let tx = mock_tx(24);
        let original_sign_id = tx.sign_id();
        let mut entry = mock_execution_entry(
            &tx,
            Chain::Ethereum,
            pending_execution_status(&tx),
        );
        let response_request =
            mock_bidi_response_request(SignId::from_u8(25), tx.id, Chain::Ethereum);

        let err = entry.respond(response_request).unwrap_err();

        assert_matches!(err, BacklogError::InvalidBidirectionalResponseTransition);
        assert_eq!(entry.sign_id(), original_sign_id);
        assert_matches!(
            entry.status(),
            SignStatus::Bidirectional(BidirectionalProgress::Executing(_))
        );
    }

    #[tokio::test]
    async fn test_checkpoint_digest_ignores_timestamp() {
        let tx = mock_tx(8);

        let entry1 = mock_execution_entry_with_timestamp(
            &tx,
            Chain::Ethereum,
            bidi_initial_status(),
            0,
        );
        let entry2 = mock_execution_entry_with_timestamp(
            &tx,
            Chain::Ethereum,
            bidi_initial_status(),
            9999,
        );

        let mut pending1 = PendingRequests::new();
        pending1.insert(tx.sign_id(), entry1);
        pending1.set_processed_block(200);

        let mut pending2 = PendingRequests::new();
        pending2.insert(tx.sign_id(), entry2);
        pending2.set_processed_block(200);

        let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
        let checkpoint2 = pending2.checkpoint(Chain::Ethereum);

        assert_eq!(checkpoint1.digest(), checkpoint2.digest());
    }

    #[tokio::test]
    async fn test_checkpoint_digest_differs_for_different_requests() {
        let tx1 = mock_tx(10);
        let tx2 = mock_tx(11);

        let mut pending1 = PendingRequests::new();
        pending1.insert(
            tx1.sign_id(),
            mock_execution_entry(&tx1, Chain::Ethereum, bidi_initial_status()),
        );
        pending1.set_processed_block(100);

        let mut pending2 = PendingRequests::new();
        pending2.insert(
            tx2.sign_id(),
            mock_execution_entry(&tx2, Chain::Ethereum, bidi_initial_status()),
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
        let tx1 = mock_tx(1);

        let mut pending = PendingRequests::new();
        pending.insert(
            tx1.sign_id(),
            mock_execution_entry(&tx1, Chain::Ethereum, pending_execution_status(&tx1)),
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
        assert_eq!(restored_entry.sign_id(), tx1.sign_id());
        let SignKind::SignBidirectional(ref event) = restored_entry.request.kind else {
            panic!("Expected SignBidirectional kind");
        };
        assert_eq!(event.dest, "test_dest");
        assert_eq!(restored_entry.status, pending_execution_status(&tx1));
    }

    #[tokio::test]
    async fn test_recover_restores_execution_watchers() {
        let backlog = Backlog::new();
        let tx = mock_tx(6);
        let sign_id = tx.sign_id();

        backlog
            .insert_mock_bidirectional(sign_id, Chain::Solana)
            .await
            .advance(mock_publish_state(true))
            .await
            .unwrap()
            .advance(Arc::new(tx.clone()))
            .await
            .unwrap();
        backlog.set_processed_block(Chain::Solana, 10).await;

        let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

        let recovered = Backlog::new();
        recovered
            .recover_by_checkpoint(checkpoint)
            .await
            .expect("failed to recover");

        let entry = recovered
            .get_by::<Bidirectional<Executing>>(Chain::Solana, &sign_id)
            .await
            .expect("entry should exist");
        assert_eq!(entry.sign_id(), sign_id);
        assert_eq!(&*entry.state().0 .0, &tx);

        let watchers = recovered.get_execution_watchers(Chain::Ethereum).await;
        assert_eq!(watchers.len(), 1);
        assert!(watchers.contains_key(&tx.id));
    }

    #[tokio::test]
    async fn test_recovery_makes_checkpoint_visible_as_latest() {
        let backlog = Backlog::new();
        let tx = mock_tx(16);
        let sign_id = tx.sign_id();

        backlog
            .insert_mock_bidirectional(sign_id, Chain::Solana)
            .await
            .advance(mock_publish_state(true))
            .await
            .unwrap()
            .advance(Arc::new(tx.clone()))
            .await
            .unwrap();
        backlog.set_processed_block(Chain::Solana, 10).await;

        let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

        let recovered = Backlog::new();
        recovered
            .checkpoint_storage()
            .persist(&checkpoint)
            .await
            .unwrap();
        recovered
            .recover_by_checkpoint(checkpoint.clone())
            .await
            .expect("failed to recover");

        assert_eq!(
            recovered.latest_checkpoint(Chain::Solana).await,
            Some(checkpoint),
            "recovered checkpoint should be visible via latest_checkpoint for /checkpoint"
        );
    }

    #[tokio::test]
    async fn test_recover_preserves_sign_kind() {
        let backlog = Backlog::new();
        let sign_id = SignId::from_u8(42);
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

        let req = Arc::new(IndexedSignRequest::new(
            sign_id,
            args,
            Chain::Solana,
            0,
            sign_kind,
        ));
        backlog.insert_bidirectional(req).await;
        backlog.set_processed_block(Chain::Solana, 10).await;

        let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

        let recovered = Backlog::new();
        recovered
            .recover_by_checkpoint(checkpoint)
            .await
            .expect("failed to recover");

        let recovered_entry = recovered
            .get(Chain::Solana, &sign_id)
            .await
            .expect("missing recovered entry");

        assert_matches!(recovered_entry.request.kind, SignKind::SignBidirectional(_));
    }

    #[tokio::test]
    async fn test_recovered_completed_bidirectional_requests_are_requeued_for_final_respond() {
        for offset in 0..2 {
            let backlog = Backlog::new();
            let tx = mock_tx(8 + offset as u8);
            let sign_id = tx.sign_id();

            let completion_request = mock_bidi_response_request(sign_id, tx.id, Chain::Solana);
            let _entry = backlog
                .insert_mock_bidirectional(sign_id, Chain::Solana)
                .await
                .advance(mock_publish_state(true))
                .await
                .expect("phase 1 publishing")
                .advance(Arc::new(tx.clone()))
                .await
                .expect("executing")
                .advance(completion_request)
                .await
                .expect("final generating");
            backlog.set_processed_block(Chain::Solana, 10).await;

            let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

            let recovered = Backlog::new();
            recovered
                .recover_by_checkpoint(checkpoint)
                .await
                .expect("failed to recover");

            let requeued = recovered.take_requeueable_requests(Chain::Solana).await;
            assert_eq!(
                requeued.len(),
                1,
                "completed bidirectional request should be requeued for final respond"
            );
            assert_matches!(requeued[0].kind, SignKind::RespondBidirectional(_));
        }
    }

    #[tokio::test]
    async fn test_awaiting_response_bidirectional_requeues() {
        let backlog = Backlog::new();
        let tx = mock_tx(42);
        let sign_id = tx.sign_id();

        let completion_request = mock_bidi_response_request(sign_id, tx.id, Chain::Solana);

        let _entry = backlog
            .insert_mock_bidirectional(sign_id, Chain::Solana)
            .await
            .advance(mock_publish_state(true))
            .await
            .expect("phase 1 publishing")
            .advance(Arc::new(tx.clone()))
            .await
            .expect("executing")
            .advance(completion_request)
            .await
            .expect("final generating");

        let requeued = backlog.take_requeueable_requests(Chain::Solana).await;
        assert_eq!(requeued.len(), 1);
        assert_matches!(requeued[0].kind, SignKind::RespondBidirectional(_));
    }

    #[tokio::test]
    async fn test_publish_accepts_bidirectional_pending_generation() {
        let backlog = Backlog::new();
        let tx = mock_tx(43);
        let sign_id = tx.sign_id();

        let entry = backlog
            .insert_mock_bidirectional(sign_id, Chain::Solana)
            .await;

        let entry = entry
            .advance(mock_publish_state(true))
            .await
            .expect("pending generation should transition to publishing");

        let fetched = backlog
            .get_by::<Bidirectional<Initial<Publishing>>>(Chain::Solana, &sign_id)
            .await
            .expect("entry should remain in backlog");
        assert_eq!(fetched.request().id, sign_id);
        assert_eq!(entry.request().id, sign_id);
    }

    #[tokio::test]
    async fn test_publish_accepts_final_respond_generation() {
        let backlog = Backlog::new();
        let tx = mock_tx(44);
        let sign_id = tx.sign_id();

        let completion_request = mock_bidi_response_request(sign_id, tx.id, Chain::Solana);

        let entry = backlog
            .insert_mock_bidirectional(sign_id, Chain::Solana)
            .await
            .advance(mock_publish_state(true))
            .await
            .expect("phase 1 publishing")
            .advance(Arc::new(tx.clone()))
            .await
            .expect("executing")
            .advance(completion_request)
            .await
            .expect("final generating")
            .advance(mock_publish_state(true))
            .await
            .expect("final publishing");

        let fetched = backlog
            .get_by::<Bidirectional<Final<Publishing>>>(Chain::Solana, &sign_id)
            .await
            .expect("entry should remain in backlog");
        assert_eq!(fetched.request().id, sign_id);
        assert_eq!(entry.request().id, sign_id);
    }

    #[tokio::test]
    async fn test_watch_unwatch_and_respond() {
        let backlog = Backlog::new();
        let tx = mock_tx(7);
        let sign_id = tx.sign_id();

        // Insert a pending Sign request on the source chain
        backlog.insert_mock_sign(sign_id, tx.source_chain).await;

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

        // respond should transition to final response signing
        let completion_request = mock_bidi_response_request(sign_id, tx.id, tx.source_chain);
        backlog
            .respond(tx.source_chain, &sign_id, completion_request)
            .await
            .expect("respond should transition to final generating");
        assert!(backlog
            .get_by::<Bidirectional<Final<Generating>>>(tx.source_chain, &sign_id)
            .await
            .is_some());
    }

    #[tokio::test]
    async fn test_automatic_checkpoint_on_interval() {
        let backlog = Backlog::new();

        // Add some transactions
        let sign_id1 = SignId::from_u8(1);
        backlog
            .insert_mock_bidirectional(sign_id1, Chain::Ethereum)
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
        let sign_id1 = SignId::from_u8(1);
        backlog
            .insert_mock_bidirectional(sign_id1, Chain::Solana)
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
        backlog
            .insert_mock_bidirectional(SignId::from_u8(1), Chain::Solana)
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
        let tx = mock_tx(8);
        let sign_id = tx.sign_id();

        let _entry = backlog.insert_mock_sign(sign_id, tx.source_chain).await;

        let err = backlog
            .advance(tx.source_chain, sign_id, Arc::new(tx))
            .await
            .expect_err("advance should fail for plain Sign requests");

        assert_matches!(err, BacklogError::InvalidAdvanceTransition);
    }

    #[tokio::test]
    async fn test_advance_accepts_pending_generation_bidirectional() {
        let backlog = Backlog::new();
        let tx = mock_tx(9);
        let sign_id = tx.sign_id();

        let _entry = backlog
            .insert_mock_bidirectional(sign_id, tx.source_chain)
            .await;

        backlog
            .advance(tx.source_chain, sign_id, Arc::new(tx.clone()))
            .await
            .expect("advance should accept catchup advancement from PendingGeneration");

        let entry = backlog
            .get_by::<Bidirectional<Executing>>(tx.source_chain, &sign_id)
            .await
            .expect("entry should remain in backlog");
        assert_eq!(entry.execution_tx().id, tx.id);
    }

    #[tokio::test]
    async fn test_advance_accepts_pending_publish_bidirectional() {
        let backlog = Backlog::new();
        let tx = mock_tx(10);
        let sign_id = tx.sign_id();

        let entry = backlog
            .insert_mock_bidirectional(sign_id, tx.source_chain)
            .await
            .advance(mock_publish_state(true))
            .await
            .expect("should transition to publishing")
            .advance(Arc::new(tx.clone()))
            .await
            .expect("advance should succeed once respond() is confirmed from PendingPublish");

        assert_eq!(entry.execution_tx().id, tx.id);
        let fetched = backlog
            .get_by::<Bidirectional<Executing>>(tx.source_chain, &sign_id)
            .await
            .expect("entry should remain in backlog");
        assert_eq!(fetched.execution_tx().id, tx.id);
    }

    #[tokio::test]
    async fn test_total_pending_increments_on_insert() {
        let backlog = Backlog::new();

        backlog
            .insert_mock_sign(SignId::from_u8(1), Chain::Ethereum)
            .await;

        assert_eq!(backlog.len(), 1);
        assert!(!backlog.is_empty());
    }

    #[tokio::test]
    async fn test_total_pending_ignores_duplicate_inserts() {
        let backlog = Backlog::new();
        let sign_id = SignId::from_u8(1);

        // Insert first time
        backlog.insert_mock_sign(sign_id, Chain::Ethereum).await;
        assert_eq!(backlog.len(), 1);

        // Insert exactly the same ID again (overwrites)
        backlog.insert_mock_sign(sign_id, Chain::Ethereum).await;
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
            .insert_mock_sign(SignId::from_u8(1), Chain::Ethereum)
            .await;
        backlog
            .insert_mock_sign(SignId::from_u8(2), Chain::Solana)
            .await;

        assert_eq!(backlog.len(), 2);
    }

    #[tokio::test]
    async fn test_total_pending_decrements_on_remove() {
        let backlog = Backlog::new();
        let sign_id = SignId::from_u8(1);

        backlog.insert_mock_sign(sign_id, Chain::Ethereum).await;
        assert_eq!(backlog.len(), 1);

        backlog.remove(Chain::Ethereum, &sign_id).await;
        assert_eq!(backlog.len(), 0);
        assert!(backlog.is_empty());
    }

    #[tokio::test]
    async fn test_total_pending_ignores_invalid_removes() {
        let backlog = Backlog::new();
        let sign_id1 = SignId::from_u8(1);
        let sign_id2 = SignId::from_u8(2); // Not inserted

        backlog.insert_mock_sign(sign_id1, Chain::Ethereum).await;

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
                .insert_mock_sign(SignId::from_u8(i), Chain::Ethereum)
                .await;
        }
        backlog.set_processed_block(Chain::Ethereum, 10).await;
        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();

        // Clean backlog recovers the checkpoint
        let recovered = Backlog::new();
        assert_eq!(recovered.len(), 0);

        recovered
            .recover_by_checkpoint(checkpoint)
            .await
            .expect("failed to recover");

        assert_eq!(recovered.len(), 3);
    }

    #[tokio::test]
    async fn test_total_pending_updates_on_dirty_recovery() {
        let backlog = Backlog::new();

        // Populate 3 requests and create a checkpoint
        for i in 1..=3 {
            backlog
                .insert_mock_sign(SignId::from_u8(i), Chain::Ethereum)
                .await;
        }
        backlog.set_processed_block(Chain::Ethereum, 10).await;
        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();

        // Dirty backlog has 1 entirely different request before recovery
        let dirty_backlog = Backlog::new();
        dirty_backlog
            .insert_mock_sign(SignId::from_u8(99), Chain::Ethereum)
            .await;

        assert_eq!(dirty_backlog.len(), 1);

        // Recover from checkpoint (should overwrite the dirty state)
        dirty_backlog
            .recover_by_checkpoint(checkpoint)
            .await
            .expect("failed to recover");

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
            backlog.pending_checkpoint_count(chain).await,
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

        backlog.recover_by_checkpoint(fresh_cp).await.unwrap();
        assert_eq!(
            backlog.pending_checkpoint_count(chain).await,
            2,
            "pending checkpoints should remain available for consensus matching"
        );
    }
}
