pub mod selection;

use self::selection::select_checkpoints;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::{Chain, IndexedSignRequest, SignKind};
use crate::sign_bidirectional::{BidirectionalTx, BidirectionalTxId, SignStatus};
use crate::storage::checkpoint_storage::CheckpointStorage;

use anyhow::Context;
use mpc_primitives::{PendingTx, SignId};
use std::collections::{hash_map, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub use mpc_primitives::Checkpoint;

// Clean up old checkpoints (older than 30 minutes)
const RETENTION_DURATION: Duration = Duration::from_secs(30 * 60);

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

    /// Returns all sign-respond transactions with a specific status
    pub fn get_by_status(&self, status: SignStatus) -> HashMap<SignId, BacklogEntry> {
        self.requests
            .iter()
            .filter(|(_, entry)| entry.status() == status)
            .map(|(id, entry)| (*id, entry.clone()))
            .collect()
    }

    fn pending_execution(&self) -> Vec<(SignId, BacklogEntry)> {
        self.requests
            .iter()
            .filter(|(_, entry)| entry.status() == SignStatus::PendingExecution)
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

    fn checkpoint(&self, chain: Chain) -> Checkpoint {
        let mut encoded = self
            .requests
            .iter()
            .map(|(&sign_id, entry)| {
                let mut transaction = Vec::new();
                ciborium::ser::into_writer(entry, &mut transaction)
                    .expect("serialize backlog entry for checkpoint");
                PendingTx {
                    sign_id,
                    transaction,
                }
            })
            .collect::<Vec<_>>();
        encoded.sort_by_key(|pending| pending.sign_id);

        Checkpoint {
            chain,
            block_height: self.processed_block_height.unwrap_or(0),
            pending_requests: encoded,
        }
    }

    fn from_checkpoint(checkpoint: Checkpoint) -> anyhow::Result<Self> {
        fn decode(pending: mpc_primitives::PendingTx) -> anyhow::Result<(SignId, BacklogEntry)> {
            let entry: BacklogEntry = ciborium::de::from_reader(pending.transaction.as_slice())
                .with_context(|| {
                    format!(
                        "failed to deserialize pending backlog entry for sign_id {:?}",
                        pending.sign_id
                    )
                })?;
            Ok((pending.sign_id, entry))
        }

        let mut requests = HashMap::new();
        for pending_tx in checkpoint.pending_requests {
            let (sign_id, tx) = decode(pending_tx)?;
            requests.insert(sign_id, tx);
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
    tx: BidirectionalTx,
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

    fn all(&self) -> HashMap<BidirectionalTxId, (SignId, BidirectionalTx)> {
        self.watchers
            .iter()
            .map(|(id, watcher)| (*id, (watcher.sign_id, watcher.tx.clone())))
            .collect()
    }
}

/// Historical checkpoint with timestamp for retention management
#[derive(Debug, Clone)]
struct HistoricalCheckpoint {
    checkpoint: Checkpoint,
    created_at: Instant,
}

/// Backlog manages pending sign-respond requests across multiple chains.
/// Each chain has its own isolated set of pending requests with their own
/// publish queues.
#[derive(Debug, Clone)]
pub struct Backlog {
    storage: CheckpointStorage,
    requests: Arc<RwLock<HashMap<Chain, PendingRequests>>>,
    recovered_requests: Arc<RwLock<HashMap<Chain, HashSet<SignId>>>>,
    execution_watchers: Arc<RwLock<HashMap<Chain, ExecutionWatchers>>>,
    /// Historical checkpoints kept for 30 minutes, indexed by chain
    historical_checkpoints: Arc<RwLock<HashMap<Chain, Vec<HistoricalCheckpoint>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryRequeueMode {
    #[default]
    Immediate,
    AfterCatchup,
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

    pub fn persisted(storage: CheckpointStorage) -> Self {
        Self {
            storage,
            requests: Arc::new(RwLock::new(HashMap::new())),
            recovered_requests: Arc::new(RwLock::new(HashMap::new())),
            execution_watchers: Arc::new(RwLock::new(HashMap::new())),
            historical_checkpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, request: IndexedSignRequest) -> Option<BacklogEntry> {
        let chain = request.chain;
        let id = request.id;
        let entry = BacklogEntry::new(request);
        let (prev, len) = {
            let mut requests = self.requests.write().await;
            let pending = requests.entry(chain).or_insert_with(PendingRequests::new);
            let p = pending.insert(id, entry);
            (p, pending.len())
        };

        self.observe_backlog_size(chain, len);
        self.unmark_recovered_request(chain, &id).await;
        prev
    }

    pub async fn remove(&self, chain: Chain, id: &SignId) -> Option<BacklogEntry> {
        let (removed, len) = {
            let mut requests = self.requests.write().await;
            let pending = requests.entry(chain).or_insert_with(PendingRequests::new);
            let rem = pending.remove(id);
            (rem, pending.len())
        };

        self.observe_backlog_size(chain, len);
        self.unmark_recovered_request(chain, id).await;
        removed
    }

    pub async fn get(&self, chain: Chain, id: &SignId) -> Option<BacklogEntry> {
        self.requests
            .read()
            .await
            .get(&chain)
            .and_then(|pending_requests| pending_requests.get(id).cloned())
    }

    /// Returns the number of pending requests in total
    pub async fn len(&self) -> usize {
        self.requests
            .read()
            .await
            .values()
            .map(|requests| requests.len())
            .sum()
    }

    /// Returns true if there are no pending requests
    pub async fn is_empty(&self) -> bool {
        self.requests.read().await.is_empty()
    }

    fn observe_backlog_size(&self, chain: Chain, len: usize) {
        crate::metrics::requests::BACKLOG_SIZE
            .with_label_values(&[chain.as_str()])
            .set(len as i64);
    }

    async fn unmark_recovered_request(&self, chain: Chain, id: &SignId) {
        let mut recovered_requests = self.recovered_requests.write().await;
        let Some(recovered) = recovered_requests.get_mut(&chain) else {
            return;
        };

        recovered.remove(id);
        if recovered.is_empty() {
            recovered_requests.remove(&chain);
        }
    }

    async fn set_recovered_requests(&self, chain: Chain, sign_ids: HashSet<SignId>) {
        let mut recovered_requests = self.recovered_requests.write().await;
        match recovered_requests.entry(chain) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(sign_ids);
            }
            hash_map::Entry::Occupied(entry) => {
                tracing::error!(
                    %chain,
                    new_requests_len = sign_ids.len(),
                    old_requests_len = entry.get().len(),
                    "attempting to set recovered requests but it already has an entry",
                );
            }
        }
    }

    /// Removes recovered requests for a chain and returns a list of them filtered
    /// to only those that should be enqueued for processing.
    pub async fn take_requeueable_requests(&self, chain: Chain) -> Vec<IndexedSignRequest> {
        let recovered_sign_ids = {
            let mut recovered_requests = self.recovered_requests.write().await;
            let Some(recovered) = recovered_requests.remove(&chain) else {
                return Vec::new();
            };
            recovered
        };

        let requests = self.requests.read().await;
        let Some(pending) = requests.get(&chain) else {
            return Vec::new();
        };

        recovered_sign_ids
            .into_iter()
            .filter_map(|sign_id| pending.get(&sign_id))
            .filter_map(|entry| {
                if entry.status() == SignStatus::AwaitingResponseBidirectional
                    || (entry.status() == SignStatus::AwaitingResponse
                        && entry.execution_tx().is_none())
                {
                    Some(entry.request.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns all sign-respond transactions with a specific status
    pub async fn get_by_status(
        &self,
        chain: Chain,
        status: SignStatus,
    ) -> HashMap<SignId, BacklogEntry> {
        self.requests
            .read()
            .await
            .get(&chain)
            .map(|requests| requests.get_by_status(status))
            .unwrap_or_default()
    }

    pub async fn len_by_chain(&self, chain: Chain) -> usize {
        self.requests
            .read()
            .await
            .get(&chain)
            .map(|requests| requests.len())
            .unwrap_or(0)
    }

    /// Mark a request as published (success or failure)
    pub async fn mark_published(
        &self,
        _chain: Chain,
        _id: &SignId,
        _success: bool,
    ) -> Result<(), BacklogError> {
        // TODO: implement
        Ok(())
    }

    // TODO: the backlog is a bit bloated with transition functions, so we need to do a proper cleanup
    // where we can have proper typestate on a set of types. With these types, we can easily guide
    // ourselves into the right transitions. For now, this is used to set the request in
    // `execution_confirmed` to transition from PendingExecution to AwaitingResponseBidirectional.
    pub async fn set_request(
        &self,
        chain: Chain,
        id: &SignId,
        request: IndexedSignRequest,
    ) -> Result<(), BacklogError> {
        let mut requests = self.requests.write().await;
        let Some(pending) = requests.get_mut(&chain) else {
            return Err(BacklogError::ChainNotFound);
        };
        let Some(entry) = pending.requests.get_mut(id) else {
            return Err(BacklogError::NotFound { chain, id: *id });
        };
        entry.set_request(request);
        Ok(())
    }

    /// Begin watching for execution of a bidirectional transaction on the destination chain.
    pub async fn watch_execution(
        &self,
        chain: Chain,
        sign_id: SignId,
        tx: BidirectionalTx,
    ) -> Option<(SignId, BidirectionalTx)> {
        let mut watchers = self.execution_watchers.write().await;
        let entry = watchers.entry(chain).or_default();
        entry
            .insert(tx.id, ExecutionWatcher { sign_id, tx })
            .map(|previous| (previous.sign_id, previous.tx))
    }

    /// Stop watching for execution of a bidirectional transaction on the destination chain.
    pub async fn unwatch_execution(
        &self,
        chain: Chain,
        tx_id: &BidirectionalTxId,
    ) -> Option<(SignId, BidirectionalTx)> {
        let mut watchers = self.execution_watchers.write().await;
        watchers
            .get_mut(&chain)
            .and_then(|entry| entry.remove(tx_id))
            .map(|watcher| (watcher.sign_id, watcher.tx))
    }

    /// Get the set of bidirectional transactions currently awaiting execution on the
    /// specified destination chain.
    pub async fn pending_execution(
        &self,
        chain: Chain,
    ) -> HashMap<BidirectionalTxId, (SignId, BidirectionalTx)> {
        self.execution_watchers
            .read()
            .await
            .get(&chain)
            .map(ExecutionWatchers::all)
            .unwrap_or_default()
    }

    /// Update the status of a tracked bidirectional transaction on the source chain.
    pub async fn set_status(
        &self,
        chain: Chain,
        id: &SignId,
        status: SignStatus,
    ) -> Option<BacklogEntry> {
        let mut requests = self.requests.write().await;
        let Some(pending) = requests.get_mut(&chain) else {
            tracing::warn!(?chain, ?id, ?status, "set_status: chain not found");
            return None;
        };
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
        bidirectional_tx: BidirectionalTx,
    ) -> Result<(), BacklogError> {
        // Update the transaction in the backlog from Sign to Bidirectional
        let mut requests = self.requests.write().await;
        let pending = requests
            .get_mut(&chain)
            .ok_or(BacklogError::ChainNotFound)?;

        let entry = pending
            .requests
            .get_mut(&sign_id)
            .ok_or(BacklogError::NotFound { chain, id: sign_id })?;

        entry.advance_to_execution(bidirectional_tx.clone())?;

        // Registration successful, now register the execution watcher on the target chain
        let target_chain = bidirectional_tx.target_chain;
        drop(requests);
        self.watch_execution(target_chain, sign_id, bidirectional_tx)
            .await;
        Ok(())
    }

    /// Get the processed block height for a specific chain
    pub async fn processed_block(&self, chain: Chain) -> Option<u64> {
        self.requests
            .read()
            .await
            .get(&chain)
            .and_then(|pr| pr.processed_block_height())
    }

    /// Set the processed block height for a specific chain.
    /// Returns Some(Checkpoint) if a checkpoint should be created and submitted at this block height.
    pub async fn set_processed_block(&self, chain: Chain, height: u64) -> Option<Checkpoint> {
        let interval = chain.checkpoint_interval()?;
        self.set_processed_block_interval(chain, height, interval)
            .await
    }

    pub async fn set_processed_block_interval(
        &self,
        chain: Chain,
        height: u64,
        interval: u64,
    ) -> Option<Checkpoint> {
        let mut requests = self.requests.write().await;
        let pending = requests.entry(chain).or_default();
        pending.set_processed_block(height);

        tracing::trace!(
            ?chain,
            height,
            ?interval,
            "backlog updated processed block height"
        );

        // create a checkpoint on interval
        if height.is_multiple_of(interval) {
            let tx_count = pending.len();
            drop(requests);
            let checkpoint = self.checkpoint(chain).await;
            tracing::info!(?chain, height, tx_count, ?checkpoint, "creating checkpoint");

            Some(checkpoint)
        } else {
            None
        }
    }

    /// Create a checkpoint of the current backlog state for a specific chain
    pub async fn checkpoint(&self, chain: Chain) -> Checkpoint {
        let checkpoint = self
            .requests
            .read()
            .await
            .get(&chain)
            .map(|pr| pr.checkpoint(chain))
            .unwrap_or_else(|| Checkpoint::empty(chain));

        // Store checkpoint in historical checkpoints
        let mut historical = self.historical_checkpoints.write().await;
        let historical = historical.entry(chain).or_insert_with(Vec::new);
        historical.push(HistoricalCheckpoint {
            checkpoint: checkpoint.clone(),
            created_at: Instant::now(),
        });
        historical.retain(|hcp| hcp.created_at.elapsed() < RETENTION_DURATION);

        if let Err(err) = self.storage.persist(&checkpoint).await {
            tracing::warn!(?chain, %err, "failed to persist checkpoint");
        }

        checkpoint
    }

    pub async fn latest_checkpoint(&self, chain: Chain) -> Option<Checkpoint> {
        let historical = self.historical_checkpoints.read().await;
        historical.get(&chain).and_then(|checkpoints| {
            checkpoints
                .iter()
                .max_by_key(|hcp| hcp.checkpoint.block_height)
                .map(|hcp| hcp.checkpoint.clone())
        })
    }

    /// Find a historical checkpoint by hash
    pub async fn find_checkpoint_by_hash(&self, chain: Chain, hash: u64) -> Option<Checkpoint> {
        let historical = self.historical_checkpoints.read().await;
        if let Some(checkpoints) = historical.get(&chain) {
            for hcp in checkpoints {
                let mut hasher = hash_map::DefaultHasher::new();
                hcp.checkpoint.hash(&mut hasher);
                if hasher.finish() == hash {
                    return Some(hcp.checkpoint.clone());
                }
            }
        }
        None
    }

    /// Recover backlog state from a checkpoint
    /// This is called when a node restarts and needs to catch up
    pub async fn recover_by_checkpoint(&self, checkpoint: Checkpoint) -> anyhow::Result<()> {
        let chain = checkpoint.chain;
        tracing::info!(
            ?chain,
            block_height = checkpoint.block_height,
            num_pending = checkpoint.pending_requests.len(),
            "recovering from checkpoint"
        );

        let mut requests = self.requests.write().await;
        let pending = requests
            .entry(checkpoint.chain)
            .or_insert_with(PendingRequests::new);

        let previous_height = pending.processed_block_height().unwrap_or(0);
        let checkpoint_height = checkpoint.block_height;

        // Execution watchers are ephemeral, we need to get all the execution watchers here
        let execution_to_watch = if checkpoint_height > previous_height {
            let cleared = pending.len();
            *pending = PendingRequests::from_checkpoint(checkpoint)?;
            let execution_to_watch = pending.pending_execution();

            tracing::info!(
                ?chain,
                old_block = previous_height,
                new_block = checkpoint_height,
                cleared_requests = cleared,
                restored_requests = pending.len(),
                "successfully recovered from checkpoint"
            );

            execution_to_watch
        } else {
            tracing::warn!(
                chain = ?checkpoint.chain,
                checkpoint_block = checkpoint.block_height,
                previous_height,
                "checkpoint block is not newer than current block, skipping recovery"
            );

            Vec::new()
        };
        drop(requests);

        // now repopulate our execution watchers
        for (sign_id, tx) in execution_to_watch {
            // Only restore execution watchers for bidirectional transactions
            if let Some(tx) = tx.take_execution_tx() {
                self.watch_execution(tx.target_chain, sign_id, tx).await;
            }
        }

        Ok(())
    }

    pub async fn recover(
        &self,
        mesh_state: &MeshState,
        node_client: &NodeClient,
        threshold: usize,
        chains: &[Chain],
    ) -> HashMap<Chain, RecoveryRequeueMode> {
        tracing::info!("attempting to recover from latest checkpoints via node selection");

        // Load local checkpoints first
        let mut local_checkpoints = HashMap::new();
        for &chain in chains {
            match self.storage.load_latest(chain).await {
                Ok(Some(checkpoint)) => {
                    tracing::info!(
                        ?chain,
                        block_height = checkpoint.block_height,
                        "loaded local checkpoint"
                    );
                    local_checkpoints.insert(chain, checkpoint);
                }
                Ok(None) => {
                    tracing::info!(?chain, "no local checkpoint found");
                }
                Err(err) => {
                    tracing::warn!(?chain, %err, "failed to load local checkpoint");
                }
            }
        }

        // p2p node selection to find checkpoints.
        // Fetches all checkpoints from active participants and creates a selected checkpoint:
        // - sorts all checkpoints by block height
        // - selects threshold lowest block height checkpoint
        let mut remote_checkpoints =
            select_checkpoints(mesh_state, node_client, threshold, chains).await;

        if local_checkpoints.is_empty() && remote_checkpoints.is_empty() {
            tracing::info!("no selected checkpoints found, starting with empty state");
            return HashMap::new();
        }

        let mut recovered_modes = HashMap::new();
        for &chain in chains {
            let local_checkpoint = local_checkpoints.remove(&chain);
            let remote_checkpoint = remote_checkpoints.remove(&chain);

            let Some((checkpoint, requeue_mode)) =
                select_recovery_checkpoint(chain, local_checkpoint, remote_checkpoint).await
            else {
                continue;
            };
            tracing::info!(
                ?chain,
                block_height = checkpoint.block_height,
                ?requeue_mode,
                "found selected checkpoint, attempting recovery"
            );
            if let Err(err) = self.recover_by_checkpoint(checkpoint).await {
                tracing::warn!(
                    ?chain,
                    %err,
                    "failed to recover from selected checkpoint, continuing with empty state"
                );
                continue;
            }

            recovered_modes.insert(chain, requeue_mode);
        }

        // Mark the following sign_ids as recovered to requeue them after catchup.
        // If they're removed before catchup completes, they're unmarked from recovery
        // and will not be requeued
        let requests = self.requests.read().await;
        for &chain in chains {
            if let Some(pending) = requests.get(&chain) {
                let sign_ids: HashSet<_> = pending.requests.keys().copied().collect();
                if !sign_ids.is_empty() {
                    self.set_recovered_requests(chain, sign_ids).await;
                }
            }
        }

        recovered_modes
    }
}

/// Errors that can occur when working with Backlog
#[derive(Debug, thiserror::Error)]
pub enum BacklogError {
    #[error("request not found for chain {chain:?} with id {id:?}")]
    NotFound { chain: Chain, id: SignId },
    #[error("chain not initialized: {chain:?}")]
    ChainNotInitialized { chain: Chain },
    #[error("chain not found")]
    ChainNotFound,
    #[error("transaction not found")]
    TransactionNotFound,
    #[error("cannot advance non-bidirectional or already-advanced backlog entry")]
    InvalidAdvanceTransition,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BacklogEntry {
    pub request: IndexedSignRequest,
    pub status: SignStatus,
    pub execution: Option<BidirectionalTx>,
}

impl BacklogEntry {
    pub fn new(request: IndexedSignRequest) -> Self {
        Self {
            request,
            status: SignStatus::AwaitingResponse,
            execution: None,
        }
    }

    pub fn with_status(
        request: IndexedSignRequest,
        status: SignStatus,
        execution: Option<BidirectionalTx>,
    ) -> Self {
        Self {
            request,
            status,
            execution,
        }
    }

    pub fn pending_execution(request: IndexedSignRequest, tx: BidirectionalTx) -> Self {
        Self::with_status(request, SignStatus::PendingExecution, Some(tx))
    }

    pub fn sign_id(&self) -> SignId {
        self.request.id
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
        self.status
    }

    /// Set the status of this transaction
    pub fn set_status(&mut self, status: SignStatus) {
        self.status = status;
    }

    pub fn set_request(&mut self, request: IndexedSignRequest) {
        self.request = request;
    }

    pub fn advance_to_execution(
        &mut self,
        bidirectional_tx: BidirectionalTx,
    ) -> Result<(), BacklogError> {
        match (&self.request.kind, self.status) {
            (SignKind::SignBidirectional(_), SignStatus::AwaitingResponse) => {
                self.status = SignStatus::PendingExecution;
                self.execution = Some(bidirectional_tx);
                Ok(())
            }
            _ => Err(BacklogError::InvalidAdvanceTransition),
        }
    }

    /// Get target chain if this is a bidirectional transaction
    // TODO: looks a bit weird having two different ways to get target_chain in the match
    pub fn target_chain(&self) -> Option<Chain> {
        self.execution
            .as_ref()
            .map(|tx| tx.target_chain)
            .or_else(|| match &self.request.kind {
                SignKind::Sign => None,
                SignKind::SignBidirectional(event) => event.target_chain().ok(),
                SignKind::RespondBidirectional(_) => None,
            })
    }

    /// Check if this is a bidirectional transaction
    pub fn is_bidirectional(&self) -> bool {
        matches!(self.request.kind, SignKind::SignBidirectional(_))
    }

    pub fn execution_tx(&self) -> Option<&BidirectionalTx> {
        self.execution.as_ref()
    }

    pub fn take_execution_tx(self) -> Option<BidirectionalTx> {
        self.execution
    }

    pub fn typename(&self) -> &'static str {
        match (&self.request.kind, self.execution.is_some(), self.status) {
            (SignKind::Sign, _, _) => "Sign",
            (SignKind::SignBidirectional(_), true, _) => "BidirectionalExecution",
            (SignKind::SignBidirectional(_), false, SignStatus::AwaitingResponse) => {
                "BidirectionalPending"
            }
            (SignKind::SignBidirectional(_), false, _) => "BidirectionalPending",
            (SignKind::RespondBidirectional(_), _, SignStatus::AwaitingResponseBidirectional) => {
                "BidirectionalRespondPending"
            }
            (SignKind::RespondBidirectional(_), _, _) => "RespondBidirectional",
        }
    }
}

fn chain_supports_catchup(chain: Chain) -> bool {
    matches!(chain, Chain::Ethereum)
}

async fn select_recovery_checkpoint(
    chain: Chain,
    local_checkpoint: Option<Checkpoint>,
    remote_checkpoint: Option<Checkpoint>,
) -> Option<(Checkpoint, RecoveryRequeueMode)> {
    let checkpoint = match (local_checkpoint, remote_checkpoint) {
        (Some(local), None) => local,
        (None, Some(remote)) => remote,
        (Some(local), Some(remote)) => {
            if local.block_height >= remote.block_height {
                local
            } else {
                remote
            }
        }
        (None, None) => {
            tracing::warn!(?chain, "no checkpoint available for recovery");
            return None;
        }
    };

    let requeue_mode = if chain_supports_catchup(chain) {
        tracing::info!(
            ?chain,
            block_height = checkpoint.block_height,
            "recovering from local checkpoint; requeue deferred until catchup"
        );
        RecoveryRequeueMode::AfterCatchup
    } else {
        RecoveryRequeueMode::Immediate
    };

    Some((checkpoint, requeue_mode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::SignKind,
        respond_bidirectional::RespondBidirectionalTx,
        sign_bidirectional::{BidirectionalTx, BidirectionalTxId, SignStatus},
        stream::ops::SignBidirectionalEvent,
    };
    use alloy::primitives::{Address, B256};
    use anchor_lang::prelude::Pubkey;
    use mpc_primitives::{SignArgs, SignId};

    fn create_test_tx(id: u8) -> BidirectionalTx {
        BidirectionalTx {
            id: BidirectionalTxId(B256::from([id; 32])),
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
            respond_serialization_schema: vec![],
            request_id: [id; 32],
            from_address: Address::ZERO,
            nonce: 0,
        }
    }

    fn create_test_event(dest: &str) -> SignBidirectionalEvent {
        let mut program_id = [0u8; 32];
        let prefix_len = dest.len().min(program_id.len());
        program_id[..prefix_len].copy_from_slice(&dest.as_bytes()[..prefix_len]);

        SignBidirectionalEvent::Solana(signet_program::SignBidirectionalEvent {
            sender: Default::default(),
            serialized_transaction: vec![],
            dest: dest.to_string(),
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 0,
            deposit: 0,
            path: "".to_string(),
            algo: "".to_string(),
            params: "".to_string(),
            program_id: Pubkey::new_from_array(program_id),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
        })
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
    ) -> IndexedSignRequest {
        IndexedSignRequest::new(sign_id, args, chain, unix_timestamp_indexed, kind)
    }

    fn create_bidirectional_request(
        sign_id: SignId,
        chain: Chain,
        dest: &str,
        unix_timestamp_indexed: u64,
    ) -> IndexedSignRequest {
        IndexedSignRequest::sign_bidirectional(
            sign_id,
            create_test_args(sign_id.request_id[0]),
            chain,
            unix_timestamp_indexed,
            create_test_event(dest),
        )
    }

    fn create_execution_entry(
        tx: BidirectionalTx,
        chain: Chain,
        status: SignStatus,
        dest: &str,
    ) -> BacklogEntry {
        let sign_id = SignId::new(tx.request_id);
        let request = IndexedSignRequest::new(
            sign_id,
            create_test_args(tx.request_id[0]),
            chain,
            0,
            SignKind::SignBidirectional(create_test_event(dest)),
        );
        BacklogEntry::with_status(request, status, Some(tx))
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
            SignStatus::AwaitingResponse => {}
            SignStatus::AwaitingResponseBidirectional => {
                let completion_request = IndexedSignRequest::respond_bidirectional(
                    sign_id,
                    create_test_args(sign_id.request_id[0]),
                    chain,
                    0,
                    RespondBidirectionalTx {
                        tx_id: tx.id,
                        output: vec![],
                    },
                );
                backlog
                    .set_request(chain, &sign_id, completion_request)
                    .await
                    .unwrap();
            }
            SignStatus::PendingExecution => {
                backlog.advance(chain, sign_id, tx).await.unwrap();
            }
        }

        if status == SignStatus::AwaitingResponseBidirectional {
            backlog.set_status(chain, &sign_id, status).await;
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
            SignStatus::AwaitingResponse,
            "ethereum",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::Solana,
            tx_sol.clone(),
            SignStatus::AwaitingResponse,
            "solana",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::NEAR,
            tx_near.clone(),
            SignStatus::AwaitingResponse,
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
        let tx1 = create_test_tx(1);
        let tx2 = create_test_tx(2);
        let tx3 = create_test_tx(3);

        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx1,
            SignStatus::AwaitingResponse,
            "ethereum",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx2,
            SignStatus::AwaitingResponseBidirectional,
            "ethereum",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx3,
            SignStatus::PendingExecution,
            "ethereum",
        )
        .await;

        // Add transactions to Solana
        let tx4 = create_test_tx(4);
        insert_bidirectional_with_status(
            &backlog,
            Chain::Solana,
            tx4,
            SignStatus::PendingExecution,
            "solana",
        )
        .await;

        // Filter Ethereum by Pending
        let eth_pending = backlog
            .get_by_status(Chain::Ethereum, SignStatus::PendingExecution)
            .await;
        assert_eq!(eth_pending.len(), 1);

        let eth_awaiting = backlog
            .get_by_status(Chain::Ethereum, SignStatus::AwaitingResponse)
            .await;
        assert_eq!(eth_awaiting.len(), 1);

        // Filter Ethereum by bidirectional completion awaiting final respond
        let eth_completion = backlog
            .get_by_status(Chain::Ethereum, SignStatus::AwaitingResponseBidirectional)
            .await;
        assert_eq!(eth_completion.len(), 1);

        // Filter Solana by Pending
        let sol_pending = backlog
            .get_by_status(Chain::Solana, SignStatus::PendingExecution)
            .await;
        assert_eq!(sol_pending.len(), 1);

        // Filter non-existent chain returns empty
        let near_pending = backlog
            .get_by_status(Chain::NEAR, SignStatus::PendingExecution)
            .await;
        assert_eq!(near_pending.len(), 0);
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
                    SignStatus::AwaitingResponse,
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
                    SignStatus::AwaitingResponse,
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
        backlog.set_processed_block(Chain::Ethereum, 100).await;

        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx1.clone(),
            SignStatus::PendingExecution,
            "ethereum",
        )
        .await;
        insert_bidirectional_with_status(
            &backlog,
            Chain::Ethereum,
            tx2.clone(),
            SignStatus::AwaitingResponseBidirectional,
            "ethereum",
        )
        .await;

        let checkpoint = backlog.checkpoint(Chain::Ethereum).await;
        assert_eq!(checkpoint.block_height, 100);
        assert_eq!(checkpoint.chain, Chain::Ethereum);
        assert_eq!(checkpoint.pending_requests.len(), 2);
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
                SignStatus::AwaitingResponse,
                "ethereum",
            ),
        );
        pending1.insert(
            SignId::new(tx2.request_id),
            create_execution_entry(
                tx2.clone(),
                Chain::Ethereum,
                SignStatus::AwaitingResponse,
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
                SignStatus::AwaitingResponse,
                "ethereum",
            ),
        );
        pending2.insert(
            SignId::new(tx2.request_id),
            create_execution_entry(
                tx2.clone(),
                Chain::Ethereum,
                SignStatus::AwaitingResponse,
                "ethereum",
            ),
        );
        pending2.set_processed_block(100);

        let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
        let checkpoint2 = pending2.checkpoint(Chain::Ethereum);
        // Same data should be equal
        assert_eq!(checkpoint1, checkpoint2);

        // Different block height should not be equal
        let mut checkpoint3 = pending2.checkpoint(Chain::Ethereum);
        checkpoint3.block_height = 101;
        assert_ne!(checkpoint1, checkpoint3);
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
                SignStatus::AwaitingResponse,
                "ethereum",
            ),
        );
        pending.set_processed_block(100);
        let checkpoint = pending.checkpoint(Chain::Ethereum);

        // Test JSON serialization
        let json = serde_json::to_string(&checkpoint).unwrap();
        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(checkpoint, deserialized);

        let (sign_id, restored_tx) = {
            let pending = &checkpoint.pending_requests[0];
            let backlog_entry: BacklogEntry =
                ciborium::de::from_reader(pending.transaction.as_slice()).unwrap();
            let tx = backlog_entry
                .take_execution_tx()
                .expect("Expected pending execution entry");
            (pending.sign_id, tx)
        };
        assert_eq!(sign_id, SignId::new(tx1.request_id));
        assert_eq!(
            restored_tx.serialized_transaction,
            tx1.serialized_transaction
        );
    }

    #[tokio::test]
    async fn test_recover_restores_execution_watchers() {
        let backlog = Backlog::new();
        let tx = create_test_tx(6);

        insert_bidirectional_with_status(
            &backlog,
            Chain::Solana,
            tx.clone(),
            SignStatus::PendingExecution,
            "ethereum",
        )
        .await;
        backlog.set_processed_block(Chain::Solana, 10).await;

        let checkpoint = backlog.checkpoint(Chain::Solana).await;

        let recovered = Backlog::new();
        recovered
            .recover_by_checkpoint(checkpoint)
            .await
            .expect("failed to recover");

        let watchers = recovered.pending_execution(Chain::Ethereum).await;
        assert_eq!(watchers.len(), 1);
        assert!(watchers.contains_key(&tx.id));
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
        let sign_kind = SignKind::SignBidirectional(SignBidirectionalEvent::Solana(
            signet_program::SignBidirectionalEvent {
                sender: Default::default(),
                serialized_transaction: vec![1, 2, 3],
                dest: "ethereum".to_string(),
                caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
                key_version: 1,
                deposit: 10,
                path: "m/0".to_string(),
                algo: "ECDSA".to_string(),
                params: "{}".to_string(),
                program_id,
                output_deserialization_schema: vec![9],
                respond_serialization_schema: vec![8],
            },
        ));

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

        let checkpoint = backlog.checkpoint(Chain::Solana).await;

        let recovered = Backlog::new();
        recovered
            .recover_by_checkpoint(checkpoint)
            .await
            .expect("failed to recover");

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
        let status = SignStatus::AwaitingResponseBidirectional;
        for offset in 0..2 {
            let backlog = Backlog::new();
            let tx = create_test_tx(8 + offset as u8);
            let sign_id = SignId::new(tx.request_id);

            insert_bidirectional_with_status(
                &backlog,
                Chain::Solana,
                tx.clone(),
                status,
                "ethereum",
            )
            .await;
            backlog.set_processed_block(Chain::Solana, 10).await;

            let checkpoint = backlog.checkpoint(Chain::Solana).await;

            let recovered = Backlog::new();
            recovered
                .recover_by_checkpoint(checkpoint)
                .await
                .expect("failed to recover");

            let completion_request = IndexedSignRequest::respond_bidirectional(
                sign_id,
                create_test_args(sign_id.request_id[0]),
                Chain::Solana,
                0,
                RespondBidirectionalTx {
                    tx_id: tx.id,
                    output: vec![],
                },
            );
            recovered
                .set_request(Chain::Solana, &sign_id, completion_request)
                .await
                .expect("failed to store completion request");
            recovered
                .set_status(
                    Chain::Solana,
                    &sign_id,
                    SignStatus::AwaitingResponseBidirectional,
                )
                .await;
            recovered
                .set_recovered_requests(Chain::Solana, HashSet::from([sign_id]))
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
            },
        );

        backlog.insert(completion_request).await;
        backlog
            .set_status(
                Chain::Solana,
                &sign_id,
                SignStatus::AwaitingResponseBidirectional,
            )
            .await;
        backlog
            .set_recovered_requests(Chain::Solana, HashSet::from([sign_id]))
            .await;

        let requeued = backlog.take_requeueable_requests(Chain::Solana).await;
        assert_eq!(requeued.len(), 1);
        assert!(matches!(
            requeued[0].kind,
            SignKind::RespondBidirectional(_)
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
            .watch_execution(tx.target_chain, sign_id, tx.clone())
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
                SignStatus::AwaitingResponseBidirectional,
            )
            .await;
        let successes = backlog
            .get_by_status(tx.source_chain, SignStatus::AwaitingResponseBidirectional)
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
            SignStatus::PendingExecution,
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
            SignStatus::PendingExecution,
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
            .advance(tx.source_chain, sign_id, tx)
            .await
            .expect_err("advance should fail for plain Sign requests");

        assert!(matches!(err, BacklogError::InvalidAdvanceTransition));
    }
}
