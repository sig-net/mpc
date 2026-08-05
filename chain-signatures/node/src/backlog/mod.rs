pub mod consensus;

use crate::sign_bidirectional::{
    CheckpointPhase, PublishState, SignBidirectionalEventExt, SignStatus,
};
use crate::storage::checkpoint_storage::CheckpointStorage;

use anyhow::Context;
use mpc_chain_integration_core::StateManager;
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainConfig as _, IndexedSignRequest, PendingTx,
    SignId, SignKind,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

pub use mpc_primitives::Checkpoint;

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

fn canonical_request_bytes(request: &IndexedSignRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &(request.id, &request.args, request.chain, &request.kind),
        &mut bytes,
    )
    .expect("serialize canonical checkpoint request");
    bytes
}

fn canonical_execution_tx(entry: &BacklogEntry) -> Option<&BidirectionalTx> {
    // A watcher attached to an ordinary `Sign` entry is local recovery state
    // and must not enter consensus. For completion work, the transaction is
    // derived from the source-chain response and is therefore safe to commit;
    // target execution output is not part of `BidirectionalTx` and remains local.
    if entry.status().checkpoint_phase() == CheckpointPhase::AwaitingInitialResponse {
        return None;
    }

    entry.execution_tx()
}

fn canonical_entry_bytes(entry: &BacklogEntry) -> Vec<u8> {
    let phase = match entry.status().checkpoint_phase() {
        CheckpointPhase::AwaitingInitialResponse => 0u8,
        CheckpointPhase::AwaitingBidirectionalCompletion => 1u8,
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &(
            canonical_request_bytes(entry.original_request()),
            phase,
            canonical_execution_tx(entry),
        ),
        &mut bytes,
    )
    .expect("serialize canonical checkpoint entry");
    bytes
}

fn normalize_recovered_entry(mut entry: BacklogEntry) -> anyhow::Result<BacklogEntry> {
    // Checkpoint consensus carries the source projection only. Never restore
    // a donor's publisher identity, publication signature, final response, or
    // target output. Rewatch source-derived execution from the original request
    // and regenerate the final response locally when execution is observed.
    let original_request = entry.original_request().clone();
    match entry.status().checkpoint_phase() {
        CheckpointPhase::AwaitingInitialResponse => {
            entry.request = original_request.clone();
            entry.original_request = Some(original_request);
            entry.execution = None;
            entry.status = SignStatus::PendingGeneration;
        }
        CheckpointPhase::AwaitingBidirectionalCompletion => {
            let tx = entry.execution_tx().cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "completion checkpoint entry is missing its source-derived execution transaction"
                )
            })?;
            validate_execution_tx(&original_request, &tx)?;
            entry.request = original_request.clone();
            entry.original_request = Some(original_request);
            entry.execution = Some(tx.clone());
            entry.status = SignStatus::PendingExecution { tx };
        }
    }
    Ok(entry)
}

fn validate_execution_tx(
    original_request: &IndexedSignRequest,
    tx: &BidirectionalTx,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(
            original_request.kind,
            SignKind::Sign | SignKind::SignBidirectional(_)
        ),
        "completion checkpoint entry must originate from a sign request"
    );
    anyhow::ensure!(
        tx.request_id == original_request.id.request_id
            && tx.source_chain == original_request.chain,
        "execution transaction does not match its source request"
    );
    if let SignKind::SignBidirectional(event) = &original_request.kind {
        let target_chain = event
            .target_chain()
            .context("source bidirectional request has an invalid target chain")?;
        anyhow::ensure!(
            tx.target_chain == target_chain,
            "execution transaction target chain does not match its source request"
        );
    }
    Ok(())
}

pub(crate) fn validate_checkpoint_payload(checkpoint: &Checkpoint) -> anyhow::Result<()> {
    checkpoint
        .validate()
        .context("invalid checkpoint canonical ordering")?;

    for pending in &checkpoint.pending_requests {
        let entry: BacklogEntry = ciborium::de::from_reader(pending.transaction.as_slice())
            .with_context(|| {
                format!(
                    "failed to deserialize pending backlog entry for sign_id {:?}",
                    pending.sign_id
                )
            })?;
        anyhow::ensure!(
            pending.sign_id == entry.sign_id(),
            "checkpoint sign id does not match recovered backlog entry"
        );
        let original_request = entry.original_request();
        anyhow::ensure!(
            original_request.id == entry.request.id
                && original_request.chain == entry.request.chain,
            "checkpoint backlog entry has inconsistent original and active request identity"
        );

        match entry.status().checkpoint_phase() {
            CheckpointPhase::AwaitingInitialResponse => {
                anyhow::ensure!(
                    matches!(
                        original_request.kind,
                        SignKind::Sign | SignKind::SignBidirectional(_)
                    ),
                    "initial-response checkpoint entry must originate from a sign request"
                );
                anyhow::ensure!(
                    matches!(
                        entry.request.kind,
                        SignKind::Sign | SignKind::SignBidirectional(_)
                    ),
                    "initial-response checkpoint entry must contain a sign request"
                );
                anyhow::ensure!(
                    entry.execution_tx().is_none(),
                    "initial-response entry cannot contain an execution transaction"
                );
            }
            CheckpointPhase::AwaitingBidirectionalCompletion => {
                anyhow::ensure!(
                    matches!(
                        original_request.kind,
                        SignKind::Sign | SignKind::SignBidirectional(_)
                    ),
                    "completion checkpoint entry must originate from a sign request"
                );
                anyhow::ensure!(
                    matches!(
                        entry.request.kind,
                        SignKind::SignBidirectional(_) | SignKind::RespondBidirectional(_)
                    ),
                    "completion checkpoint entry must contain bidirectional work"
                );
                let tx = entry.execution_tx().ok_or_else(|| {
                    anyhow::anyhow!(
                        "completion checkpoint entry is missing its source-derived execution transaction"
                    )
                })?;
                validate_execution_tx(original_request, tx)?;
                if let SignKind::RespondBidirectional(response) = &entry.request.kind {
                    anyhow::ensure!(
                        response.tx_id == tx.id,
                        "final bidirectional response does not match its execution transaction"
                    );
                }
            }
        }
        anyhow::ensure!(
            !pending.canonical_transaction.is_empty(),
            "checkpoint is missing canonical pending transaction payload"
        );
        anyhow::ensure!(
            pending.canonical_transaction == canonical_entry_bytes(&entry),
            "checkpoint canonical pending transaction payload does not match entry"
        );
    }
    Ok(())
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

    fn checkpoint(&self, chain: Chain) -> Checkpoint {
        let mut pending_requests = self
            .requests
            .iter()
            .map(|(&sign_id, entry)| {
                let mut transaction = Vec::new();
                ciborium::ser::into_writer(entry, &mut transaction)
                    .expect("serialize backlog entry for checkpoint");
                PendingTx {
                    sign_id,
                    canonical_transaction: canonical_entry_bytes(entry),
                    transaction,
                }
            })
            .collect::<Vec<_>>();
        pending_requests.sort_by_key(|pending| pending.sign_id);

        Checkpoint {
            schema_version: mpc_primitives::CHECKPOINT_SCHEMA_VERSION,
            chain,
            block_height: self.processed_block_height.unwrap_or(0),
            pending_requests,
            // Retained only for compatibility with the legacy checkpoint wire format.
            cumulative_digest: Checkpoint::empty_cumulative_digest(),
        }
    }

    fn from_checkpoint(checkpoint: &Checkpoint) -> anyhow::Result<Self> {
        validate_checkpoint_payload(checkpoint)?;

        fn decode(pending: &mpc_primitives::PendingTx) -> anyhow::Result<(SignId, BacklogEntry)> {
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
        for pending_tx in &checkpoint.pending_requests {
            let (sign_id, tx) = decode(pending_tx)?;
            let tx = normalize_recovered_entry(tx)?;
            anyhow::ensure!(
                requests.insert(sign_id, tx).is_none(),
                "checkpoint contains duplicate pending request"
            );
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

/// Backlog manages pending sign-respond requests across multiple chains.
/// Each chain has its own isolated set of pending requests with their own
/// publish queues.
#[derive(Debug, Clone)]
pub struct Backlog {
    /// Storage for checkpoints, which can be in-memory or persisted to disk
    pub(crate) storage: CheckpointStorage,
    /// Pending requests indexed by chain
    requests: Arc<HashMap<Chain, RwLock<PendingRequests>>>,
    /// Execution watchers indexed by chain
    execution_watchers: Arc<HashMap<Chain, RwLock<ExecutionWatchers>>>,
    /// Unconfirmed checkpoints pending MPC signing consensus.
    /// Size is capped by MAX_PENDING_CHECKPOINTS to provide backpressure.
    /// When full, new checkpoint creation is stalled until a slot opens.
    /// This is the single in-memory checkpoint store (no separate historical).
    pending_checkpoints: Arc<HashMap<Chain, RwLock<BTreeMap<u64, Checkpoint>>>>,
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

    /// Initialize the backlog with storage and pre-allocate maps for all chains
    pub fn persisted(storage: CheckpointStorage) -> Self {
        let mut requests = HashMap::new();
        let mut execution_watchers = HashMap::new();
        let mut pending_checkpoints = HashMap::new();

        // Pre-allocate the maps for all chains
        for chain in Chain::iter() {
            requests.insert(chain, RwLock::new(PendingRequests::new()));
            execution_watchers.insert(chain, RwLock::new(ExecutionWatchers::default()));
            pending_checkpoints.insert(chain, RwLock::new(BTreeMap::new()));
        }

        Self {
            storage,
            requests: Arc::new(requests),
            execution_watchers: Arc::new(execution_watchers),
            pending_checkpoints: Arc::new(pending_checkpoints),
            total_pending: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get the pending requests for a specific chain.
    /// Panics if the chain is not initialized, which should never happen since we pre-allocate for all chains in `persisted`.
    #[inline]
    fn pending(&self, chain: &Chain) -> &RwLock<PendingRequests> {
        self.requests
            .get(chain)
            .expect("chain should be initialized within `persisted` method")
    }

    /// Get the execution watchers for a specific chain.
    /// Panics if the chain is not initialized, which should never happen since we pre-allocate for all chains in `persisted`.
    #[inline]
    fn watchers(&self, chain: &Chain) -> &RwLock<ExecutionWatchers> {
        self.execution_watchers
            .get(chain)
            .expect("chain should be initialized within `persisted` method")
    }

    /// Get the pending (unconfirmed) checkpoints for a specific chain.
    /// Panics if the chain is not initialized, which should never happen since we pre-allocate for all chains in `persisted`.
    #[inline]
    fn pending_checkpoints(&self, chain: &Chain) -> &RwLock<BTreeMap<u64, Checkpoint>> {
        self.pending_checkpoints
            .get(chain)
            .expect("chain should be initialized within `persisted` method")
    }

    /// Insert a new Sign request into the backlog for the specified chain.
    pub async fn insert(&self, request: IndexedSignRequest) -> Option<BacklogEntry> {
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

    fn observe_pending_checkpoints(&self, chain: Chain, len: usize) {
        crate::metrics::requests::PENDING_CHECKPOINTS
            .with_label_values(&[chain.as_str()])
            .set(len as i64);
    }

    /// Returns backlog requests for a chain that are still eligible to be
    /// enqueued for processing after catchup completes.
    pub async fn take_requeueable_requests(&self, chain: Chain) -> Vec<IndexedSignRequest> {
        let pending = self.pending(&chain).write().await;

        let mut requeueable: Vec<_> = pending
            .requests
            .values()
            .filter(|entry| entry.status().is_pending_generation())
            .map(|entry| entry.request.clone())
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
    ) -> Vec<(IndexedSignRequest, PublishState)> {
        let pending = self.pending(&chain).write().await;

        let mut publishable: Vec<_> = pending
            .requests
            .values()
            .filter_map(|entry| match entry.status() {
                SignStatus::PendingPublish { publish }
                | SignStatus::PendingPublishBidirectional { publish } => {
                    Some((entry.request.clone(), publish))
                }
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
        publish: PublishState,
    ) -> Result<(), BacklogError> {
        let mut pending = self.pending(&chain).write().await;

        let Some(entry) = pending.requests.get_mut(id) else {
            return Err(BacklogError::NotFound { chain, id: *id });
        };

        entry.mark_publishing(publish)
    }

    // TODO: the backlog is a bit bloated with transition functions, so we need to do a proper cleanup
    // where we can have proper typestate on a set of types. With these types, we can easily guide
    // ourselves into the right transitions. For now, this is used to set the request in
    // `execution_confirmed` to transition from PendingExecution to PendingGenerationBidirectional.
    pub async fn set_request(
        &self,
        chain: Chain,
        id: &SignId,
        request: IndexedSignRequest,
    ) -> Result<(), BacklogError> {
        let mut pending = self.pending(&chain).write().await;

        let Some(entry) = pending.requests.get_mut(id) else {
            return Err(BacklogError::NotFound { chain, id: *id });
        };
        let original = entry.original_request();
        if request.id != original.id || request.chain != original.chain {
            return Err(BacklogError::InvalidRequestTransition);
        }
        match (&original.kind, &request.kind) {
            (SignKind::SignBidirectional(_), SignKind::RespondBidirectional(response)) => {
                if let Some(execution) = entry.execution_tx() {
                    if response.tx_id != execution.id {
                        return Err(BacklogError::InvalidExecutionTransition);
                    }
                }
            }
            (SignKind::SignBidirectional(_), _) => {
                return Err(BacklogError::InvalidRequestTransition);
            }
            (SignKind::Sign, SignKind::RespondBidirectional(response)) => {
                let Some(execution) = entry.execution_tx() else {
                    return Err(BacklogError::InvalidExecutionTransition);
                };
                if response.tx_id != execution.id {
                    return Err(BacklogError::InvalidExecutionTransition);
                }
            }
            (SignKind::Sign, SignKind::Sign)
            | (SignKind::RespondBidirectional(_), SignKind::RespondBidirectional(_)) => {}
            _ => return Err(BacklogError::InvalidRequestTransition),
        }
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
        // The watcher is local recovery state, but the transaction itself is
        // part of the source request's durable projection. Retain it on the
        // source entry so a later execution confirmation can safely transition
        // even when the original request was represented as a plain `Sign`.
        {
            let mut pending = self.pending(&tx.source_chain).write().await;
            let Some(entry) = pending.requests.get_mut(&sign_id) else {
                tracing::warn!(
                    ?sign_id,
                    ?tx,
                    "execution watcher source request was not found"
                );
                return None;
            };
            if tx.request_id != entry.original_request().id.request_id
                || tx.source_chain != entry.original_request().chain
            {
                tracing::warn!(
                    ?sign_id,
                    ?tx,
                    "execution watcher transaction does not match source request"
                );
                return None;
            }
            entry.execution = Some(tx.clone());
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
    ) -> Option<(SignId, BidirectionalTx)> {
        let mut entry = self.watchers(&chain).write().await;

        entry
            .remove(tx_id)
            .map(|watcher| (watcher.sign_id, watcher.tx))
    }

    /// Update the status of a tracked bidirectional transaction on the source chain.
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
        if let SignStatus::PendingExecution { tx } = &status {
            if tx.request_id != entry.original_request().id.request_id
                || tx.source_chain != entry.original_request().chain
            {
                tracing::warn!(
                    ?chain,
                    ?id,
                    "set_status: execution transaction does not match request"
                );
                return None;
            }
            entry.execution = Some(tx.clone());
        }
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
        let mut pending = self.pending(&chain).write().await;

        let entry = pending
            .requests
            .get_mut(&sign_id)
            .ok_or(BacklogError::NotFound { chain, id: sign_id })?;

        entry.advance_to_execution(bidirectional_tx.clone())?;

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
            if let Some(checkpoint) = self.checkpoint(chain).await {
                tracing::info!(?chain, height, tx_count, ?checkpoint, "creating checkpoint");
                Some(checkpoint)
            } else {
                tracing::warn!(
                    ?chain,
                    height,
                    tx_count,
                    "checkpoint creation stalled (pending cap reached)"
                );
                None
            }
        } else {
            None
        }
    }

    /// Create a checkpoint of the current backlog state for a specific chain.
    ///
    /// Returns `None` if the pending checkpoint cap has been reached (stalling).
    /// Persists only when a consensus confirmation arrives via `on_consensus_confirmed`.
    pub async fn checkpoint(&self, chain: Chain) -> Option<Checkpoint> {
        // Serialize the backlog snapshot with candidate admission. Otherwise a
        // concurrent backlog update could make the candidate stale, and a
        // retry could be rejected by the cap before finding its existing height.
        let mut pending_checkpoints = self.pending_checkpoints(&chain).write().await;
        let checkpoint = self.pending(&chain).read().await.checkpoint(chain);
        checkpoint
            .validate()
            .expect("locally constructed checkpoint must be canonically ordered");

        // A block height is a finalized cursor, so its first local snapshot is
        // immutable. This also makes concurrent checkpoint requests at one
        // height deterministic instead of silently replacing a candidate.
        if let Some(existing) = pending_checkpoints.get(&checkpoint.block_height) {
            return Some(existing.clone());
        }

        if pending_checkpoints.len() >= MAX_PENDING_CHECKPOINTS {
            tracing::warn!(
                ?chain,
                count = pending_checkpoints.len(),
                "pending checkpoint cap reached; stalling checkpoint creation"
            );
            return None;
        }

        pending_checkpoints.insert(checkpoint.block_height, checkpoint.clone());
        let len = pending_checkpoints.len();
        drop(pending_checkpoints);
        self.observe_pending_checkpoints(chain, len);

        Some(checkpoint)
    }

    /// Called when consensus confirms a checkpoint (via the watcher).
    /// Removes it from pending and persists to storage as the latest consensus checkpoint.
    pub async fn on_consensus_confirmed(&self, chain: Chain, checkpoint: &Checkpoint) {
        if checkpoint.chain != chain {
            tracing::warn!(?chain, checkpoint_chain = ?checkpoint.chain, "refusing checkpoint for a different chain");
            return;
        }
        if let Err(err) = validate_checkpoint_payload(checkpoint) {
            tracing::warn!(?chain, %err, "refusing to persist invalid consensus checkpoint");
            return;
        }

        // Remove from pending checkpoints (frees a slot for future checkpoints)
        let len = {
            let mut pending = self.pending_checkpoints(&chain).write().await;
            pending.retain(|&height, _| height > checkpoint.block_height);
            pending.len()
        };
        self.observe_pending_checkpoints(chain, len);

        // Persist as the latest consensus checkpoint
        if let Err(err) = self.storage.persist(checkpoint).await {
            tracing::warn!(?chain, %err, "failed to persist consensus checkpoint");
        }

        tracing::info!(
            ?chain,
            height = checkpoint.block_height,
            "consensus checkpoint confirmed and persisted"
        );
    }

    /// Get the latest checkpoint for a specific chain.
    pub async fn latest_checkpoint(&self, chain: Chain) -> Option<Checkpoint> {
        {
            let pending = self.pending_checkpoints(&chain).read().await;
            if let Some(cp) = pending.values().next_back().cloned() {
                return Some(cp);
            }
        }
        self.storage.load_latest(chain).await.ok().flatten()
    }

    /// Check if the chain backlog has an available checkpoint slot.
    pub async fn has_checkpoint_slot(&self, chain: Chain) -> bool {
        let pending = self.pending_checkpoints(&chain).read().await;
        pending.len() < MAX_PENDING_CHECKPOINTS
    }

    /// Number of pending checkpoints for a chain.
    pub async fn pending_checkpoint_count(&self, chain: Chain) -> usize {
        self.pending_checkpoints(&chain).read().await.len()
    }

    /// Find a checkpoint by its consensus digest.
    pub async fn find_checkpoint_by_digest(
        &self,
        chain: Chain,
        digest: [u8; 32],
    ) -> Option<Checkpoint> {
        {
            let pending = self.pending_checkpoints(&chain).read().await;
            for cp in pending.values() {
                if cp.digest() == digest {
                    return Some(cp.clone());
                }
            }
        }
        if let Ok(Some(latest)) = self.storage.load_latest(chain).await {
            if latest.digest() == digest {
                return Some(latest);
            }
        }
        None
    }

    /// Recover backlog state from a checkpoint.
    /// This is called when a node restarts or when it needs to align/regress to consensus.
    pub async fn recover_by_checkpoint(&self, checkpoint: Checkpoint) -> anyhow::Result<()> {
        validate_checkpoint_payload(&checkpoint)?;

        let chain = checkpoint.chain;
        let checkpoint_height = checkpoint.block_height;
        tracing::info!(
            ?chain,
            height = checkpoint_height,
            num_pending = checkpoint.pending_requests.len(),
            "recovering backlog to checkpoint"
        );

        // Clear all pending (unconfirmed) checkpoints for this chain.
        // Any checkpoint that was waiting for consensus is now obsolete.
        self.pending_checkpoints(&chain).write().await.clear();
        self.observe_pending_checkpoints(chain, 0);

        let execution_to_watch = {
            let mut pending = self.pending(&checkpoint.chain).write().await;
            let previous_height = pending.processed_block_height().unwrap_or(0);

            // Execution watchers are ephemeral, we need to get all the execution watchers here
            let cleared = pending.len();
            *pending = PendingRequests::from_checkpoint(&checkpoint)?;
            let restored = pending.len();

            // Update total pending count based on the difference between cleared and restored requests
            self.total_pending.fetch_sub(cleared, Ordering::Relaxed);
            self.total_pending.fetch_add(restored, Ordering::Relaxed);

            tracing::info!(
                ?chain,
                old_block = previous_height,
                new_block = checkpoint_height,
                cleared_requests = cleared,
                restored_requests = restored,
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
        for (sign_id, tx) in execution_to_watch {
            // Only restore execution watchers for bidirectional transactions
            if let Some(tx) = tx.execution_tx().cloned() {
                self.watch_execution(tx.target_chain, sign_id, tx).await;
            }
        }

        Ok(())
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
    ) -> HashMap<BidirectionalTxId, (SignId, BidirectionalTx)> {
        self.watchers(&chain).read().await.all()
    }
}

/// Errors that can occur when working with Backlog
#[derive(Debug, thiserror::Error)]
pub enum BacklogError {
    #[error("request not found for chain {chain:?} with id {id:?}")]
    NotFound { chain: Chain, id: SignId },
    #[error("chain not initialized: {chain:?}")]
    ChainNotInitialized { chain: Chain },
    #[error("transaction not found")]
    TransactionNotFound,
    #[error("cannot mark publishing for current backlog state")]
    InvalidPublishingTransition,
    #[error("cannot advance non-bidirectional or already-advanced backlog entry")]
    InvalidAdvanceTransition,
    #[error("request identity does not match backlog entry")]
    InvalidRequestTransition,
    #[error("execution transaction does not match backlog entry")]
    InvalidExecutionTransition,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BacklogEntry {
    /// The currently active source-chain request. For bidirectional work this
    /// becomes the final response request after target execution.
    pub request: IndexedSignRequest,
    pub status: SignStatus,
    /// Original source-chain request, retained when `request` advances to a
    /// final bidirectional response. Optional for legacy checkpoint payloads.
    #[serde(default)]
    pub original_request: Option<IndexedSignRequest>,
    /// Bidirectional target transaction retained independently of local status.
    /// Optional for legacy checkpoint payloads.
    #[serde(default)]
    pub execution: Option<BidirectionalTx>,
}

impl BacklogEntry {
    pub fn new(request: IndexedSignRequest) -> Self {
        Self {
            original_request: Some(request.clone()),
            request,
            status: SignStatus::PendingGeneration,
            execution: None,
        }
    }

    pub fn with_status(request: IndexedSignRequest, status: SignStatus) -> Self {
        Self {
            original_request: Some(request.clone()),
            request,
            status,
            execution: None,
        }
    }

    pub fn pending_execution(request: IndexedSignRequest, tx: BidirectionalTx) -> Self {
        Self {
            original_request: Some(request.clone()),
            request,
            status: SignStatus::PendingExecution { tx: tx.clone() },
            execution: Some(tx),
        }
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
        self.status.clone()
    }

    /// Set the status of this transaction
    fn set_status(&mut self, status: SignStatus) {
        if let SignStatus::PendingExecution { tx } = &status {
            self.execution = Some(tx.clone());
        }
        self.status = status;
    }

    fn set_request(&mut self, request: IndexedSignRequest) {
        self.request = request;
    }

    pub fn original_request(&self) -> &IndexedSignRequest {
        self.original_request.as_ref().unwrap_or(&self.request)
    }

    pub fn mark_publishing(&mut self, publish: PublishState) -> Result<(), BacklogError> {
        match (&self.request.kind, self.status.clone()) {
            (SignKind::Sign | SignKind::SignBidirectional(_), SignStatus::PendingGeneration) => {
                self.status = SignStatus::PendingPublish { publish };
                Ok(())
            }
            (SignKind::RespondBidirectional(_), SignStatus::PendingGenerationBidirectional) => {
                self.status = SignStatus::PendingPublishBidirectional { publish };
                Ok(())
            }
            _ => Err(BacklogError::InvalidPublishingTransition),
        }
    }

    pub fn advance_to_execution(
        &mut self,
        bidirectional_tx: BidirectionalTx,
    ) -> Result<(), BacklogError> {
        if bidirectional_tx.request_id != self.original_request().id.request_id
            || bidirectional_tx.source_chain != self.original_request().chain
        {
            return Err(BacklogError::InvalidExecutionTransition);
        }

        match (&self.request.kind, self.status.clone()) {
            (
                SignKind::SignBidirectional(_),
                SignStatus::PendingGeneration | SignStatus::PendingPublish { .. },
            ) => {
                self.status = SignStatus::PendingExecution {
                    tx: bidirectional_tx.clone(),
                };
                self.execution = Some(bidirectional_tx);
                Ok(())
            }
            _ => Err(BacklogError::InvalidAdvanceTransition),
        }
    }

    /// Get target chain if this is a bidirectional transaction
    // TODO: looks a bit weird having two different ways to get target_chain in the match
    pub fn target_chain(&self) -> Option<Chain> {
        self.execution_tx().map(|tx| tx.target_chain).or_else(|| {
            match &self.original_request().kind {
                SignKind::SignBidirectional(event) => event.target_chain().ok(),
                SignKind::Sign | SignKind::RespondBidirectional(_) => None,
            }
        })
    }

    /// Check if this is a bidirectional transaction
    pub fn is_bidirectional(&self) -> bool {
        matches!(self.original_request().kind, SignKind::SignBidirectional(_))
    }

    pub fn execution_tx(&self) -> Option<&BidirectionalTx> {
        self.execution
            .as_ref()
            .or_else(|| self.status.execution_tx())
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
    use crate::sign_bidirectional::{CheckpointPhase, PublishState, SignStatus};
    use alloy::primitives::{Address, B256};
    use cait_sith::protocol::Participant;
    use k256::{AffinePoint, Scalar};
    use mpc_chain_solana::Pubkey;
    use mpc_primitives::{
        BidirectionalTx, BidirectionalTxId, RespondBidirectionalTx, SignArgs,
        SignBidirectionalEvent, SignId, SignKind,
    };
    use sha3::Digest;

    fn test_signature() -> mpc_primitives::Signature {
        mpc_primitives::Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0)
    }

    fn test_publish_state(is_proposer: bool) -> PublishState {
        PublishState {
            signature: test_signature(),
            participants: vec![Participant::from(0u32), Participant::from(1u32)],
            is_proposer,
        }
    }

    fn pending_execution_status(tx: &BidirectionalTx) -> SignStatus {
        SignStatus::PendingExecution { tx: tx.clone() }
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

        match status {
            SignStatus::PendingExecution { .. } => BacklogEntry::pending_execution(request, tx),
            status => BacklogEntry::with_status(request, status),
        }
    }

    async fn insert_bidirectional_with_status(
        backlog: &Backlog,
        chain: Chain,
        tx: BidirectionalTx,
        status: SignStatus,
        dest: &str,
    ) {
        let mut tx = tx;
        tx.source_chain = chain;
        let sign_id = SignId::new(tx.request_id);
        backlog
            .insert(create_bidirectional_request(sign_id, chain, dest, 0))
            .await;

        match status {
            SignStatus::PendingGeneration => {}
            SignStatus::PendingGenerationBidirectional => {
                backlog
                    .set_status(
                        chain,
                        &sign_id,
                        SignStatus::PendingExecution { tx: tx.clone() },
                    )
                    .await;
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
                    .set_request(chain, &sign_id, completion_request)
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
                backlog.advance(chain, sign_id, tx).await.unwrap();
            }
            SignStatus::PendingPublishBidirectional { .. } => {
                backlog
                    .set_status(
                        chain,
                        &sign_id,
                        SignStatus::PendingExecution { tx: tx.clone() },
                    )
                    .await;
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
                    .set_request(chain, &sign_id, completion_request)
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
        backlog.set_processed_block(Chain::Ethereum, 100).await;

        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();
        assert_eq!(checkpoint.block_height, 100);
        assert_eq!(checkpoint.chain, Chain::Ethereum);
        assert_eq!(checkpoint.pending_requests.len(), 2);
        assert_eq!(
            checkpoint.digest(),
            <[u8; 32]>::from(sha3::Sha3_256::digest(checkpoint.canonical_payload_bytes()))
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

    #[tokio::test]
    async fn test_checkpoint_digest_differs_for_different_status() {
        let tx = create_test_tx(7);

        let mut pending1 = PendingRequests::new();
        pending1.insert(
            SignId::new(tx.request_id),
            create_execution_entry(
                tx.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            ),
        );
        pending1.set_processed_block(100);

        let mut pending2 = PendingRequests::new();
        pending2.insert(
            SignId::new(tx.request_id),
            create_execution_entry(
                tx.clone(),
                Chain::Ethereum,
                pending_execution_status(&tx),
                "ethereum",
            ),
        );
        pending2.set_processed_block(100);

        let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
        let checkpoint2 = pending2.checkpoint(Chain::Ethereum);

        // Different canonical phases must produce different checkpoint digests.
        assert_ne!(checkpoint1.digest(), checkpoint2.digest());
    }

    #[test]
    fn test_checkpoint_phase_groups_local_initial_response_states() {
        let statuses = [
            SignStatus::PendingGeneration,
            SignStatus::PendingPublish {
                publish: test_publish_state(true),
            },
            SignStatus::PendingPublish {
                publish: test_publish_state(false),
            },
        ];

        for status in statuses {
            assert_eq!(
                status.checkpoint_phase(),
                CheckpointPhase::AwaitingInitialResponse
            );
        }
    }

    #[test]
    fn test_checkpoint_phase_groups_local_bidirectional_states() {
        let tx = create_test_tx(13);
        let statuses = [
            pending_execution_status(&tx),
            SignStatus::PendingGenerationBidirectional,
            SignStatus::PendingPublishBidirectional {
                publish: test_publish_state(true),
            },
            SignStatus::PendingPublishBidirectional {
                publish: test_publish_state(false),
            },
        ];

        for status in statuses {
            assert_eq!(
                status.checkpoint_phase(),
                CheckpointPhase::AwaitingBidirectionalCompletion
            );
        }
    }

    #[tokio::test]
    async fn test_checkpoint_digest_differs_for_generation_vs_publish() {
        let tx = create_test_tx(12);

        let mut pending1 = PendingRequests::new();
        pending1.insert(
            SignId::new(tx.request_id),
            create_execution_entry(
                tx.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            ),
        );
        pending1.set_processed_block(100);

        let mut pending2 = PendingRequests::new();
        pending2.insert(
            SignId::new(tx.request_id),
            create_execution_entry(
                tx.clone(),
                Chain::Ethereum,
                SignStatus::PendingPublish {
                    publish: test_publish_state(true),
                },
                "ethereum",
            ),
        );
        pending2.set_processed_block(100);

        let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
        let checkpoint2 = pending2.checkpoint(Chain::Ethereum);

        // Generation and publication are the same canonical initial-response phase.
        assert_eq!(checkpoint1.digest(), checkpoint2.digest());
    }

    #[tokio::test]
    async fn test_checkpoint_digest_ignores_publish_local_state() {
        let tx = create_test_tx(9);

        let mut pending1 = PendingRequests::new();
        pending1.insert(
            SignId::new(tx.request_id),
            create_execution_entry(
                tx.clone(),
                Chain::Ethereum,
                SignStatus::PendingPublish {
                    publish: test_publish_state(true),
                },
                "ethereum",
            ),
        );
        pending1.set_processed_block(100);

        let mut pending2 = PendingRequests::new();
        pending2.insert(
            SignId::new(tx.request_id),
            create_execution_entry(
                tx.clone(),
                Chain::Ethereum,
                SignStatus::PendingPublish {
                    publish: test_publish_state(false),
                },
                "ethereum",
            ),
        );
        pending2.set_processed_block(100);

        let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
        let checkpoint2 = pending2.checkpoint(Chain::Ethereum);

        assert_eq!(checkpoint1.digest(), checkpoint2.digest());
    }

    #[tokio::test]
    async fn test_checkpoint_digest_commits_active_payload() {
        let tx = create_test_tx(18);
        let mut first = create_execution_entry(
            tx.clone(),
            Chain::Ethereum,
            SignStatus::PendingGeneration,
            "ethereum",
        );
        let mut second = first.clone();
        first.request.unix_timestamp_indexed = 1000;
        second.request.unix_timestamp_indexed = 9999;

        let mut pending1 = PendingRequests::new();
        pending1.insert(SignId::new(tx.request_id), first);
        pending1.set_processed_block(200);
        let mut pending2 = PendingRequests::new();
        pending2.insert(SignId::new(tx.request_id), second);
        pending2.set_processed_block(200);

        assert_eq!(
            pending1.checkpoint(Chain::Ethereum).digest(),
            pending2.checkpoint(Chain::Ethereum).digest(),
            "indexing timestamps must remain outside the canonical commitment"
        );

        let mut changed = create_execution_entry(
            tx.clone(),
            Chain::Ethereum,
            SignStatus::PendingGeneration,
            "ethereum",
        );
        let mut changed_request = changed.request.clone();
        changed_request.args.path.push_str("/changed");
        changed.request = changed_request.clone();
        changed.original_request = Some(changed_request);
        let mut pending3 = PendingRequests::new();
        pending3.insert(SignId::new(tx.request_id), changed);
        pending3.set_processed_block(200);
        assert_ne!(
            pending1.checkpoint(Chain::Ethereum).digest(),
            pending3.checkpoint(Chain::Ethereum).digest()
        );
    }

    #[tokio::test]
    async fn test_checkpoint_digest_ignores_timestamp() {
        let tx = create_test_tx(8);

        let entry1 = {
            let mut e = create_execution_entry(
                tx.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            );
            e.request.unix_timestamp_indexed = 1000;
            e
        };
        let entry2 = {
            let mut e = create_execution_entry(
                tx.clone(),
                Chain::Ethereum,
                SignStatus::PendingGeneration,
                "ethereum",
            );
            e.request.unix_timestamp_indexed = 9999;
            e
        };

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
        assert_eq!(
            checkpoint.digest(),
            <[u8; 32]>::from(sha3::Sha3_256::digest(checkpoint.canonical_payload_bytes()))
        );
        assert_eq!(checkpoint.digest(), deserialized.digest());

        let (sign_id, restored_tx) = {
            let pending = &deserialized.pending_requests[0];
            let backlog_entry: BacklogEntry =
                ciborium::de::from_reader(pending.transaction.as_slice()).unwrap();
            let tx = backlog_entry
                .execution_tx()
                .cloned()
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
    async fn test_recovery_rejects_tampered_canonical_payload_before_mutation() {
        let source = Backlog::new();
        let tx = create_test_tx(17);
        insert_bidirectional_with_status(
            &source,
            Chain::Solana,
            tx.clone(),
            pending_execution_status(&tx),
            "ethereum",
        )
        .await;
        source.set_processed_block(Chain::Solana, 10).await;
        let mut checkpoint = source.checkpoint(Chain::Solana).await.unwrap();
        checkpoint.pending_requests[0].canonical_transaction[0] ^= 1;

        let recovered = Backlog::new();
        let error = recovered
            .recover_by_checkpoint(checkpoint)
            .await
            .expect_err("tampered canonical payload must be rejected");
        assert!(error
            .to_string()
            .contains("canonical pending transaction payload"));
        assert!(recovered
            .get(Chain::Solana, &SignId::new(tx.request_id))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn test_recover_restores_execution_watchers() {
        let backlog = Backlog::new();
        let tx = create_test_tx(6);

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
            .recover_by_checkpoint(checkpoint)
            .await
            .expect("failed to recover");

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
        recovered.storage.persist(&checkpoint).await.unwrap();
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
    async fn test_recover_preserves_plain_sign_completion() {
        let backlog = Backlog::new();
        let tx = create_test_tx(48);
        let sign_id = SignId::new(tx.request_id);
        let request = IndexedSignRequest::sign(sign_id, create_test_args(48), Chain::Solana, 0);

        backlog.insert(request.clone()).await;
        backlog
            .set_status(
                Chain::Solana,
                &sign_id,
                SignStatus::PendingExecution { tx: tx.clone() },
            )
            .await;
        let completion = IndexedSignRequest::respond_bidirectional(
            sign_id,
            create_test_args(48),
            Chain::Solana,
            1,
            RespondBidirectionalTx {
                tx_id: tx.id,
                output: vec![9],
                chain_ctx: None,
            },
        );
        backlog
            .set_request(Chain::Solana, &sign_id, completion)
            .await
            .unwrap();
        backlog
            .set_status(
                Chain::Solana,
                &sign_id,
                SignStatus::PendingGenerationBidirectional,
            )
            .await;
        backlog.set_processed_block(Chain::Solana, 10).await;

        let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();
        let recovered = Backlog::new();
        recovered
            .recover_by_checkpoint(checkpoint)
            .await
            .expect("plain Sign completion should be recoverable");

        let entry = recovered
            .get(Chain::Solana, &sign_id)
            .await
            .expect("plain Sign completion should remain in the backlog");
        assert!(matches!(entry.request.kind, SignKind::Sign));
        assert!(matches!(
            entry.status(),
            SignStatus::PendingExecution { .. }
        ));
        assert_eq!(entry.execution_tx(), Some(&tx));
    }

    #[test]
    fn test_legacy_backlog_entry_deserializes_with_projection_fallbacks() {
        let request = IndexedSignRequest::sign(
            SignId::new([47; 32]),
            create_test_args(47),
            Chain::Solana,
            0,
        );
        let entry = BacklogEntry::new(request.clone());
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&entry, &mut encoded).unwrap();
        let mut value: ciborium::Value = ciborium::de::from_reader(encoded.as_slice()).unwrap();
        let ciborium::Value::Map(map) = &mut value else {
            panic!("backlog entry must serialize as a CBOR map");
        };
        map.retain(|(key, _)| {
            !matches!(
                key,
                ciborium::Value::Text(name)
                    if name == "original_request" || name == "execution"
            )
        });
        let mut legacy_encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut legacy_encoded).unwrap();

        let restored: BacklogEntry = ciborium::de::from_reader(legacy_encoded.as_slice()).unwrap();
        assert_eq!(restored.original_request(), &request);
        assert!(restored.execution_tx().is_none());
    }

    #[tokio::test]
    async fn test_bidirectional_transition_preserves_original_request_and_execution() {
        let backlog = Backlog::new();
        let tx = create_test_tx(45);
        let sign_id = SignId::new(tx.request_id);
        let original = create_bidirectional_request(sign_id, Chain::Solana, "ethereum", 0);

        backlog.insert(original.clone()).await;
        backlog
            .advance(Chain::Solana, sign_id, tx.clone())
            .await
            .unwrap();

        let completion = IndexedSignRequest::respond_bidirectional(
            sign_id,
            create_test_args(sign_id.request_id[0]),
            Chain::Solana,
            1,
            RespondBidirectionalTx {
                tx_id: tx.id,
                output: vec![9],
                chain_ctx: None,
            },
        );
        backlog
            .set_request(Chain::Solana, &sign_id, completion)
            .await
            .unwrap();

        let entry = backlog.get(Chain::Solana, &sign_id).await.unwrap();
        assert!(matches!(
            entry.original_request().kind,
            SignKind::SignBidirectional(_)
        ));
        assert_eq!(entry.original_request().id, original.id);
        assert_eq!(entry.execution_tx(), Some(&tx));

        let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();
        let recovered = Backlog::new();
        recovered.recover_by_checkpoint(checkpoint).await.unwrap();
        let recovered_entry = recovered.get(Chain::Solana, &sign_id).await.unwrap();
        assert!(matches!(
            recovered_entry.original_request().kind,
            SignKind::SignBidirectional(_)
        ));
        assert_eq!(recovered_entry.execution_tx(), Some(&tx));
    }

    #[tokio::test]
    async fn test_backlog_rejects_mismatched_request_and_execution_updates() {
        let backlog = Backlog::new();
        let tx = create_test_tx(46);
        let sign_id = SignId::new(tx.request_id);
        backlog
            .insert(create_bidirectional_request(
                sign_id,
                Chain::Solana,
                "ethereum",
                0,
            ))
            .await;

        let wrong_request = IndexedSignRequest::sign(
            SignId::new([99; 32]),
            create_test_args(99),
            Chain::Solana,
            0,
        );
        assert!(matches!(
            backlog
                .set_request(Chain::Solana, &sign_id, wrong_request)
                .await,
            Err(BacklogError::InvalidRequestTransition)
        ));

        let mut wrong_tx = tx.clone();
        wrong_tx.request_id = [99; 32];
        assert!(backlog
            .set_status(
                Chain::Solana,
                &sign_id,
                SignStatus::PendingExecution {
                    tx: wrong_tx.clone(),
                },
            )
            .await
            .is_none());
        assert!(backlog
            .watch_execution(Chain::Ethereum, sign_id, wrong_tx.clone())
            .await
            .is_none());
        assert!(backlog
            .get_execution_watchers(Chain::Ethereum)
            .await
            .is_empty());
        assert!(matches!(
            backlog.advance(Chain::Solana, sign_id, wrong_tx).await,
            Err(BacklogError::InvalidExecutionTransition)
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
                    chain_ctx: None,
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

        backlog.insert(completion_request).await;
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

        backlog.insert(completion_request).await;
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
            .await;
        assert!(cp.is_some());
        let cp = cp.unwrap();
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
            .advance(tx.source_chain, sign_id, tx)
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
            .advance(tx.source_chain, sign_id, tx.clone())
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
            .advance(tx.source_chain, sign_id, tx.clone())
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
        backlog.insert(request.clone()).await;
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
    async fn test_checkpoint_stalls_at_cap() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let interval = chain.checkpoint_interval().unwrap();

        // Fill pending to MAX_PENDING_CHECKPOINTS using set_processed_block
        // which auto-creates checkpoints at interval boundaries.
        for i in 1..=MAX_PENDING_CHECKPOINTS {
            let h = i as u64 * interval;
            assert!(
                backlog.set_processed_block(chain, h).await.is_some(),
                "auto-checkpoint at height {} should succeed",
                h
            );
        }

        // Next checkpoint should be None (stalled)
        let h = (MAX_PENDING_CHECKPOINTS as u64 + 1) * interval;
        assert!(
            backlog.set_processed_block(chain, h).await.is_none(),
            "checkpoint should stall at cap"
        );
    }

    #[tokio::test]
    async fn test_checkpoint_unblocks_after_confirmation() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let interval = chain.checkpoint_interval().unwrap();

        // Fill pending to cap using set_processed_block
        for i in 1..=MAX_PENDING_CHECKPOINTS {
            let h = i as u64 * interval;
            backlog.set_processed_block(chain, h).await.unwrap();
        }

        // Confirm one checkpoint → frees a slot
        let cp = backlog.latest_checkpoint(chain).await.unwrap();
        backlog.on_consensus_confirmed(chain, &cp).await;

        // Should be able to create a new checkpoint now
        let h = (MAX_PENDING_CHECKPOINTS as u64 + 1) * interval;
        assert!(
            backlog.set_processed_block(chain, h).await.is_some(),
            "checkpoint should unblock after confirmation"
        );
    }

    #[tokio::test]
    async fn test_on_consensus_confirmed_removes_from_pending() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let interval = chain.checkpoint_interval().unwrap();

        // Use set_processed_block at interval boundaries which auto-creates
        // checkpoints. Each call creates one checkpoint.
        let cp1 = backlog.set_processed_block(chain, interval).await.unwrap();
        let cp2 = backlog
            .set_processed_block(chain, 2 * interval)
            .await
            .unwrap();

        assert_eq!(
            backlog.pending_checkpoints(&chain).read().await.len(),
            2,
            "two checkpoints should be pending"
        );

        // Confirm first → pending has 1
        backlog.on_consensus_confirmed(chain, &cp1).await;
        assert_eq!(backlog.pending_checkpoints(&chain).read().await.len(), 1);
        assert_eq!(
            backlog.latest_checkpoint(chain).await.unwrap().block_height,
            2 * interval,
            "latest pending is the confirmed checkpoint"
        );

        // Confirm second → pending has 0
        backlog.on_consensus_confirmed(chain, &cp2).await;
        assert_eq!(backlog.pending_checkpoints(&chain).read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_recovery_clears_pending_checkpoints() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let interval = chain.checkpoint_interval().unwrap();

        backlog.set_processed_block(chain, interval).await.unwrap();
        backlog
            .set_processed_block(chain, 2 * interval)
            .await
            .unwrap();

        assert_eq!(
            backlog.pending_checkpoints(&chain).read().await.len(),
            2,
            "two checkpoints should be pending"
        );

        // Recover to a new checkpoint (simulating regression)
        let fresh = Backlog::new();
        let recovery_cp = fresh.set_processed_block(chain, interval / 2).await;
        // interval/2 is not a multiple of interval → no auto-checkpoint
        assert!(recovery_cp.is_none());
        // Force create a checkpoint at that height
        let fresh_cp = fresh.checkpoint(chain).await.unwrap();
        assert_eq!(fresh_cp.block_height, interval / 2);

        backlog.storage.persist(&fresh_cp).await.unwrap();
        backlog.recover_by_checkpoint(fresh_cp).await.unwrap();
        assert_eq!(
            backlog.pending_checkpoints(&chain).read().await.len(),
            0,
            "pending checkpoints should be completely cleared"
        );
        assert_eq!(
            backlog.latest_checkpoint(chain).await.unwrap().block_height,
            interval / 2,
            "latest should be the recovered checkpoint"
        );
    }

    #[tokio::test]
    async fn test_on_consensus_confirmed_evicts_older_pending_checkpoints() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let interval = chain.checkpoint_interval().unwrap();

        // Generate 3 checkpoints. Each call creates one checkpoint.
        let _cp1 = backlog.set_processed_block(chain, interval).await.unwrap();
        let cp2 = backlog
            .set_processed_block(chain, 2 * interval)
            .await
            .unwrap();
        let cp3 = backlog
            .set_processed_block(chain, 3 * interval)
            .await
            .unwrap();

        assert_eq!(
            backlog.pending_checkpoints(&chain).read().await.len(),
            3,
            "three checkpoints should be pending"
        );

        // Confirming the second checkpoint should evict the first and second
        backlog.on_consensus_confirmed(chain, &cp2).await;
        assert_eq!(
            backlog.pending_checkpoints(&chain).read().await.len(),
            1,
            "only checkpoints newer than cp2 should remain"
        );

        // Verify remaining is cp3
        assert!(backlog
            .pending_checkpoints(&chain)
            .read()
            .await
            .contains_key(&(3 * interval)));

        // Verify latest_checkpoint returns cp3 (highest pending)
        assert_eq!(
            backlog.latest_checkpoint(chain).await.unwrap().block_height,
            3 * interval,
        );

        // Confirming the third checkpoint should evict cp3 (0 pending)
        backlog.on_consensus_confirmed(chain, &cp3).await;
        assert_eq!(
            backlog.pending_checkpoints(&chain).read().await.len(),
            0,
            "all checkpoints confirmed, pending should be empty"
        );

        // Verify latest_checkpoint fallback to storage returns cp3
        assert_eq!(
            backlog.latest_checkpoint(chain).await.unwrap().block_height,
            3 * interval,
        );
    }

    #[tokio::test]
    async fn test_find_checkpoint_by_digest_falls_back_to_storage() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let interval = chain.checkpoint_interval().unwrap();

        let cp = backlog.set_processed_block(chain, interval).await.unwrap();
        let digest = cp.digest();

        // Confirm it (removes from pending, persists to storage)
        backlog.on_consensus_confirmed(chain, &cp).await;

        assert_eq!(
            backlog.pending_checkpoints(&chain).read().await.len(),
            0,
            "should not be in pending"
        );

        // Should still be findable by digest
        let found = backlog
            .find_checkpoint_by_digest(chain, digest)
            .await
            .unwrap();
        assert_eq!(found.block_height, interval);
    }

    #[tokio::test]
    async fn test_concurrent_checkpoint_creation_keeps_one_candidate_per_height() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let height = chain.checkpoint_interval().unwrap();
        backlog.set_processed_block(chain, height).await;

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let backlog = backlog.clone();
            tasks.push(tokio::spawn(async move { backlog.checkpoint(chain).await }));
        }
        let mut checkpoints = Vec::with_capacity(tasks.len());
        for task in tasks {
            checkpoints.push(task.await.expect("checkpoint task should not panic"));
        }

        let first = checkpoints
            .first()
            .and_then(Option::as_ref)
            .expect("a checkpoint should be created");
        assert!(checkpoints
            .iter()
            .all(|checkpoint| checkpoint.as_ref() == Some(first)));
        assert_eq!(backlog.pending_checkpoint_count(chain).await, 1);
    }

    #[tokio::test]
    async fn test_checkpoint_retry_returns_existing_candidate_at_capacity() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let height = chain.checkpoint_interval().unwrap();
        backlog.set_processed_block(chain, height).await;

        let first = backlog.checkpoint(chain).await.unwrap();
        {
            let mut pending = backlog.pending_checkpoints(&chain).write().await;
            for offset in 1..MAX_PENDING_CHECKPOINTS {
                let mut checkpoint = first.clone();
                checkpoint.block_height += offset as u64;
                pending.insert(checkpoint.block_height, checkpoint);
            }
        }
        assert_eq!(
            backlog.pending_checkpoint_count(chain).await,
            MAX_PENDING_CHECKPOINTS
        );

        assert_eq!(backlog.checkpoint(chain).await, Some(first));
    }

    #[tokio::test]
    async fn test_checkpoint_rejects_inconsistent_bidirectional_projection() {
        let backlog = Backlog::new();
        let chain = Chain::Solana;
        let tx = create_test_tx(23);
        insert_bidirectional_with_status(
            &backlog,
            chain,
            tx.clone(),
            pending_execution_status(&tx),
            "ethereum",
        )
        .await;
        backlog.set_processed_block(chain, 10).await;
        let mut checkpoint = backlog.checkpoint(chain).await.unwrap();

        let pending = &mut checkpoint.pending_requests[0];
        let mut entry: BacklogEntry =
            ciborium::de::from_reader(pending.transaction.as_slice()).unwrap();
        entry.request.kind = SignKind::RespondBidirectional(RespondBidirectionalTx {
            tx_id: BidirectionalTxId([99; 32]),
            output: vec![],
            chain_ctx: None,
        });
        pending.transaction.clear();
        ciborium::ser::into_writer(&entry, &mut pending.transaction).unwrap();
        pending.canonical_transaction = canonical_entry_bytes(&entry);

        let error = backlog
            .recover_by_checkpoint(checkpoint)
            .await
            .expect_err("inconsistent bidirectional projection must be rejected");
        assert!(error.to_string().contains("final bidirectional response"));
    }

    #[tokio::test]
    async fn test_checkpoint_rejects_initial_response_with_plain_respond_kind() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let tx = create_test_tx(24);
        insert_bidirectional_with_status(
            &backlog,
            chain,
            tx.clone(),
            SignStatus::PendingGeneration,
            "ethereum",
        )
        .await;
        backlog.set_processed_block(chain, 10).await;
        let mut checkpoint = backlog.checkpoint(chain).await.unwrap();

        let pending = &mut checkpoint.pending_requests[0];
        let mut entry: BacklogEntry =
            ciborium::de::from_reader(pending.transaction.as_slice()).unwrap();
        entry.request.kind = SignKind::RespondBidirectional(RespondBidirectionalTx {
            tx_id: tx.id,
            output: vec![],
            chain_ctx: None,
        });
        pending.transaction.clear();
        ciborium::ser::into_writer(&entry, &mut pending.transaction).unwrap();
        pending.canonical_transaction = canonical_entry_bytes(&entry);

        let error = backlog
            .recover_by_checkpoint(checkpoint)
            .await
            .expect_err("initial response with a final request must be rejected");
        assert!(error.to_string().contains("must contain a sign request"));
    }
}
