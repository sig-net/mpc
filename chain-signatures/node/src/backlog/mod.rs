pub mod selection;

use self::selection::select_checkpoints;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::{Chain, SignRequestType};
use crate::sign_bidirectional::{BidirectionalTx, BidirectionalTxId, PendingRequestStatus};
use crate::storage::checkpoint_storage::CheckpointStorage;

use anyhow::Context;
use mpc_primitives::{PendingTx, SignArgs, SignId};
use std::collections::{hash_map, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub use mpc_primitives::Checkpoint;

// Clean up old checkpoints (older than 30 minutes)
const RETENTION_DURATION: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone)]
pub struct PendingRequests {
    requests: HashMap<SignId, BacklogTransaction>,
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
    fn insert(&mut self, id: SignId, tx: BacklogTransaction) -> Option<BacklogTransaction> {
        self.requests.insert(id, tx)
    }

    /// Removes a sign-respond transaction from the pending requests map
    /// Returns Some(value) if the key was present
    fn remove(&mut self, id: &SignId) -> Option<BacklogTransaction> {
        self.requests.remove(id)
    }

    /// Gets a clone of a sign-respond transaction from the pending requests map
    /// Returns Some(value) if the key is present
    fn get(&self, id: &SignId) -> Option<BacklogTransaction> {
        self.requests.get(id).cloned()
    }

    /// Returns the number of pending requests
    fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns all sign-respond transactions with a specific status
    pub fn get_by_status(
        &self,
        status: PendingRequestStatus,
    ) -> HashMap<SignId, BacklogTransaction> {
        self.requests
            .iter()
            .filter(|(_, tx)| tx.status() == status)
            .map(|(id, tx)| (*id, tx.clone()))
            .collect()
    }

    fn pending_execution(&self) -> Vec<(SignId, BacklogTransaction)> {
        self.requests
            .iter()
            .filter(|(_, tx)| tx.status() == PendingRequestStatus::PendingExecution)
            .map(|(&id, tx)| (id, tx.clone()))
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
            .map(|(&sign_id, tx)| {
                let transaction = serde_json::to_vec(&tx)
                    .expect("serialize bidirectional transaction for checkpoint");
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
        fn decode(
            pending: mpc_primitives::PendingTx,
        ) -> anyhow::Result<(SignId, BacklogTransaction)> {
            let tx: BacklogTransaction = serde_json::from_slice(&pending.transaction)
                .with_context(|| {
                    format!(
                        "failed to deserialize pending transaction for sign_id {:?}",
                        pending.sign_id
                    )
                })?;
            Ok((pending.sign_id, tx))
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
    execution_watchers: Arc<RwLock<HashMap<Chain, ExecutionWatchers>>>,
    sign_request_types: Arc<RwLock<HashMap<(Chain, SignId), SignRequestType>>>,
    /// Historical checkpoints kept for 30 minutes, indexed by chain
    historical_checkpoints: Arc<RwLock<HashMap<Chain, Vec<HistoricalCheckpoint>>>>,
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
            execution_watchers: Arc::new(RwLock::new(HashMap::new())),
            sign_request_types: Arc::new(RwLock::new(HashMap::new())),
            historical_checkpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(
        &self,
        chain: Chain,
        id: SignId,
        tx: BacklogTransaction,
        sign_type: SignRequestType,
    ) -> Option<BacklogTransaction> {
        self.set_sign_request_type(chain, id, sign_type).await;

        let (prev, len) = {
            let mut requests = self.requests.write().await;
            let pending = requests.entry(chain).or_insert_with(PendingRequests::new);
            let p = pending.insert(id, tx);
            (p, pending.len())
        };

        self.observe_backlog_size(chain, len);
        prev
    }

    pub async fn remove(&self, chain: Chain, id: &SignId) -> Option<BacklogTransaction> {
        // Also remove the sign request type tracking
        self.remove_sign_request_type(chain, id).await;

        let (removed, len) = {
            let mut requests = self.requests.write().await;
            let pending = requests.entry(chain).or_insert_with(PendingRequests::new);
            let rem = pending.remove(id);
            (rem, pending.len())
        };

        self.observe_backlog_size(chain, len);
        removed
    }

    pub async fn get(&self, chain: Chain, id: &SignId) -> Option<BacklogTransaction> {
        self.requests
            .read()
            .await
            .get(&chain)
            .and_then(|pending_requests| pending_requests.get(id))
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

    /// Track the sign request type for a given sign ID
    /// Store the sign request type for a given sign ID (internal only, set during insert)
    async fn set_sign_request_type(
        &self,
        chain: Chain,
        id: SignId,
        sign_request_type: SignRequestType,
    ) {
        self.sign_request_types
            .write()
            .await
            .insert((chain, id), sign_request_type);
    }

    /// Get the sign request type for a given sign ID
    pub async fn sign_type(&self, chain: Chain, id: &SignId) -> Option<SignRequestType> {
        self.sign_request_types
            .read()
            .await
            .get(&(chain, *id))
            .cloned()
    }

    /// Remove the sign request type tracking for a given sign ID (internal only, removed during remove)
    async fn remove_sign_request_type(&self, chain: Chain, id: &SignId) {
        self.sign_request_types.write().await.remove(&(chain, *id));
    }

    fn observe_backlog_size(&self, chain: Chain, len: usize) {
        crate::metrics::requests::BACKLOG_SIZE
            .with_label_values(&[chain.as_str()])
            .set(len as i64);
    }

    /// Returns all sign-respond transactions with a specific status
    pub async fn get_by_status(
        &self,
        chain: Chain,
        status: PendingRequestStatus,
    ) -> HashMap<SignId, BacklogTransaction> {
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
        status: PendingRequestStatus,
    ) -> Option<BacklogTransaction> {
        let mut requests = self.requests.write().await;
        let Some(pending) = requests.get_mut(&chain) else {
            tracing::warn!(?chain, ?id, ?status, "set_status: chain not found");
            return None;
        };
        let Some(tx) = pending.requests.get_mut(id) else {
            tracing::warn!(
                ?chain,
                ?id,
                ?status,
                "set_status: tx id not found in chain pending requests"
            );
            return None;
        };
        tracing::info!(?chain, ?id, before = ?tx.status(), after = ?status, "set_status: updating");
        tx.set_status(status);
        Some(tx.clone())
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

        // Replace the Sign transaction with the Bidirectional transaction
        pending.requests.insert(
            sign_id,
            BacklogTransaction::Bidirectional(bidirectional_tx.clone()),
        );

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
            if let Some(target_chain) = tx.target_chain() {
                // Extract the BidirectionalTx from the BacklogTransaction
                if let BacklogTransaction::Bidirectional(bidirectional_tx) = tx {
                    self.watch_execution(target_chain, sign_id, bidirectional_tx)
                        .await;
                }
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
    ) -> HashMap<Chain, HashMap<SignId, BacklogTransaction>> {
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
        let remote_checkpoints =
            select_checkpoints(mesh_state, node_client, threshold, chains).await;

        // Merge local and remote checkpoints, preferring the one with higher block height
        let checkpoints = merge_checkpoints(local_checkpoints, remote_checkpoints);

        if checkpoints.is_empty() {
            tracing::info!("no selected checkpoints found, starting with empty state");
            return HashMap::new();
        }

        for (chain, checkpoint) in checkpoints {
            tracing::info!(
                ?chain,
                block_height = checkpoint.block_height,
                "found selected checkpoint, attempting recovery"
            );
            if let Err(err) = self.recover_by_checkpoint(checkpoint).await {
                tracing::warn!(
                    ?chain,
                    %err,
                    "failed to recover from selected checkpoint, continuing with empty state"
                );
            }
        }

        // Snapshot pending requests for the requested chains
        let requests = self.requests.read().await;
        let mut recovered = HashMap::new();
        for &chain in chains {
            if let Some(pending) = requests.get(&chain) {
                recovered.insert(chain, pending.requests.clone());
            }
        }

        recovered
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
}

/// Sign request transaction metadata (non-bidirectional).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignTx {
    pub request_id: [u8; 32],
    pub source_chain: Chain,
    pub status: PendingRequestStatus,
    pub args: SignArgs,
    pub unix_timestamp_indexed: u64,
}

/// Pending transaction in the backlog - can be either a sign-only or bidirectional.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum BacklogTransaction {
    Sign(SignTx),
    Bidirectional(BidirectionalTx),
}

impl BacklogTransaction {
    /// Get the request ID for this transaction
    pub fn request_id(&self) -> [u8; 32] {
        match self {
            Self::Sign(tx) => tx.request_id,
            Self::Bidirectional(tx) => tx.request_id,
        }
    }

    /// Get the source chain for this transaction
    pub fn source_chain(&self) -> Chain {
        match self {
            Self::Sign(tx) => tx.source_chain,
            Self::Bidirectional(tx) => tx.source_chain,
        }
    }

    /// Get the status of this transaction
    pub fn status(&self) -> PendingRequestStatus {
        match self {
            Self::Sign(tx) => tx.status,
            Self::Bidirectional(tx) => tx.status,
        }
    }

    /// Set the status of this transaction
    pub fn set_status(&mut self, status: PendingRequestStatus) {
        match self {
            Self::Sign(tx) => tx.status = status,
            Self::Bidirectional(tx) => tx.status = status,
        }
    }

    /// Get target chain if this is a bidirectional transaction
    pub fn target_chain(&self) -> Option<Chain> {
        match self {
            Self::Sign(_) => None,
            Self::Bidirectional(tx) => Some(tx.target_chain),
        }
    }

    /// Check if this is a bidirectional transaction
    pub fn is_bidirectional(&self) -> bool {
        matches!(self, Self::Bidirectional(_))
    }
}

fn merge_checkpoints(
    local: HashMap<Chain, Checkpoint>,
    mut remote: HashMap<Chain, Checkpoint>,
) -> HashMap<Chain, Checkpoint> {
    for (chain, local_cp) in local {
        remote
            .entry(chain)
            .and_modify(|remote_cp| {
                if local_cp.block_height > remote_cp.block_height {
                    tracing::info!(
                        ?chain,
                        local_height = local_cp.block_height,
                        remote_height = remote_cp.block_height,
                        "local checkpoint is newer than remote selection"
                    );
                    *remote_cp = local_cp.clone();
                }
            })
            .or_insert(local_cp);
    }
    remote
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::SignRequestType,
        sign_bidirectional::{BidirectionalTx, BidirectionalTxId, PendingRequestStatus},
    };
    use alloy::primitives::{Address, B256};
    use anchor_lang::prelude::Pubkey;
    use mpc_primitives::SignId;
    use signet_program::SignBidirectionalEvent;

    fn create_test_tx(id: u8, status: PendingRequestStatus) -> BidirectionalTx {
        BidirectionalTx {
            id: BidirectionalTxId(B256::from([id; 32])),
            sender: [0u8; 32],
            serialized_transaction: vec![1, 2, 3],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "test_caip2_id".to_string(),
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
            status,
        }
    }

    #[tokio::test]
    async fn test_backlog_chain_isolation() {
        let backlog = Backlog::new();

        let tx_eth = create_test_tx(1, PendingRequestStatus::AwaitingResponse);
        let tx_sol = create_test_tx(2, PendingRequestStatus::AwaitingResponse);
        let tx_near = create_test_tx(3, PendingRequestStatus::AwaitingResponse);

        let sign_id_eth = SignId::new(tx_eth.request_id);
        let sign_id_sol = SignId::new(tx_sol.request_id);
        let sign_id_near = SignId::new(tx_near.request_id);

        let program_id = Pubkey::new_unique();

        // Insert into different chains
        backlog
            .insert(
                Chain::Ethereum,
                sign_id_eth,
                BacklogTransaction::Bidirectional(tx_eth.clone()),
                SignRequestType::SignBidirectional(
                    crate::stream::ops::SignBidirectionalEvent::Solana(SignBidirectionalEvent {
                        sender: Default::default(),
                        serialized_transaction: vec![],
                        dest: "ethereum".to_string(),
                        caip2_id: "eip155:1".to_string(),
                        key_version: 0,
                        deposit: 0,
                        path: "".to_string(),
                        algo: "".to_string(),
                        params: "".to_string(),
                        program_id,
                        output_deserialization_schema: vec![],
                        respond_serialization_schema: vec![],
                    }),
                ),
            )
            .await;
        backlog
            .insert(
                Chain::Solana,
                sign_id_sol,
                BacklogTransaction::Bidirectional(tx_sol.clone()),
                SignRequestType::SignBidirectional(
                    crate::stream::ops::SignBidirectionalEvent::Solana(SignBidirectionalEvent {
                        sender: Default::default(),
                        serialized_transaction: vec![],
                        dest: "solana".to_string(),
                        caip2_id: "solana:5eykt4UsFY6PZFX8nTM1".to_string(),
                        key_version: 0,
                        deposit: 0,
                        path: "".to_string(),
                        algo: "".to_string(),
                        params: "".to_string(),
                        program_id,
                        output_deserialization_schema: vec![],
                        respond_serialization_schema: vec![],
                    }),
                ),
            )
            .await;
        backlog
            .insert(
                Chain::NEAR,
                sign_id_near,
                BacklogTransaction::Bidirectional(tx_near.clone()),
                SignRequestType::SignBidirectional(
                    crate::stream::ops::SignBidirectionalEvent::Solana(SignBidirectionalEvent {
                        sender: Default::default(),
                        serialized_transaction: vec![],
                        dest: "near".to_string(),
                        caip2_id: "near:mainnet".to_string(),
                        key_version: 0,
                        deposit: 0,
                        path: "".to_string(),
                        algo: "".to_string(),
                        params: "".to_string(),
                        program_id,
                        output_deserialization_schema: vec![],
                        respond_serialization_schema: vec![],
                    }),
                ),
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
        let tx1 = create_test_tx(1, PendingRequestStatus::AwaitingResponse);
        let tx2 = create_test_tx(2, PendingRequestStatus::Success);
        let tx3 = create_test_tx(3, PendingRequestStatus::PendingExecution);

        backlog
            .insert(
                Chain::Ethereum,
                SignId::new(tx1.request_id),
                BacklogTransaction::Bidirectional(tx1),
                SignRequestType::Sign,
            )
            .await;
        backlog
            .insert(
                Chain::Ethereum,
                SignId::new(tx2.request_id),
                BacklogTransaction::Bidirectional(tx2),
                SignRequestType::Sign,
            )
            .await;
        backlog
            .insert(
                Chain::Ethereum,
                SignId::new(tx3.request_id),
                BacklogTransaction::Bidirectional(tx3),
                SignRequestType::Sign,
            )
            .await;

        // Add transactions to Solana
        let tx4 = create_test_tx(4, PendingRequestStatus::PendingExecution);
        backlog
            .insert(
                Chain::Solana,
                SignId::new(tx4.request_id),
                BacklogTransaction::Bidirectional(tx4),
                SignRequestType::Sign,
            )
            .await;

        // Filter Ethereum by Pending
        let eth_pending = backlog
            .get_by_status(Chain::Ethereum, PendingRequestStatus::PendingExecution)
            .await;
        assert_eq!(eth_pending.len(), 1);

        let eth_awaiting = backlog
            .get_by_status(Chain::Ethereum, PendingRequestStatus::AwaitingResponse)
            .await;
        assert_eq!(eth_awaiting.len(), 1);

        // Filter Ethereum by Success
        let eth_success = backlog
            .get_by_status(Chain::Ethereum, PendingRequestStatus::Success)
            .await;
        assert_eq!(eth_success.len(), 1);

        // Filter Solana by Pending
        let sol_pending = backlog
            .get_by_status(Chain::Solana, PendingRequestStatus::PendingExecution)
            .await;
        assert_eq!(sol_pending.len(), 1);

        // Filter non-existent chain returns empty
        let near_pending = backlog
            .get_by_status(Chain::NEAR, PendingRequestStatus::PendingExecution)
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
                let tx = create_test_tx(i, PendingRequestStatus::AwaitingResponse);
                let sign_id = SignId::new(tx.request_id);
                backlog
                    .insert(
                        Chain::Ethereum,
                        sign_id,
                        BacklogTransaction::Bidirectional(tx),
                        SignRequestType::Sign,
                    )
                    .await;
            });
            handles.push(handle);
        }

        for i in 5..10 {
            let backlog = backlog.clone();
            let handle = tokio::spawn(async move {
                let tx = create_test_tx(i, PendingRequestStatus::AwaitingResponse);
                let sign_id = SignId::new(tx.request_id);
                backlog
                    .insert(
                        Chain::Solana,
                        sign_id,
                        BacklogTransaction::Bidirectional(tx),
                        SignRequestType::Sign,
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
        let tx1 = create_test_tx(1, PendingRequestStatus::PendingExecution);
        let tx2 = create_test_tx(2, PendingRequestStatus::Success);
        backlog.set_processed_block(Chain::Ethereum, 100).await;

        backlog
            .insert(
                Chain::Ethereum,
                SignId::new(tx1.request_id),
                BacklogTransaction::Bidirectional(tx1.clone()),
                SignRequestType::Sign,
            )
            .await;
        backlog
            .insert(
                Chain::Ethereum,
                SignId::new(tx2.request_id),
                BacklogTransaction::Bidirectional(tx2.clone()),
                SignRequestType::Sign,
            )
            .await;

        let checkpoint = backlog.checkpoint(Chain::Ethereum).await;
        assert_eq!(checkpoint.block_height, 100);
        assert_eq!(checkpoint.chain, Chain::Ethereum);
        assert_eq!(checkpoint.pending_requests.len(), 2);
    }

    #[tokio::test]
    async fn test_checkpoint_equality() {
        let tx1 = create_test_tx(1, PendingRequestStatus::AwaitingResponse);
        let tx2 = create_test_tx(2, PendingRequestStatus::AwaitingResponse);
        let mut pending1 = PendingRequests::new();
        pending1.insert(
            SignId::new(tx1.request_id),
            BacklogTransaction::Bidirectional(tx1.clone()),
        );
        pending1.insert(
            SignId::new(tx2.request_id),
            BacklogTransaction::Bidirectional(tx2.clone()),
        );
        pending1.set_processed_block(100);

        let mut pending2 = PendingRequests::new();
        pending2.insert(
            SignId::new(tx1.request_id),
            BacklogTransaction::Bidirectional(tx1.clone()),
        );
        pending2.insert(
            SignId::new(tx2.request_id),
            BacklogTransaction::Bidirectional(tx2.clone()),
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
        let tx1 = create_test_tx(1, PendingRequestStatus::AwaitingResponse);

        let mut pending = PendingRequests::new();
        pending.insert(
            SignId::new(tx1.request_id),
            BacklogTransaction::Bidirectional(tx1.clone()),
        );
        pending.set_processed_block(100);
        let checkpoint = pending.checkpoint(Chain::Ethereum);

        // Test JSON serialization
        let json = serde_json::to_string(&checkpoint).unwrap();
        let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(checkpoint, deserialized);

        let (sign_id, restored_tx): (SignId, BidirectionalTx) = {
            let pending = &checkpoint.pending_requests[0];
            let backlog_tx: BacklogTransaction =
                serde_json::from_slice(&pending.transaction).unwrap();
            let tx = match backlog_tx {
                BacklogTransaction::Bidirectional(tx) => tx,
                BacklogTransaction::Sign(_) => panic!("Expected Bidirectional transaction"),
            };
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
        let tx = create_test_tx(6, PendingRequestStatus::PendingExecution);
        let sign_id = SignId::new(tx.request_id);

        backlog
            .insert(
                Chain::Solana,
                sign_id,
                BacklogTransaction::Bidirectional(tx.clone()),
                SignRequestType::Sign,
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
    async fn test_watch_unwatch_and_set_status() {
        use k256::Scalar;
        let backlog = Backlog::new();
        let tx = create_test_tx(7, PendingRequestStatus::PendingExecution);
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
            .insert(
                tx.source_chain,
                sign_id,
                BacklogTransaction::Sign(SignTx {
                    request_id: sign_id.request_id,
                    source_chain: tx.source_chain,
                    status: PendingRequestStatus::AwaitingResponse,
                    args: args.clone(),
                    unix_timestamp_indexed,
                }),
                SignRequestType::Sign,
            )
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
            .set_status(tx.source_chain, &sign_id, PendingRequestStatus::Success)
            .await;
        let successes = backlog
            .get_by_status(tx.source_chain, PendingRequestStatus::Success)
            .await;
        assert!(successes.contains_key(&sign_id));
    }

    #[tokio::test]
    async fn test_automatic_checkpoint_on_interval() {
        let backlog = Backlog::new();

        // Add some transactions
        let tx1 = create_test_tx(1, PendingRequestStatus::PendingExecution);
        backlog
            .insert(
                Chain::Ethereum,
                SignId::new(tx1.request_id),
                BacklogTransaction::Bidirectional(tx1.clone()),
                SignRequestType::Sign,
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
        let tx1 = create_test_tx(1, PendingRequestStatus::PendingExecution);
        backlog
            .insert(
                Chain::Solana,
                SignId::new(tx1.request_id),
                BacklogTransaction::Bidirectional(tx1.clone()),
                SignRequestType::Sign,
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
    #[test]
    fn test_merge_checkpoints() {
        let mut local = HashMap::new();
        let mut remote = HashMap::new();

        // Case 1: Only local
        local.insert(
            Chain::Ethereum,
            Checkpoint {
                chain: Chain::Ethereum,
                block_height: 100,
                pending_requests: vec![],
            },
        );
        let merged = merge_checkpoints(local.clone(), remote.clone());
        assert_eq!(merged.get(&Chain::Ethereum).unwrap().block_height, 100);

        // Case 2: Only remote
        local.clear();
        remote.insert(
            Chain::Ethereum,
            Checkpoint {
                chain: Chain::Ethereum,
                block_height: 200,
                pending_requests: vec![],
            },
        );
        let merged = merge_checkpoints(local.clone(), remote.clone());
        assert_eq!(merged.get(&Chain::Ethereum).unwrap().block_height, 200);

        // Case 3: Local higher
        local.insert(
            Chain::Ethereum,
            Checkpoint {
                chain: Chain::Ethereum,
                block_height: 300,
                pending_requests: vec![],
            },
        );
        let merged = merge_checkpoints(local.clone(), remote.clone());
        assert_eq!(merged.get(&Chain::Ethereum).unwrap().block_height, 300);

        // Case 4: Remote higher
        remote.insert(
            Chain::Ethereum,
            Checkpoint {
                chain: Chain::Ethereum,
                block_height: 400,
                pending_requests: vec![],
            },
        );
        let merged = merge_checkpoints(local.clone(), remote.clone());
        assert_eq!(merged.get(&Chain::Ethereum).unwrap().block_height, 400);
    }
}
