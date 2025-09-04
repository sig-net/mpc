use crate::sign_respond_tx::{SignRespondTx, SignRespondTxId, SignRespondTxStatus};
use mpc_primitives::SignId;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

pub use crate::protocol::Chain;

/// Chain identifier for cross-chain management
pub type BlockHeight = u64;

/// Status of a pending bidirectional request
#[derive(Debug, Clone, PartialEq)]
pub enum PendingTxStatus {
    /// Waiting for signature to be generated
    PendingSignAndRespond,
    /// Signature generated, waiting for transaction to be executed on target chain
    PendingExecuteRespond,
    /// Transaction executed, waiting for read_respond to be called
    PendingRespond,
}

/// Information about a pending transaction including full transaction data
#[derive(Debug, Clone)]
pub struct PendingTxInfo {
    pub request_id: SignId,
    pub chain: Chain,
    pub block_height: BlockHeight,
    pub status: PendingTxStatus,
    pub timestamp: u64,
    /// Full transaction data for processing
    pub tx_data: Option<SignRespondTx>,
    pub tx_id: Option<SignRespondTxId>,
}

/// Chain-specific checkpoint tracking pending requests and logical dependencies
#[derive(Debug, Default, Clone)]
pub struct ChainCheckpoint {
    /// The last processed block for this chain
    pub processed_block_height: BlockHeight,

    /// For each other chain, the target height of the latest seen dependency
    /// where the other chain was the source and this chain was the target
    pub latest_logical_dependency: BTreeMap<Chain, BlockHeight>,

    /// All pending requests by status
    pub pending_tx: BTreeMap<SignId, PendingTxInfo>,
}

/// Network-wide checkpoint manager for bidirectional messaging
#[derive(Debug, Clone)]
pub struct CheckpointManager {
    /// Per-chain checkpoints
    pub chain_checkpoints: Arc<RwLock<BTreeMap<Chain, ChainCheckpoint>>>,

    /// Map from SignRespondTxId to SignId for bidirectional tracking
    pub tx_id_to_sign_id: Arc<RwLock<HashMap<SignRespondTxId, SignId>>>,
}

impl Default for CheckpointManager {
    fn default() -> Self {
        CheckpointManager::new()
    }
}

impl ChainCheckpoint {
    /// Add a new sign_and_respond request
    pub fn new_sign_and_respond_request(
        &mut self,
        request_id: SignId,
        chain: Chain,
        block_height: BlockHeight,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let pending_info = PendingTxInfo {
            request_id,
            chain,
            block_height,
            status: PendingTxStatus::PendingSignAndRespond,
            timestamp,
            tx_data: None,
            tx_id: None,
        };

        self.pending_tx.insert(request_id, pending_info);

        // Update the processed block height to the latest block
        if block_height > self.processed_block_height {
            self.processed_block_height = block_height;
        }
    }

    /// Mark that a signed transaction has been published
    pub fn published_signed_transaction(
        &mut self,
        request_id: &SignId,
        tx_data: SignRespondTx,
    ) -> bool {
        if let Some(pending_info) = self.pending_tx.get_mut(request_id) {
            pending_info.status = PendingTxStatus::PendingExecuteRespond;
            pending_info.tx_data = Some(tx_data.clone());
            pending_info.tx_id = Some(tx_data.id);
            true
        } else {
            false
        }
    }

    /// Mark that transaction output has been found
    pub fn found_tx_output(&mut self, request_id: &SignId) -> bool {
        if let Some(pending_info) = self.pending_tx.get_mut(request_id) {
            pending_info.status = PendingTxStatus::PendingRespond;
            true
        } else {
            false
        }
    }

    /// Mark that signed output has been published (request completed)
    pub fn published_signed_output(&mut self, request_id: &SignId) -> bool {
        self.pending_tx.remove(request_id).is_some()
    }

    /// Update the processed block height
    pub fn processed_block(&mut self, height: BlockHeight) {
        self.processed_block_height = height;
    }

    /// Observe a dependency from another chain
    pub fn observe_dependency(&mut self, source_chain: Chain, target_height: BlockHeight) {
        let current_height = self
            .latest_logical_dependency
            .get(&source_chain)
            .copied()
            .unwrap_or(0);

        self.latest_logical_dependency
            .insert(source_chain, target_height.max(current_height));
    }

    /// Get all pending requests by status
    pub fn get_pending_by_status(&self, status: PendingTxStatus) -> Vec<SignId> {
        self.pending_tx
            .values()
            .filter(|info| info.status == status)
            .map(|info| info.request_id)
            .collect()
    }

    /// Check if we can delete blocks up to a certain height
    pub fn can_delete_blocks_up_to(&self, height: BlockHeight) -> bool {
        // Can only delete blocks if all other chains have progressed logically after
        self.latest_logical_dependency
            .values()
            .all(|&dep_height| dep_height >= height)
    }

    /// Get all pending transactions with their data
    pub fn get_pending_txs_by_status(
        &self,
        status: PendingTxStatus,
    ) -> HashMap<SignRespondTxId, SignRespondTx> {
        self.pending_tx
            .values()
            .filter(|info| info.status == status && info.tx_data.is_some())
            .filter_map(|info| {
                info.tx_id.and_then(|tx_id| {
                    info.tx_data
                        .as_ref()
                        .map(|tx_data| (tx_id, tx_data.clone()))
                })
            })
            .collect()
    }

    /// Update transaction status by tx_id
    pub fn update_tx_status_by_id(
        &mut self,
        tx_id: &SignRespondTxId,
        new_status: SignRespondTxStatus,
    ) -> bool {
        for pending_info in self.pending_tx.values_mut() {
            if pending_info.tx_id == Some(*tx_id) {
                if let Some(ref mut tx_data) = pending_info.tx_data {
                    tx_data.status = new_status;
                    return true;
                }
            }
        }
        false
    }

    /// Get transaction data by tx_id
    pub fn get_tx_by_id(&self, tx_id: &SignRespondTxId) -> Option<SignRespondTx> {
        for pending_info in self.pending_tx.values() {
            if pending_info.tx_id == Some(*tx_id) {
                return pending_info.tx_data.clone();
            }
        }
        None
    }

    /// Store transaction data for a pending request
    pub fn store_tx_data(&mut self, request_id: &SignId, tx_data: SignRespondTx) -> bool {
        if let Some(pending_info) = self.pending_tx.get_mut(request_id) {
            pending_info.tx_data = Some(tx_data.clone());
            pending_info.tx_id = Some(tx_data.id);
            true
        } else {
            false
        }
    }

    /// Remove transaction by tx_id
    pub fn remove_tx_by_id(&mut self, tx_id: &SignRespondTxId) -> Option<SignRespondTx> {
        for (request_id, pending_info) in &self.pending_tx {
            if pending_info.tx_id == Some(*tx_id) {
                let result = pending_info.tx_data.clone();
                let request_id_to_remove = *request_id;
                self.pending_tx.remove(&request_id_to_remove);
                return result;
            }
        }
        None
    }

    /// Insert or update a transaction
    pub fn insert_or_update_tx(&mut self, tx_id: SignRespondTxId, tx_data: SignRespondTx) -> bool {
        // Find existing entry by tx_id or create new one
        for pending_info in self.pending_tx.values_mut() {
            if pending_info.tx_id == Some(tx_id) {
                pending_info.tx_data = Some(tx_data);
                return true;
            }
        }

        // Create new entry if not found/updated
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let request_id = SignId::new(tx_data.request_id);
        let status = match tx_data.status {
            SignRespondTxStatus::Pending => PendingTxStatus::PendingExecuteRespond,
            SignRespondTxStatus::Success => PendingTxStatus::PendingRespond,
            SignRespondTxStatus::Failed => PendingTxStatus::PendingRespond,
        };

        let pending_info = PendingTxInfo {
            request_id,
            chain: Chain::Ethereum, // Default to ethereum for now
            block_height: 0,        // Will be updated when we know the block
            status,
            timestamp,
            tx_data: Some(tx_data),
            tx_id: Some(tx_id),
        };

        self.pending_tx.insert(request_id, pending_info);
        false
    }
}

impl CheckpointManager {
    pub fn new() -> Self {
        Self {
            chain_checkpoints: Arc::new(RwLock::new(BTreeMap::new())),
            tx_id_to_sign_id: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a new sign_and_respond request to the checkpoint system
    pub async fn new_sign_and_respond_request(
        &self,
        chain: Chain,
        request_id: SignId,
        block_height: BlockHeight,
    ) {
        let mut checkpoints = self.chain_checkpoints.write().await;
        let checkpoint = checkpoints
            .entry(chain)
            .or_insert_with(ChainCheckpoint::default);

        checkpoint.new_sign_and_respond_request(request_id, chain, block_height);
    }

    /// Mark that a signed transaction has been published
    pub async fn published_signed_transaction(
        &self,
        chain: &Chain,
        request_id: &SignId,
        tx_id: SignRespondTxId,
        tx_data: SignRespondTx,
    ) -> bool {
        // Store mapping for future lookup
        self.tx_id_to_sign_id
            .write()
            .await
            .insert(tx_id, *request_id);

        let mut checkpoints = self.chain_checkpoints.write().await;
        if let Some(checkpoint) = checkpoints.get_mut(chain) {
            checkpoint.published_signed_transaction(request_id, tx_data)
        } else {
            false
        }
    }

    /// Mark that transaction output has been found
    pub async fn found_tx_output(&self, chain: Chain, request_id: &SignId) -> bool {
        let mut checkpoints = self.chain_checkpoints.write().await;
        if let Some(checkpoint) = checkpoints.get_mut(&chain) {
            checkpoint.found_tx_output(request_id)
        } else {
            false
        }
    }

    /// Mark that signed output has been published (request completed)
    pub async fn published_signed_output(&self, chain: Chain, request_id: &SignId) -> bool {
        let mut checkpoints = self.chain_checkpoints.write().await;
        if let Some(checkpoint) = checkpoints.get_mut(&chain) {
            checkpoint.published_signed_output(request_id)
        } else {
            false
        }
    }

    /// Update processed block height for a chain
    pub async fn processed_block(&self, chain: Chain, height: BlockHeight) {
        let mut checkpoints = self.chain_checkpoints.write().await;
        let checkpoint = checkpoints
            .entry(chain)
            .or_insert_with(ChainCheckpoint::default);

        checkpoint.processed_block(height);
    }

    /// Observe a dependency between chains
    pub async fn observe_dependency(
        &self,
        target_chain: Chain,
        source_chain: Chain,
        target_height: BlockHeight,
    ) {
        let mut checkpoints = self.chain_checkpoints.write().await;
        let checkpoint = checkpoints
            .entry(target_chain)
            .or_insert_with(ChainCheckpoint::default);

        checkpoint.observe_dependency(source_chain, target_height);
    }

    /// Get pending requests by status for a chain
    pub async fn get_pending_by_status(
        &self,
        chain: &Chain,
        status: PendingTxStatus,
    ) -> Vec<SignId> {
        let checkpoints = self.chain_checkpoints.read().await;
        if let Some(checkpoint) = checkpoints.get(chain) {
            checkpoint.get_pending_by_status(status)
        } else {
            Vec::new()
        }
    }

    /// Get a checkpoint for a specific chain
    pub async fn get_chain_checkpoint(&self, chain: &Chain) -> Option<ChainCheckpoint> {
        let checkpoints = self.chain_checkpoints.read().await;
        checkpoints.get(chain).cloned()
    }

    /// Lookup SignId from SignRespondTxId
    pub async fn get_sign_id_from_tx_id(&self, tx_id: &SignRespondTxId) -> Option<SignId> {
        let mapping = self.tx_id_to_sign_id.read().await;
        mapping.get(tx_id).copied()
    }

    /// Get all pending requests that need to be retried
    pub async fn get_retry_candidates(&self, chain: &Chain) -> Vec<SignId> {
        let mut retry_candidates = Vec::new();

        // Get all pending requests that might need retry
        retry_candidates.extend(
            self.get_pending_by_status(chain, PendingTxStatus::PendingSignAndRespond)
                .await,
        );
        retry_candidates.extend(
            self.get_pending_by_status(chain, PendingTxStatus::PendingExecuteRespond)
                .await,
        );
        retry_candidates.extend(
            self.get_pending_by_status(chain, PendingTxStatus::PendingRespond)
                .await,
        );

        retry_candidates
    }

    /// Get all pending transactions with their data by status for a specific chain
    pub async fn get_pending_txs_by_status(
        &self,
        chain: Chain,
        status: PendingTxStatus,
    ) -> HashMap<SignRespondTxId, SignRespondTx> {
        let checkpoints = self.chain_checkpoints.read().await;
        if let Some(checkpoint) = checkpoints.get(&chain) {
            checkpoint.get_pending_txs_by_status(status)
        } else {
            HashMap::new()
        }
    }

    /// Get all pending transactions with status Pending (for SignRespondTxStatus compatibility)
    pub async fn get_pending_sign_respond_txs(
        &self,
        chain: Chain,
    ) -> HashMap<SignRespondTxId, SignRespondTx> {
        // Get all transactions that are in PendingExecuteRespond status (equivalent to SignRespondTxStatus::Pending)
        self.get_pending_txs_by_status(chain, PendingTxStatus::PendingExecuteRespond)
            .await
    }

    /// Update transaction status by tx_id
    pub async fn update_tx_status_by_id(
        &self,
        chain: Chain,
        tx_id: &SignRespondTxId,
        new_status: SignRespondTxStatus,
    ) -> bool {
        let mut checkpoints = self.chain_checkpoints.write().await;
        if let Some(checkpoint) = checkpoints.get_mut(&chain) {
            checkpoint.update_tx_status_by_id(tx_id, new_status)
        } else {
            false
        }
    }

    /// Get transaction data by tx_id
    pub async fn get_tx_by_id(
        &self,
        chain: Chain,
        tx_id: &SignRespondTxId,
    ) -> Option<SignRespondTx> {
        let checkpoints = self.chain_checkpoints.read().await;
        if let Some(checkpoint) = checkpoints.get(&chain) {
            checkpoint.get_tx_by_id(tx_id)
        } else {
            None
        }
    }

    /// Store transaction data for a pending request
    pub async fn store_tx_data(
        &self,
        chain: &Chain,
        request_id: &SignId,
        tx_data: SignRespondTx,
    ) -> bool {
        let mut checkpoints = self.chain_checkpoints.write().await;
        if let Some(checkpoint) = checkpoints.get_mut(chain) {
            checkpoint.store_tx_data(request_id, tx_data)
        } else {
            false
        }
    }

    /// Insert or update a transaction
    pub async fn insert_or_update_tx(
        &self,
        chain: Chain,
        tx_id: SignRespondTxId,
        tx_data: SignRespondTx,
    ) -> bool {
        let mut checkpoints = self.chain_checkpoints.write().await;
        let checkpoint = checkpoints
            .entry(chain)
            .or_insert_with(ChainCheckpoint::default);

        checkpoint.insert_or_update_tx(tx_id, tx_data.clone())
    }

    /// Remove transaction by tx_id
    pub async fn remove_tx_by_id(
        &self,
        chain: Chain,
        tx_id: &SignRespondTxId,
    ) -> Option<SignRespondTx> {
        let mut checkpoints = self.chain_checkpoints.write().await;
        let result = if let Some(checkpoint) = checkpoints.get_mut(&chain) {
            checkpoint.remove_tx_by_id(tx_id)
        } else {
            None
        };

        result
    }
}
