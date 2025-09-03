use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use mpc_primitives::SignId;
use crate::sign_respond_tx::{SignRespondTx, SignRespondTxId};

/// Chain identifier for cross-chain management
pub type ChainId = String;
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

/// Information about a pending transaction
#[derive(Debug, Clone)]
pub struct PendingTxInfo {
    pub request_id: SignId,
    pub chain_id: ChainId,
    pub block_height: BlockHeight,
    pub status: PendingTxStatus,
    pub timestamp: u64,
}

/// Chain-specific checkpoint tracking pending requests and logical dependencies
#[derive(Debug, Clone)]
pub struct ChainCheckpoint {
    /// The last processed block for this chain
    pub processed_block_height: BlockHeight,
    
    /// For each other chain, the target height of the latest seen dependency
    /// where the other chain was the source and this chain was the target
    pub latest_logical_dependency: BTreeMap<ChainId, BlockHeight>,
    
    /// All pending requests by status
    pub pending_tx: BTreeMap<SignId, PendingTxInfo>,
}

/// Network-wide checkpoint manager for bidirectional messaging
#[derive(Debug)]
pub struct CheckpointManager {
    /// Per-chain checkpoints
    pub chain_checkpoints: Arc<RwLock<BTreeMap<ChainId, ChainCheckpoint>>>,
    
    /// Map from SignRespondTxId to SignId for bidirectional tracking
    pub tx_id_to_sign_id: Arc<RwLock<HashMap<SignRespondTxId, SignId>>>,
    
    /// Legacy sign_respond_tx_map for compatibility
    pub sign_respond_tx_map: Arc<RwLock<HashMap<SignRespondTxId, SignRespondTx>>>,
}

impl Default for ChainCheckpoint {
    fn default() -> Self {
        Self {
            processed_block_height: 0,
            latest_logical_dependency: BTreeMap::new(),
            pending_tx: BTreeMap::new(),
        }
    }
}

impl ChainCheckpoint {
    /// Add a new sign_and_respond request
    pub fn new_sign_and_respond_request(
        &mut self, 
        request_id: SignId, 
        chain_id: ChainId, 
        block_height: BlockHeight
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let pending_info = PendingTxInfo {
            request_id,
            chain_id,
            block_height,
            status: PendingTxStatus::PendingSignAndRespond,
            timestamp,
        };
        
        self.pending_tx.insert(request_id, pending_info);
        
        // Update the processed block height to the latest block
        if block_height > self.processed_block_height {
            self.processed_block_height = block_height;
        }
    }

    /// Mark that a signed transaction has been published
    pub fn published_signed_transaction(&mut self, request_id: &SignId) -> bool {
        if let Some(pending_info) = self.pending_tx.get_mut(request_id) {
            pending_info.status = PendingTxStatus::PendingExecuteRespond;
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
    pub fn observe_dependency_from(&mut self, source_chain: ChainId, target_height: BlockHeight) {
        let current_height = self.latest_logical_dependency
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
}

impl CheckpointManager {
    pub fn new(sign_respond_tx_map: Arc<RwLock<HashMap<SignRespondTxId, SignRespondTx>>>) -> Self {
        Self {
            chain_checkpoints: Arc::new(RwLock::new(BTreeMap::new())),
            tx_id_to_sign_id: Arc::new(RwLock::new(HashMap::new())),
            sign_respond_tx_map,
        }
    }

    /// Add a new sign_and_respond request to the checkpoint system
    pub async fn new_sign_and_respond_request(
        &self,
        chain_id: ChainId,
        request_id: SignId,
        block_height: BlockHeight,
    ) {
        let mut checkpoints = self.chain_checkpoints.write().await;
        let checkpoint = checkpoints
            .entry(chain_id.clone())
            .or_insert_with(ChainCheckpoint::default);
        
        checkpoint.new_sign_and_respond_request(request_id, chain_id, block_height);
    }

    /// Mark that a signed transaction has been published
    pub async fn published_signed_transaction(
        &self,
        chain_id: &ChainId,
        request_id: &SignId,
        tx_id: SignRespondTxId,
    ) -> bool {
        // Store mapping for future lookup
        self.tx_id_to_sign_id.write().await.insert(tx_id, *request_id);
        
        let mut checkpoints = self.chain_checkpoints.write().await;
        if let Some(checkpoint) = checkpoints.get_mut(chain_id) {
            checkpoint.published_signed_transaction(request_id)
        } else {
            false
        }
    }

    /// Mark that transaction output has been found
    pub async fn found_tx_output(&self, chain_id: &ChainId, request_id: &SignId) -> bool {
        let mut checkpoints = self.chain_checkpoints.write().await;
        if let Some(checkpoint) = checkpoints.get_mut(chain_id) {
            checkpoint.found_tx_output(request_id)
        } else {
            false
        }
    }

    /// Mark that signed output has been published (request completed)
    pub async fn published_signed_output(&self, chain_id: &ChainId, request_id: &SignId) -> bool {
        let mut checkpoints = self.chain_checkpoints.write().await;
        if let Some(checkpoint) = checkpoints.get_mut(chain_id) {
            checkpoint.published_signed_output(request_id)
        } else {
            false
        }
    }

    /// Update processed block height for a chain
    pub async fn processed_block(&self, chain_id: ChainId, height: BlockHeight) {
        let mut checkpoints = self.chain_checkpoints.write().await;
        let checkpoint = checkpoints
            .entry(chain_id)
            .or_insert_with(ChainCheckpoint::default);
        
        checkpoint.processed_block(height);
    }

    /// Observe a dependency between chains
    pub async fn observe_dependency(
        &self,
        target_chain: ChainId,
        source_chain: ChainId,
        target_height: BlockHeight,
    ) {
        let mut checkpoints = self.chain_checkpoints.write().await;
        let checkpoint = checkpoints
            .entry(target_chain)
            .or_insert_with(ChainCheckpoint::default);
        
        checkpoint.observe_dependency_from(source_chain, target_height);
    }

    /// Get pending requests by status for a chain
    pub async fn get_pending_by_status(
        &self,
        chain_id: &ChainId,
        status: PendingTxStatus,
    ) -> Vec<SignId> {
        let checkpoints = self.chain_checkpoints.read().await;
        if let Some(checkpoint) = checkpoints.get(chain_id) {
            checkpoint.get_pending_by_status(status)
        } else {
            Vec::new()
        }
    }

    /// Get a checkpoint for a specific chain
    pub async fn get_chain_checkpoint(&self, chain_id: &ChainId) -> Option<ChainCheckpoint> {
        let checkpoints = self.chain_checkpoints.read().await;
        checkpoints.get(chain_id).cloned()
    }

    /// Lookup SignId from SignRespondTxId
    pub async fn get_sign_id_from_tx_id(&self, tx_id: &SignRespondTxId) -> Option<SignId> {
        let mapping = self.tx_id_to_sign_id.read().await;
        mapping.get(tx_id).copied()
    }

    /// Get all pending requests that need to be retried
    pub async fn get_retry_candidates(&self, chain_id: &ChainId) -> Vec<SignId> {
        let mut retry_candidates = Vec::new();
        
        // Get all pending requests that might need retry
        retry_candidates.extend(
            self.get_pending_by_status(chain_id, PendingTxStatus::PendingSignAndRespond)
                .await,
        );
        retry_candidates.extend(
            self.get_pending_by_status(chain_id, PendingTxStatus::PendingExecuteRespond)
                .await,
        );
        retry_candidates.extend(
            self.get_pending_by_status(chain_id, PendingTxStatus::PendingRespond)
                .await,
        );
        
        retry_candidates
    }
}
