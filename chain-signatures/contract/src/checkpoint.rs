use mpc_primitives::SignId;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::BlockHeight;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ChainCheckpoint {
    /// The last processed block for this chain.
    /// Invariant: No requests with smaller block height will appear.
    pub processed_block_height: BlockHeight,
    
    /// For each other chain, the target height of the latest seen dependency
    /// where the other chain was the source and this chain was the target.
    pub latest_logical_dependency: BTreeMap<String, BlockHeight>,
    
    /// All requests that have a `sign_and_respond` call but no `read_respond` 
    /// delivered in the block range [0, processed_block_height]
    pub pending_tx: BTreeMap<SignId, PendingTxInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct PendingTxInfo {
    pub request_id: SignId,
    pub chain_id: String,
    pub block_height: BlockHeight,
    pub status: PendingTxStatus,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub enum PendingTxStatus {
    /// Waiting for signature to be generated
    PendingSignAndRespond,
    /// Signature generated, waiting for transaction to be executed on target chain
    PendingExecuteRespond,
    /// Transaction executed, waiting for read_respond to be called
    PendingRespond,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct NetworkCheckpoint {
    /// Map of chain_id to its checkpoint
    pub chain_checkpoints: BTreeMap<String, ChainCheckpoint>,
    /// Global checkpoint timestamp
    pub timestamp: u64,
    /// Height at which this checkpoint was created
    pub checkpoint_height: BlockHeight,
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

impl Default for NetworkCheckpoint {
    fn default() -> Self {
        Self {
            chain_checkpoints: BTreeMap::new(),
            timestamp: 0,
            checkpoint_height: 0,
        }
    }
}

impl ChainCheckpoint {
    pub fn new_sign_and_respond_request(
        &mut self, 
        request_id: SignId, 
        chain_id: String, 
        block_height: BlockHeight,
        timestamp: u64,
    ) {
        let pending_info = PendingTxInfo {
            request_id,
            chain_id,
            block_height,
            status: PendingTxStatus::PendingSignAndRespond,
            timestamp,
        };
        self.pending_tx.insert(request_id, pending_info);
    }

    pub fn published_signed_transaction(&mut self, request_id: &SignId) -> bool {
        if let Some(pending_info) = self.pending_tx.get_mut(request_id) {
            pending_info.status = PendingTxStatus::PendingExecuteRespond;
            true
        } else {
            false
        }
    }

    pub fn found_tx_output(&mut self, request_id: &SignId) -> bool {
        if let Some(pending_info) = self.pending_tx.get_mut(request_id) {
            pending_info.status = PendingTxStatus::PendingRespond;
            true
        } else {
            false
        }
    }

    pub fn published_signed_output(&mut self, request_id: &SignId) -> bool {
        self.pending_tx.remove(request_id).is_some()
    }

    pub fn processed_block(&mut self, height: BlockHeight) {
        self.processed_block_height = height;
    }

    pub fn observe_dependency_from(&mut self, source_chain: String, target_height: BlockHeight) {
        let current_height = self.latest_logical_dependency
            .get(&source_chain)
            .copied()
            .unwrap_or(0);
        
        self.latest_logical_dependency
            .insert(source_chain, target_height.max(current_height));
    }

    pub fn get_pending_by_status(&self, status: PendingTxStatus) -> Vec<SignId> {
        self.pending_tx
            .values()
            .filter(|info| std::mem::discriminant(&info.status) == std::mem::discriminant(&status))
            .map(|info| info.request_id)
            .collect()
    }
}
