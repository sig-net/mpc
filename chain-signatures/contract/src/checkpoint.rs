use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::IterableMap;
use near_sdk::{CryptoHash, PublicKey};
use std::collections::BTreeMap;

use crate::primitives::StorageKey;

/// A unique identifier for a chain in the multichain system
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ChainId(pub String);

/// Block height for a specific chain
pub type BlockHeight = u64;

/// A unique identifier for a cross-chain request
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Hash,
    PartialEq,
    Eq,
)]
#[borsh(crate = "near_sdk::borsh")]
pub struct RequestId(pub [u8; 32]);

/// Minimal contract state for tracking chain progress and dependencies
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ChainState {
    /// The chain this state tracks
    pub chain_id: ChainId,
    
    /// The latest block height processed by the indexer for this chain
    pub latest_block_height: BlockHeight,
    
    /// For each other chain, the target height of the latest seen dependency
    /// where the other chain was the source and this chain was the target.
    pub latest_logical_dependency: BTreeMap<ChainId, BlockHeight>,
    
    /// Last time this chain state was updated
    pub last_updated: u64,
}

impl ChainState {
    pub fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            latest_block_height: 0,
            latest_logical_dependency: BTreeMap::new(),
            last_updated: near_sdk::env::block_timestamp(),
        }
    }

    /// Update the latest block height for this chain
    pub fn update_block_height(&mut self, height: BlockHeight) {
        if height > self.latest_block_height {
            self.latest_block_height = height;
            self.last_updated = near_sdk::env::block_timestamp();
        }
    }

    /// Record a logical dependency from another chain
    pub fn observe_dependency_from(
        &mut self,
        source_chain: ChainId,
        _source_height: BlockHeight,
        target_height: BlockHeight,
    ) {
        let current_height = self.latest_logical_dependency
            .get(&source_chain)
            .copied()
            .unwrap_or(0);
        
        self.latest_logical_dependency
            .insert(source_chain, target_height.max(current_height));
        self.last_updated = near_sdk::env::block_timestamp();
    }
}

/// A checkpoint represents a snapshot of pending requests and chain state at a specific time
/// This is stored in the contract and can be requested by nodes for recovery
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Checkpoint {
    /// The chain this checkpoint is for
    pub chain_id: ChainId,
    
    /// Block height when this checkpoint was created
    pub block_height: BlockHeight,
    
    /// Latest logical dependencies at checkpoint time
    pub latest_logical_dependency: BTreeMap<ChainId, BlockHeight>,
    
    /// Snapshot of pending request IDs at this checkpoint
    /// Nodes will need to reconstruct the full Request objects from on-chain data
    pub pending_request_ids: Vec<RequestId>,
    
    /// Timestamp when checkpoint was created
    pub timestamp: u64,
    
    /// Signature from the MPC network to verify authenticity
    pub signature: Option<Vec<u8>>,
    
    /// Hash of the checkpoint data for integrity verification
    pub hash: CryptoHash,
}

impl Checkpoint {
    pub fn new(
        chain_id: ChainId,
        block_height: BlockHeight,
        latest_logical_dependency: BTreeMap<ChainId, BlockHeight>,
        pending_request_ids: Vec<RequestId>,
    ) -> Self {
        let timestamp = near_sdk::env::block_timestamp();
        
        // Create a simple hash of the checkpoint data
        let data = format!(
            "{}:{}:{}:{}:{}",
            chain_id.0,
            block_height,
            serde_json::to_string(&latest_logical_dependency).unwrap_or_default(),
            serde_json::to_string(&pending_request_ids).unwrap_or_default(),
            timestamp
        );
        let hash_bytes = near_sdk::env::keccak256(data.as_bytes());
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);

        Self {
            chain_id,
            block_height,
            latest_logical_dependency,
            pending_request_ids,
            timestamp,
            signature: None,
            hash: CryptoHash::from(hash_array),
        }
    }

    /// Verify the checkpoint signature (placeholder for actual implementation)
    pub fn verify_signature(&self, _signature: &[u8], _public_key: &PublicKey) -> bool {
        // TODO: Implement proper signature verification
        // This would verify that the checkpoint was signed by the MPC network
        true
    }

    /// Check if this checkpoint should be created based on block height and timestamp
    pub fn should_create_checkpoint(block_height: BlockHeight, timestamp: u64) -> bool {
        // Create checkpoint at the first block after every full hour
        let hour_in_nanoseconds = 3_600_000_000_000u64;
        
        // Also create checkpoint every 1000 blocks as a fallback
        (timestamp % hour_in_nanoseconds < 1_000_000_000) || (block_height % 1000 == 0)
    }
}

/// Contract-side checkpoint manager - stores minimal state for indexer coordination
#[derive(BorshDeserialize, BorshSerialize, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub struct CheckpointManager {
    /// Current state for each tracked chain
    pub chain_states: BTreeMap<ChainId, ChainState>,
    
    /// Stored checkpoints for recovery - nodes can request these via API
    pub checkpoints: IterableMap<(ChainId, BlockHeight), Checkpoint>,
    
    /// Maximum number of checkpoints to keep per chain
    pub max_checkpoints_per_chain: u32,
    
    /// Minimum interval between checkpoints (in nanoseconds)
    pub min_checkpoint_interval: u64,
}

impl CheckpointManager {
    pub fn new() -> Self {
        Self {
            chain_states: BTreeMap::new(),
            checkpoints: IterableMap::new(StorageKey::Checkpoints),
            max_checkpoints_per_chain: 100,
            min_checkpoint_interval: 3_600_000_000_000, // 1 hour in nanoseconds
        }
    }

    /// Get or create chain state
    pub fn get_or_create_chain_state(&mut self, chain_id: ChainId) -> &mut ChainState {
        self.chain_states
            .entry(chain_id.clone())
            .or_insert_with(|| ChainState::new(chain_id))
    }

    /// Update the latest block height for a chain
    pub fn update_chain_height(&mut self, chain_id: ChainId, height: BlockHeight) {
        let chain_state = self.get_or_create_chain_state(chain_id);
        chain_state.update_block_height(height);
    }

    /// Record a logical dependency between chains
    pub fn observe_dependency(
        &mut self,
        source_chain: ChainId,
        target_chain: ChainId,
        source_height: BlockHeight,
        target_height: BlockHeight,
    ) {
        let chain_state = self.get_or_create_chain_state(target_chain);
        chain_state.observe_dependency_from(source_chain, source_height, target_height);
    }

    /// Store a checkpoint (typically called by MPC nodes)
    pub fn store_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<(), &'static str> {
        // Verify checkpoint timing
        if let Some(last_checkpoint) = self.get_latest_checkpoint(&checkpoint.chain_id) {
            if checkpoint.timestamp < last_checkpoint.timestamp + self.min_checkpoint_interval {
                return Err("Checkpoint interval too short");
            }
        }

        let key = (checkpoint.chain_id.clone(), checkpoint.block_height);
        self.checkpoints.insert(key, checkpoint.clone());
        
        // Cleanup old checkpoints
        self.cleanup_old_checkpoints(&checkpoint.chain_id);
        
        Ok(())
    }

    /// Get the latest checkpoint for a chain
    pub fn get_latest_checkpoint(&self, chain_id: &ChainId) -> Option<Checkpoint> {
        let mut latest: Option<Checkpoint> = None;
        
        for ((stored_chain_id, _), checkpoint) in self.checkpoints.iter() {
            if stored_chain_id == chain_id {
                if latest.is_none() || checkpoint.block_height > latest.as_ref().unwrap().block_height {
                    latest = Some(checkpoint.clone());
                }
            }
        }
        
        latest
    }

    /// Get checkpoints after a certain block height for a chain
    pub fn get_checkpoints_after(
        &self,
        chain_id: &ChainId,
        after_height: BlockHeight,
    ) -> Vec<Checkpoint> {
        let mut checkpoints = Vec::new();
        
        for ((stored_chain_id, height), checkpoint) in self.checkpoints.iter() {
            if stored_chain_id == chain_id && *height > after_height {
                checkpoints.push(checkpoint.clone());
            }
        }
        
        // Sort by block height
        checkpoints.sort_by_key(|c| c.block_height);
        checkpoints
    }

    /// Get the current state for all chains
    pub fn get_all_chain_states(&self) -> BTreeMap<ChainId, ChainState> {
        self.chain_states.clone()
    }

    /// Check if a checkpoint should be created for a chain
    pub fn should_create_checkpoint(&self, chain_id: &ChainId) -> bool {
        if let Some(chain_state) = self.chain_states.get(chain_id) {
            if let Some(last_checkpoint) = self.get_latest_checkpoint(chain_id) {
                let time_since_last = near_sdk::env::block_timestamp() - last_checkpoint.timestamp;
                let height_since_last = chain_state.latest_block_height - last_checkpoint.block_height;
                
                // Create checkpoint if enough time has passed or enough blocks have been processed
                time_since_last >= self.min_checkpoint_interval || height_since_last >= 1000
            } else {
                // Create first checkpoint
                true
            }
        } else {
            false
        }
    }

    /// Cleanup old checkpoints to prevent unbounded growth
    fn cleanup_old_checkpoints(&mut self, chain_id: &ChainId) {
        let mut checkpoints_for_chain: Vec<(BlockHeight, (ChainId, BlockHeight))> = Vec::new();
        
        for ((stored_chain_id, height), _) in self.checkpoints.iter() {
            if stored_chain_id == chain_id {
                checkpoints_for_chain.push((*height, (stored_chain_id.clone(), *height)));
            }
        }
        
        // Sort by height (newest first)
        checkpoints_for_chain.sort_by(|a, b| b.0.cmp(&a.0));
        
        // Remove old checkpoints beyond the limit
        for (_, key) in checkpoints_for_chain.into_iter().skip(self.max_checkpoints_per_chain as usize) {
            self.checkpoints.remove(&key);
        }
    }
}

impl Default for CheckpointManager {
    fn default() -> Self {
        Self::new()
    }
}
