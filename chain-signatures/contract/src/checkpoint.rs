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

/// Chain state computed by nodes and voted on in the contract
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ChainState {
    /// The chain this state tracks
    pub chain_id: ChainId,
    
    /// The latest block height processed by the indexer for this chain
    pub latest_block_height: BlockHeight,
    
    /// For each other chain, the target height of the latest seen dependency
    /// where the other chain was the source and this chain was the target.
    pub latest_logical_dependency: BTreeMap<ChainId, BlockHeight>,
    
    /// Timestamp when this state was computed by the node
    pub computed_at: u64,
}

impl ChainState {
    pub fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            latest_block_height: 0,
            latest_logical_dependency: BTreeMap::new(),
            computed_at: near_sdk::env::block_timestamp(),
        }
    }

    /// Get the minimum block height across all dependencies
    /// This is useful for ordering chain states by their "completeness"
    pub fn min_dependency_height(&self) -> BlockHeight {
        self.latest_logical_dependency
            .values()
            .min()
            .copied()
            .unwrap_or(0)
    }
}

/// A vote for a particular chain state from a node
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ChainStateVote {
    /// The node (participant) submitting this vote
    pub voter: PublicKey,
    
    /// The chain state being voted for
    pub chain_state: ChainState,
    
    /// When this vote was submitted
    pub voted_at: u64,
    
    /// Signature of the chain state by the voting node
    pub signature: Vec<u8>,
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

/// Contract-side checkpoint manager - coordinates chain state voting and consensus
#[derive(BorshDeserialize, BorshSerialize, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub struct CheckpointManager {
    /// Current votes for chain states by participants
    /// Key: (chain_id, voter), Value: their latest vote
    pub chain_state_votes: BTreeMap<(ChainId, PublicKey), ChainStateVote>,
    
    /// Consensus chain states (computed from votes)
    /// This represents the agreed-upon state up to a certain threshold
    pub consensus_chain_states: BTreeMap<ChainId, ChainState>,
    
    /// Stored checkpoints for recovery - nodes can request these via API
    pub checkpoints: IterableMap<(ChainId, BlockHeight), Checkpoint>,
    
    /// Maximum number of checkpoints to keep per chain
    pub max_checkpoints_per_chain: u32,
    
    /// Minimum interval between checkpoints (in nanoseconds)
    pub min_checkpoint_interval: u64,
    
    /// Voting threshold (fraction of participants that must agree)
    /// e.g., 0.67 means 67% of participants must have voted for states at or above the consensus
    pub voting_threshold: f64,
}

impl CheckpointManager {
    pub fn new() -> Self {
        Self {
            chain_state_votes: BTreeMap::new(),
            consensus_chain_states: BTreeMap::new(),
            checkpoints: IterableMap::new(StorageKey::Checkpoints),
            max_checkpoints_per_chain: 100,
            min_checkpoint_interval: 3_600_000_000_000, // 1 hour in nanoseconds
            voting_threshold: 0.67, // 67% threshold
        }
    }

    /// Submit a vote for a chain state (called by MPC nodes)
    pub fn vote_chain_state(
        &mut self,
        voter: PublicKey,
        chain_state: ChainState,
        signature: Vec<u8>,
        total_participants: u32,
    ) -> Result<(), &'static str> {
        // TODO: Verify signature of chain_state by voter
        
        let vote = ChainStateVote {
            voter: voter.clone(),
            chain_state,
            voted_at: near_sdk::env::block_timestamp(),
            signature,
        };
        
        let chain_id = vote.chain_state.chain_id.clone();
        let key = (vote.chain_state.chain_id.clone(), voter);
        self.chain_state_votes.insert(key, vote);
        
        // Recompute consensus for this chain
        self.compute_consensus_for_chain(&chain_id, total_participants);
        
        Ok(())
    }

    /// Compute consensus chain state for a given chain based on votes
    fn compute_consensus_for_chain(&mut self, chain_id: &ChainId, total_participants: u32) {
        // Collect all votes for this chain
        let mut votes: Vec<&ChainStateVote> = self.chain_state_votes
            .iter()
            .filter_map(|((voted_chain_id, _), vote)| {
                if voted_chain_id == chain_id {
                    Some(vote)
                } else {
                    None
                }
            })
            .collect();
        
        if votes.is_empty() {
            return;
        }
        
        // Sort votes by minimum dependency height (most conservative first)
        votes.sort_by_key(|vote| vote.chain_state.min_dependency_height());
        
        // Find the threshold position
        let threshold_count = ((total_participants as f64) * self.voting_threshold).ceil() as usize;
        
        if votes.len() >= threshold_count {
            // Take the chain state at the threshold position (most conservative that meets threshold)
            let consensus_state = votes[threshold_count - 1].chain_state.clone();
            self.consensus_chain_states.insert(chain_id.clone(), consensus_state);
        }
    }

    /// Get the consensus chain state for a given chain
    pub fn get_consensus_chain_state(&self, chain_id: &ChainId) -> Option<&ChainState> {
        self.consensus_chain_states.get(chain_id)
    }

    /// Get all current votes for a chain
    pub fn get_votes_for_chain(&self, chain_id: &ChainId) -> Vec<ChainStateVote> {
        self.chain_state_votes
            .iter()
            .filter_map(|((voted_chain_id, _), vote)| {
                if voted_chain_id == chain_id {
                    Some(vote.clone())
                } else {
                    None
                }
            })
            .collect()
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

    /// Get the current consensus state for all chains
    pub fn get_all_consensus_chain_states(&self) -> BTreeMap<ChainId, ChainState> {
        self.consensus_chain_states.clone()
    }

    /// Check if a checkpoint should be created for a chain based on consensus state
    pub fn should_create_checkpoint(&self, chain_id: &ChainId) -> bool {
        if let Some(consensus_state) = self.consensus_chain_states.get(chain_id) {
            if let Some(last_checkpoint) = self.get_latest_checkpoint(chain_id) {
                let time_since_last = near_sdk::env::block_timestamp() - last_checkpoint.timestamp;
                let height_since_last = consensus_state.latest_block_height - last_checkpoint.block_height;
                
                // Create checkpoint if enough time has passed or enough blocks have been processed
                time_since_last >= self.min_checkpoint_interval || height_since_last >= 1000
            } else {
                // Create first checkpoint if we have consensus
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
