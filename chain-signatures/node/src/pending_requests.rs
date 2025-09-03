// This file contains the node-side PendingRequests implementation
// It should be used by chain-signatures/node, not by the contract

use std::collections::{BTreeMap, HashMap};
use serde::{Deserialize, Serialize};

/// A unique identifier for a chain in the multichain system
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChainId(pub String);

/// Block height for a specific chain
pub type BlockHeight = u64;

/// A unique identifier for a cross-chain request
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestId(pub [u8; 32]);

/// Represents a cross-chain request with all necessary metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: RequestId,
    pub source_chain: ChainId,
    pub target_chain: ChainId,
    pub requester: String, // AccountId as string
    pub payload: Vec<u8>,
    pub path: String,
    pub key_version: u32,
    pub block_height: BlockHeight,
    pub timestamp: u64,
}

/// Represents a block with potentially required outcomes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub height: BlockHeight,
    pub chain_id: ChainId,
    pub timestamp: u64,
    pub hash: [u8; 32],
    pub finalized: bool,
}

/// Node-side pending requests tracker - this is the complex state that nodes maintain
/// This implements the pseudocode from the GitHub issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequests {
    /// The chain this pending requests tracker is for
    pub chain_id: ChainId,
    
    /// The last processed block for this chain.
    /// Invariant: No requests with smaller block height will appear.
    pub processed_block_height: BlockHeight,
    
    /// For each other chain, the target height of the latest seen dependency
    /// where the other chain was the source and this chain was the target.
    pub latest_logical_dependency: BTreeMap<ChainId, BlockHeight>,
    
    /// Invariant: All requests that have a `sign_and_respond` call 
    /// but no `read_respond` delivered in the block range [0, processed_block_height]
    pub pending_tx: HashMap<RequestId, Request>,
    
    /// These blocks might contain outcomes to requests we haven't processed, yet.
    /// Invariant: Contains all blocks in range
    /// `min(latest_logical_dependency[..])` to `processed_block_height`.
    pub blocks_with_potentially_required_outcomes: BTreeMap<BlockHeight, Block>,
    
    /// Invariant: All requests that have a `sign_and_respond` call but 
    /// no `respond` delivered in the block range [0, processed_block_height]
    pub pending_sign_and_respond: Vec<RequestId>,
    
    /// Invariant: All requests that have a `respond` call but no `read_respond`
    ///                 delivered in the block range [0, processed_block_height]
    ///             AND the corresponding tx has NOT been executed on the target chain
    ///                 block range [0, last_chain_response[target_chain]]
    pub pending_execute_respond: Vec<RequestId>,
    
    /// Invariant: All requests that have a `respond` call but no `read_respond`
    ///                 delivered in the block range [0, processed_block_height]
    ///             AND the corresponding tx has been executed on the target chain 
    ///                 block range [0, last_chain_response[target_chain]]
    pub pending_respond: Vec<RequestId>,
}

impl PendingRequests {
    pub fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            processed_block_height: 0,
            latest_logical_dependency: BTreeMap::new(),
            pending_tx: HashMap::new(),
            blocks_with_potentially_required_outcomes: BTreeMap::new(),
            pending_sign_and_respond: Vec::new(),
            pending_execute_respond: Vec::new(),
            pending_respond: Vec::new(),
        }
    }

    /// Call when a request has been indexed (MPC starts signing)
    pub fn new_sign_and_respond_request(
        &mut self,
        request_id: RequestId,
        request: Request,
        _block_height: BlockHeight,
    ) {
        self.pending_tx.insert(request_id.clone(), request);
        self.pending_sign_and_respond.push(request_id);
    }

    /// Call when the signed tx has been indexed
    pub fn published_signed_transaction(
        &mut self,
        request_id: RequestId,
        _block_height: BlockHeight,
    ) {
        if let Some(pos) = self.pending_sign_and_respond.iter().position(|id| *id == request_id) {
            self.pending_sign_and_respond.remove(pos);
            self.pending_execute_respond.push(request_id);
        }
    }

    /// Call when the tx output has been indexed (MPC starts signing)
    pub fn found_tx_output(&mut self, request_id: RequestId) {
        if let Some(pos) = self.pending_execute_respond.iter().position(|id| *id == request_id) {
            self.pending_execute_respond.remove(pos);
            self.pending_respond.push(request_id);
        }
    }

    /// Call when the read_respond has been indexed
    pub fn published_signed_output(&mut self, request_id: RequestId, _block_height: BlockHeight) {
        if let Some(pos) = self.pending_respond.iter().position(|id| *id == request_id) {
            self.pending_respond.remove(pos);
            self.pending_tx.remove(&request_id);
        }
    }

    /// Call after all txs of a block have been applied
    pub fn processed_block(&mut self, height: BlockHeight) {
        self.processed_block_height = height;
    }

    /// Call when a dependency was observed with this chain as target
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
    }

    /// Add a block that might contain required outcomes
    pub fn add_block_with_outcomes(&mut self, block: Block) {
        self.blocks_with_potentially_required_outcomes
            .insert(block.height, block);
    }

    /// Remove old blocks that are no longer needed
    pub fn cleanup_old_blocks(&mut self) {
        let min_height = self.latest_logical_dependency
            .values()
            .min()
            .copied()
            .unwrap_or(0);
        
        self.blocks_with_potentially_required_outcomes
            .retain(|&height, _| height >= min_height);
    }

    /// Restore from contract checkpoint data
    pub fn restore_from_checkpoint(
        &mut self,
        block_height: BlockHeight,
        latest_logical_dependency: BTreeMap<ChainId, BlockHeight>,
        pending_request_ids: Vec<RequestId>,
    ) {
        self.processed_block_height = block_height;
        self.latest_logical_dependency = latest_logical_dependency;
        
        // Clear current state
        self.pending_tx.clear();
        self.pending_sign_and_respond.clear();
        self.pending_execute_respond.clear();
        self.pending_respond.clear();
        
        // Initially mark all as pending_sign_and_respond
        // The correct state will be determined as the node catches up by processing blocks
        self.pending_sign_and_respond = pending_request_ids.clone();
        
        // Note: The actual Request objects need to be reconstructed from on-chain data
        // This is intentionally left incomplete as nodes will need to query the blockchain
        // to rebuild the full Request structures
    }

    /// Get statistics for monitoring
    pub fn get_stats(&self) -> (u64, usize, usize, usize, usize) {
        (
            self.processed_block_height,
            self.pending_tx.len(),
            self.pending_sign_and_respond.len(),
            self.pending_execute_respond.len(),
            self.pending_respond.len(),
        )
    }
}

/// Manager for all chain pending requests (node-side)
#[derive(Debug)]
pub struct NodePendingRequestsManager {
    /// Pending requests for each chain
    pub pending_requests_by_chain: HashMap<ChainId, PendingRequests>,
}

impl NodePendingRequestsManager {
    pub fn new() -> Self {
        Self {
            pending_requests_by_chain: HashMap::new(),
        }
    }

    /// Get or create pending requests for a chain
    pub fn get_or_create_pending_requests(&mut self, chain_id: ChainId) -> &mut PendingRequests {
        self.pending_requests_by_chain
            .entry(chain_id.clone())
            .or_insert_with(|| PendingRequests::new(chain_id))
    }

    /// Restore from contract checkpoints
    pub fn restore_from_contract_checkpoint(
        &mut self,
        chain_id: ChainId,
        block_height: BlockHeight,
        latest_logical_dependency: BTreeMap<ChainId, BlockHeight>,
        pending_request_ids: Vec<RequestId>,
    ) {
        let pending_requests = self.get_or_create_pending_requests(chain_id);
        pending_requests.restore_from_checkpoint(
            block_height,
            latest_logical_dependency,
            pending_request_ids,
        );
    }

    /// Process a new request
    pub fn process_new_request(&mut self, request: Request, block_height: BlockHeight) {
        let source_chain = request.source_chain.clone();
        let pending_requests = self.get_or_create_pending_requests(source_chain);
        pending_requests.new_sign_and_respond_request(request.id.clone(), request, block_height);
    }

    /// Process when a signed transaction is published
    pub fn process_signed_transaction(
        &mut self,
        request_id: RequestId,
        source_chain: ChainId,
        block_height: BlockHeight,
    ) {
        if let Some(pending_requests) = self.pending_requests_by_chain.get_mut(&source_chain) {
            pending_requests.published_signed_transaction(request_id, block_height);
        }
    }

    /// Process when transaction output is found
    pub fn process_tx_output(&mut self, request_id: RequestId, target_chain: ChainId) {
        if let Some(pending_requests) = self.pending_requests_by_chain.get_mut(&target_chain) {
            pending_requests.found_tx_output(request_id);
        }
    }

    /// Process when read_respond is published
    pub fn process_read_respond(
        &mut self,
        request_id: RequestId,
        target_chain: ChainId,
        block_height: BlockHeight,
    ) {
        if let Some(pending_requests) = self.pending_requests_by_chain.get_mut(&target_chain) {
            pending_requests.published_signed_output(request_id, block_height);
        }
    }
}

impl Default for NodePendingRequestsManager {
    fn default() -> Self {
        Self::new()
    }
}
