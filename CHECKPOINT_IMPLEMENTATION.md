# Checkpoint Implementation for MPC Bidirectional Messaging

This document describes the implementation of the checkpointing system for pending request management in bidirectional messaging, as specified in [GitHub issue #499](https://github.com/sig-net/mpc/issues/499).

## Architecture Overview

The implementation separates concerns between the **contract** and the **node**:

### Contract Responsibilities (Minimal State)
- Store latest block heights for each chain
- Track logical dependencies between chains  
- Store periodic checkpoints for recovery
- Provide APIs for nodes to coordinate

### Node Responsibilities (Complex State)
- Maintain the full `PendingRequests` state as described in the pseudocode
- Rebuild state from contract checkpoints after restarts
- Process cross-chain requests through their lifecycle

## Contract Implementation

### Key Types

```rust
/// Chain identifier
pub struct ChainId(pub String);

/// Request identifier  
pub struct RequestId(pub [u8; 32]);

/// Minimal state per chain
pub struct ChainState {
    pub chain_id: ChainId,
    pub latest_block_height: u64,
    pub latest_logical_dependency: BTreeMap<ChainId, u64>,
    pub last_updated: u64,
}

/// Checkpoint for recovery
pub struct Checkpoint {
    pub chain_id: ChainId,
    pub block_height: u64,
    pub latest_logical_dependency: BTreeMap<ChainId, u64>,
    pub pending_request_ids: Vec<RequestId>, // Just IDs, not full requests
    pub timestamp: u64,
    pub signature: Option<Vec<u8>>,
    pub hash: CryptoHash,
}
```

### Contract APIs

```rust
// Update chain progress (called by indexers)
pub fn update_chain_height(&mut self, chain_id: String, height: u64) -> Result<(), Error>

// Record dependencies between chains
pub fn observe_dependency(&mut self, source_chain: String, target_chain: String, 
                         source_height: u64, target_height: u64) -> Result<(), Error>

// Store checkpoint (called by MPC nodes)
pub fn store_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<(), Error>

// Recovery APIs
pub fn get_latest_checkpoint(&self, chain_id: String) -> Option<Checkpoint>
pub fn get_checkpoints_after(&self, chain_id: String, after_height: u64) -> Vec<Checkpoint>
pub fn get_all_chain_states(&self) -> BTreeMap<String, ChainState>

// Monitoring
pub fn should_create_checkpoint(&self, chain_id: String) -> bool
pub fn get_checkpoint_stats(&self) -> BTreeMap<String, (u64, u32, u64)>
```

## Node Implementation

### PendingRequests State (Node-side)

The node maintains the complex state described in the GitHub issue pseudocode:

```rust
pub struct PendingRequests {
    pub chain_id: ChainId,
    pub processed_block_height: u64,
    pub latest_logical_dependency: BTreeMap<ChainId, u64>,
    
    // The core state tracking
    pub pending_tx: HashMap<RequestId, Request>,
    pub blocks_with_potentially_required_outcomes: BTreeMap<u64, Block>,
    
    // Request lifecycle tracking
    pub pending_sign_and_respond: Vec<RequestId>,
    pub pending_execute_respond: Vec<RequestId>, 
    pub pending_respond: Vec<RequestId>,
}
```

### State Transitions

The node implements the methods from the pseudocode:

```rust
// Lifecycle methods
impl PendingRequests {
    pub fn new_sign_and_respond_request(&mut self, id: RequestId, request: Request, height: u64)
    pub fn published_signed_transaction(&mut self, id: RequestId, height: u64)
    pub fn found_tx_output(&mut self, id: RequestId)
    pub fn published_signed_output(&mut self, id: RequestId, height: u64)
    pub fn processed_block(&mut self, height: u64)
    pub fn observe_dependency_from(&mut self, source: ChainId, source_height: u64, target_height: u64)
}
```

## Recovery Process

When a node restarts:

1. **Query contract** for latest checkpoint for each chain
2. **Restore minimal state** from checkpoint (block heights, dependencies, request IDs)
3. **Reconstruct full requests** by querying blockchain data for each RequestId
4. **Catch up** by processing all blocks since the checkpoint
5. **Correct state** as the node processes recent blocks

## Checkpoint Creation

Checkpoints are created:
- **Time-based**: Every hour (configurable)
- **Block-based**: Every 1000 blocks (fallback)
- **Manual**: When requested by operators

## Benefits

### Solves the Original Problems
1. **Reboot recovery**: Nodes can restore from checkpoints
2. **Indexer timing**: Contract state provides canonical source of truth
3. **Request persistence**: No requests are lost during restarts

### Additional Benefits
1. **Minimal contract storage**: Only essential coordination data stored on-chain
2. **Node flexibility**: Nodes rebuild complex state as needed
3. **Monitoring**: Contract provides APIs for system health monitoring
4. **Scalability**: Contract state grows slowly, complex state stays off-chain

## Integration with Existing Code

### Contract Changes
- Add `CheckpointManager` to `MpcContract`
- Add new public APIs for checkpoint management
- Existing functionality unchanged

### Node Changes  
- Replace in-memory `Map<SignRespondTxId, SignRespondTx>` with `PendingRequests`
- Add checkpoint restoration logic on startup
- Add periodic checkpoint creation
- Integrate with existing indexer logic

## File Structure

```
chain-signatures/
├── contract/src/
│   ├── checkpoint.rs          # Contract-side minimal state
│   └── lib.rs                 # Updated with checkpoint APIs
└── node/src/
    └── pending_requests.rs    # Node-side complex state
```

## Future Enhancements

1. **Signature verification**: Implement proper MPC signature verification for checkpoints
2. **Compression**: Compress checkpoint data for large request sets
3. **Cleanup policies**: More sophisticated checkpoint retention policies
4. **Cross-validation**: Nodes can verify checkpoints against each other
5. **External storage**: Option to store checkpoints in external systems (IPFS, etc.)

## Migration Strategy

1. **Phase 1**: Deploy contract changes (new APIs, backward compatible)
2. **Phase 2**: Update nodes to use checkpoint system alongside existing logic  
3. **Phase 3**: Remove old in-memory storage, rely fully on checkpoints
4. **Phase 4**: Enable automatic checkpoint creation and cleanup

This implementation provides a robust foundation for managing pending requests across chain restarts while maintaining the separation of concerns between contract and node responsibilities.
