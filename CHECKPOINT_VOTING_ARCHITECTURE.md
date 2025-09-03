# Checkpoint Voting Architecture

## Overview

The checkpoint system has been redesigned to implement a **voting-based consensus mechanism** where MPC nodes vote on chain states rather than the contract computing them directly. This ensures that the contract acts purely as a coordination layer while nodes maintain the complex state computation logic.

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Node A    │    │   Node B    │    │   Node C    │
│             │    │             │    │             │
│ Computes    │    │ Computes    │    │ Computes    │
│ ChainState  │    │ ChainState  │    │ ChainState  │
└─────┬───────┘    └─────┬───────┘    └─────┬───────┘
      │                  │                  │
      └──────────────────┼──────────────────┘
                         │
                    ┌────▼────┐
                    │Contract │
                    │         │
                    │ Votes & │
                    │Consensus│
                    └─────────┘
```

### Key Components

## Contract-Side (`CheckpointManager`)

### 1. **ChainStateVote**
```rust
pub struct ChainStateVote {
    pub voter: PublicKey,           // Which node submitted this vote
    pub chain_state: ChainState,    // The chain state being voted for
    pub voted_at: u64,             // Timestamp of vote submission
    pub signature: Vec<u8>,         // Signature verifying authenticity
}
```

### 2. **ChainState**
```rust  
pub struct ChainState {
    pub chain_id: ChainId,
    pub latest_block_height: BlockHeight,
    pub latest_logical_dependency: BTreeMap<ChainId, BlockHeight>,
    pub computed_at: u64,
}
```

### 3. **Voting Storage**
- `chain_state_votes: BTreeMap<(ChainId, PublicKey), ChainStateVote>` - Latest vote from each participant for each chain
- `consensus_chain_states: BTreeMap<ChainId, ChainState>` - Agreed-upon states after consensus

### 4. **Consensus Algorithm**

The contract computes consensus using a **threshold-based approach**:

1. **Collection**: Gather all votes for a specific chain
2. **Ordering**: Sort votes by `min_dependency_height()` (most conservative first)  
3. **Threshold**: Take the state at position `ceil(total_participants * voting_threshold)`
4. **Selection**: The state at the threshold position becomes consensus

**Example with 67% threshold (3 nodes):**
```
Node A votes: ChainState { min_dependency: 100 }
Node B votes: ChainState { min_dependency: 105 }  ← CONSENSUS (position 2 of 3)
Node C votes: ChainState { min_dependency: 110 }

Consensus = Node B's state (most conservative that meets 67% threshold)
```

## Contract API Methods

### `vote_chain_state(chain_state, signature)`
- **Purpose**: Submit a vote for a computed chain state
- **Caller**: MPC nodes only (verified via `self.voter()`)
- **Process**: 
  1. Validates caller is participant
  2. Stores vote with timestamp and signature
  3. Recomputes consensus for the affected chain
  4. Updates consensus state if threshold is met

### `get_consensus_chain_state(chain_id)` 
- **Purpose**: Retrieve the agreed-upon state for a chain
- **Returns**: `Option<ChainState>` - consensus state or None if no consensus
- **Use Case**: Nodes query this to sync their understanding

### `get_votes_for_chain(chain_id)`
- **Purpose**: Get all current votes for transparency/debugging  
- **Returns**: `Vec<ChainStateVote>` - all votes for the specified chain
- **Use Case**: Monitoring consensus progress, debugging disagreements

## Node-Side Workflow

### 1. **State Computation**
```rust
// Node computes chain state from its local indexer data
let chain_state = ChainState {
    chain_id: ChainId("ethereum".to_string()),
    latest_block_height: 18_500_000,
    latest_logical_dependency: dependencies, // Computed from bidirectional messages
    computed_at: current_timestamp(),
};
```

### 2. **Vote Submission**
```rust  
// Node signs and submits its computed state
let signature = sign_chain_state(&chain_state, &node_private_key);
contract.vote_chain_state(chain_state, signature).await?;
```

### 3. **Consensus Monitoring**
```rust
// Node checks if consensus has been reached
if let Some(consensus) = contract.get_consensus_chain_state("ethereum").await? {
    // Use consensus state for checkpoint creation or recovery
}
```

## Benefits

### 1. **Separation of Concerns**
- **Contract**: Pure coordination, voting, consensus
- **Nodes**: Complex state computation, indexing, validation

### 2. **Fault Tolerance** 
- Byzantine fault tolerant up to threshold
- Handles nodes with different indexing speeds/views
- Naturally selects most conservative safe state

### 3. **Transparency**
- All votes are stored and queryable  
- Clear audit trail of consensus decisions
- Debugging capabilities for disagreements

### 4. **Flexibility**
- Configurable voting threshold
- Extensible consensus algorithms
- Support for different chain types

## Security Considerations

### 1. **Signature Verification**
- Each vote must be signed by the submitting node
- Prevents vote spoofing and replay attacks
- TODO: Implement actual signature verification

### 2. **Monotonic Progress**
- States can only advance (higher block heights)
- Prevents rollback attacks
- Conservative consensus prevents premature advancement

### 3. **Threshold Safety**
- 67% threshold ensures Byzantine fault tolerance
- Configurable based on security requirements
- Fails safe when insufficient votes

## Integration with Bidirectional Messaging

### 1. **Dependency Tracking**
```rust
// Nodes compute dependencies from cross-chain messages
chain_state.latest_logical_dependency.insert(
    ChainId("polygon".to_string()),
    observed_target_height
);
```

### 2. **Checkpoint Creation**
```rust
// Use consensus state for checkpoint coordination
if manager.should_create_checkpoint(&chain_id) {
    let consensus = manager.get_consensus_chain_state(&chain_id)?;
    let checkpoint = Checkpoint::new(
        chain_id,
        consensus.latest_block_height,
        consensus.latest_logical_dependency,
        pending_request_ids,
    );
}
```

### 3. **Recovery Process**
```rust
// Nodes use consensus to determine safe recovery points
let safe_state = contract.get_consensus_chain_state(&chain_id).await?;
node.recover_to_state(safe_state).await?;
```

## Monitoring and Debugging

### 1. **Vote Disagreement Detection**
```rust
let votes = contract.get_votes_for_chain("ethereum").await?;
for vote in votes {
    if vote.chain_state.latest_block_height differs significantly {
        log::warn!("Node {} has divergent view", vote.voter);
    }
}
```

### 2. **Consensus Progress Tracking**
```rust
let votes = contract.get_votes_for_chain("ethereum").await?;
let total_participants = get_participant_count().await?;
let threshold_needed = (total_participants as f64 * 0.67).ceil() as usize;

if votes.len() >= threshold_needed {
    // Consensus should be available
} else {
    log::info!("Waiting for {} more votes", threshold_needed - votes.len());
}
```

## Future Enhancements

1. **Weighted Voting**: Different nodes could have different voting weights
2. **Time-based Consensus**: Automatic consensus after timeout periods
3. **Slashing**: Penalties for nodes that consistently vote incorrectly
4. **Dynamic Thresholds**: Adjust threshold based on network conditions
5. **Multi-round Consensus**: More sophisticated consensus algorithms

This architecture provides a robust foundation for coordinating chain state across multiple MPC nodes while maintaining the security and decentralization properties required for the bidirectional messaging system.
