# Signature Task Consolidation - Implementation Complete

## Overview
Successfully consolidated the posit and signature generator workflows into a singular `SignatureTask` state machine. This provides a unified interface for managing the complete lifecycle of signature generation from proposal negotiation through generation completion.

## New Structures Added

### 1. SinglePositCounter
**Location**: `chain-signatures/node/src/protocol/signature.rs` (lines 378-428)

A lightweight posit counter for individual signature tasks:
- Tracks participant votes (accepts/rejects)
- Replaces the need for a global `Posits` mapping per task
- Methods:
  - `new(me, participants)`: Initialize with participant set
  - `enough_accepts(threshold)`: Check if threshold reached
  - `enough_rejects(threshold)`: Check if too many rejections
  - `meets_totality()`: Check if all participants voted
  - `process_action(from, action)`: Handle Accept/Reject votes

```rust
struct SinglePositCounter {
    participants: HashSet<Participant>,
    accepts: HashSet<Participant>,
    rejects: HashSet<Participant>,
    created: Instant,
}
```

### 2. SignatureTaskPositAction Enum
**Location**: `chain-signatures/node/src/protocol/signature.rs` (lines 430-442)

Represents the result of processing a posit action:
```rust
enum SignatureTaskPositAction {
    Waiting,
    Reject,
    Ready { participants: Vec<Participant>, proposer: Participant },
}
```

### 3. SignatureTaskPhase Enum
**Location**: `chain-signatures/node/src/protocol/signature.rs` (lines 444-460)

Represents the three phases of a signature task:
```rust
enum SignatureTaskPhase {
    Posit { counter, proposer, participants },
    Generating { generator: Box<SignatureGenerator> },
    Complete(Result<(), SignError>),
}
```

### 4. SignatureTask Struct
**Location**: `chain-signatures/node/src/protocol/signature.rs` (lines 462-626)

The main task abstraction combining posit and generation:

**Public/Key Methods**:
- `new()`: Create a new task in Posit phase
- `process_posit_action()`: Handle incoming posit votes, returns action outcome
- `start_generation()`: Transition to generation phase
- `complete()`: Mark task as complete with result
- `is_complete()`: Check if task is in terminal state
- `result()`: Retrieve result if complete
- `timeout_total()`: Check if total timeout exceeded

**Internal Helper Methods**:
- `in_posit_phase()`: Check current phase
- `in_generating_phase()`: Check current phase
- `handle_posit_expiration()`: Handle timeout during posit phase

```rust
pub struct SignatureTask {
    sign_id: SignId,
    presignature_id: PresignatureId,
    request: SignRequest,
    phase: SignatureTaskPhase,
    created: Instant,
    timeout_total: Duration,
    me: Participant,
    threshold: usize,
}
```

## State Machine

### Phase Transitions

```
┌─────────────────────────────────────┐
│  Posit Phase                        │
│  - Waits for Accept/Reject votes    │
│  - Checks for consensus             │
│  - Tracks participant responses     │
└──────────────┬──────────────────────┘
               │
        (Enough votes OR Timeout)
               │
               ▼
┌─────────────────────────────────────┐
│  Generating Phase                   │
│  - Creates SignatureGenerator       │
│  - Runs signature protocol          │
│  - Sends/receives messages          │
└──────────────┬──────────────────────┘
               │
        (Completion OR Error)
               │
               ▼
┌─────────────────────────────────────┐
│  Complete Phase                     │
│  - Stores result: Ok(()) or Error   │
│  - Terminal state                   │
└─────────────────────────────────────┘
```

## Error Handling

### SignError Enum
```rust
#[derive(Debug, Clone, Copy)]
enum SignError {
    Retry,          // Transient error, can retry
    TotalTimeout,   // Exceeded total timeout
    Aborted,        // Protocol was aborted
}
```

## Key Design Decisions

1. **Task Isolation**: Each signature has its own task instance
   - No global posit mapping needed
   - Each task manages its own state
   - Tasks are independent and can be created/destroyed freely

2. **Phase Separation**: Clear separation of concerns
   - Posit phase: Consensus building
   - Generating phase: Signature generation
   - Complete phase: Result storage

3. **Message-Driven**: Tasks respond to incoming messages
   - Posit actions update the counter
   - Signature messages forwarded to generator
   - Explicit transition points

4. **Timeout Handling**: Dual-level timeout management
   - Per-phase timeouts (individual generation_timeout)
   - Total timeout for entire signature workflow
   - Explicit expiration handling

## Integration Points (Not Yet Implemented)

These structures are ready to be integrated into `SignatureSpawner`:

1. **Task Creation**: Create `SignatureTask` immediately when sign request enters queue
2. **Message Routing**: Route posit/signature messages to appropriate task
3. **Task Collection**: Store tasks in a `JoinMap` or `HashMap`
4. **Lifecycle Management**: Monitor completion, expiration, failures
5. **Result Handling**: Collect results when tasks complete

## Benefits

- ✅ **Reduced Complexity**: Single state machine vs. multiple interacting components
- ✅ **Better Testability**: Each task can be tested independently
- ✅ **Clearer Logic**: Phase transitions are explicit and bounded
- ✅ **Type Safety**: Compiler enforces state transitions
- ✅ **No Breaking Changes**: Presignatures and triples unaffected
- ✅ **Async-Ready**: Structure compatible with tokio task spawning

## Compilation Status

✅ **No Errors** - Compiles cleanly with only expected warnings about unused methods
(These methods will be called once integration is complete)

## Next Steps (Future Work)

1. Update `SignatureSpawner::handle_requests()` to create tasks
2. Modify message routing to target tasks
3. Update task lifecycle management in spawner's main loop
4. Remove legacy posit and process_posit infrastructure
5. Run component and integration tests
