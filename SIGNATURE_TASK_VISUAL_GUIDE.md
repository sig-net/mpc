# Signature Task Consolidation - Visual Guide

## Before and After

### BEFORE: Separate Components
```
SignatureSpawner
├── posits: Posits<(SignId, PresignatureId), PresignatureTaken>
│   ├── HashMap of posit state machines
│   └── Global coordination across all signatures
│
├── propose_posit()
│   ├── Create posit in global mapping
│   └── Send propose messages
│
├── process_posit()
│   ├── Handle posit actions globally
│   ├── Manage transitions
│   └── Start generation when ready
│
├── generate()
│   ├── Create SignatureGenerator
│   └── Run signature protocol
│
└── ongoing: JoinMap<(SignId, PresignatureId), Result<(), SignError>>
    └── Tasks running concurrently
```

### AFTER: Unified SignatureTask
```
SignatureSpawner
├── tasks: HashMap<(SignId, PresignatureId), SignatureTask>
│   └── Each signature is self-contained
│
└── Message Routing:
    ├── Posit messages → task.process_posit_action()
    └── Signature messages → task.generator (if in Generating phase)
```

## Code Structure

### New Types Added

```
chain-signatures/node/src/protocol/signature.rs

├── #[derive(Clone, Copy)]
│  enum SignError
│      ├── Retry
│      ├── TotalTimeout
│      └── Aborted
│
├── struct SinglePositCounter
│      ├── participants: HashSet<Participant>
│      ├── accepts: HashSet<Participant>
│      ├── rejects: HashSet<Participant>
│      └── created: Instant
│
├── enum SignatureTaskPositAction
│      ├── Waiting
│      ├── Reject
│      └── Ready { participants, proposer }
│
├── enum SignatureTaskPhase
│      ├── Posit { counter, proposer, participants }
│      ├── Generating { generator }
│      └── Complete(Result<(), SignError>)
│
└── pub struct SignatureTask
       ├── sign_id: SignId
       ├── presignature_id: PresignatureId
       ├── request: SignRequest
       ├── phase: SignatureTaskPhase
       ├── created: Instant
       ├── timeout_total: Duration
       ├── me: Participant
       ├── threshold: usize
       │
       └── Methods:
           ├── new()
           ├── process_posit_action()
           ├── start_generation()
           ├── complete()
           ├── is_complete()
           ├── timeout_total()
           ├── in_posit_phase()
           ├── in_generating_phase()
           └── handle_posit_expiration()
```

## Phase Progression Example

### Scenario: Signature Task Lifecycle

```
Timeline:
t=0ms    Task Created
         ├─ State: Posit { counter, proposer, participants }
         ├─ Threshold: 3
         ├─ Participants: [P0, P1, P2, P3]
         └─ Proposer: P0

t=10ms   P1 accepts
         ├─ Counter: accepts=[P0, P1], rejects=[]
         └─ Result: Waiting

t=20ms   P2 accepts
         ├─ Counter: accepts=[P0, P1, P2], rejects=[]
         └─ Result: Waiting

t=30ms   P3 accepts (meets_totality!)
         ├─ Counter: accepts=[P0, P1, P2, P3], rejects=[]
         ├─ Transition: Ready { participants=[P0,P1,P2,P3], proposer=P0 }
         └─ State: Generating { generator }

t=50ms   Generation in progress...

t=100ms  Generation complete
         ├─ Signature created
         ├─ Result: Ok(())
         └─ State: Complete(Ok(()))
```

## SinglePositCounter vs Posits

### SinglePositCounter (NEW - Per Task)
```rust
// Each task has its own counter
struct SinglePositCounter {
    participants: HashSet<Participant>,    // Fixed set
    accepts: HashSet<Participant>,          // Accumulated votes
    rejects: HashSet<Participant>,          // Accumulated votes
    created: Instant,                       // When created
}

// Simple state checking
counter.enough_accepts(threshold)
counter.enough_rejects(threshold)
counter.meets_totality()
counter.process_action(from, action)
```

### Posits (OLD - Global Mapping)
```rust
// Single global structure managing ALL posits
struct Posits<Id, S> {
    me: Participant,
    posits: HashMap<Id, (Positor<PositCounter<S>>, Instant)>,
    //      ↑ Maps (SignId, PresignatureId) → state
}

// Complex global operations
posits.propose(id, store, participants)
posits.act(id, from, threshold, action)
posits.expire_and_start(threshold, timeout)
```

## Benefits of Consolidation

| Aspect | Before | After |
|--------|--------|-------|
| **Task Scope** | Global `Posits` + distributed `generate()` | Unified `SignatureTask` |
| **State Mgmt** | Multiple entry points | Single state machine |
| **Lifecycle** | Split: posit vs generator | Unified phases |
| **Debugging** | Multiple locations | Task-centric |
| **Testing** | Complex state coordination | Test individual tasks |
| **Message Flow** | Global handler + local handler | Task processes own messages |

## Message Flow Comparison

### BEFORE
```
Incoming Posit Message
    ↓
SignatureSpawner.process_posit()
    ↓
    ├─ Lookup in global posits map
    ├─ Update posit state
    ├─ Check for completion
    └─ Call start_generation() separately
        ↓
    SignatureSpawner.generate()
        ↓
    Create SignatureGenerator
```

### AFTER
```
Incoming Posit Message
    ↓
Route to task: task.process_posit_action()
    ↓
    ├─ Update task's counter
    ├─ Check phase transitions
    └─ Return action (Waiting/Reject/Ready)

If Ready:
    ↓
    Task transitions internally:
    phase = Generating { generator }
```

## Lines of Code Summary

- **SinglePositCounter**: ~52 lines
- **SignatureTaskPositAction enum**: ~13 lines
- **SignatureTaskPhase enum**: ~17 lines
- **SignatureTask struct**: ~160 lines
- **Total Added**: ~242 lines
- **No deletions yet** (legacy code still in place)

## Compilation Status

```
✅ cargo check -p mpc-node --lib
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 14.64s
   Warnings: 8 (expected - unused methods until integration)
```

## Integration Roadmap (Next Phase)

1. **Create tasks in SignatureSpawner::handle_requests()**
   ```rust
   let task = SignatureTask::new(
       me, sign_id, presignature_id, request,
       participants, threshold, timeout
   );
   self.tasks.insert((sign_id, presignature_id), task);
   ```

2. **Route posit messages to tasks**
   ```rust
   if let Some(task) = self.tasks.get_mut(&(sign_id, presignature_id)) {
       task.process_posit_action(from, &action)
   }
   ```

3. **Handle task expiration**
   ```rust
   if task.timeout_total() {
       task.handle_posit_expiration(threshold)
   }
   ```

4. **Collect results and cleanup**
   ```rust
   if task.is_complete() {
       if let Some(result) = task.result() {
           // Handle result
       }
       self.tasks.remove(&(sign_id, presignature_id));
   }
   ```

## Summary

This consolidation provides a **cleaner, more maintainable architecture** for signature generation by:
- ✅ Creating a **unified state machine** per signature
- ✅ Eliminating **global posit mapping** complexity
- ✅ Making **phase transitions explicit**
- ✅ Improving **testability and debugging**
- ✅ Maintaining **backward compatibility** with other components
