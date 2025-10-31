# Signature Task Consolidation Summary

## What We've Completed

### 1. Created SinglePositCounter Abstraction
- Replaces the global `Posits` mapping for individual signature tasks
- Tracks participants accepting/rejecting a proposal
- Methods:
  - `new()`: Initialize with me and participants
  - `enough_accepts(threshold)`: Check if threshold reached
  - `enough_rejects(threshold)`: Check if enough rejections
  - `meets_totality()`: All participants have voted
  - `process_action()`: Handle Accept/Reject actions

### 2. Created SignatureTaskPositAction Enum
Represents outcomes of posit action processing:
- `Waiting`: More votes needed
- `Reject`: Task rejected (enough rejects)
- `Ready { participants, proposer }`: Ready for generation phase

### 3. Created SignatureTaskPhase Enum
Represents the task's state machine:
- `Posit { counter, proposer, participants }`: Negotiation phase
- `Generating { generator: Box<SignatureGenerator> }`: Generation phase
- `Complete(Result<(), SignError>)`: Terminal state

### 4. Created SignatureTask Struct
Main task abstraction with:
- `new()`: Start in Posit phase
- `process_posit_action()`: Handle incoming posit votes
- `start_generation()`: Transition to Generating phase
- `complete()`: Mark task as complete
- `is_complete()`, `result()`, `timeout_total()`: Status checks

## What Still Needs to Be Done

### Phase 1: Task Spawning Infrastructure
1. Update `SignatureSpawner` to create `SignatureTask` immediately when sign request enters queue
2. Store tasks in a `JoinMap<(SignId, PresignatureId), SignatureTask>` or similar
3. Create channel/mechanism for `SignatureTask` to send/receive posit messages
4. Create channel/mechanism for `SignatureTask` to send/receive signature messages

### Phase 2: Task Message Routing
1. Route incoming posit messages to the appropriate `SignatureTask`
2. Route incoming signature messages to the `SignatureTask`'s generator phase
3. Handle message responses from `SignatureTask` (posit replies, signature broadcasts)

### Phase 3: Task Lifecycle Management
1. Update the main event loop in `SignatureSpawner::run()` to:
   - Create tasks on new sign requests
   - Route messages to tasks
   - Monitor task completion/expiration
   - Handle task failures (retry vs discard)

### Phase 4: Remove Old Infrastructure
1. Remove the global `posits: Posits<(SignId, PresignatureId), PresignatureTaken>` from `SignatureSpawner`
2. Remove `propose_posit()` method
3. Remove `process_posit()` method
4. Consolidate all logic into task management

### Phase 5: Testing
- Run component tests in `integration-tests/tests/cases/mpc.rs`
- Run integration tests to verify end-to-end functionality
- Ensure presignatures and triples are unaffected

## Key Design Principles

1. **Single Responsibility**: Each task handles its own lifecycle
2. **State Machine**: Clear phases with well-defined transitions
3. **Message Routing**: Messages flow to tasks, not processed globally
4. **Async/Await**: Tasks are tokio tasks, not just state structs
5. **No Breaking Changes**: Presignatures and triples remain unchanged
