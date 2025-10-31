# Technical Reference: SignatureTask API

## Type Definitions

### SignError
```rust
#[derive(Debug, Clone, Copy)]
enum SignError {
    Retry,          // Temporary failure, can retry
    TotalTimeout,   // Exceeded total timeout
    Aborted,        // Protocol was aborted by peers
}
```

**Traits**: Clone, Copy, Debug
**Size**: Small (single enum discriminant)
**Use**: Result error type in task lifecycle

---

### SinglePositCounter
```rust
struct SinglePositCounter {
    participants: HashSet<Participant>,
    accepts: HashSet<Participant>,
    rejects: HashSet<Participant>,
    created: Instant,
}
```

**Methods**:

#### new(me: Participant, participants: &[Participant]) -> Self
Creates a new counter with:
- All participants initialized
- Me added to accepts initially
- Current timestamp recorded

**Example**:
```rust
let counter = SinglePositCounter::new(
    Participant::from(0),
    &[Participant::from(0), Participant::from(1), ...]
);
```

#### enough_accepts(&self, threshold: usize) -> bool
Check if accept count ≥ threshold.

**Example**:
```rust
if counter.enough_accepts(3) {
    println!("Consensus reached");
}
```

#### enough_rejects(&self, threshold: usize) -> bool
Check if reject count > (total_participants - threshold).

**Example**:
```rust
if counter.enough_rejects(3) {
    println!("Quorum cannot be reached");
}
```

#### meets_totality(&self) -> bool
Check if all participants have voted (accepts + rejects == total).

**Example**:
```rust
if counter.meets_totality() {
    println!("All participants have responded");
}
```

#### process_action(&mut self, from: Participant, action: &PositAction) -> bool
Process a single vote from a participant.
- Returns false if participant not in set or invalid action
- Returns true if vote recorded

**Example**:
```rust
if counter.process_action(Participant::from(1), &PositAction::Accept) {
    println!("Vote recorded");
}
```

---

### SignatureTaskPositAction
```rust
enum SignatureTaskPositAction {
    Waiting,                              // More votes needed
    Reject,                               // Task rejected
    Ready {                               // Ready for generation
        participants: Vec<Participant>,
        proposer: Participant,
    },
}
```

**Use**: Return type from `process_posit_action()`

**Interpretation**:
- `Waiting`: Continue waiting for more votes
- `Reject`: Posit failed, task aborted
- `Ready`: Transition to generation phase

---

### SignatureTaskPhase
```rust
enum SignatureTaskPhase {
    Posit {
        counter: SinglePositCounter,
        proposer: Participant,
        participants: Vec<Participant>,
    },
    Generating {
        generator: Box<SignatureGenerator>,
    },
    Complete(Result<(), SignError>),
}
```

**Variants**:

**Posit**: Negotiation phase
- `counter`: Vote tracker
- `proposer`: Expected proposer
- `participants`: Proposed participants

**Generating**: Signature generation phase
- `generator`: Active protocol instance

**Complete**: Terminal state
- `Ok(())`: Successful signature
- `Err(SignError)`: Error outcome

---

### SignatureTask
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

**Fields**:
- `sign_id`: Signature request ID
- `presignature_id`: Associated presignature ID
- `request`: The sign request details
- `phase`: Current phase of task
- `created`: Task creation time
- `timeout_total`: Total timeout for entire task
- `me`: Current participant
- `threshold`: Consensus threshold

---

## SignatureTask Methods

### new()
```rust
fn new(
    me: Participant,
    sign_id: SignId,
    presignature_id: PresignatureId,
    request: SignRequest,
    participants: Vec<Participant>,
    threshold: usize,
    timeout_total: Duration,
) -> Self
```

**Creates**: Task in Posit phase

**Parameters**:
- `me`: Current participant
- `sign_id`: Request ID
- `presignature_id`: Presignature ID
- `request`: Sign request
- `participants`: Participants in proposal
- `threshold`: Consensus threshold
- `timeout_total`: Timeout budget

**Returns**: New SignatureTask in Posit phase

**Example**:
```rust
let task = SignatureTask::new(
    Participant::from(0),
    sign_id,
    presignature_id,
    request,
    vec![Participant::from(0), Participant::from(1), ...],
    3,
    Duration::from_secs(120),
);
```

---

### process_posit_action()
```rust
fn process_posit_action(
    &mut self,
    from: Participant,
    action: &PositAction
) -> Option<SignatureTaskPositAction>
```

**Input**:
- `from`: Participant voting
- `action`: Action (Accept/Reject)

**Returns**:
- `None`: Action processed, still waiting
- `Some(Waiting)`: More votes needed
- `Some(Reject)`: Task rejected
- `Some(Ready {...})`: Ready for generation

**Behavior**:
1. Only works in Posit phase
2. Records vote in counter
3. Checks for enough accepts → Ready
4. Checks for enough rejects → Reject
5. Marks Complete if needed

**Example**:
```rust
match task.process_posit_action(from, &action) {
    Some(SignatureTaskPositAction::Ready { participants, proposer }) => {
        // Start generation
    }
    Some(SignatureTaskPositAction::Reject) => {
        // Task rejected
    }
    _ => {} // Still waiting
}
```

---

### start_generation()
```rust
fn start_generation(&mut self, generator: Box<SignatureGenerator>)
```

**Input**: SignatureGenerator instance

**Effect**: Transitions task to Generating phase

**Precondition**: Task must be in Posit phase

**Example**:
```rust
let generator = Box::new(/* create generator */);
task.start_generation(generator);
```

---

### complete()
```rust
fn complete(&mut self, result: Result<(), SignError>)
```

**Input**: Task result

**Effect**: Transitions task to Complete phase

**Precondition**: Task must be in Generating phase

**Example**:
```rust
task.complete(Ok(()));  // Success
task.complete(Err(SignError::Retry));  // Failure
```

---

### is_complete()
```rust
fn is_complete(&self) -> bool
```

**Returns**: true if in Complete phase

**Example**:
```rust
while !task.is_complete() {
    // Poll task
}
```

---

### result()
```rust
fn result(&self) -> Option<Result<(), SignError>>
```

**Returns**:
- `None`: Not complete yet
- `Some(Ok(()))`: Success
- `Some(Err(error))`: Failure with error

**Example**:
```rust
if let Some(Ok(())) = task.result() {
    println!("Signature generated!");
}
```

---

### timeout_total()
```rust
fn timeout_total(&self) -> bool
```

**Returns**: true if total timeout exceeded

**Checks**: `created.elapsed() >= timeout_total`

**Example**:
```rust
if task.timeout_total() {
    task.handle_posit_expiration(threshold);
}
```

---

### in_posit_phase()
```rust
fn in_posit_phase(&self) -> bool
```

**Returns**: true if in Posit phase

**Example**:
```rust
if task.in_posit_phase() {
    println!("Still negotiating");
}
```

---

### in_generating_phase()
```rust
fn in_generating_phase(&self) -> bool
```

**Returns**: true if in Generating phase

**Example**:
```rust
if task.in_generating_phase() {
    println!("Generating signature");
}
```

---

### handle_posit_expiration()
```rust
fn handle_posit_expiration(&mut self, threshold: usize)
    -> Option<SignatureTaskPositAction>
```

**Input**: Consensus threshold

**Effect**: Handles timeout during Posit phase

**Returns**:
- `Some(Ready {...})`: If enough accepts despite timeout
- `Some(Reject)`: If not enough accepts, transitions to Complete(Error)
- `None`: If not in Posit phase

**Example**:
```rust
if task.timeout_total() && task.in_posit_phase() {
    match task.handle_posit_expiration(3) {
        Some(SignatureTaskPositAction::Ready { .. }) => {
            // Proceed to generation
        }
        _ => {} // Task completed or still waiting
    }
}
```

---

## State Transition Table

| Current | Trigger | Next | Method |
|---------|---------|------|--------|
| Posit | Enough accepts + all voted | Ready | process_posit_action() |
| Posit | Enough rejects | Rejected | process_posit_action() |
| Posit | Timeout + enough accepts | Ready | handle_posit_expiration() |
| Posit | Timeout + not enough accepts | Rejected | handle_posit_expiration() |
| Generating | Success | Complete(Ok) | complete() |
| Generating | Failure | Complete(Err) | complete() |

---

## Usage Patterns

### Pattern 1: Creating and Processing Votes
```rust
let mut task = SignatureTask::new(...);

for (participant, action) in incoming_votes {
    if let Some(SignatureTaskPositAction::Ready { participants, proposer })
        = task.process_posit_action(participant, &action) {
        task.start_generation(create_generator(&participants));
        break;
    }
}
```

### Pattern 2: Timeout Handling
```rust
if task.timeout_total() && task.in_posit_phase() {
    match task.handle_posit_expiration(threshold) {
        Some(SignatureTaskPositAction::Ready { participants, proposer }) => {
            task.start_generation(create_generator(&participants));
        }
        _ => task.complete(Err(SignError::TotalTimeout)),
    }
}
```

### Pattern 3: Result Checking
```rust
if task.is_complete() {
    match task.result() {
        Some(Ok(())) => handle_success(),
        Some(Err(error)) => handle_error(error),
        None => {} // Shouldn't happen
    }
    tasks.remove(&(sign_id, presignature_id));
}
```

### Pattern 4: Task Collection Management
```rust
let mut tasks: HashMap<(SignId, u64), SignatureTask> = HashMap::new();

// Create
tasks.insert((sign_id, pre_id), SignatureTask::new(...));

// Route message
if let Some(task) = tasks.get_mut(&(sign_id, pre_id)) {
    task.process_posit_action(from, &action);
}

// Cleanup
for key in tasks.keys().filter(|(_, _)| tasks[key].is_complete()).collect::<Vec<_>>() {
    tasks.remove(&key);
}
```

---

## Thread Safety

**Note**: `SignatureTask` is NOT `Send` or `Sync` by default because:
- Contains `Instant` (thread-local friendly but not Sync)
- May eventually contain `Box<SignatureGenerator>` (depends on generator)

**For async usage**: Create task in tokio task, don't share across tasks

---

## Memory Layout

**Approximate sizes**:
- SignError: 1 byte (enum discriminant)
- SinglePositCounter: 3 HashSets + Instant ≈ 500 bytes
- SignatureTaskPhase: varies, typically 500-3000 bytes
- SignatureTask: ~1500 bytes + phase overhead

**Comparison to Posits mapping**: SinglePostCounter << Posits mapping for large systems

---

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `new()` | O(n) | n = participants, builds initial HashSet |
| `process_posit_action()` | O(1) | HashSet insert/contains |
| `enough_accepts()` | O(1) | Simple count comparison |
| `meets_totality()` | O(1) | Simple addition |
| `handle_posit_expiration()` | O(1) | State transition, no allocation |

---

## Error Handling

### SignError Variants

**Retry**: Transient error
- Indicates temporary failure
- Task can be retried with new presignature
- Action: Re-enter posit phase or discard

**TotalTimeout**: Exceeded deadline
- Indicates total timeout exceeded
- Task is considered failed
- Action: Remove task, mark request as failed

**Aborted**: Protocol aborted by peers
- Indicates peers rejected proposal
- Task is considered failed
- Action: Remove task, potentially retry

---

## Integration Checklist

Before integrating into SignatureSpawner:

- [ ] Create tasks in `handle_requests()`
- [ ] Route posit messages to `process_posit_action()`
- [ ] Route signature messages to task's generator
- [ ] Poll tasks for completion
- [ ] Clean up completed tasks
- [ ] Handle task timeouts
- [ ] Test phase transitions
- [ ] Verify result handling
- [ ] Performance test with many tasks
- [ ] Integration test with full system
