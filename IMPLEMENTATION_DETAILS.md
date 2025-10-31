# Implementation Details: Signature Task Consolidation

## File Modified
**File**: `chain-signatures/node/src/protocol/signature.rs`

## Imports Updated
**Lines 1-19**: Added `HashSet` to imports
```rust
// ADDED: HashSet to imports
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
```

## New Type Definitions

### 1. SignError Enum
**Lines 372-376**
```rust
#[derive(Debug, Clone, Copy)]
enum SignError {
    Retry,
    TotalTimeout,
    Aborted,
}
```

### 2. SinglePositCounter Struct
**Lines 378-428**
- `new()`: Lines 383-392
- `enough_accepts()`: Lines 394-396
- `enough_rejects()`: Lines 398-400
- `meets_totality()`: Lines 402-404
- `process_action()`: Lines 406-428

### 3. SignatureTaskPositAction Enum
**Lines 430-442**
- `Waiting` variant: Line 432
- `Reject` variant: Line 434
- `Ready` variant: Lines 436-439

### 4. SignatureTaskPhase Enum
**Lines 444-460**
- `Posit` variant: Lines 446-450
- `Generating` variant: Lines 452-454
- `Complete` variant: Line 456

### 5. SignatureTask Struct
**Lines 462-472** (Declaration)
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

### 6. SignatureTask Implementation
**Lines 474-626** (impl block)

**Methods**:

| Method | Lines | Purpose |
|--------|-------|---------|
| `new()` | 476-501 | Constructor, starts in Posit phase |
| `timeout_total()` | 503-505 | Check if total timeout exceeded |
| `is_complete()` | 507-509 | Check if in Complete phase |
| `result()` | 511-517 | Get result if complete |
| `process_posit_action()` | 519-565 | Handle posit votes |
| `start_generation()` | 567-569 | Transition to Generating |
| `complete()` | 571-573 | Transition to Complete |
| `in_posit_phase()` | 575-577 | Check current phase |
| `in_generating_phase()` | 579-581 | Check current phase |
| `handle_posit_expiration()` | 583-626 | Handle posit timeout |

## Key Method Details

### process_posit_action()
**Lines 519-565**
- Input: `from: Participant, action: &PositAction`
- Output: `Option<SignatureTaskPositAction>`
- Behavior:
  - Processes Accept/Reject votes
  - Checks for enough accepts → `Ready`
  - Checks for enough rejects → `Reject`
  - Stays in `Waiting` if more votes needed

```rust
fn process_posit_action(&mut self, from: Participant, action: &PositAction)
    -> Option<SignatureTaskPositAction> {
    // Implemented at lines 524-565
}
```

### handle_posit_expiration()
**Lines 583-626**
- Called when posit phase times out
- If threshold met: → `Ready`
- If threshold not met: → `Reject` + `Complete(Err(TotalTimeout))`

### Transitions Implemented

1. **Posit → Generating**
   - Triggered: When `process_posit_action()` returns `Ready`
   - Method: Call `start_generation()` with generator
   - Line: 567-569

2. **Posit → Complete(Reject)**
   - Triggered: When enough rejects received
   - Method: Automatic in `process_posit_action()`
   - Line: 535-540

3. **Posit → Complete(TotalTimeout)**
   - Triggered: When timeout without enough accepts
   - Method: Call `handle_posit_expiration()`
   - Line: 616-620

4. **Generating → Complete(Ok)**
   - Triggered: When generator completes successfully
   - Method: Call `complete(Ok(()))`
   - External coordination needed

5. **Generating → Complete(Error)**
   - Triggered: When generator fails
   - Method: Call `complete(Err(error))`
   - External coordination needed

## Integration Points

The following existing methods/structures interact with SignatureTask:

### SignatureGenerator
**Lines 630-943**
- Used as inner generator during Generating phase
- Will be stored in `SignatureTaskPhase::Generating`
- No changes needed to existing structure

### SignatureSpawner
**Lines 945-1370**
- Will need to:
  - Create tasks in `handle_requests()`
  - Route messages to tasks in `process_posit()`
  - Track tasks in a HashMap
  - Handle task completion/cleanup
- **Not yet modified** (legacy code remains for now)

### Related Structs (Unchanged)
- `SignRequest`: Lines 124-131
- `SignQueue`: Lines 133-359
- `PendingRequest`: Lines 51-88
- `IndexedSignRequest`: Lines 37-49
- `PendingPresignature`: Lines 1388-1410

## Compilation Verification

```bash
cd /home/ubuntu/space/mpc0
cargo check -p mpc-node --lib

# Result: ✅ Compiles successfully
# Warnings: 8 (expected - methods not yet used)
# Time: ~14.64s
```

## Breaking Changes
**None** - All existing code remains in place and functional.
New structures are additive only.

## Backward Compatibility
✅ Fully maintained:
- All existing methods remain
- SignatureGenerator unchanged
- SignatureSpawner interface unchanged
- Message types unchanged
- Storage structures unchanged

## Code Statistics

| Metric | Count |
|--------|-------|
| New lines added | ~242 |
| New types defined | 5 |
| New enums | 3 |
| New structs | 2 |
| Files modified | 1 |
| Breaking changes | 0 |

## Documentation Added

Three comprehensive documents created:
1. `SIGNATURE_TASK_CONSOLIDATION.md` - Implementation details
2. `SIGNATURE_TASK_VISUAL_GUIDE.md` - Visual comparisons
3. This file - Exact line numbers and locations

## Next Steps for Integration

1. **Update `SignatureSpawner::handle_requests()`**
   - Create `SignatureTask` instances
   - Store in task collection

2. **Refactor message routing**
   - Posit messages → `task.process_posit_action()`
   - Signature messages → task's generator

3. **Update main event loop in `SignatureSpawner::run()`**
   - Monitor task completion
   - Handle expiration
   - Clean up completed tasks

4. **Remove legacy code**
   - Remove `posits` field
   - Remove `propose_posit()` method
   - Remove `process_posit()` method
   - Consolidate `generate()` logic into tasks

5. **Run tests**
   - Component tests: `integration-tests/tests/cases/mpc.rs`
   - Integration tests
   - Benchmark tests

## Files for Review

All changes are in a single file for easy review:
- **File**: `/home/ubuntu/space/mpc0/chain-signatures/node/src/protocol/signature.rs`
- **Lines added**: Approximately 242 lines
- **Sections**:
  - Imports: Line 19 (added HashSet)
  - SignError: Lines 372-376
  - SinglePositCounter: Lines 378-428
  - SignatureTaskPositAction: Lines 430-442
  - SignatureTaskPhase: Lines 444-460
  - SignatureTask: Lines 462-626
