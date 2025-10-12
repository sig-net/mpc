# Inconsistent Storage Sync Tests

## Overview
Added comprehensive tests to verify that the sync system can handle and recover from inconsistent storage states where different nodes have conflicting views of who owns which shares.

## New Tests Added

### 1. `test_state_sync_inconsistent_triple_storage`

**Purpose**: Test syncing with inconsistent triple storage states across multiple owners.

**Scenario**:
- 3 different owners (participants 1, 2, 3)
- Each owner *should* have 50 triples
- Node storage has random inconsistencies:
  - **Owner 1**: Has 70% of expected triples + 30% extra invalid triples
  - **Owner 2**: Has 80% of expected triples + 10 extra invalid triples  
  - **Owner 3**: Has only 50% of expected triples + 30 extra invalid triples

**What it tests**:
- Handling of missing shares (owner doesn't have all they should)
- Handling of extra shares (owner has shares they shouldn't have)
- Convergence to authoritative state after sync
- Multiple concurrent ownership conflicts

**Verification**:
- ✅ After sync, each owner has exactly the triples they claim to own
- ✅ Extra/invalid triples are removed
- ✅ Missing triples are correctly identified (not present in storage)
- ✅ Final state matches the authoritative owner's claimed state

### 2. `test_state_sync_inconsistent_presignature_storage`

**Purpose**: Test syncing with inconsistent presignature storage states.

**Scenario**:
- 3 different owners
- Each owner *should* have 40 presignatures
- Node storage has random inconsistencies:
  - **Owner 1**: Has 60% of expected presignatures + 15 extras
  - **Owner 2**: Has 90% of expected presignatures + 5 extras
  - **Owner 3**: Has only 40% of expected presignatures + 25 extras

**What it tests**:
- Same as triple test but for presignatures
- Ensures both storage types handle inconsistencies correctly
- Tests that presignature cleanup works independently

**Verification**:
- ✅ After sync, each owner has exactly the presignatures they claim
- ✅ Extra/invalid presignatures are removed
- ✅ Final state converges to authoritative state

## Key Test Features

### Randomization
- Uses `rand::seq::SliceRandom` to shuffle and randomly select subsets
- Creates realistic inconsistent states that could occur in production
- Different percentages of inconsistency for each owner (70%, 80%, 50%, etc.)

### Real-World Simulation
This simulates scenarios like:
- **Partial sync failures**: Node only received part of a sync update
- **Data loss**: Node lost some storage but not all
- **Stale data**: Node has outdated ownership information
- **Ghost shares**: Node thinks it has shares that the owner no longer claims

### Convergence Verification
Each test verifies:
1. **Count correctness**: Exact number of shares matches authoritative state
2. **ID correctness**: Exact IDs match (using HashSet comparison)
3. **Cleanup**: Extra/invalid shares are properly removed
4. **Consistency**: All owners reach their authoritative state

## Technical Details

### Test Structure
```rust
1. Setup: Create Redis storage and sync infrastructure
2. Create ground truth: Define what each owner SHOULD have
3. Create inconsistency: Randomly store subset + extras
4. Verify inconsistency: Confirm storage doesn't match ground truth
5. Sync: Send authoritative updates from each owner
6. Verify convergence: Confirm storage matches ground truth
```

### Storage Operations
- Uses `insert_triples()` and `insert_presignatures()` helpers
- Uses `fetch_owned()` to retrieve current state
- Uses `SyncUpdate` to send authoritative state
- Cleanup happens automatically in `remove_outdated()` Redis Lua script

### Timing
- 500ms between sync updates (allows processing)
- 3 seconds final wait (allows cleanup to complete)
- Total test time: ~5-6 seconds per test

## Running the Tests

```bash
# Run both inconsistent storage tests
cargo test -p integration-tests test_state_sync_inconsistent

# Run just triple test
cargo test -p integration-tests test_state_sync_inconsistent_triple_storage

# Run just presignature test
cargo test -p integration-tests test_state_sync_inconsistent_presignature_storage

# With logging to see the randomization details
RUST_LOG=debug cargo test -p integration-tests test_state_sync_inconsistent -- --nocapture
```

## Expected Output

```
Creating inconsistent initial state...
Owner1 should have 50 triples, but node0 has 50 (including 15 extras)
Owner2 should have 50 triples, but node0 has 50 (including extras)
Owner3 should have 50 triples, but node0 has 55 (including 30 extras)
Verifying inconsistent initial state...
Before sync - Owner1: 50 items, Owner2: 50 items, Owner3: 55 items
Sending sync updates with authoritative state...
Verifying convergence after sync...
After sync - Owner1: 50 items, Owner2: 50 items, Owner3: 50 items
✅ Inconsistent triple storage sync test completed successfully
```

## What These Tests Catch

### Bugs in Sync Logic
- ❌ Not removing extra shares that owner doesn't claim
- ❌ Incorrectly removing shares that owner does claim
- ❌ Race conditions when multiple owners sync concurrently
- ❌ Partial cleanup leaving some invalid shares

### Edge Cases
- ❌ Owner has 0% of their expected shares (complete loss)
- ❌ Owner has 200% (all expected + many extras)
- ❌ Overlapping ID ranges between owners
- ❌ Large gaps in ID ranges (sparse ownership)

### Production Scenarios
- ✅ Network partitions causing partial syncs
- ✅ Node restart with stale cached data
- ✅ Redis data corruption or inconsistency
- ✅ Multiple nodes syncing simultaneously

## Implementation Notes

### Why Randomization?
- Makes tests more robust (tests many permutations)
- Catches edge cases that fixed tests might miss
- Simulates real-world unpredictability
- Each test run exercises slightly different scenarios

### Why Different Percentages?
- Tests system under various stress levels
- 70% missing = moderate inconsistency
- 50% missing = severe inconsistency
- 90% present = minor inconsistency
- Ensures system works across the spectrum

### Why Use HashSet for Verification?
- Order doesn't matter for ownership
- Efficient O(1) membership testing
- Clear equality semantics
- Makes test assertions clear and correct

## Future Enhancements

Potential additions to these tests:
1. **Combined inconsistency**: Both triples AND presignatures inconsistent simultaneously
2. **Timing variations**: Test with different sync delays
3. **Scale testing**: Test with hundreds of owners and thousands of shares
4. **Persistence**: Restart node mid-sync and verify recovery
5. **Byzantine scenarios**: Malicious owner claims shares they don't have

## Conclusion

These tests provide comprehensive coverage of real-world inconsistent storage scenarios. They verify that the sync system can recover from various types of data inconsistencies and converge to a correct, authoritative state based on what each owner claims to possess.

✅ **Status**: Both tests compile successfully and are ready to run with Redis infrastructure.
