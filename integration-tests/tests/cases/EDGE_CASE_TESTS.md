# Edge Case Sync Tests

This document describes the edge case tests for the MPC sync protocol, focusing on corrupted/invalid IDs and ownership conflicts.

## Test Overview

### 1. test_state_sync_corrupted_invalid_ids

**Purpose:** Test sync behavior when storage contains edge case IDs that might cause issues.

**Test Scenario:**
- **Node1** owns valid IDs: triples [100, 200, 300, 400, 500], presigs [1000, 2000, 3000, 4000, 5000]
- **Node2** owns edge case IDs:
  - Triple IDs: [0, u64::MAX-1, u64::MAX/2, 12345678901234567, 999999999]
  - Presig IDs: [0, u64::MAX-2, u64::MAX/3, 98765432109876543, 888888888]

**Edge Cases Tested:**
- **ID 0:** Minimum boundary value
- **Near u64::MAX:** Maximum boundary values (u64::MAX-1, u64::MAX-2)
- **Mid-range extremes:** u64::MAX/2, u64::MAX/3
- **Sparse IDs:** Large arbitrary numbers with huge gaps

**Validation:**
1. Node1's sync update claims only its valid IDs
2. Node1 retains all its valid IDs after sync
3. Node2's edge case IDs are preserved (not claimed by node1)
4. Both nodes maintain their separate ID spaces

**Key Insights:**
- The system handles extreme ID values (0, u64::MAX-1) gracefully
- Sparse ID distributions work correctly
- Redis Lua scripts don't overflow with large ID values
- No issues with serialization/deserialization of extreme values

**Performance:**
- Sync update processed in ~10-40 microseconds
- Test completes in ~9 seconds

---

### 2. test_state_sync_ownership_conflict

**Purpose:** Test sync behavior when different nodes claim ownership of the same IDs (ownership conflicts).

**Test Scenario:**
- **Node1** initially owns: triples [1, 2, 3, 4, 5], presigs [10, 20, 30, 40, 50]
- **Node2** later claims: triples [3, 4, 5, 6, 7], presigs [30, 40, 50, 60, 70]
- **Node3** owns non-conflicting: triples [100, 200], presigs [1000, 2000]

**Conflict Creation:**
- IDs 3, 4, 5 (triples) are contested between Node1 and Node2
- IDs 30, 40, 50 (presigs) are contested between Node1 and Node2

**Test Flow:**
1. Node1 inserts IDs 1-5 and 10-50
2. Node2 sends sync update claiming IDs 3-7 and 30-70 (conflicts with Node1)
3. Node1 sends sync update asserting original ownership of IDs 1-5 and 10-50

**Critical Discovery:**
**IDs are globally unique in the storage system**, not per-owner. The storage design:
- `reserved_key`: Global set of all reserved IDs
- `triple_key`/`presignature_key`: Global hash of all stored items
- `owner_keys/{owner}`: Set of IDs owned by specific participant

**Key Behavior:**
- **First to insert wins:** Once Node1 inserts ID 3, Node2 cannot insert the same ID 3
- Node2's attempt to reserve already-stored IDs fails with: `"WARN triple 3 has already been stored"`
- This prevents ownership conflicts at the storage layer

**Validation:**
1. Node1 keeps its originally claimed IDs (first to insert)
2. Node2 does NOT have the conflicting IDs (3, 4, 5, 30, 40, 50)
3. Node3's non-conflicting IDs remain unaffected
4. Storage maintains global ID uniqueness invariant

**Key Insights:**
- IDs are globally unique across all owners (fundamental design constraint)
- Storage reservation system prevents ID collisions
- "First to insert wins" rule is enforced at the Redis layer
- Sync protocol cannot override this storage-level constraint
- This prevents Byzantine nodes from claiming others' IDs

**Performance:**
- Sync updates processed in ~10-15 microseconds
- Test completes in ~10 seconds

---

## Architecture Implications

### Global ID Uniqueness

The tests reveal a critical architectural constraint:

```
Triple/Presignature IDs are globally unique, NOT per-owner
```

**Storage Keys:**
```
triples:{version}:{account_id}            # Global hash: ID -> Triple data
triples_reserved:{version}:{account_id}   # Global set: all reserved IDs
triples_owners:{version}:{account_id}:{participant}  # Per-owner set: IDs owned by participant
```

**Implications:**
1. **ID Generation:** Must be coordinated to avoid collisions (likely using random u64)
2. **Ownership Transfer:** Not possible after insertion
3. **Byzantine Resistance:** Malicious nodes cannot claim others' IDs
4. **Sync Behavior:** Can only declare ownership of IDs that don't exist yet

### Lua Script Protection

Redis Lua scripts provide atomic operations that enforce invariants:

```lua
-- Reserve script checks:
if redis.call("SADD", reserved_key, triple_id) == 0 then
    return {err = "WARN triple " .. triple_id .. " has already been reserved"}
end

if redis.call("HEXISTS", triple_key, triple_id) == 1 then
    return {err = "WARN triple " .. triple_id .. " has already been stored"}
end
```

This prevents:
- Double reservation
- Overwriting existing triples
- Ownership conflicts

---

## Test Results

### Summary
```
Running 10 tests (1 ignored):
✅ test_state_sync_concurrent_updates
✅ test_state_sync_corrupted_invalid_ids          (NEW)
✅ test_state_sync_empty_state
✅ test_state_sync_inconsistent_presignature_storage
✅ test_state_sync_inconsistent_triple_storage
✅ test_state_sync_large_outdated_cleanup
✅ test_state_sync_ownership_conflict             (NEW)
⏭️  test_state_sync_very_large_inconsistent_storage (ignored - expensive)
✅ test_state_sync_very_large_update
✅ test_sync_update_large_creation

Result: 9 passed, 0 failed, 1 ignored
Total time: 171.53 seconds
```

### Coverage

**Edge Cases Covered:**
- ✅ Extreme ID values (0, u64::MAX-1)
- ✅ Sparse ID distributions
- ✅ Ownership conflicts
- ✅ Global ID uniqueness enforcement
- ✅ Storage-level collision prevention

**Still TODO (from original list):**
- Network failure scenarios during sync
- Redis unavailability handling
- Sync during active protocol operations
- Byzantine node behavior (partially covered)
- State consistency after node restart

---

## Files Modified

- `integration-tests/tests/cases/sync_large.rs`: Added 2 new tests
  - Lines ~1330-1490: `test_state_sync_corrupted_invalid_ids`
  - Lines ~1492-1690: `test_state_sync_ownership_conflict`

---

## Usage

Run the new tests:
```bash
# Run corrupted IDs test
cargo test -p integration-tests test_state_sync_corrupted_invalid_ids -- --nocapture

# Run ownership conflict test  
cargo test -p integration-tests test_state_sync_ownership_conflict -- --nocapture

# Run all sync_large tests
cargo test -p integration-tests --test lib cases::sync_large -- --test-threads=1
```

---

## Related Documentation

- `SYNC_TESTING.md`: Overview of all sync tests
- `INCONSISTENT_STORAGE_TESTS.md`: Randomized inconsistent storage tests
- `SYNC_TEST_FINAL_SUMMARY.md`: Comprehensive test suite summary
- `../../../chain-signatures/node/src/storage/triple_storage.rs`: Storage implementation
- `../../../chain-signatures/node/src/storage/presignature_storage.rs`: Presignature storage
