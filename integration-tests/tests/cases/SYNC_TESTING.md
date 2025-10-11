# Sync Testing Documentation

## Overview
This document describes the comprehensive tests added for the state synchronization system to ensure it can handle edge cases and large-scale scenarios.

## Tests Added

### 1. Large State Sync Test (`test_state_sync_very_large_update`)
**Purpose**: Test syncing a very large state to ensure we don't hit networking or Redis limits.

**Scenario**: 
- Creates 50,000 triples and 50,000 presignatures
- Tests that sync can handle large payloads without failures
- Validates all items remain present after sync

**What it catches**:
- HTTP payload size limits (current limit: 20MB)
- Redis command size limits
- Serialization/deserialization limits with CBOR encoding
- Memory issues with large data structures

### 2. Large Outdated Cleanup Test (`test_state_sync_large_outdated_cleanup`)
**Purpose**: Test syncing when a node has a large stockpile that needs to be cleaned up.

**Scenario**:
- Creates 30,000 outdated items and 100 valid items
- Tests that sync can efficiently clean up large numbers of outdated items
- Validates that valid items remain and invalid items are removed

**What it catches**:
- Redis Lua script limits (currently batches at 4096 items)
- Performance issues with large cleanup operations
- Correctness of the cleanup logic at scale

### 3. Empty State Sync Test (`test_state_sync_empty_state`)
**Purpose**: Test that sync works correctly when a node has an empty state.

**Scenario**:
- First inserts 11 items
- Then sends a sync update with empty arrays
- Validates all items are removed

**What it catches**:
- Edge case handling for empty updates
- Proper cleanup when a node loses all its data
- Graceful handling of zero-length arrays

### 4. Concurrent Updates Test (`test_state_sync_concurrent_updates`)
**Purpose**: Test concurrent sync updates from multiple sources to ensure no race conditions.

**Scenario**:
- Creates different sets of items for three different nodes
- Sends all sync updates concurrently
- Validates each node's items are correctly handled

**What it catches**:
- Race conditions in sync processing
- Correctness when multiple updates arrive simultaneously
- Proper isolation between different participants' data

### 5. Large Data Structure Unit Test (`test_sync_update_large_creation`)
**Purpose**: Unit test to verify large SyncUpdate structures can be created without issues.

**Scenario**:
- Creates a SyncUpdate with 100,000 triples and 100,000 presignatures
- Tests memory allocation and basic operations
- Estimates memory usage

**What it catches**:
- Memory allocation issues with large vectors
- Basic functionality of SyncUpdate with large data

## Current System Limits

### HTTP/Network Layer
- **Body size limit**: 20MB for sync endpoints (configurable in `web/mod.rs`)
- **Timeout**: Configurable via `MPC_NODE_TIMEOUT` (default: 1000ms)

### Redis Layer
- **Batch size**: 4096 items per batch in cleanup operations (hardcoded in Lua script)
- **Script argument size**: Redis has limits on script arguments, but the current implementation passes large arrays as ARGV which could potentially hit limits

### Serialization
- **Format**: CBOR (Concise Binary Object Representation)
- **No explicit size limits** in the code, but CBOR is efficient for large data structures

## Potential Issues Discovered

### 1. Redis Script Argument Size
The `remove_outdated` function passes `owner_shares` as a Lua script argument:
```rust
redis::Script::new(SCRIPT)
    .arg(owner_shares)  // This could be very large (50,000+ items)
```

**Issue**: Redis Lua scripts have limits on the size of arguments that can be passed. With very large owner_shares (e.g., 50,000+ items), this could exceed Redis limits.

**Status**: Needs testing with actual Redis to see if this causes issues.

**Potential fix**: If issues occur, batch the owner_shares array or use a different approach (e.g., store the list in Redis temporarily).

### 2. HTTP Request Size
With 50,000 items, the CBOR-encoded payload is approximately:
- Each u64 ID: ~9 bytes in CBOR (varint encoding)
- 100,000 items (triples + presignatures): ~900KB - 1.5MB

**Status**: Well within the 20MB limit, should not cause issues.

### 3. Memory Usage
A SyncUpdate with 100,000 items uses approximately:
- Vector headers: negligible
- Data: 100,000 × 8 bytes × 2 = ~1.6MB

**Status**: Reasonable memory usage, should not cause issues.

## Running the Tests

```bash
# Run all sync tests
cd integration-tests
cargo test sync_large

# Run specific test
cargo test test_state_sync_very_large_update

# Run with logging
RUST_LOG=debug cargo test test_state_sync_very_large_update -- --nocapture
```

## Notes for Future Development

1. **Pagination/Batching**: If tests reveal issues with very large sync updates, consider implementing pagination or batching for sync operations.

2. **Incremental Sync**: Instead of sending full state, consider sending only deltas to reduce payload size.

3. **Compression**: For very large payloads, consider adding compression (e.g., gzip) to reduce network bandwidth.

4. **Monitoring**: Add metrics for sync payload sizes and processing times to detect issues in production.

5. **Rate Limiting**: Consider adding rate limiting for sync operations to prevent resource exhaustion.

## Related Files

- `integration-tests/tests/cases/sync_large.rs` - New comprehensive tests
- `integration-tests/tests/cases/sync.rs` - Original sync tests
- `chain-signatures/node/src/protocol/sync/mod.rs` - Sync implementation
- `chain-signatures/node/src/storage/triple_storage.rs` - Storage layer with Redis scripts
- `chain-signatures/node/src/storage/presignature_storage.rs` - Storage layer for presignatures
- `chain-signatures/node/src/web/mod.rs` - HTTP layer with body size limits
