# TASKS: Fix Sync Payload Size Issue

## Problem Analysis

The sync functionality currently fails when payload sizes become too large due to:

1. **Large HTTP Payloads**: When a node has thousands of triple/presignature IDs, the `SyncUpdate` struct becomes extremely large (potentially >1MB)
2. **Redis Operation Limits**: Redis operations with huge ID lists can timeout or fail
3. **Serialization Issues**: Serializing/deserializing large Vec<TripleId> and Vec<PresignatureId> can cause memory issues
4. **Network Timeouts**: Large payloads take longer to transmit and can cause network timeouts

## Root Causes

- **Sync Protocol Design**: Current sync sends ALL owned IDs in a single HTTP request
- **No Pagination**: `fetch_owned()` returns entire list without chunking
- **Redis Batching**: No batching mechanism for large ID operations
- **Fixed Payload Limits**: Hard-coded 20MB limit may not be sufficient for very large datasets

## Solution Strategy

Implement chunked/paginated sync protocol:

1. **Chunk-based Sync**: Split large ID lists into smaller chunks (e.g., 1000 IDs per chunk)
2. **Pagination Support**: Add offset/limit parameters to storage operations
3. **Incremental Processing**: Process chunks incrementally to avoid memory spikes
4. **Graceful Degradation**: Fallback to smaller chunk sizes if operations fail
5. **Progress Tracking**: Track sync progress across multiple chunks

## Tasks

### ✅ Task 1: Create TASKS.md with problem analysis
Status: COMPLETED

### ⏳ Task 2: Write test reproducing large payload sync failure
- Create test with 50,000+ triple/presignature IDs per node
- Verify that current sync fails with large datasets
- Document failure modes (timeout, memory, serialization)

### ⏳ Task 3: Implement chunked sync protocol
- Modify `SyncUpdate` to support chunks/pagination
- Add chunk metadata (chunk_id, total_chunks, offset)
- Implement chunked sync logic in `SyncTask`

### ⏳ Task 4: Update storage operations for batch processing  
- Add `fetch_owned_chunked()` with offset/limit parameters
- Implement `remove_outdated_chunked()` for batch processing
- Add Redis operation batching/pipelining

### ⏳ Task 5: Modify web server payload limits appropriately
- Reduce default payload limit for sync endpoint
- Add chunked sync endpoints if needed
- Handle chunk reassembly server-side

### ⏳ Task 6: Add pagination to fetch_owned operations
- Implement cursor-based or offset-based pagination
- Add Redis SCAN support for large sets
- Optimize memory usage during iteration

### ⏳ Task 7: Test chunked sync with large datasets
- Verify chunked sync works with 100,000+ IDs
- Test edge cases (empty chunks, single chunk, network failures)
- Benchmark performance improvements

### ⏳ Task 8: Update existing tests to ensure compatibility
- Ensure existing small sync tests still pass
- Add mixed chunk size testing
- Test backwards compatibility

## Implementation Notes

### Chunk Size Strategy
- Start with 1000 IDs per chunk (reasonable for HTTP/Redis)
- Make configurable via environment variable
- Implement adaptive chunking based on failure rates

### Error Handling
- Retry failed chunks with exponential backoff
- Track which chunks succeeded/failed
- Implement partial sync recovery

### Performance Considerations
- Use Redis pipelining for batch operations
- Implement async chunk processing where possible
- Monitor memory usage during large operations

### Backwards Compatibility
- Ensure old nodes can still sync with new chunked protocol
- Support both chunked and non-chunked sync methods
- Gradual rollout strategy