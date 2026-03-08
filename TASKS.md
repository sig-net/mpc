# Async/Tokio Improvement Tasks

## Phase 1: High-Impact, Low-Effort (Week 1)

### Task 1.1: Fix Sync Task Broadcast Completion Polling
- **File**: `chain-signatures/node/src/protocol/sync/mod.rs`
- **Lines**: 141-155
- **Priority**: HIGH
- **Effort**: LOW (1-2 hours)
- **Status**: ✅ DONE

**Changes:**
- Remove `broadcast_check_interval` polling loop
- Use `select!` with `JoinHandle` directly
- Handle completion immediately instead of polling every 100ms

**Implementation:**
- Removed 100ms polling interval
- Used async block with fused `JoinHandle` in `select!`
- Completion is now detected immediately (<1ms) instead of 0-100ms delay

**Testing:**
- Verify broadcasts complete successfully
- Check that cleanup happens immediately after broadcast finishes
- Monitor task count to ensure no leaks

---

### Task 1.2: Fix Ethereum Batch Response Polling
- **File**: `chain-signatures/node/src/rpc.rs`
- **Lines**: 1016-1047
- **Priority**: HIGH
- **Effort**: LOW (2-3 hours)
- **Status**: ✅ DONE

**Changes:**
- Replace `try_recv()` with `select!` on `actions_rx.recv()`
- Add timeout branch for batch flushing
- Add size-based flushing when batch reaches limit

**Implementation:**
- Replaced polling loop with proper `select!` pattern
- Batch flushes immediately on timeout or size limit
- Actions are processed as they arrive instead of polling
- Improved batching efficiency with immediate wakeup

**Testing:**
- Verify batches flush on timeout
- Verify batches flush on size limit
- Check no messages are lost
- Measure improved batching efficiency

---

### Task 1.3: Replace `try_recv()` in Cryptography
- **Files**:
  - `chain-signatures/node/src/protocol/cryptography.rs` (lines 73-85, 268-280)
  - `chain-signatures/node/src/protocol/message/filter.rs` (line 44)
- **Priority**: MEDIUM
- **Effort**: MEDIUM (4-6 hours)
- **Status**: TODO
- **⚠️ NOTE**: Should be completed alongside Task 2.1 (Event-Driven Main Protocol Loop) as they both touch the polling mechanism in `MpcSignProtocol::run`

**Changes:**
- Replace `try_recv()` loops with timeout-based collection
- Consider using `recv_many()` if tokio version allows
- Document the message batching pattern

**Testing:**
- Verify all messages are processed
- Check protocol completion time is unchanged
- Validate error handling

---

### Task 1.4: Add RPC Rate Limiting Semaphore
- **Files**:
  - `chain-signatures/node/src/rpc.rs`
  - `chain-signatures/node/src/indexer_eth/mod.rs`
  - Other files making RPC calls
- **Priority**: MEDIUM
- **Effort**: MEDIUM (4-6 hours)
- **Status**: ✅ DONE

**Changes:**
- Add global `Semaphore` for RPC concurrency control
- Set limit to 100 concurrent requests (configurable)
- Wrap all external RPC calls with permit acquisition
- Add metrics for semaphore pressure

**Implementation:**
- Added `RPC_SEMAPHORE` with LazyLock pattern
- Set `MAX_CONCURRENT_EXTERNAL_RPC = 100`
- Wrapped `fetch_state()`, `fetch_config()`, and `try_publish_near()` with permit acquisition
- Added `multichain_rpc_semaphore_available_permits` metric
- Background task updates metric every 5 seconds

**Testing:****
- Load test with high RPC volume
- Verify semaphore prevents overload
- Check no deadlocks occur
- Monitor external service health

---

## Phase 2: Performance Improvements (Week 2)

### Task 2.1: Event-Driven Main Protocol Loop
- **File**: `chain-signatures/node/src/protocol/mod.rs`
- **Lines**: 103-139
- **Priority**: HIGH
- **Effort**: MEDIUM (6-8 hours)
- **Status**: TODO
- **⚠️ NOTE**: Should be completed alongside Task 1.3 (try_recv in cryptography) as they both touch the polling mechanism in `MpcSignProtocol::run`

**Changes:**
- Add `tokio::sync::Notify` for work availability
- Use `select!` to wait on:
  - Contract state changes
  - Mesh state changes
  - Message availability
  - Notify signal
- Remove sleep-based throttling
- Fix `try_recv()` patterns in message handling (coordinate with Task 1.3)
- Add minimal backoff for rapid-fire events (10ms)

**Testing:**
- Measure idle CPU usage (should drop 80-90%)
- Verify all events still trigger processing
- Check latency hasn't increased
- Stress test with rapid state changes

---

### Task 2.2: Contract State Update Task Coordination
- **File**: `chain-signatures/node/src/rpc.rs`
- **Lines**: 380-390
- **Priority**: MEDIUM
- **Effort**: LOW (2-3 hours)
- **Status**: TODO

**Changes:**
- Replace fire-and-forget spawns with `tokio::join!`
- Handle update results properly
- Log errors from updates
- Add metrics for update duration

**Testing:**
- Verify updates complete before next interval
- Check error handling
- Monitor task count stays stable

---

### Task 2.3: Presignature Availability Notifications
- **Files**:
  - `chain-signatures/node/src/storage/presignature_storage.rs`
  - `chain-signatures/node/src/protocol/signature.rs`
- **Priority**: MEDIUM
- **Effort**: MEDIUM (4-6 hours)
- **Status**: TODO

**Changes:**
- Add `Arc<Notify>` to `PresignatureStorage`
- Call `notify_waiters()` when presignatures inserted
- Update signature task to wait on notification instead of polling
- Add optional timeout for waiting

**Testing:**
- Verify immediate wakeup when presignature available
- Measure latency improvement
- Check no race conditions

---

## Phase 3: Robustness (Week 3)

### Task 3.1: Add Graceful Shutdown with CancellationToken
- **Files**:
  - `chain-signatures/node/src/main.rs`
  - `chain-signatures/node/src/cli.rs`
  - All task spawn sites
- **Priority**: HIGH
- **Effort**: HIGH (8-10 hours)
- **Status**: TODO

**Changes:**
- Add `tokio-util` dependency for `CancellationToken`
- Create root cancellation token in main
- Thread token through all long-running tasks
- Add `cancel.cancelled()` branches to all task loops
- Implement cleanup logic for each task
- Add signal handler for SIGTERM/SIGINT

**Testing:**
- Send SIGTERM and verify clean shutdown
- Check all connections closed properly
- Verify state is flushed to storage
- Ensure no panics during shutdown
- Load test shutdown under heavy load

---

### Task 3.2: Wrap Crypto Operations in spawn_blocking
- **Files**:
  - `chain-signatures/node/src/protocol/cryptography.rs`
  - `chain-signatures/node/src/protocol/signature.rs`
- **Priority**: MEDIUM
- **Effort**: MEDIUM (6-8 hours)
- **Status**: TODO

**Changes:**
- Identify all `protocol.poke()` calls
- Wrap in `spawn_blocking` with proper error handling
- Consider using thread pool specifically for crypto
- Add metrics for crypto blocking time

**Challenges:**
- `poke()` requires mutable protocol reference
- May need `Arc<Mutex<Protocol>>` pattern
- Benchmark to ensure overhead is worth it

**Testing:**
- Measure protocol completion time (should be similar)
- Check other async tasks aren't starved during crypto
- Monitor CPU usage across cores
- Stress test with many concurrent protocols

---

### Task 3.3: Fix Large JSON Serialization
- **Files**:
  - `chain-signatures/node/src/backlog/mod.rs`
  - Other storage operations with large data
- **Priority**: LOW
- **Effort**: LOW (2-3 hours)
- **Status**: TODO

**Changes:**
- Identify serialization operations >10KB
- Wrap in `spawn_blocking`
- Consider using `bincode` for internal storage (faster)
- Add size tracking metrics

**Testing:**
- Benchmark serialization time before/after
- Verify correctness
- Check async runtime not blocked

---

### Task 3.4: Migrate Metrics Mutex to tokio::sync::Mutex
- **File**: `chain-signatures/node/src/metrics/mod.rs`
- **Lines**: 62-92
- **Priority**: LOW
- **Effort**: LOW (1-2 hours)
- **Status**: TODO

**Changes:**
- Replace `std::sync::Mutex` with `tokio::sync::Mutex`
- Update all lock sites to use `.await`
- Add documentation about async-safe usage

**Alternative:**
- Use `parking_lot::Mutex` if performance critical
- Add explicit documentation with `#[must_not_suspend]`

**Testing:**
- Verify metrics still work correctly
- Benchmark to check for performance regression
- Check no deadlocks under load

---

## Stretch Goals

### Task S.1: Ethereum Indexer Event Streaming
- **File**: `chain-signatures/node/src/indexer_eth/mod.rs`
- **Priority**: LOW
- **Effort**: HIGH (2-3 days)
- **Status**: TODO

**Changes:**
- Investigate WebSocket subscription APIs for Ethereum
- Replace polling with event streaming where available
- Keep polling as fallback

---

### Task S.2: Protocol Message Backpressure
- **Files**: Various protocol message handlers
- **Priority**: LOW
- **Effort**: MEDIUM (4-6 hours)
- **Status**: TODO

**Changes:**
- Review message accumulation patterns
- Add bounded queues with backpressure where needed
- Add metrics for queue depth

---

## Testing Checklist

For each task:
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Metrics added/updated
- [ ] Documentation updated
- [ ] Performance benchmarked
- [ ] Code reviewed
- [ ] No new warnings

---

## Overall Progress

- **Phase 1**: 3/4 tasks complete (Task 1.3 deferred to Phase 2)
- **Phase 2**: 0/3 tasks complete (Task 2.4 removed - no NEAR work needed)
- **Phase 3**: 0/4 tasks complete
- **Stretch**: 0/2 tasks complete (Task S.2 removed)

**Total**: 3/13 tasks complete (23%)

### Phase 1 Summary
✅ Task 1.1: Sync task broadcast polling fixed - eliminated 10 wakeups/second
✅ Task 1.2: ETH batch response polling fixed - proper event-driven batching
✅ Task 1.4: RPC rate limiting added - prevents overload with 100 concurrent limit
⏸️ Task 1.3: Deferred to Phase 2 (combined with Task 2.1)

---

## Notes

- Start with Phase 1 tasks as they are quick wins
- Phase 3 Task 3.1 (graceful shutdown) is critical for production
- Benchmark each change to ensure improvements
- Consider feature flags for gradual rollout
- Keep monitoring idle CPU usage as primary KPI

---

## Dependencies

Required additions to `Cargo.toml`:

```toml
[dependencies]
tokio-util = { version = "0.7", features = ["sync"] }

# Optional but recommended:
parking_lot = "0.12"  # For faster mutexes if needed
```

---

## Rollout Strategy

1. **Development**: Implement on feature branch `feat/improve-async`
2. **Testing**: Run full integration test suite + load tests
3. **Staging**: Deploy to testnet nodes for 1 week
4. **Production**: Gradual rollout with monitoring
5. **Rollback**: Keep previous version ready if issues found

---

## Success Metrics

Track these before and after full implementation:

| Metric | Before | Target | Actual |
|--------|--------|--------|--------|
| Idle CPU % | ~10% | <3% | TBD |
| Protocol wakeups/sec | ~10 | ~1 | TBD |
| RPC calls/min (idle) | ~80 | <40 | TBD |
| Sign latency p50 (ms) | TBD | -10% | TBD |
| Sign latency p99 (ms) | TBD | -10% | TBD |
| Graceful shutdown time | N/A | <5s | TBD |
