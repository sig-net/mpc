# Async/Tokio Improvements Plan

## Overview

This document outlines improvements to async patterns, tokio idiom usage, and elimination of polling/blocking in the MPC node codebase. The goal is to improve performance, reduce CPU usage, and follow Rust async best practices.

## Current State Analysis

The codebase demonstrates solid async fundamentals in several areas:
- ✅ Proper use of `spawn_blocking` for system metrics collection
- ✅ Good `watch` channel patterns for state propagation
- ✅ Async file I/O with `tokio::fs`
- ✅ Well-structured message passing with `mpsc` channels

However, there are opportunities to improve:
- 🔴 Multiple polling loops instead of event-driven patterns
- 🔴 Lack of graceful shutdown coordination
- 🟡 Some blocking operations in async contexts
- 🟡 Missing rate limiting for external calls
- 🟡 Inconsistent use of async primitives

---

## 1. Polling → Event-Driven Patterns

### 1.1 Main Protocol Loop

**Location:** `chain-signatures/node/src/protocol/mod.rs:103-139`

**Current Pattern:**
```rust
loop {
    // ... do work ...
    let sleep_ms = match node.state {
        NodeState::Running(_) => 100,
        _ => 1000,
    };
    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
}
```

**Issue:** Wakes up 10 times/second when running, even if no work is available.

**Solution:** Replace sleep-based throttling with event-driven wakeups using `tokio::sync::Notify` or `select!` over existing watch channels. Wake only when:
- Contract state changes
- Mesh state changes
- New messages arrive

**Impact:** Reduces idle CPU usage by ~90%, improves power efficiency.

---

### 1.2 NEAR Indexer Fixed Interval Polling

**Location:** `chain-signatures/node/src/indexer.rs:250-265`

**Current Pattern:**
```rust
let mut interval = tokio::time::interval(Duration::from_millis(750));
loop {
    interval.tick().await;
    poll_pending_requests(&mut context).await?;
}
```

**Issue:** Fixed 750ms polling regardless of blockchain activity.

**Solution:** Implement adaptive polling:
- Start with fast polling (500ms) when requests detected
- Back off exponentially to 5s when idle
- Consider NEAR event streaming in future

**Impact:** Reduces RPC load by 50-80% during idle periods, improves request detection latency when active.

---

### 1.3 Sync Task Broadcast Completion

**Location:** `chain-signatures/node/src/protocol/sync/mod.rs:141-155`

**Current Pattern:**
```rust
let mut broadcast_check_interval = tokio::time::interval(Duration::from_millis(100));
// ...
_ = broadcast_check_interval.tick() => {
    if !handle.is_finished() {
        broadcast = Some((start, handle));
        continue;
    }
    // process result
}
```

**Issue:** Polls every 100ms to check if a task finished.

**Solution:** Use `select!` with the `JoinHandle` directly:
```rust
tokio::select! {
    result = &mut broadcast_handle, if broadcast_handle.is_some() => {
        // process immediately when done
    }
    // ... other branches ...
}
```

**Impact:** Eliminates 10 wakeups/second, reduces completion detection latency from 0-100ms to <1ms.

---

### 1.4 Ethereum Batch Response Polling

**Location:** `chain-signatures/node/src/rpc.rs:1016-1047`

**Current Pattern:**
```rust
let mut interval = tokio::time::interval(Duration::from_millis(100));
loop {
    interval.tick().await;
    if let Ok(action) = actions_rx.try_recv() {
        actions_batch.push(action);
    }
}
```

**Issue:** Uses `try_recv()` polling instead of proper async receive.

**Solution:** Use `select!` with timeout:
```rust
tokio::select! {
    _ = tokio::time::sleep(batch_interval) => {
        flush_batch(&mut actions_batch).await;
    }
    Some(action) = actions_rx.recv() => {
        actions_batch.push(action);
        if actions_batch.len() >= batch_size {
            flush_batch(&mut actions_batch).await;
        }
    }
}
```

**Impact:** More efficient batching, immediate wakeup on new actions instead of up to 100ms delay.

---

## 2. Blocking Operations in Async Contexts

### 2.1 Metrics Histogram Mutex

**Location:** `chain-signatures/node/src/metrics/mod.rs:62-92`

**Current Pattern:**
```rust
pub struct Histogram {
    pub label_values: Mutex<Vec<String>>,  // std::sync::Mutex
    pub exact: Mutex<Vec<f64>>,
}
```

**Issue:** Uses `std::sync::Mutex` in async code. Currently safe but fragile - if anyone holds the lock across an `.await`, it will deadlock the runtime.

**Solution Options:**
1. Switch to `tokio::sync::Mutex` (safest, slight overhead)
2. Use `parking_lot::Mutex` (faster, still requires discipline)
3. Document explicitly with `#[must_not_suspend]` and comments

**Recommendation:** Use `tokio::sync::Mutex` for safety and consistency with async context.

---

### 2.2 Cryptographic Operations (cait-sith)

**Location:** `chain-signatures/node/src/protocol/cryptography.rs`, `signature.rs`

**Current Pattern:**
```rust
let action = match self.protocol.poke() {  // CPU-intensive, synchronous
    Ok(action) => action,
    Err(err) => { /* ... */ }
};
```

**Issue:** Heavy cryptographic operations (key generation, signing) run synchronously, blocking the tokio runtime and starving other async tasks.

**Solution:** Wrap CPU-intensive poke operations in `spawn_blocking`:
```rust
let protocol_clone = Arc::clone(&protocol);
let action = tokio::task::spawn_blocking(move || {
    protocol_clone.poke()
}).await??;
```

**Note:** System metrics already use `spawn_blocking` correctly - apply the same pattern here.

**Impact:** Prevents cryptographic work from blocking other tasks, improves overall responsiveness.

---

### 2.3 JSON Serialization in Storage

**Location:** `chain-signatures/node/src/backlog/mod.rs:95-100`, storage operations

**Current Pattern:**
```rust
let transaction = serde_json::to_vec(&tx)
    .expect("serialize bidirectional transaction for checkpoint");
```

**Issue:** Large checkpoint serialization blocks the runtime.

**Solution:** Use `spawn_blocking` for large serialization:
```rust
let serialized = tokio::task::spawn_blocking(move || {
    serde_json::to_vec(&tx)
}).await??;
```

**Threshold:** Apply for data >10KB or serialization expected to take >1ms.

---

## 3. Missing Tokio Idioms

### 3.1 Graceful Shutdown with CancellationToken

**Current State:** No coordinated shutdown mechanism. Tasks are abruptly cancelled.

**Solution:** Introduce `tokio_util::sync::CancellationToken`:

```rust
use tokio_util::sync::CancellationToken;

// In main/CLI
let shutdown_token = CancellationToken::new();

// Pass to all long-running tasks
tokio::spawn(run_task(shutdown_token.clone()));

// On shutdown signal
shutdown_token.cancel();
```

**In each task:**
```rust
async fn run_task(cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                // Cleanup, flush state, close connections
                tracing::info!("task shutting down gracefully");
                break;
            }
            // ... normal work ...
        }
    }
}
```

**Benefits:**
- Prevents data loss during shutdown
- Ensures consistent state
- Allows flushing pending work
- Clean connection closure

---

### 3.2 Rate Limiting with Semaphore

**Location:** RPC operations throughout codebase

**Current State:** `MAX_CONCURRENT_RPC_REQUESTS = 1024` enforced by channel capacity only.

**Solution:** Add `tokio::sync::Semaphore` for precise concurrency control:

```rust
use std::sync::LazyLock;
use tokio::sync::Semaphore;

static RPC_SEMAPHORE: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(100));

async fn make_rpc_call() -> Result<Response> {
    let _permit = RPC_SEMAPHORE.acquire().await?;
    // Make the call - permit automatically released on drop
    client.request().await
}
```

**Benefits:**
- Prevents overwhelming external services
- Better backpressure
- Precise control over concurrent requests

---

### 3.3 Replace `try_recv()` Anti-pattern

**Location:** `chain-signatures/node/src/protocol/cryptography.rs:73-85`

**Current Pattern:**
```rust
loop {
    let msg = match ctx.generating.try_recv() {
        Ok(msg) => msg,
        Err(mpsc::error::TryRecvError::Empty) => break,
        // ...
    };
}
```

**Solution:** Use timeout-based collection or `recv_many`:

**Option 1 - Timeout-based:**
```rust
let mut messages = Vec::new();
while let Ok(Ok(msg)) = tokio::time::timeout(Duration::ZERO, ctx.generating.recv()).await {
    messages.push(msg);
}
```

**Option 2 - recv_many (Tokio 1.32+):**
```rust
let mut buffer = Vec::with_capacity(100);
let count = ctx.generating.recv_many(&mut buffer, 100).await;
```

**Impact:** More idiomatic, works better with async runtime scheduling.

---

### 3.4 Contract State Update Task Coordination

**Location:** `chain-signatures/node/src/rpc.rs:380-390`

**Current Pattern:**
```rust
loop {
    interval.tick().await;
    tokio::spawn(update_contract(...));  // Fire and forget
    tokio::spawn(update_config(...));
}
```

**Issue:** Unbounded task spawning without backpressure.

**Solution:** Await tasks or use bounded `JoinSet`:

```rust
loop {
    interval.tick().await;
    let (contract_result, config_result) = tokio::join!(
        update_contract(near.clone(), contract.clone()),
        update_config(near.clone(), config.clone())
    );
    // Handle results
}
```

**Impact:** Prevents task accumulation if updates take longer than interval.

---

### 3.5 Presignature Availability Notification

**Location:** `chain-signatures/node/src/protocol/signature.rs`

**Current State:** No notification when presignatures become available. Must poll or wait with retry loops.

**Solution:** Add `tokio::sync::Notify` or `watch` channel:

```rust
// In PresignatureStorage
pub struct PresignatureStorage {
    // ... existing fields ...
    available_notify: Arc<Notify>,
}

impl PresignatureStorage {
    pub async fn insert(&self, presig: Presignature) {
        // ... insert logic ...
        self.available_notify.notify_waiters();
    }

    pub async fn wait_available(&self) {
        self.available_notify.notified().await;
    }
}
```

**Impact:** Immediate start of signature generation when presignatures ready, instead of waiting for next poll cycle.

---

## 4. Good Patterns to Preserve

### System Metrics Collection ✓
**Location:** `chain-signatures/node/src/protocol/mod.rs:177-210`

Correctly uses `spawn_blocking` for blocking system calls:
```rust
tokio::task::spawn_blocking(move || {
    loop {
        let mut system = System::new_all();
        system.refresh_all();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        // Update metrics
    }
})
```

**This is the template for handling other blocking operations.**

---

### Connection Pool Watch Patterns ✓
**Location:** `chain-signatures/node/src/mesh/connection.rs`

Good use of `watch` channels and `StreamMap` for multiplexing connection status. The `ConnectionWatcher` pattern is well-designed.

---

### Async File I/O ✓
**Location:** `chain-signatures/node/src/storage/secret_storage.rs`

Properly uses `tokio::fs` for async file operations.

---

## Implementation Priority

### Phase 1: High-Impact, Low-Effort (Week 1)
1. Fix Sync task broadcast polling → `select!` pattern
2. Fix ETH batch response `try_recv()` → proper `select!`
3. Replace `try_recv()` patterns in cryptography with timeout-based collection
4. Add rate limiting `Semaphore` for RPC calls

### Phase 2: Performance Improvements (Week 2)
1. Main protocol loop sleep → event-driven
2. Contract update task coordination
3. Add presignature availability notifications
4. Implement adaptive polling for NEAR indexer

### Phase 3: Robustness (Week 3)
1. Add `CancellationToken` for graceful shutdown
2. Wrap crypto operations in `spawn_blocking`
3. Fix large JSON serialization with `spawn_blocking`
4. Switch metrics `Mutex` to `tokio::sync::Mutex`

---

## Testing Strategy

1. **Idle CPU Usage**: Measure before/after with no activity
2. **Latency**: Track time from event → response for sign requests
3. **RPC Load**: Monitor number of RPC calls during idle periods
4. **Graceful Shutdown**: Verify no data loss on SIGTERM
5. **Load Testing**: Run with high sign request volume

---

## Metrics to Track

- Protocol loop wakeup count per second (before: ~10/s, target: ~1/s)
- RPC calls per minute during idle (target: 50% reduction)
- Sign request end-to-end latency (target: 10% improvement)
- Task count growth over time (should be stable)
- CPU usage during idle (target: 30% reduction)

---

## Dependencies to Add

```toml
[dependencies]
tokio-util = { version = "0.7", features = ["sync"] }  # For CancellationToken
parking_lot = "0.12"  # Optional: faster mutexes
```

---

## References

- [Tokio Best Practices](https://tokio.rs/tokio/topics/bridging)
- [Async Rust Book](https://rust-lang.github.io/async-book/)
- [tokio-util docs](https://docs.rs/tokio-util/)
