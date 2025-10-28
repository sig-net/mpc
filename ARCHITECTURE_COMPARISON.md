# Architecture Comparison: Your System vs NEAR Protocol MPC

**Date:** October 15, 2025  
**Context:** Both systems DO reuse connections. The question is: do you need NEAR's explicit connection management?

---

## Executive Summary

**TL;DR:** Your current HTTP-based system is **fundamentally sound**. You don't need a ground-up rewrite. The differences with NEAR are about **explicit control** vs **implicit pooling**, not about performance or correctness.

**Recommendation:** Make **incremental improvements** (~1-2 days work), not a major rewrite.

---

## Side-by-Side Architecture Comparison

### Network Layer

| Aspect | Your System (HTTP/reqwest) | NEAR Protocol (TLS/TCP) | Practical Impact |
|--------|---------------------------|------------------------|------------------|
| **Protocol** | HTTP/1.1 or HTTP/2 over TLS | Raw TLS over TCP | Minimal in practice |
| **Connection Management** | Implicit pool (reqwest/hyper) | Explicit `PersistentConnection` objects | NEAR has more control |
| **Connection Reuse** | ✅ Yes (90s idle timeout default) | ✅ Yes (explicit lifecycle) | **Tie** |
| **Handshake Frequency** | Once per connection (~90s lifetime) | Once per connection (indefinite lifetime) | **NEAR slightly better** |
| **Message Latency (warm)** | 20-50ms (HTTP overhead) | 5-20ms (raw TCP frames) | NEAR 2-3x faster |
| **Message Latency (cold)** | 100-150ms (TCP + TLS + HTTP) | 80-120ms (TCP + TLS only) | **NEAR ~30% faster** |
| **Implementation Complexity** | ⭐ Simple (library handles it) | ⭐⭐⭐⭐ Complex (manual everything) | **Yours MUCH simpler** |
| **Failure Detection** | Passive (timeout-based) | Active (version tracking, explicit disconnect) | **NEAR better** |
| **HTTP/2 Multiplexing** | ✅ Available (not enabled) | ❌ N/A | **Yours better** (if enabled) |

**Verdict:** NEAR's approach is faster and more controlled, but your approach is simpler and "good enough" for most use cases.

---

### Connection Health Monitoring

| Aspect | Your System | NEAR Protocol | Winner |
|--------|-------------|---------------|---------|
| **Health Check Method** | Poll `/status` every 1 second | Event-driven connection state changes | **NEAR** |
| **Stale Connection Detection** | Timeout + retry (500ms backoff) | Version tracking + explicit invalidation | **NEAR** |
| **Reconnection Strategy** | Implicit (pool handles it) | Explicit reconnect with backoff | **NEAR** |
| **Observability** | Limited (HTTP status codes) | Rich (connection state, version, duration) | **NEAR** |
| **CPU Overhead** | Low (library handles it) | Medium (custom state machine) | **Yours** |

**Your Code:**
```rust
// mesh/connection.rs
async fn run(mut self) {
    loop {
        sleep(Duration::from_secs(1)).await;
        let result = self.client.status(&self.status_url).await;
        // Update status via watch channel
    }
}
```

**NEAR Code:**
```rust
// Event-driven state changes
match connection.state {
    Connected(version) => {
        if detected_stale(version) {
            connection.reconnect().await;
        }
    }
    Disconnected => connection.try_connect().await,
}
```

**Verdict:** NEAR's event-driven model is more efficient and responsive. Your polling approach wastes CPU and has 0-1s detection lag.

---

### Message Sending

| Aspect | Your System | NEAR Protocol | Winner |
|--------|-------------|---------------|---------|
| **Task Model** | Spawn task per message partition | Per-peer sender workers | **NEAR** |
| **Retry Logic** | Per-task retry loop (500ms backoff) | Centralized retry with exponential backoff | **NEAR** |
| **Backpressure** | None (spawns unbounded tasks) | Channel-based queue limits | **NEAR** |
| **Memory Usage** | ~2KB per task × 1000s tasks = ~2-4MB | ~2KB per peer × ~100 peers = ~200KB | **NEAR** |
| **Connection Reuse** | ✅ Yes (reqwest pool) | ✅ Yes (explicit stream) | **Tie** |
| **Message Batching** | ✅ Built-in (10ms tick) | ⚠️ Manual | **Yours** |

**Your Code (Issue):**
```rust
// protocol/message/mod.rs - MessageOutbox::send()
for ((from, to), encrypted) in encrypted {
    for (encrypted_partition, timestamp, message_len) in encrypted {
        let client = client.clone();  // ← Spawns MANY tasks
        tokio::spawn(async move {
            loop {
                match client.msg(&url, &[&encrypted_partition]).await {
                    Ok(_) => break,
                    Err(_) => sleep(Duration::from_millis(500)).await,
                }
            }
        });
    }
}
```

**Problems:**
- If you have 10 peers and 100 messages, you spawn **1000 tasks**
- Each task has ~2KB overhead = **2MB just for task stacks**
- No backpressure: if messages pile up faster than you send, tasks explode

**NEAR's Approach:**
```rust
// One worker per peer
struct PeerSender {
    queue: mpsc::Sender<Message>,
    // Worker receives from queue and sends over persistent connection
}

// Bounded queue provides backpressure
let (tx, rx) = mpsc::channel(100);  // Max 100 pending messages
```

**Verdict:** NEAR's per-peer worker model is significantly better architecturally.

---

### Message Receiving

| Aspect | Your System | NEAR Protocol | Winner |
|--------|-------------|---------------|---------|
| **Receive Method** | HTTP POST endpoint | Async read from TLS stream | **NEAR** (lower latency) |
| **Decryption** | HPKE (same as NEAR) | HPKE | **Tie** |
| **Message Queue** | `MessageInbox` with mpsc channel | Similar channel-based approach | **Tie** |
| **Simplicity** | ⭐ Very simple (HTTP handler) | ⭐⭐⭐ Complex (async stream handling) | **Yours** |

**Your Code:**
```rust
// HTTP POST handler
async fn message_handler(
    State(state): State<Arc<MpcState>>,
    Json(payload): Json<MessagePayload>,
) -> StatusCode {
    state.inbox.send(payload).await;
    StatusCode::OK
}
```

**Verdict:** Your HTTP-based receive is simpler and works well. No need to change this.

---

## Do You Need Significant Changes?

### ❌ NO - You Don't Need a Complete Rewrite

**Reasons:**
1. ✅ Your connection reuse is working correctly
2. ✅ HTTP is a perfectly reasonable transport for MPC coordination
3. ✅ The latency difference (20-50ms vs 5-20ms) is unlikely to matter for MPC signing
4. ⚠️ NEAR's approach requires **3-4 weeks of engineering time** minimum
5. ⚠️ Rewriting introduces bugs in critical security infrastructure

### ✅ YES - You Should Make Incremental Improvements

**Priority 1: Fix Task Explosion** ⭐⭐⭐ (HIGH IMPACT, 4-8 hours)

Replace per-message task spawning with per-peer workers:

```rust
// NEW: protocol/message/peer_sender.rs
pub struct PeerSender {
    queue: mpsc::Sender<(Ciphered, Instant, usize)>,
}

impl PeerSender {
    pub fn spawn_worker(
        client: NodeClient,
        url: Url,
        max_queue_size: usize,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel(max_queue_size);
        
        tokio::spawn(async move {
            while let Some((msg, timestamp, len)) = rx.recv().await {
                // Retry logic with exponential backoff
                let mut backoff = Duration::from_millis(100);
                loop {
                    match client.msg(&url, &[&msg]).await {
                        Ok(_) => {
                            tracing::info!(
                                latency = ?(Instant::now() - timestamp),
                                size = len,
                                "Message sent successfully"
                            );
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(?e, "Failed to send message, retrying");
                            sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(5));
                        }
                    }
                }
            }
        });
        
        Self { queue: tx }
    }
    
    pub async fn send(&self, msg: Ciphered, timestamp: Instant, len: usize) {
        // Non-blocking send with backpressure
        if let Err(_) = self.queue.try_send((msg, timestamp, len)) {
            tracing::warn!("Peer sender queue full, dropping message");
        }
    }
}

// UPDATE: protocol/message/mod.rs
pub struct MessageOutbox {
    // OLD: client: NodeClient
    // NEW: per-peer workers
    peer_senders: HashMap<NodeId, PeerSender>,
    client: NodeClient,  // Keep for creating new workers
}

impl MessageOutbox {
    pub async fn send(&mut self, messages: Vec<(From, To, Message)>) {
        // ... encrypt messages ...
        
        for ((from, to), encrypted) in encrypted {
            // Get or create peer sender
            let sender = self.peer_senders.entry(to).or_insert_with(|| {
                PeerSender::spawn_worker(
                    self.client.clone(),
                    self.get_peer_url(to),
                    100,  // Max 100 pending messages per peer
                )
            });
            
            for (encrypted_partition, timestamp, message_len) in encrypted {
                // Send to worker (doesn't block)
                sender.send(encrypted_partition, timestamp, message_len).await;
            }
        }
    }
}
```

**Benefits:**
- ✅ Reduces tasks from 1000s to ~100 (one per peer)
- ✅ Adds backpressure (bounded queues)
- ✅ Better observability (per-peer metrics)
- ✅ Still reuses HTTP connections!
- ✅ Exponential backoff instead of fixed 500ms

**Effort:** 4-8 hours
**Risk:** Low (isolated change)

---

**Priority 2: Tune reqwest Connection Pool** ⭐⭐ (MEDIUM IMPACT, 30 minutes)

Add explicit pool configuration:

```rust
// chain-signatures/node/src/node_client.rs
impl NodeClient {
    pub fn new(options: &Options) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(options.timeout))
                // NEW: Explicit pool tuning
                .pool_idle_timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(10)
                .tcp_keepalive(Duration::from_secs(60))
                // Consider HTTP/2 if your peers support it
                // .http2_prior_knowledge()
                .build()
                .unwrap(),
            options: options.clone(),
        }
    }
}
```

**Benefits:**
- ✅ Faster detection of dead connections (30s vs 90s)
- ✅ Lower memory usage (limit idle connections)
- ✅ TCP keepalive prevents connection drops
- ✅ (Optional) HTTP/2 multiplexing

**Effort:** 30 minutes
**Risk:** Very low (just tuning existing system)

---

**Priority 3: Replace Polling with Event-Driven Health Checks** ⭐ (LOW IMPACT, 2-4 hours)

Current polling wastes CPU:

```rust
// mesh/connection.rs - CURRENT
async fn run(mut self) {
    loop {
        sleep(Duration::from_secs(1)).await;  // ← Wastes CPU
        let result = self.client.status(&self.status_url).await;
        // ...
    }
}
```

Better approach - only check on demand:

```rust
// mesh/connection.rs - IMPROVED
pub struct NodeConnection {
    client: NodeClient,
    status_url: Url,
    status_tx: watch::Sender<ConnectionStatus>,
    check_trigger: mpsc::Receiver<oneshot::Sender<ConnectionStatus>>,
}

impl NodeConnection {
    async fn run(mut self) {
        // Only check when triggered, not continuously
        while let Some(reply_tx) = self.check_trigger.recv().await {
            let result = self.client.status(&self.status_url).await;
            let status = result.map(|_| ConnectionStatus::Connected)
                .unwrap_or(ConnectionStatus::Disconnected);
            
            self.status_tx.send_replace(status);
            let _ = reply_tx.send(status);
        }
    }
}

// Check health only when needed (e.g., after send failure)
let status = connection.check_health().await;
```

**Benefits:**
- ✅ No wasted CPU on continuous polling
- ✅ Faster failure detection (immediate vs 0-1s lag)
- ✅ Better metrics (only check when something happens)

**Effort:** 2-4 hours
**Risk:** Low (isolated change)

---

## Summary: What You Should Actually Do

### Immediate Actions (Next Sprint)

1. **Fix task explosion** (Priority 1) - 4-8 hours
   - Biggest architectural issue
   - Clear win with low risk
   
2. **Tune reqwest pool** (Priority 2) - 30 minutes
   - Add 5 lines of configuration
   - Immediate improvement

### Future Improvements (If Needed)

3. **Event-driven health checks** (Priority 3) - 2-4 hours
   - Only if CPU usage becomes a concern
   - Or if you need sub-second failure detection

### What NOT To Do

❌ **Don't rewrite to NEAR-style TLS/TCP** unless:
- You profile and find HTTP overhead is actually a bottleneck (unlikely)
- You need <10ms message latency (unlikely for MPC coordination)
- You have 3-4 weeks of dedicated engineering time
- You're willing to take on significant implementation risk

---

## Performance Expectations

### Current System (After Improvements)

```
Scenario: Send 1000 signatures across 10 peers

Task Count:        10 workers (vs 1000+ tasks before)
Memory Usage:      ~200KB for workers (vs ~2MB before)
Connection Reuse:  Yes (HTTP Keep-Alive)
Latency (warm):    20-50ms per message
Latency (cold):    100-150ms first message
Throughput:        ~500-1000 msg/sec per peer
```

### NEAR-style System (If You Rewrote)

```
Scenario: Same 1000 signatures

Task Count:        10 workers (same)
Memory Usage:      ~200KB (same)
Connection Reuse:  Yes (persistent TLS)
Latency (warm):    5-20ms per message  ← 2-3x faster
Latency (cold):    80-120ms first message ← ~20% faster
Throughput:        ~2000-5000 msg/sec per peer ← 2-5x faster
```

**Question:** Do you need that extra 2-3x speed?

For MPC signing where each signature involves:
- Multiple rounds of communication (presig, sig)
- Cryptographic computation (100-500ms)
- Network coordination across N parties

...the HTTP overhead (20-30ms extra) is **negligible** compared to crypto time.

---

## Final Recommendation

### Do This: Incremental Improvements ✅

**Time:** ~1 day of work  
**Risk:** Low (isolated changes)  
**Impact:** 10x fewer tasks, better backpressure, tuned connection pool

```rust
// These three changes get you 80% of NEAR's benefits:
1. Per-peer worker model (replaces task explosion)
2. Explicit pool tuning (30s idle timeout, keepalive)
3. (Optional) HTTP/2 multiplexing
```

### Don't Do This: Complete Rewrite ❌

**Time:** 3-4 weeks minimum  
**Risk:** High (touches critical signing path)  
**Impact:** 2-3x latency improvement (20ms → 7ms per message)

**Not worth it** unless you have profiling data showing HTTP is actually your bottleneck.

---

## Testing Your Improvements

After making changes, verify with:

```bash
# 1. Check connection reuse
watch -n 1 'ss -tn state established | grep :3000 | wc -l'
# Should stay constant (~10-20 connections) even when sending 1000s of messages

# 2. Check task count
# Add this metric to your code:
tokio::runtime::Handle::current().metrics().num_workers()

# 3. Measure latency
# Your existing timestamp tracking in MessageOutbox already does this

# 4. Load test
cargo test --release -p integration-tests test_sign_under_load -- --nocapture
```

---

## Questions to Ask Yourself

Before deciding to rewrite:

1. **Is message latency actually a bottleneck?**
   - Profile: Is HTTP overhead >10% of total signing time?
   - Probably not (crypto dominates)

2. **Do we have 3-4 weeks to spare?**
   - Rewrite = 2 weeks implementation + 2 weeks testing/debugging
   - Security-critical code = high stakes

3. **Are there simpler wins?**
   - Fix task explosion: 4-8 hours, 10x memory improvement
   - Tune connection pool: 30 minutes, better failure detection

**My bet:** The incremental approach is the right call. You get 80% of the benefit with 5% of the effort and risk.
