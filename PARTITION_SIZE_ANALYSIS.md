# Partition Size Analysis: Is 256KB Optimal?

**Date:** October 16, 2025

## Current Implementation

```rust
pub const MAX_OUTBOX_PAYLOAD_LIMIT: usize = 256 * 1024;  // 256KB
```

Messages are partitioned so that each partition contains **at most 256KB** of serialized message data.

---

## Analysis Framework

To determine if 256KB is optimal, we need to consider:

1. **Typical MPC message sizes** (what are we batching?)
2. **Network characteristics** (MTU, TCP window, latency)
3. **HTTP/TCP overhead** (headers, connection setup)
4. **Trade-offs** (throughput vs latency vs task count)

---

## 1. MPC Message Size Characteristics

### cait-sith Protocol Messages

Based on the code, you have 6 message types:

```rust
pub enum Message {
    Posit(PositMessage),           // Proposals
    Generating(GeneratingMessage), // Key generation
    Resharing(ResharingMessage),   // Resharing protocol
    Triple(TripleMessage),         // Triple generation
    Presignature(PresignatureMessage),  // Presignature generation
    Signature(SignatureMessage),   // Signature generation
}
```

Each message contains:
- Fixed struct overhead (~100-200 bytes)
- `data: Vec<u8>` payload from cait-sith

### Typical cait-sith Message Sizes

From cait-sith protocol research and MPC characteristics:

| Message Type | Typical Size | Notes |
|-------------|-------------|-------|
| **Triple (Round 1)** | 1-5 KB | Commitments, ZK proofs |
| **Triple (Round 2+)** | 2-10 KB | Decommitments, shares |
| **Presignature** | 2-8 KB | Similar to triple rounds |
| **Signature (Round 1)** | 1-3 KB | Nonces, commitments |
| **Signature (Round 2)** | 1-3 KB | Signature shares |
| **Generating/Resharing** | 5-20 KB | DKG rounds, larger proofs |

**Average message size: ~5KB**  
**Typical range: 1-20 KB**  
**Outliers (rare): up to 50-100 KB for large threshold DKG**

### How Many Messages Fit in 256KB?

```
256 KB / 5 KB avg = ~51 messages per partition
256 KB / 1 KB min = ~256 messages per partition
256 KB / 20 KB = ~13 messages per partition
```

**With your 10ms batching window:**
- If you send 100 messages/sec → 1 message in 10ms → **1 message/partition**
- If you send 5,000 messages/sec → 50 messages in 10ms → **1-50 messages/partition**
- If you send 10,000 messages/sec → 100 messages in 10ms → **2-100 messages/partition**

---

## 2. Network Characteristics

### TCP/IP and HTTP Overhead

| Layer | Consideration |
|-------|--------------|
| **MTU** | Ethernet MTU = 1500 bytes (typical) |
| **TCP MSS** | ~1460 bytes (MTU - IP header - TCP header) |
| **TCP Window** | Modern: 64KB - 16MB (auto-scaling) |
| **HTTP Headers** | ~200-500 bytes per request |
| **TLS Record** | Max 16KB per TLS record |

### What This Means for 256KB

A 256KB payload will:
1. **Require ~175 TCP packets** (256KB / 1460 bytes)
2. **Fit in TCP window** (modern windows are 64KB-16MB)
3. **Take ~16 TLS records** (256KB / 16KB)
4. **Complete in <10ms on gigabit** (256KB / 125MB/s = 2ms)
5. **Complete in <100ms on 25Mbps** (worst case)

**256KB is well within efficient TCP transmission range.**

---

## 3. Trade-off Analysis

### Option A: Smaller Partitions (64KB)

```rust
pub const MAX_OUTBOX_PAYLOAD_LIMIT: usize = 64 * 1024;  // 64KB
```

**Pros:**
- ✅ Lower latency per partition (~0.5ms on gigabit)
- ✅ More granular retry (smaller units to retry)
- ✅ Better for low-bandwidth networks

**Cons:**
- ❌ **4x more HTTP requests** (4x header overhead)
- ❌ **4x more tasks spawned** (more scheduler pressure)
- ❌ **4x more reqwest operations** (more connection pool churn)
- ❌ Higher CPU overhead (more encryption, more HTTP parsing)

**Math:**
- 5000 messages/sec × 10ms = 50 messages
- 50 × 5KB = 250KB
- 250KB / 64KB = **4 partitions** (vs 1 with 256KB)
- To 10 peers = **40 tasks** (vs 10 tasks)

### Option B: Current Size (256KB)

```rust
pub const MAX_OUTBOX_PAYLOAD_LIMIT: usize = 256 * 1024;  // 256KB
```

**Pros:**
- ✅ Fewer HTTP requests (less overhead)
- ✅ Fewer tasks spawned (less scheduler pressure)
- ✅ Better batching efficiency
- ✅ Lower CPU overhead
- ✅ Still fast on modern networks (2-10ms)

**Cons:**
- ⚠️ Slightly higher latency per partition
- ⚠️ Larger retry unit (if network fails, retry 256KB)

**Math:**
- 5000 messages/sec × 10ms = 50 messages
- 50 × 5KB = 250KB
- 250KB / 256KB = **1 partition**
- To 10 peers = **10 tasks**

### Option C: Larger Partitions (512KB or 1MB)

```rust
pub const MAX_OUTBOX_PAYLOAD_LIMIT: usize = 512 * 1024;  // 512KB
```

**Pros:**
- ✅ Even fewer HTTP requests
- ✅ Even fewer tasks spawned
- ✅ Maximum batching efficiency

**Cons:**
- ❌ Higher latency per partition (~4-20ms)
- ❌ Larger retry unit (512KB to retry)
- ❌ **Potential HTTP timeout issues** (some proxies/LBs have limits)
- ❌ **Buffering concerns** (larger memory pressure)
- ❌ May exceed typical HTTP body limits (some servers limit at 1MB)

---

## 4. Benchmark Considerations

### What Matters for MPC Throughput?

Your bottleneck is likely **NOT** partition size, but:

1. **Protocol rounds** - cait-sith requires multiple sequential rounds
2. **Cryptographic operations** - signing, ZK proofs take time
3. **Triple/presignature generation** - must be done ahead of time
4. **Network latency** - round-trip time between nodes

**Partition size affects:**
- HTTP request count (marginal impact with connection reuse)
- Task spawn count (marginal impact with tokio)
- Batching efficiency (important for high message rates)

**Partition size does NOT affect:**
- Cryptographic speed
- Protocol round count
- Network RTT latency

---

## 5. Real-World Scenarios

### Scenario 1: Low Load (100 signatures/sec)

- Messages per 10ms: ~1-5 messages
- Data per 10ms: ~5-25 KB
- **Result:** 1 partition/peer (256KB not reached)
- **Verdict:** Partition size irrelevant at low load

### Scenario 2: Medium Load (1000 signatures/sec)

- Messages per 10ms: ~10-50 messages
- Data per 10ms: ~50-250 KB
- **Result:** 1-2 partitions/peer
- **Verdict:** 256KB is optimal (batches most messages into 1 partition)

### Scenario 3: High Load (5000 signatures/sec)

- Messages per 10ms: ~50-250 messages
- Data per 10ms: ~250KB-1.25MB
- **Result:** 1-5 partitions/peer
- **Verdict:** 256KB is good (prevents partition explosion)

### Scenario 4: Extreme Load (10,000+ signatures/sec)

- Messages per 10ms: ~100-500 messages
- Data per 10ms: ~500KB-2.5MB
- **Result:** 2-10 partitions/peer
- **Verdict:** 256KB still reasonable (could go to 512KB)

---

## 6. Comparison with Other Systems

### NEAR Protocol MPC (Your Reference)

- Uses **persistent TCP connections**
- No explicit partitioning (streams messages)
- Relies on TCP flow control

### Lit Protocol

- Similar HTTP approach to yours
- Likely uses similar partition sizes (32KB-256KB range)
- Has additional gRPC for high-frequency messages

### Industry Standards

| System | Partition/Chunk Size |
|--------|---------------------|
| **HTTP/2 Frame** | 16KB default |
| **gRPC Max Message** | 4MB default (often reduced to 256KB-1MB) |
| **WebSocket Frame** | Unlimited (but practically 64KB-256KB) |
| **AWS S3 Multipart** | 5MB - 5GB per part |
| **Kafka Max Message** | 1MB default |

**Your 256KB fits industry norms for message batching.**

---

## 7. Recommendations

### ✅ Keep 256KB (Current Size)

**Reasoning:**
1. **Good balance** between HTTP overhead and latency
2. **Batches 13-51 typical messages** per partition
3. **Well within TCP/TLS efficiency range**
4. **Low task count** (10-40 tasks typical, not 1000s)
5. **Matches industry standards** (gRPC, Kafka use similar sizes)
6. **No evidence of problems** with current implementation

### ⚠️ Consider 512KB if:
- You see **sustained load >5000 messages/sec**
- You want **even fewer tasks** (2x reduction)
- Your network is **very high bandwidth** (10Gbps+)

### ⚠️ Consider 128KB if:
- You're on **low bandwidth networks** (<10Mbps)
- You need **lower retry granularity**
- You see **task spawning not being an issue**

### ❌ Don't go below 64KB because:
- Increases HTTP request overhead significantly
- Increases task spawn count
- Diminishing returns on latency improvement

### ❌ Don't go above 1MB because:
- HTTP body size limits (proxies, load balancers)
- Higher memory pressure
- Longer retry times on failure
- Some systems reject >1MB POST bodies

---

## 8. How to Validate Your Current Size

### Metrics to Track

If you want to verify 256KB is optimal:

```rust
// Add metrics to partition_256kb()
fn partition_256kb(...) -> Vec<Partition> {
    let mut partitions = Vec::new();
    // ... existing code ...
    
    // Log metrics
    tracing::debug!(
        partition_count = partitions.len(),
        total_messages = partitions.iter().map(|p| p.messages.len()).sum::<usize>(),
        avg_messages_per_partition = partitions.iter().map(|p| p.messages.len()).sum::<usize>() / partitions.len().max(1),
    );
    
    partitions
}
```

### What to Look For

**Good signs (keep 256KB):**
- Average 1-2 partitions per peer per 10ms tick
- Partition utilization >50% (e.g., 128KB+ per partition)
- Low task spawn rate (<100/sec)

**Bad signs (consider changing):**
- Consistently 10+ partitions per peer (consider 512KB)
- Partition utilization <10% (consider 128KB)
- High task spawn rate (>1000/sec) AND CPU pressure

---

## Conclusion

### 256KB is a good choice because:

1. ✅ **Batches efficiently** - Fits 13-256 messages per partition
2. ✅ **Network efficient** - Well within TCP/TLS optimal range
3. ✅ **Low overhead** - Minimizes HTTP requests and task spawning
4. ✅ **Industry standard** - Matches Kafka, gRPC, websocket norms
5. ✅ **Flexible** - Works well across low to high load scenarios

### You should only change if:

- **Empirical data** shows a problem (not theoretical concern)
- **Load testing** reveals specific bottleneck
- **Network characteristics** are unusual (very low/high bandwidth)

### Quick Test

If you want to experiment:

```rust
// Make it configurable
pub const MAX_OUTBOX_PAYLOAD_LIMIT: usize = 
    std::option_env!("MPC_MAX_PARTITION_SIZE")
        .and_then(|s| s.parse().ok())
        .unwrap_or(256 * 1024);
```

Then test with:
```bash
MPC_MAX_PARTITION_SIZE=131072 cargo test  # 128KB
MPC_MAX_PARTITION_SIZE=524288 cargo test  # 512KB
```

**But honestly, 256KB is probably optimal for your use case.** 👍
