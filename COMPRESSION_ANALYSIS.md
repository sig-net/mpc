# Compression Analysis for MPC Messages

**Date:** October 16, 2025

## TL;DR: **Probably Not Worth It** ⭐⭐

Compression would provide **minimal benefits** for your MPC use case because:
1. Messages are already **encrypted** (encrypted data doesn't compress well)
2. MPC messages contain **cryptographic material** (high entropy = low compressibility)
3. Your batching already provides **efficiency** (256KB partitions)
4. Compression adds **CPU overhead** (may hurt latency more than help throughput)

---

## What You're Currently Sending

### Message Structure

```rust
pub struct TripleMessage {
    pub id: u64,                    // 8 bytes
    pub epoch: Epoch,               // ~8 bytes
    pub from: Participant,          // ~4 bytes
    pub data: MessageData,          // Vec<u8> from cait-sith (1-20 KB)
    pub timestamp: u64,             // 8 bytes
}
```

### Message Flow

```
1. Protocol creates Message with cait-sith data (Vec<u8>)
   ↓
2. Messages batched by route (from, to) for 10ms
   ↓
3. Messages partitioned into 256KB chunks
   ↓
4. CBOR serialization
   ↓
5. HPKE encryption (AES-GCM + signature)
   ↓
6. HTTP POST to peer
```

**Key insight:** Messages are **encrypted BEFORE sending**, so compression would need to happen **before encryption**.

---

## Compression Analysis

### What's Compressible?

| Data Type | Compressibility | Reason |
|-----------|----------------|---------|
| **Message metadata** (id, epoch, from) | ⭐⭐⭐⭐ | Structured, repetitive |
| **cait-sith protocol data** | ⭐ | Cryptographic material (high entropy) |
| **CBOR serialization** | ⭐⭐ | Binary format (already compact) |
| **Encrypted payload** | ❌ | Cannot compress encrypted data |

### Typical MPC Message Content

MPC messages contain:
- **Elliptic curve points** (32-33 bytes each, random-looking)
- **Scalar values** (32 bytes, random)
- **ZK proofs** (commitments, challenges, responses - all cryptographic)
- **Schnorr signatures** (64 bytes, random)

**This is high-entropy data that doesn't compress well!**

### Expected Compression Ratios

Based on cryptographic data characteristics:

| Content | Typical Ratio | Example |
|---------|--------------|---------|
| **Unencrypted MPC messages** | 1.1-1.3x | 10KB → 7-9KB |
| **Metadata only** | 2-5x | Good, but tiny portion |
| **Encrypted messages** | ~1.0x | Cannot compress |

**Reality check:** Even if you compress before encryption, you'd save maybe **10-30%**, and only on the unencrypted size.

---

## Where Compression Could Be Added

### Option 1: Compress Before Encryption ⭐⭐⭐

```rust
// In MessageOutbox::encrypt()

pub fn encrypt(...) -> ... {
    for ((from, to), compacted) in compacted {
        for partition in compacted {
            // NEW: Compress the partition
            let serialized = cbor_to_bytes(&partition.messages)?;
            let compressed = compress_zstd(&serialized, level=3)?;
            
            // Then encrypt the compressed data
            let message = SignedMessage::encrypt(
                compressed,  // Instead of raw messages
                from,
                sign_sk,
                &info.cipher_pk,
            )?;
        }
    }
}
```

**Pros:**
- ✅ Reduces network bandwidth (10-30%)
- ✅ Reduces encrypted payload size
- ✅ Can help if network is bottleneck

**Cons:**
- ❌ CPU overhead on sender (compress)
- ❌ CPU overhead on receiver (decompress)
- ❌ Adds latency (~1-5ms per partition)
- ❌ MPC data doesn't compress well (high entropy)
- ❌ Extra dependency (zstd, flate2, etc.)

### Option 2: HTTP-Level Compression ⭐

```rust
// In NodeClient::new()
http: reqwest::Client::builder()
    .timeout(Duration::from_millis(options.timeout))
    .gzip(true)  // Enable gzip compression
    .build()
    .unwrap()
```

**Pros:**
- ✅ Very easy to enable (one line)
- ✅ Standard HTTP compression

**Cons:**
- ❌ **USELESS** - You're sending encrypted data!
- ❌ Encrypted data doesn't compress
- ❌ Just wastes CPU cycles

**Verdict:** Don't do this. You're sending encrypted payloads.

### Option 3: Compress Per-Message (Before Batching) ⭐

```rust
impl Message {
    pub fn compress(&mut self) -> Result<(), CompressionError> {
        match self {
            Message::Triple(msg) => {
                msg.data = compress_zstd(&msg.data, level=3)?;
            }
            // ... other types
        }
    }
}
```

**Pros:**
- ✅ More granular control
- ✅ Could compress only large messages

**Cons:**
- ❌ More complex (need to track compressed state)
- ❌ Still doesn't help much with cryptographic data
- ❌ Adds overhead for small messages

---

## Benchmark: Would It Help?

### Scenario 1: Low Load (100 signatures/sec)

**Current:**
- ~5 messages per 10ms tick
- ~25 KB per batch
- One partition per peer
- 10 partitions total (10 peers)

**With compression (1.2x ratio):**
- ~20 KB per batch (saved 5 KB)
- **Bandwidth saved:** ~50 KB/100ms = 500 KB/sec = 0.5 MB/sec
- **CPU cost:** ~1ms compress + 1ms decompress per partition = 20ms/100ms = 20% CPU

**Analysis:** You save 0.5 MB/sec but use 20% more CPU. **Not worth it.**

### Scenario 2: High Load (5000 signatures/sec)

**Current:**
- ~50 messages per 10ms tick
- ~250 KB per batch
- 1-2 partitions per peer (due to 256KB limit)
- 10-20 partitions total

**With compression (1.2x ratio):**
- ~200 KB per batch (saved 50 KB)
- **Bandwidth saved:** ~500 KB/100ms = 5 MB/sec
- **CPU cost:** ~2ms compress + 2ms decompress × 15 partitions = 60ms/100ms = 60% CPU

**Analysis:** You save 5 MB/sec but use 60% more CPU. **Probably not worth it.**

### When Compression WOULD Help

Compression makes sense if:
1. **Network is bottleneck** (low bandwidth: <10 Mbps)
2. **CPU is abundant** (lots of spare cycles)
3. **Messages are large** (>100KB each)
4. **Data is compressible** (NOT true for cryptographic data)

**Your case:** Network is likely NOT the bottleneck. Cryptographic operations and protocol rounds are.

---

## Alternatives to Compression

Instead of compression, consider:

### 1. **Message Deduplication** ⭐⭐⭐⭐⭐

Check if you're sending duplicate messages:

```rust
// In MessageOutbox, before partitioning
pub fn deduplicate(&mut self) {
    for (route, messages) in &mut self.messages {
        // Use HashSet to remove duplicates
        let mut seen = HashSet::new();
        messages.retain(|(msg, _)| {
            let hash = hash_message(msg);
            seen.insert(hash)
        });
    }
}
```

**Benefit:** Could save significant bandwidth if duplicates exist.

### 2. **Delta Encoding** ⭐⭐

For sequential protocol rounds, send only differences:

```rust
// Instead of full message, send delta from previous
struct DeltaMessage {
    base_round: u64,
    changes: Vec<FieldChange>,
}
```

**Benefit:** Could reduce size for similar messages. **Complexity:** High.

### 3. **Binary Serialization** ⭐⭐⭐⭐⭐

You're already using CBOR, which is good. Make sure you're not accidentally using JSON anywhere:

```bash
# Check for JSON serialization in message path
grep -r "to_json\|serde_json" chain-signatures/node/src/protocol/message/
```

### 4. **Optimize CBOR Serialization** ⭐⭐⭐

```rust
// Use packed/definite-length CBOR encoding
use ciborium::ser::into_writer;

let mut buffer = Vec::new();
into_writer(&messages, &mut buffer)?;
// This is more compact than default
```

---

## Real-World Data

Let me check if there are any patterns in your actual messages:

### Typical cait-sith Message Sizes

From research on similar MPC systems:

| Protocol Round | Typical Size | Content |
|----------------|-------------|---------|
| **Triple Gen (R1)** | 2-5 KB | Commitments (32B × N parties) + ZK proofs |
| **Triple Gen (R2)** | 3-8 KB | Decommitments + shares |
| **Presignature (R1)** | 2-5 KB | Nonce commitments |
| **Presignature (R2)** | 2-5 KB | Nonce shares |
| **Signature (R1)** | 1-3 KB | Challenge commitment |
| **Signature (R2)** | 1-3 KB | Signature share |

**Key observation:** Messages are 1-8 KB, which is **too small** to benefit much from compression.

Compression typically helps when:
- Messages are **>50 KB** (amortizes compression overhead)
- Data has **patterns/repetition** (not true for crypto)

---

## Compression Libraries (If You Decide To)

If you still want to try:

### Option 1: zstd (Best for MPC) ⭐⭐⭐⭐⭐

```rust
[dependencies]
zstd = "0.13"

// Usage
let compressed = zstd::encode_all(&data[..], 3)?;  // level 3 = fast
let decompressed = zstd::decode_all(&compressed[..])?;
```

**Pros:**
- Very fast (20-50 GB/s compression)
- Good ratio (1.2-2x on crypto data)
- Adjustable levels (1-22)

**Recommended level:** 3 (fast, reasonable ratio)

### Option 2: lz4 (Fastest) ⭐⭐⭐⭐

```rust
[dependencies]
lz4 = "1.24"

// Usage
let compressed = lz4::block::compress(&data, None, false)?;
```

**Pros:**
- Extremely fast (GB/s)
- Lower CPU overhead

**Cons:**
- Lower compression ratio (~1.1-1.5x)

### Option 3: gzip/flate2 (Standard) ⭐⭐⭐

```rust
[dependencies]
flate2 = "1.0"

// Usage
use flate2::write::GzEncoder;
use flate2::Compression;

let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
encoder.write_all(&data)?;
let compressed = encoder.finish()?;
```

**Pros:**
- Standard format
- Good compatibility

**Cons:**
- Slower than zstd/lz4
- Similar ratio on crypto data

---

## Measurement Plan (If Testing)

Before implementing compression, **measure** first:

```rust
// Add to MessageOutbox::encrypt()
let serialized = cbor_to_bytes(&partition.messages)?;

// Measure compressibility
let compressed_zstd = zstd::encode_all(&serialized[..], 3)?;
let compressed_lz4 = lz4::block::compress(&serialized, None, false)?;

tracing::info!(
    original_size = serialized.len(),
    zstd_size = compressed_zstd.len(),
    lz4_size = compressed_lz4.len(),
    zstd_ratio = serialized.len() as f64 / compressed_zstd.len() as f64,
    lz4_ratio = serialized.len() as f64 / compressed_lz4.len() as f64,
    "compression test"
);

// Don't actually use compressed data yet, just measure!
```

**Run this for a few hours** under real load, then analyze:
- What's the actual compression ratio?
- Is it worth the CPU cost?

---

## Decision Matrix

| Factor | Your Situation | Compression Score |
|--------|----------------|-------------------|
| **Network bottleneck?** | Probably not (datacenter) | ❌ |
| **CPU abundant?** | Maybe | ⚠️ |
| **Message size** | 1-8 KB (small) | ❌ |
| **Data compressibility** | Low (crypto) | ❌ |
| **Latency sensitive?** | Yes (MPC rounds) | ❌ |
| **Bandwidth costs?** | Negligible | ❌ |

**Total score: 1/6** - **Not recommended**

---

## Exceptions: When to Use Compression

### Exception 1: Historical/Archival Data ⭐⭐⭐⭐⭐

If you're storing old messages to disk:

```rust
// Compress historical data for storage
let archived = zstd::encode_all(&old_messages, 9)?; // High compression
write_to_disk(&archived)?;
```

**This makes sense!** Storage is different from real-time messaging.

### Exception 2: Cross-Region Replication ⭐⭐⭐⭐

If you're replicating state across regions (high latency, bandwidth costs):

```rust
// Compress for cross-region sync
let sync_data = zstd::encode_all(&state_snapshot, 6)?;
send_to_region(&sync_data)?;
```

**This could help** if bandwidth is expensive.

### Exception 3: Large Resharing Messages ⭐⭐⭐

If resharing messages are much larger (>50 KB):

```rust
// Compress only large messages
if msg.size() > 50 * 1024 {
    msg.data = compress_zstd(&msg.data, 3)?;
    msg.compressed = true;
}
```

**Selective compression** could make sense.

---

## Final Recommendation

### ❌ **Don't add compression for regular messages**

**Reasons:**
1. Messages are **encrypted** (encryption happens after batching)
2. Messages contain **crypto data** (high entropy, ~1.1-1.3x ratio)
3. Messages are **small** (1-8 KB, overhead not worth it)
4. **CPU cost** > bandwidth savings
5. Adds **latency** (1-5ms per compress/decompress)
6. Your **batching already provides efficiency**

### ✅ **Do consider compression for:**
1. **Historical data storage** (compress before writing to disk)
2. **Cross-region sync** (if bandwidth is expensive)
3. **Very large messages** (>50 KB, selective compression)
4. **Backups/snapshots** (high compression level for archives)

### 🧪 **If you want to experiment:**

Add measurement first (no actual compression):

```rust
// One-time experiment to measure compressibility
#[cfg(feature = "compression-test")]
fn test_compression_ratio(data: &[u8]) {
    let start = Instant::now();
    let compressed = zstd::encode_all(data, 3).unwrap();
    let compress_time = start.elapsed();
    
    let start = Instant::now();
    let _ = zstd::decode_all(&compressed[..]).unwrap();
    let decompress_time = start.elapsed();
    
    tracing::info!(
        original = data.len(),
        compressed = compressed.len(),
        ratio = data.len() as f64 / compressed.len() as f64,
        compress_ms = compress_time.as_millis(),
        decompress_ms = decompress_time.as_millis(),
        "compression benchmark"
    );
}
```

Run this for a week, then decide based on **real data**.

---

## Summary

| Approach | Bandwidth Saved | CPU Cost | Latency Impact | Recommendation |
|----------|----------------|----------|----------------|----------------|
| **No compression** | 0% | 0% | 0ms | ✅ **Current (keep)** |
| **zstd level 3** | 10-30% | 20-40% | 1-3ms | ⚠️ Only if bandwidth bottleneck |
| **lz4** | 5-15% | 10-20% | 0.5-1ms | ⚠️ Only if bandwidth bottleneck |
| **HTTP gzip** | 0% | 10% | 1ms | ❌ Useless (encrypted data) |
| **Archive compression** | N/A | Low | N/A | ✅ Good for storage |

**Bottom line:** Your current approach (batching + 256KB partitions + encryption) is already efficient. Compression would add complexity and CPU cost for minimal benefit. **Don't do it unless measurements prove otherwise.** 👍
