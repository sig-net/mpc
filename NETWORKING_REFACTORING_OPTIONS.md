# Networking/Mesh Refactoring Analysis

**Date:** October 16, 2025

## Current Architecture Assessment

### What You Have (Simplified View)

```
Protocol Layers (Triple/Presignature/Signature)
    ↓ (sends messages via MessageChannel::send())
MessageChannel (mpsc::Sender facade)
    ↓ (messages go to channel)
MessageOutbox::run() loop
    ├─ Receives from channel
    ├─ Accumulates for 10ms
    └─ Every 10ms tick:
        ├─ compact() → partition_256kb()
        ├─ encrypt()
        └─ send() → spawns task per partition
            └─ NodeClient::msg() → reqwest HTTP POST
```

### Complexity Points

1. **Two-layer message handling**: MessageChannel + MessageOutbox + MessageInbox
2. **Manual encryption/signing**: Each partition encrypted separately
3. **Per-partition task spawning**: Could be simplified
4. **Separate inbox/outbox loops**: Two tokio tasks per node
5. **Subscription system**: Complex routing for different message types
6. **Filter/idempotent checking**: LRU cache + filter for deduplication

---

## Refactoring Options

### Option 1: **Status Quo with Minimal Tweaks** ⭐⭐⭐⭐⭐

**What to do:**
Just add the connection pool tuning (5 minutes):

```rust
// In NodeClient::new()
http: reqwest::Client::builder()
    .timeout(Duration::from_millis(options.timeout))
    .pool_idle_timeout(Duration::from_secs(30))
    .pool_max_idle_per_host(10)
    .tcp_keepalive(Duration::from_secs(60))
    .build()
    .unwrap(),
```

**Pros:**
- ✅ Minimal risk
- ✅ Your architecture is already good
- ✅ Batching works well
- ✅ Partitioning is smart
- ✅ 5 minutes of work

**Cons:**
- ❌ None really

**Verdict:** **RECOMMENDED** - Don't fix what isn't broken.

---

### Option 2: **Consolidate Task Spawning** ⭐⭐⭐⭐

**What to do:**
Replace `tokio::spawn` per partition with `join_all`:

```rust
// Current: spawns N tasks
for ((_from, to), encrypted) in encrypted {
    for (encrypted_partition, timestamp, message_len) in encrypted {
        tokio::spawn(async move { /* retry loop */ });
    }
}

// Refactored: one spawn with structured concurrency
let futures: Vec<_> = encrypted
    .into_iter()
    .flat_map(|((_from, to), partitions)| {
        partitions.into_iter().map(move |(partition, timestamp, msg_len)| {
            let client = client.clone();
            let url = url.clone();
            async move {
                // retry loop here
            }
        })
    })
    .collect();

tokio::spawn(async move {
    futures::future::join_all(futures).await;
});
```

**Pros:**
- ✅ Single task instead of N tasks
- ✅ Easier to track completion
- ✅ Better structured concurrency
- ✅ Still concurrent HTTP requests

**Cons:**
- ⚠️ Slightly more complex code
- ⚠️ 1-2 hours of work

**Verdict:** Nice-to-have, but not critical.

---

### Option 3: **Merge MessageInbox and MessageOutbox** ⭐⭐⭐

**What to do:**
Combine inbox/outbox into single `MessageRouter` with one tokio task:

```rust
pub struct MessageRouter {
    // Current inbox fields
    inbox_rx: mpsc::Receiver<Ciphered>,
    subscribers: HashMap<...>,
    
    // Current outbox fields
    outbox_rx: mpsc::Receiver<SendMessage>,
    pending_messages: HashMap<MessageRoute, Vec<(Message, Instant)>>,
}

impl MessageRouter {
    pub async fn run(mut self, ...) {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        
        loop {
            tokio::select! {
                // Handle incoming encrypted messages
                Some(encrypted) = self.inbox_rx.recv() => {
                    self.handle_incoming(encrypted).await;
                }
                
                // Handle outgoing messages
                Some((msg, route)) = self.outbox_rx.recv() => {
                    self.pending_messages.entry(route).or_default().push(msg);
                }
                
                // Publish every 10ms
                _ = interval.tick() => {
                    self.publish_outgoing().await;
                }
            }
        }
    }
}
```

**Pros:**
- ✅ Single task instead of two
- ✅ Clearer ownership model
- ✅ Easier to reason about message flow
- ✅ Slightly less overhead

**Cons:**
- ⚠️ More complex tokio::select! block
- ⚠️ Harder to test inbox/outbox independently
- ⚠️ 4-8 hours of refactoring

**Verdict:** Worthwhile if you're already doing major refactoring, but not necessary.

---

### Option 4: **Abstract Network Layer** ⭐⭐⭐

**What to do:**
Create a trait for network transport:

```rust
#[async_trait]
pub trait NetworkTransport: Send + Sync {
    async fn send_encrypted(
        &self,
        to: &Participant,
        payload: &Ciphered,
    ) -> Result<(), NetworkError>;
    
    async fn broadcast_encrypted(
        &self,
        participants: &[Participant],
        payload: &Ciphered,
    ) -> Vec<Result<(), NetworkError>>;
}

pub struct HttpTransport {
    client: reqwest::Client,
    participants: Arc<RwLock<Participants>>,
}

#[async_trait]
impl NetworkTransport for HttpTransport {
    async fn send_encrypted(&self, to: &Participant, payload: &Ciphered) -> Result<(), NetworkError> {
        let info = self.participants.read().await.get(to)?;
        self.client.post(&info.url)
            .body(payload.clone())
            .send()
            .await?;
        Ok(())
    }
}
```

**Pros:**
- ✅ Testable with mock transport
- ✅ Could swap HTTP for gRPC later
- ✅ Cleaner separation of concerns

**Cons:**
- ❌ Adds abstraction layer
- ❌ More boilerplate
- ❌ 1-2 days of work
- ❌ Not necessarily better for your use case

**Verdict:** Overkill unless you plan to support multiple transport types.

---

### Option 5: **Switch to gRPC** ⭐⭐

**What to do:**
Replace HTTP with gRPC for node-to-node communication:

```protobuf
service MpcNode {
    rpc SendMessages(stream EncryptedMessage) returns (stream MessageAck);
    rpc GetState(StateRequest) returns (NodeState);
}

message EncryptedMessage {
    bytes payload = 1;
    int64 timestamp = 2;
    Participant from = 3;
}
```

**Pros:**
- ✅ Native streaming support
- ✅ Built-in connection pooling
- ✅ Better for high-frequency messages
- ✅ Protobuf is efficient

**Cons:**
- ❌ Major rewrite (1-2 weeks)
- ❌ More complex deployment (HTTP/2 required)
- ❌ Your current HTTP approach works fine
- ❌ Not clear it would improve performance
- ❌ Adds dependency on tonic/protobuf

**Verdict:** Not recommended. Your HTTP+batching is already efficient.

---

### Option 6: **Simplify Subscription System** ⭐⭐⭐⭐

**What to do:**
Your subscription system is complex:

```rust
// Current: manual routing per protocol type
triple: HashMap<TripleId, Subscriber<TripleMessage>>,
presignature: HashMap<PresignatureId, Subscriber<PresignatureMessage>>,
signature: HashMap<(SignId, PresignatureId), Subscriber<SignatureMessage>>,
```

Could simplify to:

```rust
pub struct MessageRouter {
    // Generic subscription by message type
    subscriptions: HashMap<TypeId, Vec<mpsc::Sender<Box<dyn Any + Send>>>>,
}

impl MessageRouter {
    pub async fn subscribe<T: Message + 'static>(&mut self) -> mpsc::Receiver<T> {
        let (tx, rx) = mpsc::channel(1024);
        let type_id = TypeId::of::<T>();
        self.subscriptions.entry(type_id).or_default().push(Box::new(tx));
        rx
    }
    
    async fn route_message(&mut self, msg: Message) {
        match msg {
            Message::Triple(m) => self.send_to_subscribers(m).await,
            Message::Presignature(m) => self.send_to_subscribers(m).await,
            // ...
        }
    }
}
```

**Pros:**
- ✅ Less boilerplate
- ✅ Type-safe subscriptions
- ✅ Easier to add new message types

**Cons:**
- ⚠️ More complex type handling
- ⚠️ Need to test type safety carefully
- ⚠️ 2-4 hours of work

**Verdict:** Nice cleanup, but low priority.

---

### Option 7: **Add Batch Send API** ⭐⭐⭐⭐

**What to do:**
Instead of individual `MessageChannel::send()`, add batch API:

```rust
impl MessageChannel {
    // Existing: one message at a time
    pub async fn send(&self, from: Participant, to: Participant, message: impl Into<Message>) {
        self.outgoing.send((message.into(), (from, to, Instant::now()))).await
    }
    
    // New: batch send
    pub async fn send_batch(&self, messages: Vec<(Participant, Participant, Message)>) {
        let now = Instant::now();
        for (from, to, msg) in messages {
            let _ = self.outgoing.send((msg, (from, to, now))).await;
        }
    }
    
    // New: broadcast to all participants
    pub async fn broadcast(&self, from: Participant, message: impl Into<Message> + Clone) {
        // Send to all participants in one go
    }
}
```

**Pros:**
- ✅ Reduces channel overhead for bulk sends
- ✅ More explicit batching control
- ✅ Better for signature generation (send to all)

**Cons:**
- ⚠️ API change required
- ⚠️ Need to update call sites

**Verdict:** Useful if you have many broadcast scenarios.

---

## Recommended Refactoring Plan

### Phase 1: Quick Wins (1 hour) ⭐⭐⭐⭐⭐

**Priority: DO THIS**

1. **Add connection pool tuning** (5 min)
   ```rust
   .pool_idle_timeout(Duration::from_secs(30))
   .pool_max_idle_per_host(10)
   .tcp_keepalive(Duration::from_secs(60))
   ```

2. **Add exponential backoff** (30 min)
   ```rust
   let mut backoff = Duration::from_millis(100);
   loop {
       match client.msg(&url, payload).await {
           Ok(_) => break,
           Err(_) => {
               sleep(backoff).await;
               backoff = (backoff * 2).min(Duration::from_secs(5));
           }
       }
   }
   ```

3. **Add metrics for partition utilization** (15 min)
   ```rust
   tracing::debug!(
       partitions = partitions.len(),
       avg_size = total_size / partitions.len(),
       "partitioned messages"
   );
   ```

### Phase 2: Nice Improvements (4-8 hours) ⭐⭐⭐⭐

**Priority: Optional**

4. **Consolidate task spawning with join_all** (2 hours)
5. **Add batch send API** (2 hours)
6. **Simplify subscription system** (4 hours)

### Phase 3: Major Refactoring (1-2 weeks) ⭐⭐

**Priority: Only if needed**

7. **Merge MessageInbox/Outbox** (8 hours)
8. **Abstract network layer** (2 days)
9. **Switch to gRPC** (2 weeks) - NOT RECOMMENDED

---

## What NOT to Do

### ❌ Don't Switch to Persistent TCP Connections

Your HTTP+batching approach is simpler and works well:
- HTTP is stateless (easier failure handling)
- reqwest handles connection pooling
- No need to manage connection lifecycle

### ❌ Don't Create Per-Peer Workers

You already have efficient batching:
- 10ms window naturally batches by peer
- partition_256kb groups messages efficiently
- No need for dedicated per-peer tasks

### ❌ Don't Over-Engineer Abstractions

NEAR's TCP approach works for them, but you don't need it:
- Your message patterns are different (batch-heavy)
- HTTP is sufficient for your throughput needs
- Simpler is better

---

## Complexity Analysis

### Current System Complexity: **MEDIUM**

**Components:**
- MessageChannel (facade): Simple ✅
- MessageInbox (receiver): Complex (subscriptions) ⚠️
- MessageOutbox (sender): Medium (batching logic) ✅
- NodeClient (HTTP): Simple ✅
- Encryption/signing: Standard ✅
- Retry logic: Simple (could be better) ⚠️

**Overall:** Well-designed, some rough edges.

### After Phase 1 (Quick Wins): **MEDIUM-LOW**

- Connection pooling: Explicit ✅
- Retry logic: Exponential backoff ✅
- Metrics: Better visibility ✅

### After Phase 2 (Nice Improvements): **LOW**

- Task management: Cleaner ✅
- Batch API: More explicit ✅
- Subscriptions: Simpler ✅

---

## Final Recommendation

### **Do Phase 1 (Quick Wins) and Stop** ⭐⭐⭐⭐⭐

Your architecture is fundamentally sound:
- ✅ Efficient batching (10ms window)
- ✅ Smart partitioning (256KB)
- ✅ Connection reuse (reqwest pool)
- ✅ Reasonable task count (~20-40 typically)
- ✅ Clean separation (inbox/outbox)

**The only real improvements are:**
1. Explicit connection pool settings (5 min) ← **DO THIS**
2. Exponential backoff (30 min) ← **DO THIS**
3. Better metrics (15 min) ← **DO THIS**

Everything else is **nice-to-have but not necessary**.

---

## Code Example: Phase 1 Implementation

### 1. Connection Pool Tuning

```rust
// File: chain-signatures/node/src/node_client.rs

impl NodeClient {
    pub fn new(options: &Options) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(options.timeout))
                // NEW: Explicit connection pool settings
                .pool_idle_timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(10)
                .tcp_keepalive(Duration::from_secs(60))
                .build()
                .unwrap(),
            options: options.clone(),
        }
    }
}
```

### 2. Exponential Backoff

```rust
// File: chain-signatures/node/src/protocol/message/mod.rs

// In MessageOutbox::send(), replace the retry loop:

tokio::spawn(async move {
    let instant = Instant::now();
    msg_send_delay_metric.observe((instant - timestamp).as_millis() as f64);
    let payload = &[&encrypted_partition];
    let timeout = tokio::time::sleep(timeout);
    tokio::pin!(timeout);

    // NEW: Exponential backoff
    let mut backoff = Duration::from_millis(100);
    let max_backoff = Duration::from_secs(5);

    loop {
        let attempt_timestamp = Instant::now();
        tokio::select! {
            () = &mut timeout => {
                tracing::warn!(
                    ?to, ?url, elapsed = ?instant.elapsed(),
                    "outbox: failed to send messages, timeout reached",
                );
                break;
            }
            result = client.msg(&url, payload) => {
                let Err(err) = result else {
                    send_encrypted_latency_metric.observe(start.elapsed().as_millis() as f64);
                    break;
                };

                tracing::warn!(
                    ?to, ?url, elapsed = ?attempt_timestamp.elapsed(), ?err,
                    ?backoff, // NEW: Log backoff duration
                    "outbox: failed to send messages, retrying...",
                );
                num_send_encrypted_failure_metric.inc_by(message_len as f64);
                failed_send_encrypted_latency_metric
                    .observe(attempt_timestamp.elapsed().as_millis() as f64);
            }
        }
        
        // NEW: Exponential backoff instead of fixed 500ms
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
});
```

### 3. Partition Metrics

```rust
// In partition_256kb(), add logging:

fn partition_256kb(outgoing: impl IntoIterator<Item = (Message, Instant)>) -> Vec<Partition> {
    let mut partitions = Vec::new();
    let mut current_messages = Vec::new();
    let mut current_size: usize = 0;
    let mut earliest = Instant::now();
    let mut total_messages = 0; // NEW

    for (msg, timestamp) in outgoing {
        total_messages += 1; // NEW
        // ... existing code ...
    }

    if !current_messages.is_empty() {
        partitions.push(Partition {
            messages: current_messages,
            timestamp: earliest,
        });
    }

    // NEW: Log partition stats
    if !partitions.is_empty() {
        let avg_messages = total_messages / partitions.len();
        let avg_size = partitions.iter()
            .map(|p| p.messages.iter().map(|m| m.size()).sum::<usize>())
            .sum::<usize>() / partitions.len();
        
        tracing::debug!(
            partitions = partitions.len(),
            total_messages,
            avg_messages_per_partition = avg_messages,
            avg_partition_size_kb = avg_size / 1024,
            "partitioned outgoing messages"
        );
    }

    partitions
}
```

---

## Summary

| Refactoring | Effort | Benefit | Priority |
|-------------|--------|---------|----------|
| **Connection pool tuning** | 5 min | Medium | ⭐⭐⭐⭐⭐ |
| **Exponential backoff** | 30 min | Medium | ⭐⭐⭐⭐⭐ |
| **Partition metrics** | 15 min | Low | ⭐⭐⭐⭐ |
| **Consolidate task spawning** | 2 hours | Low | ⭐⭐⭐ |
| **Batch send API** | 2 hours | Medium | ⭐⭐⭐ |
| **Simplify subscriptions** | 4 hours | Low | ⭐⭐ |
| **Merge inbox/outbox** | 8 hours | Low | ⭐⭐ |
| **Abstract network layer** | 2 days | Low | ⭐ |
| **Switch to gRPC** | 2 weeks | Very Low | ❌ |

**Bottom line:** Do Phase 1 (1 hour total), skip everything else unless you have specific problems. 👍
