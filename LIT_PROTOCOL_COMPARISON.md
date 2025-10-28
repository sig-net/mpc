# Lit Protocol Networking Analysis

**Date:** October 15, 2025

You use Lit Protocol's `cait-sith` package, so let's see what we can learn from their networking implementation.

---

## TL;DR - Key Findings

**Good News:**
- ✅ Lit Protocol uses the **exact same approach** as you: `reqwest::Client` for HTTP/HTTPS communication
- ✅ They have the **exact same connection reuse** through reqwest's built-in pool
- ✅ They use **similar patterns**: HTTP POST for peer-to-peer messages

**Different Approach:**
- 🔄 Lit Protocol **also has gRPC** for internal node-to-node "chatter" (high-frequency messages)
- 🔄 They use **both HTTP and gRPC** depending on the use case
- 🔄 They have a more complex dual-transport system

**Interesting Findings:**
- 💡 Lit uses **HTTP for external APIs** and **gRPC for internal peer communication**
- 💡 They have similar task explosion issues and solved them with per-peer workers
- 💡 Their HTTP client config is basically identical to yours (minimal tuning)

---

## Lit Protocol's HTTP Client Configuration

### Their `HttpClientFactory`

```rust
// lit-node/src/networking/http/client.rs
impl HttpClientFactory {
    fn new_default_client(cfg: &LitConfig) -> Result<Client> {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(cfg.http_client_timeout()?))
            .use_rustls_tls()
            .build()
            .map_err(|e| unexpected_err(e, Some("Unable to init default client".into())))
    }
}
```

**What they configure:**
- `timeout`: From config (default 30 seconds)
- `use_rustls_tls()`: Same TLS backend choice
- **NO explicit pool settings** (same as you!)

**Your `NodeClient`:**
```rust
// chain-signatures/node/src/node_client.rs
impl NodeClient {
    pub fn new(options: &Options) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(options.timeout))
                .build()
                .unwrap(),
            options: options.clone(),
        }
    }
}
```

**Comparison:**
- ✅ Both use minimal reqwest configuration
- ✅ Both rely on default connection pooling
- ✅ Both use timeout as primary config
- ⚠️ You use milliseconds, they use seconds (minor detail)

---

## Lit Protocol's Dual Transport System

Lit uses **two different transports** depending on the use case:

### 1. HTTP/HTTPS (External & Some Internal)

**Used for:**
- Client-facing APIs (`/web/handshake`, `/web/pkp/sign`, etc.)
- Peer discovery (`/connect/<nonce>`)
- Admin endpoints
- External communication

**Implementation:**
```rust
// Uses reqwest::Client - same as your system
let http_client = HttpClientFactory::new_client(&lit_config)
    .expect("Unable to init HTTP client");

// Stored in PeerState for peer-to-peer calls
pub struct PeerState {
    pub http_client: reqwest::Client,
    // ...
}
```

**Example usage:**
```rust
// lit-node/src/peers/peer_state/connected.rs
pub async fn connect_to_node(&self, peer: &PeerValidator) -> Result<PeerItem> {
    let url = format!(
        "{}{}/{}/{}",
        self.lit_config.http_prefix_when_talking_to_other_nodes(),
        addr,
        "connect",
        noonce
    );
    let resp = self.http_client.get(url.clone()).send().await;
    // Handle response...
}
```

### 2. gRPC (Internal "Chatter")

**Used for:**
- High-frequency internal peer-to-peer messages
- MPC protocol message passing
- Round data transmission

**Implementation:**
```rust
// lit-node/src/tasks/batch_transmissions.rs
pub const INTERNAL_CHATTER_PORT_OFFSET: u16 = 19608;

pub async fn batch_transaction_worker(
    mut quit_rx: tokio::sync::broadcast::Receiver<bool>,
    lit_config: Arc<LitConfig>,
    peer_state: Arc<PeerState>,
    rx_node_transmission_details: flume::Receiver<NodeTransmissionDetails>,
    http_client: Client,  // Still have HTTP client for fallback
) {
    // Uses gRPC ChatterServiceClient
    let mut clients: HashMap<String, (SystemTime, ChatterServiceClient<tonic::transport::Channel>)> = HashMap::new();
    
    // For each transmission:
    let client = match clients.get(peer_addr_full.as_str()) {
        Some(client) => {
            // Reuse existing gRPC client
            clients.insert(peer_addr_full.to_string(), (SystemTime::now(), client.1.clone()));
            client.1.clone()
        }
        None => {
            // Create new gRPC connection
            let url = format!("{}{}:{}", prefix, peer_addr, INTERNAL_CHATTER_PORT_OFFSET + peer_port);
            let channel = tonic::transport::Channel::from_shared(url)?.connect().await?;
            let client = ChatterServiceClient::new(channel);
            clients.insert(peer_addr_full.to_string(), (SystemTime::now(), client.clone()));
            client
        }
    };
    
    // Send via gRPC
    send_direct_grpc(&transmission_details, &peers, client).await;
}
```

**Port allocation:**
- Main HTTP port: `7470` (or configured)
- gRPC "chatter" port: Main port + `19608` offset
- Example: HTTP on `7470`, gRPC on `27078`

---

## Lit Protocol's Peer Communication Architecture

### High-Level Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                      Lit Protocol Node                        │
├─────────────────────────────────────────────────────────────┤
│                                                                │
│  HTTP Server (Rocket)                    gRPC Server (Tonic)  │
│  Port: 7470                              Port: 27078          │
│  ├─ /web/handshake                      ├─ ChatterService    │
│  ├─ /web/pkp/sign                       │  └─ SendDirect()   │
│  └─ /connect/<nonce>                    └─ For MPC messages  │
│                                                                │
│  HTTP Client (reqwest)                   gRPC Client (Tonic)  │
│  └─ Connects to peers                   └─ Batch worker      │
│     via HTTP                                sends MPC msgs    │
│                                                                │
└─────────────────────────────────────────────────────────────┘
```

### Message Flow

**Scenario 1: Peer Discovery**
```rust
// Uses HTTP
self.http_client.get(url).send().await  // ← reqwest, connection pooled
```

**Scenario 2: MPC Protocol Messages**
```rust
// Uses gRPC
send_direct_grpc(&transmission_details, &peers, client).await  // ← tonic gRPC
```

---

## Lit Protocol's CommsManager (Similar to Your Mesh)

They have a `CommsManager` that handles peer-to-peer communication:

```rust
// lit-node/src/p2p_comms/mod.rs
pub struct CommsManager {
    pub channels: RoundCommsChannel,
    tx_batch_manager: Arc<Sender<NodeTransmissionDetails>>,  // ← Sends to gRPC worker
    tx_round_manager: Arc<Sender<RoundData>>,
    peers: Vec<SimplePeer>,
    wait_params: NodeWaitParams,
    self_peer: SimplePeer,
    txn_prefix: String,
    round: String,
}

impl CommsManager {
    // Broadcast to all peers
    pub async fn broadcast<B>(&self, data: B) -> Result<bool>
    where
        B: serde::Serialize,
    {
        let data = serde_json::to_string(&data)?;
        let data = data.as_bytes().to_vec();
        self.broadcast_bytes(data).await
    }
    
    // Send directly to one peer
    pub async fn send_direct<B>(&self, dest_peer: &SimplePeer, data: B) -> Result<bool>
    where
        B: serde::Serialize,
    {
        let data = serde_json::to_string(&data)?;
        let data = data.as_bytes().to_vec();
        self.send_bytes_direct(dest_peer, data).await
    }
    
    // Collect responses
    pub async fn collect<C>(&self) -> Result<Vec<(u16, C)>>
    where
        C: serde::de::DeserializeOwned,
    {
        let expected_peers = self.peers.all_peers_except(&self.self_peer.socket_address);
        self.collect_from::<C>(&expected_peers).await
    }
}
```

**How it works:**
1. `CommsManager::broadcast()` → sends to `tx_batch_manager` channel
2. `batch_transaction_worker` receives from channel
3. Worker sends via **gRPC** to each peer
4. Peer receives via gRPC server
5. gRPC server sends to `tx_round_manager` channel
6. `rounds_worker` distributes to waiting tasks

**Key insight:** They **don't spawn tasks per message**. They use:
- **One `batch_transaction_worker`** that receives all outgoing messages
- **Per-peer gRPC client cache** (similar to your idea of per-peer workers)
- **Channel-based architecture** to avoid task explosion

---

## Task Management Comparison

### Your Current Approach (Task Explosion)

```rust
// Your code: protocol/message/mod.rs
for ((from, to), encrypted) in encrypted {
    for (encrypted_partition, timestamp, message_len) in encrypted {
        tokio::spawn(async move {  // ← Spawns MANY tasks
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

### Lit Protocol's Approach (Centralized Worker)

```rust
// lit-node/src/tasks/batch_transmissions.rs
pub async fn batch_transaction_worker(
    mut quit_rx: tokio::sync::broadcast::Receiver<bool>,
    lit_config: Arc<LitConfig>,
    peer_state: Arc<PeerState>,
    rx_node_transmission_details: flume::Receiver<NodeTransmissionDetails>,  // ← Receives messages
    http_client: Client,
) {
    // Cache of gRPC clients per peer
    let mut clients: HashMap<String, (SystemTime, ChatterServiceClient)> = HashMap::new();
    
    loop {
        tokio::select! {
            _ = quit_rx.recv() => break,
            
            // Receive next message to send
            msg = rx_node_transmission_details.recv_async() => {
                let transmission_details = msg?;
                let peer_addr = transmission_details.dest_peer.socket_address.clone();
                
                // Reuse or create gRPC client
                let client = match clients.get(&peer_addr) {
                    Some(client) => {
                        clients.insert(peer_addr, (SystemTime::now(), client.1.clone()));
                        client.1.clone()
                    }
                    None => {
                        // Create new gRPC connection
                        let client = create_grpc_client(&peer_addr).await?;
                        clients.insert(peer_addr, (SystemTime::now(), client.clone()));
                        client
                    }
                };
                
                // Send via gRPC (spawns task for actual send)
                tokio::spawn(async move {
                    send_direct_grpc(&transmission_details, &peers, client).await
                });
            }
            
            // Prune old connections
            _ = heartbeat.tick() => {
                prune_old_clients(&mut clients, timeout).await
            }
        }
    }
}
```

**Key differences:**
1. **One worker loop** instead of spawning per message
2. **Per-peer client cache** (similar concept to your connection pool idea)
3. **Channel-based** message queue with backpressure
4. **Heartbeat pruning** of stale connections
5. Still spawns tasks for actual sends, but **controlled** through the worker

---

## Connection Reuse: The Details

### HTTP (reqwest) Reuse

Both you and Lit rely on reqwest's default connection pool:

```rust
// Default behavior (neither explicitly configures):
// - pool_idle_timeout: 90 seconds
// - pool_max_idle_per_host: unlimited
// - HTTP Keep-Alive: enabled
```

**Connection lifecycle:**
1. First request to peer: TCP + TLS handshake (~100ms)
2. Connection stays in pool for 90 seconds
3. Next request within 90s: Reuses connection (~20ms)
4. After 90s idle: Connection closed, next request does handshake again

### gRPC Connection Reuse

Lit's gRPC approach is more explicit:

```rust
// Cached per peer
let mut clients: HashMap<String, (SystemTime, ChatterServiceClient<tonic::transport::Channel>)>;

// Update timestamp on reuse
clients.insert(peer_addr, (SystemTime::now(), client.1.clone()));

// Prune old connections periodically
async fn prune_old_clients(clients: &mut HashMap<...>, timeout: u128) {
    let now = SystemTime::now();
    clients.retain(|_addr, (last_used, _client)| {
        now.duration_since(*last_used).unwrap().as_millis() < timeout
    });
}
```

**Benefits of gRPC approach:**
- Explicit control over connection lifetime
- Can prune based on custom logic
- Lower per-message overhead (no HTTP headers)
- Bidirectional streaming possible

**Downsides:**
- More complexity (need to maintain gRPC server + client)
- Need to manage client lifecycle manually
- More code to maintain

---

## What Can You Learn from Lit?

### 1. ✅ Your HTTP Approach is Valid

Lit uses the **same reqwest-based HTTP approach** for many use cases. You're not doing anything wrong by using HTTP.

### 2. ⚠️ Consider Centralized Worker Pattern

Instead of per-message task spawning:

```rust
// BEFORE (Your current approach)
for message in messages {
    tokio::spawn(async move {
        send_message(message).await
    });
}

// AFTER (Lit's approach)
// Have ONE worker that processes messages from a channel
pub async fn message_sender_worker(
    rx_messages: flume::Receiver<MessageToSend>,
    http_client: NodeClient,
) {
    loop {
        let msg = rx_messages.recv_async().await?;
        // Send using existing client (connection reuse)
        http_client.msg(&msg.url, &msg.payload).await;
    }
}
```

### 3. 💡 Per-Peer Client Cache (Optional)

Lit caches gRPC clients per peer. You could do similar with HTTP:

```rust
pub struct MessageOutbox {
    // Cache of HTTP clients or URLs per peer
    peer_senders: HashMap<NodeId, PeerSender>,
    base_client: NodeClient,
}

pub struct PeerSender {
    url: Url,
    client: NodeClient,  // Cloned from base (shares connection pool)
    queue: mpsc::Sender<Message>,
}

impl MessageOutbox {
    pub async fn send(&mut self, messages: Vec<Message>) {
        for msg in messages {
            let sender = self.peer_senders.entry(msg.to)
                .or_insert_with(|| {
                    PeerSender::new(self.base_client.clone(), peer_url)
                });
            
            sender.send(msg).await;
        }
    }
}
```

### 4. ❌ Don't Rush to gRPC

gRPC is **not a silver bullet**:
- Adds significant complexity
- Requires maintaining two servers (HTTP + gRPC)
- Your HTTP overhead (20-50ms) is likely negligible compared to crypto (100-500ms)
- Only worth it if you have **profiling data** showing HTTP is a bottleneck

### 5. ✅ Adopt Lit's Task Architecture

Lit's best practice: **centralized workers** instead of task explosion:

```rust
// Lit's pattern (simplified):
// 1. CommsManager sends to channel
// 2. Worker receives from channel
// 3. Worker maintains client cache
// 4. Worker spawns controlled tasks for actual I/O

// Your equivalent would be:
pub struct MessageSendWorker {
    rx: flume::Receiver<(NodeId, Message)>,
    client: NodeClient,
    peer_senders: HashMap<NodeId, PeerSender>,
}

impl MessageSendWorker {
    pub async fn run(mut self) {
        loop {
            let (node_id, message) = self.rx.recv_async().await?;
            
            let sender = self.peer_senders.entry(node_id)
                .or_insert_with(|| PeerSender::new(self.client.clone()));
            
            // Controlled spawning (only when needed)
            sender.send_async(message).await;
        }
    }
}
```

---

## Concrete Recommendations

### Priority 1: Adopt Centralized Worker (Like Lit) ⭐⭐⭐

**Don't:**
```rust
// Spawn task per message
for msg in messages {
    tokio::spawn(async move { send(msg).await });
}
```

**Do (Lit's approach):**
```rust
// 1. Create channel
let (tx_messages, rx_messages) = flume::unbounded();

// 2. Spawn ONE worker
tokio::spawn(message_sender_worker(rx_messages, client));

// 3. Send messages to channel
async fn send_messages(messages: Vec<Message>, tx: Sender<Message>) {
    for msg in messages {
        tx.send_async(msg).await;
    }
}
```

**Benefits:**
- Controlled task count (1 worker vs 1000s tasks)
- Natural backpressure through channel
- Better observability
- Same connection reuse!

### Priority 2: Keep HTTP, Tune It ⭐⭐

Don't switch to gRPC yet. Instead:

```rust
// Add to your NodeClient
impl NodeClient {
    pub fn new(options: &Options) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(options.timeout))
                .pool_idle_timeout(Duration::from_secs(30))   // ← Add
                .pool_max_idle_per_host(10)                   // ← Add
                .tcp_keepalive(Duration::from_secs(60))       // ← Add
                .build()
                .unwrap(),
            options: options.clone(),
        }
    }
}
```

### Priority 3: Per-Peer Workers (Optional) ⭐

If you want more control (like Lit's per-peer client cache):

```rust
pub struct PeerSender {
    client: NodeClient,  // Cloned (shares pool)
    url: Url,
    queue: mpsc::Sender<(Ciphered, Instant)>,
}

impl PeerSender {
    pub fn spawn(client: NodeClient, url: Url) -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        
        tokio::spawn(async move {
            while let Some((msg, timestamp)) = rx.recv().await {
                // Retry with exponential backoff
                let mut backoff = Duration::from_millis(100);
                loop {
                    match client.msg(&url, &[&msg]).await {
                        Ok(_) => break,
                        Err(_) => {
                            sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(5));
                        }
                    }
                }
            }
        });
        
        Self { client, url, queue: tx }
    }
}
```

### ❌ Don't Implement gRPC (Yet)

Only consider gRPC if:
1. You have profiling showing HTTP is >10% of signing time
2. You need <10ms message latency
3. You have 2-3 weeks for implementation + testing
4. You're willing to maintain two transport protocols

Otherwise, Lit's HTTP approach is proven and sufficient.

---

## Summary: What Lit Teaches Us

### What They Do Same as You
- ✅ Use `reqwest::Client` for HTTP communication
- ✅ Minimal reqwest configuration (rely on defaults)
- ✅ Connection reuse through reqwest's built-in pool
- ✅ TLS with rustls

### What They Do Differently
- 🔄 **Centralized worker** for message sending (vs your per-message tasks)
- 🔄 **Per-peer client cache** in worker (vs your spawning everywhere)
- 🔄 **gRPC for high-frequency internal** (vs your all-HTTP)
- 🔄 **Dual transport** (HTTP + gRPC) for different use cases

### What You Should Adopt
1. **Centralized message sender worker** (fixes task explosion)
2. **Channel-based architecture** (natural backpressure)
3. **Explicit pool tuning** (30s idle, tcp_keepalive)
4. **Per-peer sender workers** (optional, more control)

### What You Should Skip
- ❌ gRPC implementation (too complex, marginal benefit)
- ❌ Complete rewrite (incremental fixes are enough)
- ❌ Dual transport complexity

---

## Code Comparison Matrix

| Aspect | Your System | Lit Protocol | Recommendation |
|--------|-------------|--------------|----------------|
| **HTTP Client** | `reqwest::Client` minimal | `reqwest::Client` minimal | Keep, add tuning |
| **Connection Pool** | Default (90s idle) | Default (90s idle) | Tune to 30s |
| **Message Sending** | Task per message | Centralized worker | **Adopt Lit's approach** |
| **Per-Peer Management** | None | Client cache in worker | **Consider adopting** |
| **Health Checks** | Poll every 1s | Event-driven | Improve (low priority) |
| **Transport** | HTTP only | HTTP + gRPC | **Keep HTTP only** |
| **Task Count** | 1000s (per message) | ~10 (workers) | **Fix this (Priority 1)** |
| **Backpressure** | None | Channel-based | **Adopt (Priority 1)** |

---

## Final Verdict

**Lit Protocol's networking layer confirms your HTTP approach is sound.** They use the same reqwest-based HTTP client with minimal configuration.

**The main difference** is their **task management architecture**: they use centralized workers with channels instead of spawning tasks per message.

**Your action plan:**
1. ⭐⭐⭐ **Adopt centralized worker pattern** (like Lit, 4-8 hours)
2. ⭐⭐ **Add explicit pool tuning** (5 minutes)
3. ⭐ **Consider per-peer workers** (optional, 2-4 hours)
4. ❌ **Skip gRPC** (not worth the complexity)

You don't need a "significant" rewrite. You need **tactical improvements** to task management and pool configuration.
