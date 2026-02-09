# Single Indexer Abstraction — Design Plan

## Goal

Reduce indexer complexity by pushing chain-specific logic into per-chain clients and running all chains through a single, shared indexer loop.

## Status Quo

### Current Data Flow

```
Chain (ETH/SOL/Hydration)
    │
    ▼
[Per-chain indexer run()]     ← 3 different implementations
    │                            each re-implements event routing,
    │                            backlog recovery, error handling,
    │                            bidirectional lifecycle
    │
    ├─ process_sign_event()           ← shared (indexer_common.rs)
    ├─ process_respond_event()        ← shared
    ├─ process_respond_bidirectional_event()  ← shared
    │
    ▼
sign_tx: mpsc::Sender<Sign>
    │
    ▼
MpcSignProtocol → RpcExecutor → chain-specific publish
```

### What's Wrong

Each indexer (`indexer_eth/mod.rs`, `indexer_sol.rs`, `indexer_hydration.rs`) has its own `run()` function that:

1. Calls `recover_backlog()` — identical across all three
2. Waits for threshold/mesh — identical
3. Subscribes to chain events — **chain-specific**
4. Parses events — **chain-specific**
5. Routes parsed events to `process_sign_event()` / `process_respond_event()` / `process_respond_bidirectional_event()` — identical routing logic, re-implemented each time
6. Handles entropy generation — identical
7. Handles errors/logging — similar

Steps 1, 2, 5, 6, 7 are repeated. Step 3-4 is the only truly chain-specific part.

**Bidirectional is the worst case.** Today only Solana fully originates bidirectional requests. Adding bidirectional to a new chain means re-implementing the event routing for `SignBidirectional`, `RespondBidirectional`, and `SignatureResponded` events in that chain's `run()`. This is fragile and scales poorly.

**Ethereum is structurally different** from Solana/Hydration:
- ETH uses a struct (`EthereumIndexer`) with `self.run()` consuming the struct
- SOL and Hydration use free `async fn run(...)` with identical signatures
- ETH has `AppDataStorage` for block cursor persistence
- ETH does multi-stage block pipeline (poll → process → wait for finality)
- ETH handles bidirectional *execution watching* (target chain), not origination

Despite these differences, the **output** is the same: parsed events that feed into the shared `process_*` functions.

### Files Involved

| File | Role |
|------|------|
| `chain-signatures/node/src/indexer_common.rs` | `SignatureEvent` trait, `process_sign_event()`, `process_respond_event()`, `process_respond_bidirectional_event()`, `recover_backlog()`, shared enums |
| `chain-signatures/node/src/indexer_eth/mod.rs` | `EthereumIndexer` struct + `run()` (1410 lines) |
| `chain-signatures/node/src/indexer_sol.rs` | Solana free `run()` (932 lines) |
| `chain-signatures/node/src/indexer_hydration.rs` | Hydration free `run()` (873 lines) |
| `chain-signatures/node/src/indexer_eth/direct_rpc.rs` | ETH raw JSON-RPC client |
| `chain-signatures/node/src/indexer_eth/helios.rs` | ETH Helios light client |
| `chain-signatures/node/src/sign_bidirectional.rs` | Bidirectional signing flow |
| `chain-signatures/node/src/respond_bidirectional.rs` | Bidirectional respond flow |
| `chain-signatures/node/src/cli.rs` | Spawns indexers ad-hoc |
| `chain-signatures/node/src/backlog/mod.rs` | `Backlog`, `ExecutionWatcher` |

---

## Proposed Design

### Core Idea

**One trait. One loop.** The per-chain client produces a stream of parsed, verified events via `next_event()`. A single shared indexer loop handles all downstream logic.

### `ChainEvent` Enum

```rust
/// A unified event that any chain client can produce.
pub enum ChainEvent {
    /// A new signature was requested (covers both regular sign and sign-bidirectional).
    /// The client has already parsed the chain-specific event into an IndexedSignRequest.
    SignRequest(IndexedSignRequest),

    /// The source chain confirmed a respond event (SignatureResponded).
    /// This either completes a regular sign (backlog removal) or advances a
    /// bidirectional request to execution watching.
    Respond(SignatureRespondedEvent),

    /// The source chain confirmed a respond-bidirectional tx landed.
    /// Final cleanup — removes from backlog.
    RespondBidirectional(RespondBidirectionalEvent),
}
```

**Why `IndexedSignRequest` directly instead of `Box<dyn SignatureEvent>`?** Simpler. The client already knows how to parse its chain-specific events. Having it produce a ready-to-use `IndexedSignRequest` avoids boxing, trait object overhead, and keeps the interface concrete. If we later need the `SignatureEvent` trait boundary (e.g., for deferred request construction), we can reintroduce it.

### `ChainClient` Trait

```rust
#[async_trait]
pub trait ChainClient: Send + 'static {
    /// Which chain this client handles.
    const CHAIN: Chain;

    /// Produce the next verified event from this chain.
    ///
    /// The client handles connection management, subscription,
    /// event parsing, verification, retries, reconnection, and
    /// deduplication internally.
    ///
    /// Returns `None` only on permanent/graceful shutdown.
    async fn next_event(&mut self) -> Option<ChainEvent>;
}
```

**Design decisions:**
- `const CHAIN` instead of `fn chain()` — known at compile time, no runtime dispatch
- `&mut self` — the client is stateful (connections, cursors, caches)
- Returns `Option` — `None` = shut down; the client never surfaces transient errors to the caller
- No `Stream` — `next_event()` is simpler to implement and lets the client internally sleep, reconnect, and retry without `Pin<Box<dyn Stream>>` gymnasics

**What lives inside the client:**
- Connection lifecycle (connect, reconnect, backoff)
- Block/event subscription (WebSocket, HTTP polling, Subxt stream)
- Event parsing (ABI decoding, Anchor CPI, Subxt composite fields)
- Event verification (Helios light client, Merkle proof)
- Deduplication (TTL cache, seen-set)
- Block cursor persistence (ETH's `AppDataStorage`)
- Retry of failed blocks (ETH's retry queue)
- Execution watcher checking (bidirectional target chain)
- Catchup from historical blocks

### Shared Indexer Loop

```rust
pub async fn run_indexer<C: ChainClient>(
    mut client: C,
    sign_tx: mpsc::Sender<Sign>,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    total_timeout: Duration,
) {
    let chain = C::CHAIN;

    // 1. Recover backlog (shared startup)
    recover_backlog(
        &backlog, &mut contract_watcher, &mut mesh_state,
        &node_client, chain, sign_tx.clone(), total_timeout,
    ).await;

    // 2. Shared event loop
    while let Some(event) = client.next_event().await {
        match event {
            ChainEvent::SignRequest(indexed_request) => {
                // Insert into backlog, send to sign queue
                process_sign_request(indexed_request, sign_tx.clone(), backlog.clone()).await;
            }
            ChainEvent::Respond(event) => {
                // Completes regular sign OR advances bidirectional to execution watching
                process_respond_event(event, sign_tx.clone(), &mut contract_watcher, &backlog).await;
            }
            ChainEvent::RespondBidirectional(event) => {
                // Final bidirectional cleanup
                process_respond_bidirectional_event(event, sign_tx.clone(), &backlog).await;
            }
        }
    }

    tracing::warn!(%chain, "indexer shut down");
}
```

**This replaces all three `run()` functions.** Every chain gets backlog recovery, event routing, bidirectional lifecycle, and error handling for free.

> Note: `process_sign_request` is a slimmed-down version of `process_sign_event` that takes `IndexedSignRequest` directly instead of `Box<dyn SignatureEvent>`. The `SignatureEvent` trait becomes an internal implementation detail of each client (or is dropped entirely if the client constructs `IndexedSignRequest` directly).

### Per-Chain Clients

#### `SolanaClient`

```rust
pub struct SolanaClient {
    config: SolConfig,
    backlog: Backlog,
    // Internal: WebSocket connections, CPI log parser,
    //           TTL dedup cache, Anchor program client
}

impl ChainClient for SolanaClient {
    const CHAIN: Chain = Chain::Solana;

    async fn next_event(&mut self) -> Option<ChainEvent> {
        // Internally select!s across:
        //   - CPI sign events (WebSocket log subscription)
        //   - Non-CPI sign events (Anchor event listener)
        //   - Respond bidirectional events
        // Handles reconnection on WebSocket drop.
        // Deduplicates via TTL cache.
        // Parses events → IndexedSignRequest / RespondBidirectionalEvent / etc.
    }
}
```

> **Note on multiple subscription loops:** Solana currently runs 3 concurrent loops.
> Inside `next_event()`, this becomes a `tokio::select!` across internal streams.
> This is an implementation detail — the caller sees a single `next_event()`.
> Unifying to fewer subscriptions is a separate optional cleanup.

#### `HydrationClient`

```rust
pub struct HydrationClient {
    config: HydrationConfig,
    backlog: Backlog,
    // Internal: Subxt client, finalized block stream,
    //           Merkle proof verifier
}

impl ChainClient for HydrationClient {
    const CHAIN: Chain = Chain::Hydration;

    async fn next_event(&mut self) -> Option<ChainEvent> {
        // Subscribes to finalized Substrate blocks.
        // For each block: verify Merkle proof, decode Signet pallet events.
        // Maps to ChainEvent variants.
        // Reconnects on stream termination.
    }
}
```

#### `EthereumClient` (indexer-side)

```rust
pub struct EthereumIndexerClient {
    config: EthConfig,
    backlog: Backlog,
    // Internal: Helios or Direct RPC, block polling pipeline,
    //           finality tracker, retry queue, AppDataStorage,
    //           internal channels for block pipeline stages
}

impl ChainClient for EthereumIndexerClient {
    const CHAIN: Chain = Chain::Ethereum;

    async fn next_event(&mut self) -> Option<ChainEvent> {
        // Manages block polling pipeline internally:
        //   - Polls latest blocks
        //   - Waits for finality
        //   - Fetches receipts, filters logs
        //   - Parses SignatureRequested → ChainEvent::SignRequest
        //   - Parses SignatureResponded → ChainEvent::Respond
        //   - Checks execution watchers for bidirectional → ChainEvent::SignRequest
        //   - Retries failed blocks internally
        //   - Persists block cursor
        //   - Handles catchup from historical blocks
    }
}
```

**Naming:** `EthereumIndexerClient` to distinguish from the existing `EthereumClient` (Helios/Direct RPC wrapper), which becomes an *internal dependency* of `EthereumIndexerClient`.

### Startup / Registration

```rust
// In cli.rs start():
let mut handles = Vec::new();

if let Some(cfg) = eth_config {
    let client = EthereumIndexerClient::new(cfg, backlog.clone(), ...)?;
    handles.push(tokio::spawn(run_indexer(
        client, sign_tx.clone(), backlog.clone(),
        contract_watcher.clone(), mesh_state.clone(),
        node_client.clone(), total_timeout,
    )));
}

if let Some(cfg) = sol_config {
    let client = SolanaClient::new(cfg, backlog.clone(), ...)?;
    handles.push(tokio::spawn(run_indexer(
        client, sign_tx.clone(), backlog.clone(),
        contract_watcher.clone(), mesh_state.clone(),
        node_client.clone(), total_timeout,
    )));
}

if let Some(cfg) = hydration_config {
    let client = HydrationClient::new(cfg, backlog.clone(), ...)?;
    handles.push(tokio::spawn(run_indexer(
        client, sign_tx.clone(), backlog.clone(),
        contract_watcher.clone(), mesh_state.clone(),
        node_client.clone(), total_timeout,
    )));
}
```

**Adding chain N+1:** implement `ChainClient`, add a config block. The indexer loop, backlog recovery, bidirectional lifecycle, and all routing is automatic.

### Execution Watching (Bidirectional)

Bidirectional flow:
1. Source chain (e.g., Solana) emits `SignBidirectionalRequested` → client produces `ChainEvent::SignRequest` → protocol signs → `process_respond_event` advances backlog + registers execution watcher on target chain (Ethereum)
2. Target chain (Ethereum) client checks `backlog.pending_execution(Chain::Ethereum)` during block processing → when watched tx hash appears in receipts → produces `ChainEvent::SignRequest` (with `SignRequestType::RespondBidirectional`) → protocol signs the respond payload
3. Source chain sees `RespondBidirectional` event → client produces `ChainEvent::RespondBidirectional` → loop removes from backlog → done

**The client accesses `Backlog` directly** (Option B) to check execution watchers. This matches ETH's current approach and avoids adding a channel between the backlog and each client.

### What Happens to Existing Code

| Current | After |
|---------|-------|
| `indexer_common.rs` — `SignatureEvent` trait | Becomes optional; clients can use it internally or construct `IndexedSignRequest` directly |
| `indexer_common.rs` — `process_sign_event()` | Simplified to `process_sign_request()` taking `IndexedSignRequest` (no trait dispatch) |
| `indexer_common.rs` — `process_respond_event()` | Unchanged — called by the shared loop |
| `indexer_common.rs` — `process_respond_bidirectional_event()` | Unchanged — called by the shared loop |
| `indexer_common.rs` — `recover_backlog()` | Unchanged — called by the shared loop at startup |
| `indexer_common.rs` — shared enums (`SignBidirectionalEvent`, etc.) | Unchanged — still used inside `ChainEvent` and backlog |
| `indexer_eth/mod.rs` — `EthereumIndexer` struct + `run()` | Replaced by `EthereumIndexerClient` implementing `ChainClient`; internal block pipeline logic moves into `next_event()` |
| `indexer_sol.rs` — free `run()` | Replaced by `SolanaClient` implementing `ChainClient` |
| `indexer_hydration.rs` — free `run()` | Replaced by `HydrationClient` implementing `ChainClient` |
| `cli.rs` — ad-hoc indexer spawning | Replaced by uniform `run_indexer(client, ...)` loop |

### What This Does NOT Touch

- **RPC / publishing** — out of scope per constraints
- **NEAR indexer** (`indexer.rs`) — testing-only, ignored
- **Protocol layer** — unchanged; consumes `Sign`, produces `PublishAction`
- **Backlog internals** — unchanged; clients and the shared loop interact with existing API
- **`ContractStateWatcher` / `MeshState`** — unchanged; passed to `run_indexer`

---

## Key Benefits

1. **New chain = implement `ChainClient` + config block.** No event routing, no backlog recovery, no bidirectional lifecycle code.
2. **Bidirectional support is automatic.** Emit the right `ChainEvent` variants; the loop handles advancement, execution watching registration, and completion.
3. **Retry/reconnection is the client's problem.** The shared loop never sees connection failures.
4. **Single point of truth** for the indexing lifecycle — one `run_indexer` function to audit, test, and maintain.

