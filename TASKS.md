# Single Indexer Abstraction — Tasks

> All tasks reference the design in [PLAN.md](PLAN.md).
> Tasks are ordered by dependency. Each task is a single, reviewable PR unless noted otherwise.

---

## Phase 1: Define the Abstraction

### Task 1.1 — Define `ChainEvent` and `ChainClient`

**Files to create/modify:**
- Create `chain-signatures/node/src/indexer_client.rs` (new module)
- Modify `chain-signatures/node/src/lib.rs` — add `pub mod indexer_client`

**Work:**
- Define `ChainEvent` enum with three variants: `SignRequest(IndexedSignRequest)`, `Respond(SignatureRespondedEvent)`, `RespondBidirectional(RespondBidirectionalEvent)`
- Define `ChainClient` trait with `const CHAIN: Chain` and `async fn next_event(&mut self) -> Option<ChainEvent>`
- Add `#[async_trait]` bound

**Acceptance:**
- Compiles with no implementations yet
- No behavior change

**Status:** ✅ Completed

---

### Task 1.2 — Write `run_indexer` shared loop


---

### Task 1.2 — Write `run_indexer` shared loop

**Files to modify:**
- `chain-signatures/node/src/indexer_client.rs` (add `run_indexer` function)
- `chain-signatures/node/src/indexer_common.rs` — add `process_sign_request()` variant that takes `IndexedSignRequest` directly (thin wrapper around existing backlog insert + sign_tx send logic from `process_sign_event`)

**Work:**
- Implement `run_indexer<C: ChainClient>(...)` as described in PLAN.md
- Call `recover_backlog()` at startup
- Match on `ChainEvent` and dispatch to existing `process_sign_request()`, `process_respond_event()`, `process_respond_bidirectional_event()`
- Add tracing for loop start/shutdown

**Acceptance:**
- Compiles
- Unit test: mock `ChainClient` that yields a fixed sequence of `ChainEvent`s, assert correct backlog/sign_tx interactions
- No behavior change to existing indexers yet

**Status:** ✅ Completed


---

## Phase 2: Implement Per-Chain Clients

### Task 2.1 — `SolanaClient` implementing `ChainClient`

**Files to create/modify:**
- Refactor `chain-signatures/node/src/indexer_sol.rs` → create `SolanaClient` struct
- Move subscription logic, CPI parsing, dedup cache, reconnection into `SolanaClient`
- Implement `ChainClient for SolanaClient` with `next_event()` that `select!`s across internal streams

**Work:**
- `SolanaClient::new(config, backlog, ...)` — constructor, sets up initial state
- `next_event()` — internally manages the three subscription loops (CPI sign, non-CPI sign, respond), reconnects on failure, deduplicates, and yields `ChainEvent`
- All `SignatureEvent` trait impls for Solana events stay internal to this module — they're used to construct `IndexedSignRequest` before yielding
- Keep the existing free `run()` temporarily so both paths can coexist during testing

**Acceptance:**
- `SolanaClient` passes existing Solana integration tests when wired through `run_indexer`
- Bidirectional events (`SignBidirectional`, `RespondBidirectional`, `SignatureResponded`) correctly map to `ChainEvent` variants
- Reconnection behavior is preserved

**Status:** 🔧 In Progress — minimal `SolanaClient` implemented with unit tests passing. Remaining: move live subscription loops, dedup cache, reconnection, and pass Solana integration tests.


---

### Task 2.2 — `HydrationClient` implementing `ChainClient`

**Files to create/modify:**
- Refactor `chain-signatures/node/src/indexer_hydration.rs` → create `HydrationClient` struct
- Move Subxt subscription, Merkle proof verification, event decoding into `HydrationClient`
- Implement `ChainClient for HydrationClient`

**Work:**
- `HydrationClient::new(config, backlog, ...)` — constructor
- `next_event()` — subscribes to finalized blocks, verifies Merkle proofs, decodes Signet pallet events, yields `ChainEvent`
- All four event types (`SignatureRequested`, `SignBidirectionalRequested`, `RespondBidirectionalRequested`, `SignatureResponded`) map to correct `ChainEvent` variants
- Reconnects on Subxt stream termination
- Keep existing free `run()` temporarily

**Acceptance:**
- `HydrationClient` passes existing Hydration integration tests when wired through `run_indexer`
- Merkle proof verification behavior is preserved
- All four event types are handled

**Status:** 🔧 In Progress — minimal `HydrationClient` implemented with unit tests passing. Remaining: move Subxt subscription, Merkle proof verification, event decoding, reconnection, and pass Hydration integration tests.


---

### Task 2.3 — `EthereumIndexerClient` implementing `ChainClient`

**Files to create/modify:**
- Refactor `chain-signatures/node/src/indexer_eth/mod.rs` → create `EthereumIndexerClient` struct
- Move block polling pipeline, finality tracking, receipt fetching, log parsing, retry queue, `AppDataStorage` cursor, execution watcher checking into `EthereumIndexerClient`
- Implement `ChainClient for EthereumIndexerClient`
- `chain-signatures/node/src/indexer_eth/direct_rpc.rs` and `helios.rs` — unchanged, become internal deps

**Work:**
- `EthereumIndexerClient::new(config, backlog, ...)` — constructor, initializes internal block pipeline channels
- `next_event()` — runs the multi-stage pipeline internally:
  - Polls latest blocks, waits for finality
  - Fetches receipts, filters contract logs
  - Parses `SignatureRequested` → `ChainEvent::SignRequest`
  - Parses `SignatureResponded` → `ChainEvent::Respond`
  - Checks execution watchers via `backlog.pending_execution(Chain::Ethereum)` → on match, produces `ChainEvent::SignRequest` with `SignRequestType::RespondBidirectional`
  - Handles catchup and failed block retry internally
  - Persists block cursor to `AppDataStorage`
- Make ETH construct `IndexedSignRequest` directly (it already does — no `SignatureEvent` impl needed)
- Keep existing `EthereumIndexer` temporarily

**Acceptance:**
- `EthereumIndexerClient` passes existing ETH integration tests when wired through `run_indexer`
- Block cursor persistence works
- Execution watcher bidirectional flow works end-to-end
- Catchup from historical blocks works
- Helios and Direct RPC backends both work

**Status:** 🔧 In Progress — minimal `EthereumIndexerClient` implemented with unit tests passing. Remaining: move block pipeline, finality tracking, receipt fetching, log parsing, retry queue, `AppDataStorage` cursor, execution watcher checking, and pass ETH integration tests.


---

## Phase 3: Wire Up & Cut Over

### Task 3.1 — Update `cli.rs` to use `run_indexer` + client registration

**Files to modify:**
- `chain-signatures/node/src/cli.rs`

**Work:**
- Replace ad-hoc indexer spawning with uniform pattern:
  ```
  for each chain config:
      construct ChainClient
      tokio::spawn(run_indexer(client, sign_tx, backlog, ...))
  ```
- Remove old `EthereumIndexer::new(...) + tokio::spawn(eth_indexer.run())` pattern
- Remove old `tokio::spawn(indexer_sol::run(...))` pattern
- Remove old `tokio::spawn(indexer_hydration::run(...))` pattern

**Acceptance:**
- All integration tests pass
- No behavioral regression
- `cli.rs` spawning logic is uniform across chains

---

### Task 3.2 — Remove old `run()` functions and dead code

**Files to modify:**
- `chain-signatures/node/src/indexer_sol.rs` — remove free `run()` function
- `chain-signatures/node/src/indexer_hydration.rs` — remove free `run()` function
- `chain-signatures/node/src/indexer_eth/mod.rs` — remove `EthereumIndexer` struct and its `run()` method
- `chain-signatures/node/src/indexer_common.rs` — remove `process_sign_event()` if fully replaced by `process_sign_request()`; keep `SignatureEvent` trait if still used internally by Solana/Hydration clients

**Acceptance:**
- No dead code warnings
- All tests pass
- Clean compile

---

## Phase 4: Validate

### Task 4.1 — End-to-end integration test

**Work:**
- Run full integration test suite with all three chains going through `run_indexer`
- Specifically validate:
  - Regular sign requests on all three chains
  - Bidirectional sign → execute → respond flow (Solana → Ethereum → Solana)
  - Bidirectional sign → execute → respond flow (Hydration → Ethereum → Hydration)
  - Backlog recovery on restart for each chain
  - ETH catchup from historical blocks
  - Reconnection behavior (Solana WebSocket drop, Hydration Subxt stream drop)

**Acceptance:**
- All existing integration tests pass with zero regressions

---

## Optional / Future

### Task F.1 — Unify Solana subscription loops

**Context:** Solana currently runs 3 concurrent subscription loops (CPI sign, non-CPI sign, respond). Inside `SolanaClient::next_event()`, these are `select!`ed. Investigate whether a single subscription loop can handle all event types.

**Priority:** Low — functional as-is, optimization only.

---

### Task F.2 — Add `ChainPublisher` trait (RPC side)

**Context:** The RPC/publishing side has the same pattern — `RpcExecutor` dispatches via match on chain. A `ChainPublisher` trait would complete the abstraction. Deferred per current constraints.

---

### Task F.3 — ETH `SignatureEvent` alignment

**Context:** ETH is the only chain that doesn't go through the `SignatureEvent` trait. If useful for consistency or testing, implement `SignatureEvent` for an ETH event struct. Low priority — ETH already produces `IndexedSignRequest` directly, which is what the new `ChainEvent::SignRequest` expects.

---

## Dependency Graph

```
Task 1.1 ─── Define ChainEvent + ChainClient trait
    │
Task 1.2 ─── Write run_indexer shared loop
    │
    ├── Task 2.1 ─── SolanaClient
    ├── Task 2.2 ─── HydrationClient
    └── Task 2.3 ─── EthereumIndexerClient
            │
        Task 3.1 ─── Wire up cli.rs
            │
        Task 3.2 ─── Remove old code
            │
        Task 4.1 ─── E2E validation
```

Tasks 2.1, 2.2, and 2.3 are independent and can be done in parallel.

