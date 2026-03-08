# Generalized Catchup for Chain Streams

## Objective
Implement a shared catchup orchestration in `run_stream` so each chain stream can safely:

1. read last persisted processed block,
2. start live subscription immediately,
3. anchor to first live block,
4. buffer live events,
5. replay historical catchup to the anchor,
6. drain buffered events,
7. continue live.

This removes per-chain ad hoc catchup behavior and standardizes restart safety.

---

## Current State (from codebase)

- Shared loop exists in `stream/mod.rs` via `run_stream`, but it only consumes `next_event()`.
- Ethereum has partial catchup logic inside `indexer_eth/mod.rs`, but not in shared orchestration and not anchor-buffer based.
- Solana and Hydration do not implement this generalized startup sequence in a shared way.
- `Backlog` already stores per-chain processed block height (`processed_block`, `set_processed_block`), which is the right cursor source of truth.

---

## Proposed Design

### 1) Extend stream abstraction

Add generalized startup/catchup API on `ChainStream` (or a supertrait):

- `const CHAIN: Chain`
- `async fn next_event(&mut self) -> Option<ChainEvent>` (existing)
- `async fn livestream(&mut self) -> anyhow::Result<Box<dyn ChainBufferedStream>>`
- `async fn catchup(&mut self, from_inclusive: u64, to_inclusive: u64) -> anyhow::Result<()>`

Add `ChainBufferedStream` abstraction:

- `async fn initial_height(&mut self) -> anyhow::Result<u64>`
- `async fn next_buffered(&mut self) -> Option<ChainEvent>`
- `fn cancel(&self)` (or drop-based cancellation)

Notes:
- `catchup` emits events into the same stream/event sink consumed by `next_event()`.
- Buffering is chain implementation detail, but contract is unified.
- Catchup range is explicitly **inclusive** on both ends: `[from_inclusive, to_inclusive]`.

### 2) Shared startup state machine in `run_stream`

`run_stream` becomes a 3-phase orchestrator:

- **Phase A: Recover backlog state** (existing `recover_backlog`).
- **Phase B: Anchor + catchup + drain**
  - read `last_processed = backlog.processed_block(CHAIN)`
  - start live buffered stream
  - read `anchor = buffered.initial_height()`
  - compute range: `from = last_processed.unwrap_or(anchor)`
  - if `from <= anchor`: run `catchup(from, anchor)`
  - then drain buffer until reaching anchor+ and transition to live
- **Phase C: steady-state live**
  - consume `next_event()` loop as today

Startup policy when no persisted height:
- Start at head (no lookback). This is implemented by `from = anchor`, i.e. a no/near-no-op catchup window.

### 3) Ordering and dedup invariants

Guarantees to enforce:

- Block progression per chain is monotonic in observed processing path.
- Events at heights `<= from` are not re-processed.
- Catchup covers `[from, anchor]` exactly once.
- Buffered/live events `> anchor` are processed after catchup.
- Duplicate events across catchup/live are dropped by `(chain, tx/log signature/event key)` dedup at stream level.

### 4) Failure behavior

- If live stream starts but anchor acquisition fails: restart stream initialization with backoff.
- If catchup fails: keep buffer alive, retry catchup with bounded backoff; if retries exhausted, restart full initialization.
- If buffer overflows during long catchup:
  - spill to bounded disk-backed queue (required default behavior).
  - if disk spill is unavailable/fails, fail-fast and restart with newer anchor.
- On shutdown/drop: cancel buffered stream task and internal subscriptions.

### 5) Catchup performance model (parallel fetch, linear apply)

Catchup should maximize fetch concurrency while preserving deterministic linear processing:

- **Fetch in parallel**: request block/event data concurrently in chunks/windows.
- **Apply linearly**: process and emit events strictly by ascending block height.
- Use a reorder buffer keyed by height so out-of-order fetch completion does not affect processing order.
- Bound in-flight concurrency and memory; overflow spills to disk queue.

Ethereum-specific optimization:
- Prefer range queries (`eth_getLogs`) over per-block log fetch when possible.
- Execute multiple non-overlapping ranges in parallel.
- Merge range results by block number/log index and apply in linear order.

### 6) Chain-specific implementation expectations

- **Ethereum**
  - Adapt current pipeline so startup catchup is driven by shared orchestration.
  - Anchor source should be latest **finalized** block from live path.
  - Catchup should use parallelized `eth_getLogs` range pulls where possible, then ordered linear application.
  - Preserve finality checks and block-hash verification before emitting effective events.
- **Solana**
  - Implement historical fetch for missed slots/signatures between heights.
  - Keep CPI/non-CPI/respond subscriptions but expose as one buffered live source.
- **Hydration**
  - Add historical finalized block scan by height/hash for `(from, anchor]`.
  - Keep Merkle proof verification for catchup and live paths consistently.

---

## Implementation Tasks

## Phase 1 — Contracts and shared orchestrator

- [ ] **Task 1.1**: Define `ChainBufferedStream` trait and extend `ChainStream` in `stream/mod.rs`.
- [ ] **Task 1.2**: Refactor `run_stream` startup into explicit phase machine (`recover -> anchor/buffer -> catchup -> drain -> live`).
- [ ] **Task 1.3**: Add shared helper utilities:
  - range computation (`from_inclusive`, `to_inclusive`)
  - dedup adapter interface
  - bounded retry/backoff policy
  - parallel-fetch + ordered-apply coordinator (reorder buffer + watermark).
- [ ] **Task 1.4**: Add metrics:
  - `catchup_start_height`, `catchup_end_height`, `catchup_lag_blocks`
  - `catchup_duration_seconds`
  - `catchup_fetch_concurrency`, `catchup_reorder_buffer_depth`
  - `buffer_depth`, `buffer_overflow_count`
  - `buffer_spill_bytes`, `buffer_spill_events`
  - `anchor_height`.

## Phase 2 — Ethereum integration

- [ ] **Task 2.1**: Wrap ETH live ingestion in `ChainBufferedStream` and expose `initial_height`.
- [ ] **Task 2.2**: Move ETH startup catchup trigger from internal ad hoc flow to shared `run_stream` flow.
- [ ] **Task 2.3**: Anchor and catchup target must use latest finalized height.
- [ ] **Task 2.4**: Implement parallel `eth_getLogs` range fetching + linear ordered apply.
- [ ] **Task 2.5**: Ensure finality/hash checks remain before emitting `ChainEvent` for catchup and live.
- [ ] **Task 2.6**: Add ETH dedup key for catchup/live overlap.

## Phase 3 — Solana integration

- [ ] **Task 3.1**: Implement Solana historical backfill for `(from, anchor]` with consistent event decoding.
- [ ] **Task 3.1**: Implement Solana historical backfill for `[from, anchor]` with consistent event decoding.
- [ ] **Task 3.2**: Expose unified buffered live stream across CPI/non-CPI/respond sources.
- [ ] **Task 3.3**: Add slot/signature dedup between catchup and live buffer.

## Phase 4 — Hydration integration

- [ ] **Task 4.1**: Introduce Hydration stream struct implementing shared stream traits (instead of bespoke `run`).
- [ ] **Task 4.2**: Implement finalized historical catchup scan `(from, anchor]`.
- [ ] **Task 4.2**: Implement finalized historical catchup scan `[from, anchor]`.
- [ ] **Task 4.3**: Keep proof verification identical for catchup/live event extraction.
- [ ] **Task 4.4**: Route Hydration through shared `run_stream` in CLI.

## Phase 5 — Validation

- [ ] **Task 5.1**: Add deterministic tests for startup ordering:
  - no previous height
  - previous height present
  - duplicates across catchup and live
  - catchup failure/retry and restart.
- [ ] **Task 5.2**: Add integration tests per chain for restart recovery and no event loss.
- [ ] **Task 5.3**: Add load test scenario where catchup is long and live continues.
- [ ] **Task 5.4**: Add observability dashboards/alerts for lag and buffer health.

---

## Rollout Strategy

1. Land traits + orchestrator behind a feature flag.
2. Migrate Ethereum first (already has most pieces).
3. Migrate Solana.
4. Migrate Hydration and remove bespoke Hydration `run` path.
5. Remove old startup/catchup code paths and feature flag.

---

## Risks and mitigations

- **Risk**: unbounded memory while catchup is slow.
  - **Mitigation**: hard buffer cap + mandatory disk spill + overflow fallback restart.
- **Risk**: parallel fetch causes ordering races.
  - **Mitigation**: strict height-ordered apply with reorder buffer watermark.
- **Risk**: inconsistent finality semantics across chains.
  - **Mitigation**: chain adapter validates finality/proof before emitting events.
- **Risk**: duplicate processing at anchor boundary.
  - **Mitigation**: explicit boundary contract `(from, anchor]` + dedup keys.
- **Risk**: partial migration drift.
  - **Mitigation**: phased rollout + per-chain parity tests.

---

## Open questions / clarifications needed

1. For Solana, which commitment level should define canonical anchor (`confirmed` vs `finalized`)?
2. Do we need a global dedup store across restarts, or is in-memory dedup enough per process lifetime?
3. What should be default concurrency/chunk sizing per chain (especially ETH log ranges) before adaptive tuning?
