# Latency work — resume context

Workspace: `/Users/entropy/Cosmos/mpc.improve.latency.artifact`  
Branch: `improve.latency.artifact`  
Constraint from user: **Solana stays finalized-only**. Do not index/sign `confirmed`/`processed`. User-submit → on-chain respond cannot go below ~13s Solana finality trail.

## Goal

Improve latencies for:

1. Triple generation (stockpile refill)
2. Presignature generation (stockpile refill)
3. Full signature e2e (indexer → posit → gen → RPC respond), especially Solana

User asked for **all three, ranked**. Work started at **#3 in the original ranked list = presignature generation** (“Let's start with 3 presignature generation”).

## Ranked plan (do not reorder without new Grafana)

Full writeup was in the earlier session. Short version:

### Signature p50 (after finality; not started)

- Start posit at `t` accepts instead of always waiting `ACCEPT_POSIT_TIMEOUT = 500ms` (`chain-signatures/node/src/protocol/request/mod.rs`).
- Solana poll 1s → ~400ms (`chain-solana/src/config.rs`). Keep `get_slot_finalized`.
- Stop polling storage (presig peek 500ms, sign fetch 250ms, triple fetch 200ms) — wait/notify.
- Outbox wake-on-enqueue instead of 10ms tick (`protocol/message/outbox.rs`).

### Signature p99 (not started)

- Prefer presigs with holder slack; `MissingArtifact` at exactly `t` burns a round (round 0 = 20s).
- Shorter round 0 (20s is expensive for a dead first proposer).
- `MAX_CONCURRENT_PROPOSERS = 4` permit wait charged against round budget.
- Mesh/sync gating `active`; catchup gate + Solana RPC split-brain (`indexer.rs` TODO on `getSlot` vs `getSignaturesForAddress`).

### Presignature generation — **in progress / mostly done**

See “What landed” below.

### Triple generation — not started

Same posit 10s expiry + intro cap 16; Redis on every stockpile tick; outbox 500ms retry; select fast OK subset in Prepare; `len_potential` vs `max_triples` is local Redis not network-wide. Triples already `spawn_blocking` poke. Floor is cait-sith OT/ZK (~30s serial, ~2s parallel).

## What landed (uncommitted)

Files:

- `chain-signatures/node/src/protocol/presignature.rs`
- `integration-tests/benches/presig.rs` (new)
- `integration-tests/Cargo.toml` (`[[bench]] name = "presig"`)

### Presig generator changes

1. **Pair search off the spawner loop.** `peek_mine` runs in a background `JoinHandle` (`spawn_search` / `searching` counts toward `len_introduced`). Stockpile no longer blocks the 100ms tick on Redis.
2. **Wait for triples instead of immediate `MissingArtifact` on Propose.** Deliberator queues `pending_waits`; Accepts if the pair appears, else rejects.
3. **`TRIPLE_WAIT` = 300ms** (was briefly 8s). 8s was sized against proposer posit expiry (10s) so a late pair could still Accept. That parked dead Proposes and blew p99. 300ms covers late Redis `contains` without a near-full posit timeout.
4. **Presig `poke()` stays inline** (not `spawn_blocking`). First attempt offloaded poke like triples; that **hurt 8-node p99** because cheap presig pokes queued behind triple CPU. Reverted. Triples keep `spawn_blocking`; presigs do not.

### Isolated bench

`integration-tests/benches/presig.rs`

- 3-node / t=2 (pregenerated keys) and 8-node / t=5 (live keygen; no 8-node fixture JSON).
- Each node generates 16 owned presigs from prestockpiled triples (`disable_prestockpile` then `stockpile_triples(..., 4)` then `wait().min_mine_presignatures(16)`).
- Samples from `/bench/metrics` → `PRESIGNATURE_LATENCY` (`start_time` of generator run → `Action::Return`). Does **not** include posit wait or `TRIPLE_WAIT`.

Run:

```sh
# from artifact root; Docker required
./build-contract.sh
mkdir -p target/wasm32-unknown-unknown/release
cp target/near/mpc_contract/mpc_contract.wasm target/wasm32-unknown-unknown/release/mpc_contract.wasm
cargo build -p mpc-node --release --features test-feature,debug-page,bench
MPC_SETUP_SKIP=1 cargo bench -p integration-tests --bench presig
```

Or `./bench.sh` (also runs sign + store benches).

## Bench results (same machine, sequential)

`PRESIGNATURE_LATENCY` wall time, all nodes pooled.

| Cluster | variant | n | mean | p50 | p99 |
|---|---|---|---|---|---|
| 3n/t2 | original | 144 | 10 ms | 8 ms | 24 ms |
| 3n/t2 | 8s wait + spawn_blocking poke | 144 | 11 ms | 9 ms | 22 ms |
| 3n/t2 | **current (300ms wait, inline poke)** | 144 | 11 ms | 9 ms | 21 ms |
| 8n/t5 | original | 1671 | 929 ms | 660 ms | 3.17 s |
| 8n/t5 | 8s wait + spawn_blocking poke | 1694 | 734 ms | 460 ms | **4.37 s** (p99 worse) |
| 8n/t5 | **current (300ms wait, inline poke)** | 1584 | **732 ms** | **605 ms** | **2.35 s** |

3-node is noise (~10 ms already). 8-node current vs original: mean −21%, p50 −8%, p99 −26%.

Criterion also printed 8-node current vs previous (8s) run as ~21% faster mean; that comparison is vs the 8s variant, not original.

## Do not

- Confirmed/processed Solana indexing.
- Cluster `just reset` / checkpoint wipe (AGENTS.md restricted).
- `git commit` unless asked.
- Raise `min_triples` / `min_presignatures` as a “latency fix”.
- Touch publish failover `observe_lag = finality+15s` for p50.

## Next (when resuming)

Priority after presig:

1. **Signature p50:** start-at-`t` posit (all chains), Solana `poll_interval` ~400ms, outbox wake-on-send, storage wait instead of poll.
2. **Signature p99:** holder slack, shorter round 0, permit vs round budget.
3. **Triples:** same non-blocking propose / intro-cap hygiene; keep `spawn_blocking` poke.

Optional presig follow-ups:

- Abort `pending_waits` when the posit already expired instead of waiting out 300ms.
- Redis notify instead of 50ms poll in `wait_for_triples`.
- Grafana: `multichain_presignature_latency_sec`, `before_poke`, `accrued_wait`, `poke_cpu` on a real cluster — isolated bench is localhost HTTP mesh.

## Key files

| Path | Why |
|---|---|
| `chain-signatures/node/src/protocol/presignature.rs` | Generator + spawner (this work) |
| `chain-signatures/node/src/protocol/triple.rs` | Pattern for `spawn_blocking` poke; stockpile twin |
| `chain-signatures/node/src/protocol/request/mod.rs` | Sign posit timeouts / 4 proposers |
| `chain-signatures/node/src/protocol/request/organize.rs` | Presig peek 500ms poll |
| `chain-signatures/chain-solana/src/config.rs` | 1s finalized poll |
| `chain-signatures/node/src/protocol/message/outbox.rs` | 10ms batch / 500ms retry |
| `doc/posit_state_machine.md` | Round schedule, MissingArtifact |
| `integration-tests/benches/presig.rs` | Isolated 3n/8n bench |
| `integration-tests/benches/sign.rs` | Old e2e sign bench (NEAR cluster, incidental presig samples) |

## Session notes

- User: keep Solana finalized-only; optimize all three ranked.
- User: start with presignature generation.
- User: add isolated 3-node and 8-node presig bench; run it; then fix p99.
- No commit yet. Restore patched `presignature.rs` is the working tree (not HEAD).
