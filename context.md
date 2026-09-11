# SignQueue / backlog scheduler

Working context for [sig-net/mpc#1145](https://github.com/sig-net/mpc/issues/1145)
and the scheduler work on this branch (`mpc.typestate.scheduler`).

## Problem

Large backlogs (+40k requests) OOMed ~1.2 GiB devnet machines. Two leaks:

1. **The OOM.** Every backlog entry was mirrored as a `SignEntry` + tokio
   `SignTask` in `SignatureSpawner`. Catchup then bulk-requeued all of them
   onto a 16k `SignCommand` channel (`MAX_SIGN_COMMANDS`).
2. **Checkpoint clones.** Pending checkpoints (`MAX_PENDING_CHECKPOINTS = 32`)
   duplicate full `BacklogEntry` bodies. Not the OOM; follow-up.

Issue 1145’s long-term idea: backlog is the only request store; spawn lazily;
drop-to-abort. This branch implements that as a **queue view**, not by putting
`JoinHandle`s on `BacklogEntry` (that type is `Clone + Serialize` and
snapshotted into every checkpoint).

## Decisions (locked)

| Question | Choice |
|---|---|
| Live cap `N` | **4 live tasks total** (`MAX_LIVE_TASKS`), any role. Not 4 proposers + unlimited deliberators (old `SignLimiter`). Not 4 per chain. |
| Priority | FIFO by `(unix_timestamp_indexed, request_id)`, **fair across chains** (fewest-live chain first; ties keep `Chain::iter` order). |
| Posit bypass | Yes. A posit for an **indexed** id admits/wakes immediately (or steals). |
| Catchup | **Deliberators only.** Proposer `fill()` waits until the chain is live. |
| Spawner ↔ backlog | Spawner never uses `Backlog` directly. Only [`SignQueue`](chain-signatures/node/src/protocol/request/queue.rs). |

Cold start cannot be “oldest N of any role”: those 4 slots would fill with
idle deliberators. Fill only admits ids where **this node is the round-0
proposer** (`proposer_per_round(0, membership, entropy)` — D2, same inputs as
`organize.rs`). Deliberators enter only via posit-wake.

## Architecture

```
indexer ──insert──► Backlog (durable + SignStatus, checkpointed)
                      ▲
                      │ get / wait / park / next_proposers
                      │
posit ──► Spawner ── SignQueue
              │
              ├─ indexed? admit deliberator (N, steal Organizing only)
              └─ not yet?  wait on insert (do not spawn, do not ACCEPT)

fill() after live + free slot:
  next_proposers(N), fair per-chain, FIFO, live chains only
```

### Durable vs live

- **Durable** (checkpointed): `BacklogEntry` = `Arc<IndexedSignRequest>` + `SignStatus`.
- **Live** (RAM, dies with `remove()` / `release_live`): `LiveSlot` (`AbortHandle` via `JoinMap`, `PositMailbox`, `carried_round`, delay watch, `LivePhase`).

Do not put handles on `BacklogEntry`.

### SignQueue API

On `SignQueue` (view over `Backlog`):

- `get(id)` / `wait(id)` — existing entry, or notify on insert (per-id; waiter cap 4096, D5)
- `park(request)` — insert if missing (Near / `SignCommand::Request`)
- `next_proposers(n, me, participants, live, live_by_chain, live_chains)` — parked, not live, this node is round-0 proposer; only `live_chains`; fair then FIFO
- `subscribe_index()` — tick on insert so the spawner can admit buffered posits
- `mark_publishing` — pass-through for generation (generation still holds `Backlog` today)

Spawner owns admit / steal / fill:

- `admit` — live.len() < 4, governance Running
- `wake_deliberator` — steal **Organizing** only if full
- `fill_proposers` — after `ChainLive`, task exit, insert-notify, `Request`
- `release_live` / `retire_task` — drop slot; completion also marks `dead_ids`

### Catchup

Old: `try_enqueue` dropped pre-catchup commands; `CatchupCompleted` dumped
every pending-generation id onto the 16k channel.

Now:

- Insert still parks during catchup (no `SignTask`).
- `CatchupCompleted` sends **`SignCommand::ChainLive(chain)`**, not a flood of `Request`.
- Deliberators may go live during catchup (posit-wake / wait-on-index).
- Proposer fill waits until that chain is in `live_chains`.
- A catchup-spawned task that `reorganize()`s **must not propose**:
  `SignTask.chain_live` is checked in Organizing (`proposer == me && chain_live`).

Near has no catchup barrier. A `SignCommand::Request` also marks that chain live
so Near can fill.

### Invariants

- **S2.** No share, ACCEPT, or Start handling until `queue.get(id)` succeeds. Unknown-id posit: buffer mailbox, `wait(id)`, never spawn.
- **S3.** Hold all admits while governance is not Running. Governance change respawns **live** only; parked stay parked.
- **Generation non-preempted.** Steal only `LivePhase::Organizing`. Abort must drop any presignature reservation (existing task abort).
- **Catchup.** Deliberators yes, proposers no, including after `reorganize`.
- **D5.** Cap unknown-id waiters (`MAX_INDEX_WAITERS = 4096`). Mailbox map for unknown ids is still only bounded by `dead_ids` LRU 4096 after completion — residual hole from `protocol_properties.md`.
- **Checkpoints.** Digest is still ids + `consensus_tag` only. Do not persist round / queue position.

## What changed (this work)

| Before | After |
|---|---|
| Eager `spawn_task` on every `Request` | Park; admit ≤ 4 |
| `SignEntry.request` mirror of backlog | Live slot only for admitted ids |
| Per-chain `SignLimiter(4)` inside Organizing | Admission **is** the cap (4 **global**) |
| Catchup dumps `take_requeueable_requests` | `ChainLive`; queue peeks |
| Spawner holds `Backlog` | Spawner holds `SignQueue` |

Generation (`SignGenerator` / `GenerateCtx`) still takes `Backlog` for
`mark_publishing`. That is status, not scheduling.

## Tests

Unit (`cargo test -p mpc-node --lib -- protocol::request stream::`):

- FIFO + fair fill (`next_proposers_fair_and_fifo`)
- Skip non-proposers on cold start
- Wait-then-admit on insert
- Steal Organizing, not Busy
- Abort-chain dead-ids lifecycle
- Catchup emits `ChainLive`, not a bulk `Request` dump

Integration tests that waited for catchup to flush `Request`s now treat
`ChainLive` as that flush (`ethereum_stream` linear catchup / late watcher).
Solana helpers already ignore non-`Request` commands.

## Still open / follow-ups

- **`LivePhase::Busy` is never set.** Steal currently sees every live task as
  Organizing. Wire Organizing → Posit/Generating to `Busy` (or the steal
  “Organizing only” rule is a no-op).
- **Unknown-id mailbox map** still unbounded until the id is indexed or later
  hits `dead_ids` (documented D5 hole).
- **Checkpoint intern.** Cap 32 still clones full entries; intern `Arc` across
  pending checkpoints separately from this scheduler.
- **Typestate `Parked | Live | Publishing`.** Status-transition TODO at
  `backlog/mod.rs` (~365) is orthogonal; do not block on it.
- **`SignQueue::mark_publishing`** is unused; generation still uses `Backlog`.
- Near still sends `Request` and skips stream insert; `park()` + mark-live
  covers it, but Near never emits `ChainLive`.
- `JoinMap::spawn` still overwrites a duplicate key without aborting the old
  handle — admit/live-map should prevent that; keep the gotcha in mind.

## Key files

- `chain-signatures/node/src/protocol/request/queue.rs` — `SignQueue`, steal, tests
- `chain-signatures/node/src/protocol/request/mod.rs` — spawner reactor
- `chain-signatures/node/src/protocol/request/organize.rs` — `chain_live` gate; `proposer_per_round` is `pub(crate)`
- `chain-signatures/node/src/backlog/mod.rs` — insert/remove wake waiters; `wait_indexed`; checkpoint restore wakes
- `chain-signatures/primitives/src/requests.rs` — `SignCommand::ChainLive`
- `chain-signatures/node/src/stream/ops.rs` — catchup → `ChainLive`
- `doc/protocol_properties.md` — S2, D5
- `doc/posit_state_machine.md` — round machine (unchanged; still not in the backlog)
