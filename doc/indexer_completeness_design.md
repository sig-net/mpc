# Indexer completeness: same events on every node, by construction

Status: design proposal. Scope: ingestion only — no contract changes, no checkpoint
format changes.

## 1. Problem

Each node runs its own per-chain indexer that turns chain activity into
`ChainEvent`s and inserts sign requests into a per-node `Backlog`. Periodically
each node snapshots that backlog into a `Checkpoint` and votes its digest on the
NEAR contract; threshold agreement settles the consensus checkpoint, and a node
whose digest disagrees must regress to the consensus body fetched from a peer
(`chain-signatures/node/src/backlog/consensus.rs`).

This converges *provided at least a threshold of nodes indexed the same events*.
It does not guarantee that. Three concrete gaps:

1. **Hydration reconnect drops history.** On WS drop or stall the hydration
   indexer reconnects and resumes from the live finalized head. Blocks produced
   while disconnected are never replayed — a sign request in a missed block is
   lost to that node. There is no persisted position marker at all: the
   hydration indexer never calls `get_processed_block` / `set_processed_block`.
   (`chain-signatures/node/src/indexer_hydration/mod.rs:464-491`)
2. **Skips surface late, or never.** Checkpoints are minted only on
   interval-boundary crossings (`node/src/backlog/mod.rs:530-542`). A skipped
   request inside a bucket waits for the next boundary to be noticed — and if
   the node's reduced set coincidentally matches (e.g. the request was already
   responded on-chain), no divergence is detected and the request is silently
   never signed.
3. **The checkpoint digest conflates two jobs.** `Checkpoint::digest()` hashes
   the pending-request set *and* their protocol statuses
   (`node/src/backlog/checkpoints.rs:62-71`). So the vote agrees on
   "what exists" and "how far execution got" simultaneously, and the regression
   path has to repair both.

The checkpoint system is not wrong — it is doing double duty as the
convergence mechanism for a problem that should not exist. Fix ingestion, and
the checkpoint goes back to agreeing on progress only.

## 2. How other projects solve this

| Project | Mechanism | Lesson |
|---|---|---|
| Wormhole | Every guardian runs its **own full node** and reads events from canonical chain data. Messages carry a **monotonic per-emitter sequence number**, so missing a message is locally decidable. A guardian that sees a gap sends a signed **re-observation request** over gossip and fills it from peers. | Completeness is decidable from the chain itself; recovery is peer-assisted, per-message. |
| Axelar | Validators submit per-message attestations into Axelar's own PoS chain; the **chain's consensus** produces the agreed event set. | Agree per-message, not per-set. |
| Chainlink CCIP | DONs commit a **Merkle root of a sequence-numbered message queue** on-chain; execution verifies against the committed root. | The "set" is a sequenced structure anchored on-chain. |
| LayerZero | **Nonce ordering enforced on-chain** by receiving contracts. | The chain, not the relayer, defines completeness. |

No major system relies on a best-effort live subscription for correctness, and
none of them need set-level consensus when each message's position in a
canonical ordering is known.

## 3. Design principle

**A node may advance its position marker only after issuing a query that is
provably complete for the skipped range.**

Consequences:

- Live subscriptions (WS, filters, lake streams) are a **latency optimization**,
  not the correctness path. Delivery failures cost latency, never events.
- Correctness comes from **anchored replay**: on start and on reconnect, resume
  from the persisted marker and re-issue a completeness-preserving query up to
  the head before following live.
- Completeness-preserving does **not** mean re-reading every block. Filtered
  historical primitives (`eth_getLogs(from,to,address,topics)`,
  `getSignaturesForAddress`, ledger offsets, lake block positions) are complete
  over a range by definition, assuming an honest full-node endpoint.
- If every node implements this, `processed through block H` implies an
  identical event set on every node: the set is a pure function of canonical
  chain data. "Same events" becomes a theorem instead of something we vote on
  after the fact.

Overlap between the live feed and the replay window is expected and harmless:
ingestion is already deduplicated by `SignId`
(`node/src/backlog/mod.rs:207`, `stream/ops.rs:16`).

## 4. Reference pattern (already exists: Ethereum)

`chain-signatures/chain-ethereum/src/indexer.rs:395-477` implements exactly
this contract:

1. Read persisted marker: `state_manager.get_processed_block(Chain::Ethereum)`,
   `next = marker + 1` (or anchor at tip on first run).
2. Sample anchor = startup tip + 1; `CatchupIter` replays `[next, anchor)`
   in batches, bloom-gated so empty blocks cost one `eth_getBlockByNumber`
   batch and zero `eth_getLogs` calls.
3. Emit `ChainEvent::CatchupCompleted`; the stream layer holds pre-catchup
   events in the backlog and requeues on completion
   (`node/src/stream/mod.rs:57-92`).
4. Live tail processes each subsequent block only once the finalized-head
   watcher covers it (`wait_processable_bound`), which doubles as the
   reorg/finality gate. Missing batch items are refetched individually.

Solana follows the same shape (live `logs_subscribe` + RPC-history catchup of
`[persisted_block, anchor)`, no in-place resubscribe so supervisor restarts
re-catchup with no gaps — `chain-solana/src/indexer.rs:432-450`). Canton
resumes its WS `GetUpdates` subscription from the persisted ledger offset
(`begin_exclusive`, `chain-canton/src/indexer.rs:179-208,333-345`). Midnight
catchups from its persisted checkpoint then runs the live finalized loop
(`chain-midnight/src/indexer.rs:1`).

The work is converging the remaining two chains on this pattern, not inventing
it.

## 5. Per-chain status and target

| Chain | Today | Target |
|---|---|---|
| Ethereum | Anchored replay + live tail gated on finalized head. Reference implementation. | None. Maybe start catchup from contract-deploy block instead of anchor (open TODO, sig-net/mpc#777). |
| Solana | Anchored catchup from persisted block. | Fix the `get_slot`-failure path where anchor/catchup never runs (`chain-solana/src/indexer.rs:474-476`). |
| Canton | WS `GetUpdates` resumes from persisted `begin_exclusive` offset with catchup to target. | Audit only: verify the reconnect path preserves the offset across supervisor restarts and that the catchup-timeout fast-forward (`indexer.rs:300-311`) cannot skip party-relevant updates. |
| Midnight | Catchup from persisted checkpoint + live finalized loop. | Audit only: confirm marker write happens before event emission (see §7) and crash windows are covered by tests. |
| Hydration | **WS-only, no marker, no replay. This is the gap that motivated this doc.** | §6. |
| NEAR | Polls contract view state `pending_requests_data` for the pending queue — inherently resumable since it reads current state, not a stream. | Audit: a request created *and* fully served between two polls never appears in the queue, so view-polling has a blind window. Either anchor event ingestion on block height (lake/framework stream position as the marker, same contract as §3) or prove the window is closed by other means. `chain-near/src/indexer.rs:84-94`. |

## 6. Hydration plan (the actual change)

WS on the hydration endpoint is unreliable, and work is underway to move
hydration ingestion toward eth-style filtered RPC. The design must survive both
transports, so the transport sits behind the same anchored-catchup contract
rather than being trusted for completeness.

Interim (Substrate-native scan):

- Track a persisted `last_processed_block` for the hydration chain via the
  existing `StateManager` (`get/set_processed_block`), exactly like Ethereum.
- On start and on every reconnect/stall, replay finalized blocks
  `[marker + 1, head]` by fetching each block's event section and extracting
  sign-request events, keeping the existing Merkle read-proof verification
  (`indexer_hydration/mod.rs:281`) so the scan stays trust-minimized against a
  dishonest RPC. This is event-section reads, not execution — modest cost.
- The existing 5s reconnect delay / 60s stall watchdog
  (`indexer_hydration/mod.rs:383-491`) becomes a *latency* trigger that always
  re-enters the replay path instead of resuming at the live head.

Target (eth-style):

- Once an `eth_getLogs`-equivalent filtered log API is available for the
  hydration contract, replace the per-block scan with range-bounded filtered
  queries `[marker + 1, head]`. The marker semantics, replay entry points, and
  tests do not change — only the range-query implementation does, behind the
  same per-chain indexer trait (`mpc-chain-integration-core::ChainIndexer`,
  `chain-integration-core/src/indexer.rs`).
- Keep proof verification if the eth-style endpoint supports it; otherwise the
  finalized-head gate plus a full-node trust assumption matches what the
  Ethereum indexer already accepts.

Either way: **the WS feed, if kept, is demoted to a hint** that wakes the
replay loop. No code path is allowed to advance the marker on subscription
delivery alone.

## 7. Edge cases (applies to every chain, including the reference ones)

- **Marker write ordering.** Persist the marker only after the block's events
  are durably enqueued (write-ahead in the other direction: emit first, then
  advance). A crash between emission and marker write replays one block on
  restart; dedup by `SignId` absorbs it. The reverse order loses events.
- **Finality gating.** Replay and live tail must cover the same finality the
  checkpoint assumes. Ethereum gates on the finalized-head watcher; every
  chain needs the equivalent (Solana commitment level, lake finality, ledger
  offsets are already final by construction on Canton).
- **Historical window clamping.** RPCs bound how far back filtered queries go.
  Ethereum already clamps (`clamp_oldest_supported`); a clamp that bites means
  the node can no longer prove completeness — surface it as a loud,
  non-voting state rather than silently resuming. Checkpoint voting while
  unable to prove completeness is how divergence starts.
- **Multi-event blocks and ordering.** Events within a block must be emitted in
  canonical order so all nodes build identical backlogs; the digest is
  order-sensitive.
- **One stall authority.** Canton already notes its 60s WS timeout overlaps the
  supervisor's per-chain `live_block_timeout` watchdog
  (`chain-canton/src/indexer.rs:37-39`). Consolidate: exactly one component
  decides "stalled" and exactly one action follows — re-enter replay.

## 8. What happens to checkpoints

Nothing changes in format or voting, but the semantics get simpler:

- With deterministic ingestion, two honest nodes at the same processed height
  hold identical request sets. The digest vote becomes an **anomaly detector**
  (a mismatch now means a bug, a lying RPC, or a chain reorg past finality —
  all worth paging on) instead of the routine convergence mechanism.
- The consensus-body regression path (`backlog/consensus.rs:71-118`) stays as
  the disaster-recovery path for those anomalies. It stops being load-bearing
  for ordinary disconnects.
- Deliberately out of scope: per-message attestation voting (Axelar-style) and
  monotonic sequence-number gap detection (Wormhole-style, needs a contract
  counter on `sign` events). Either can be layered later; neither is required
  once §3 holds.

## 9. Rollout and tests

1. Hydration: add marker + replay-on-reconnect; unit tests with a mocked WS/RPC
   server that drops the connection mid-stream and asserts the missed range is
   replayed exactly once (dup-tolerant).
2. Per-chain audits (§5 table): close the Solana anchor TODO, verify Canton
   offset survival across restarts, verify Midnight marker ordering, resolve
   the NEAR poll blind window.
3. Component test via `MpcFixture` (`integration-tests/src/mpc_fixture`, cf.
   `integration-tests/tests/cases/mpc.rs`): kill one node's chain connection
   while sign requests are emitted, restore it, assert all nodes converge on
   identical checkpoints **without** any node taking the regression path
   (assert no "divergence detected" log / no peer-body fetch). A test needing
   redis belongs in `integration-tests` per repo rules.
4. Long-running: never run the full integration suite — one fixture test at a
   time (`just to <name>`).
