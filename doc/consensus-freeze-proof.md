# Proof: consensus checkpoints are frozen because no two nodes ever compute the same checkpoint digest

**Claim.** Checkpoint consensus requires ≥ threshold nodes to threshold-sign the *same* digest (`sign_id` is a hash of the digest, and a node only participates in signing a `sign_id` it derived itself). `Checkpoint::digest()` hashes the full CBOR of every pending `BacklogEntry` — which contains node-local data (wall-clock `unix_timestamp_indexed`, live `SignStatus`, `PublishState.is_proposer`). So honest, in-sync nodes compute different digests, no checkpoint ever reaches quorum, and the value stored on NEAR has not moved in ≥ 30 days (Canton stuck at 533730, Ethereum at 11243900, while local heights are ~29k/~37k ahead).

## Exhibit A — same second, same chain state, 7 nodes, 7 different fingerprints

GCP dev cluster, `jsonPayload.message="created checkpoint"` (the logged `signId` is a pure hash of that node's digest):

### Canton, offset 561450 — all 7 nodes within the same second

| indexed at (UTC) | node | checkpoint sign_id |
|---|---|---|
| 2026-07-15T22:53:49Z | multichain-dev-0 | `72326b6c4c3bbf6a…` |
| 2026-07-15T22:53:49Z | multichain-dev-10 | `b8f00b6b5a5fac53…` |
| 2026-07-15T22:53:49Z | multichain-dev-11 | `57da7184e71c1506…` |
| 2026-07-15T22:53:49Z | multichain-dev-3 | `0f2678105b7ad308…` |
| 2026-07-15T22:53:49Z | multichain-dev-6 | `107852cf1c1df3e1…` |
| 2026-07-15T22:53:49Z | multichain-dev-8 | `a94e1e614c6e0e84…` |
| 2026-07-15T22:53:49Z | multichain-dev-9 | `9d3bc56de78fc528…` |

**7 distinct sign_ids of 7 nodes** — threshold signing can never assemble. Across a 12h window this holds at **58 of 58** heights where ≥2 nodes checkpointed the same block (25/25 Canton, 33/33 Ethereum). Crucially, on Ethereum the pending **request-id sets are byte-identical across all 7 nodes at all 33 heights** — nodes agree perfectly on *which* requests are outstanding; only the node-local serialized bytes differ.

## Exhibit B — the consequence, independently verifiable

- 30 days of log retention contain **zero** `"consensus checkpoint confirmed and persisted"` at any height other than 533730 (Canton) / 11243900 (Ethereum).
- 14 days contain **zero** NEAR checkpoint publish attempts, successes, or errors (`mpc_chain_near::publisher` is silent) — no checkpoint signature has ever completed; the write path is never reached.
- Self-serve check: `near view <mpc-contract-id> read '{"reads":["Checkpoints"]}'` — the stored heights don't move; the contract's `respond_checkpoint` call history (e.g. nearblocks) pins the exact date of the last update.
- Knock-on (same root): every restart recovers to the ancient checkpoint and replays ~29k blocks; and unconfirmed checkpoints pile up to `MAX_PENDING_CHECKPOINTS=32`, whose `has_checkpoint_slot` gate then **halts chain indexing** — 343/343 watchdog lines in 48h show `pendingCheckpoints: 32, hasCheckpointSlot: false`, all 7 nodes, both chains (Canton cycling every 5.3 min, Ethereum every 35 min — the exact per-chain watchdog constants).

## Exhibit C — why it's structural (code)

- `primitives/src/backlog.rs:65-74` — `digest()` hashes `pending.transaction` = full CBOR of `BacklogEntry` (request **+ live status**).
- Node-local fields in those bytes: `unix_timestamp_indexed` stamped with `SystemTime::now()` at parse time (`chain-canton/src/events.rs:15,62`; `chain-ethereum/src/event_parsing.rs:150`); `SignStatus` advances per-node asynchronously; `PublishState.is_proposer` is true on exactly one node by definition (`node/src/sign_bidirectional.rs:14-18`).
- The repo's own unit test **asserts** the divergence: `test_checkpoint_digest_changes_with_status` (`node/src/backlog/mod.rs`) — two nodes holding the same request in different phases are *required* to produce different digests.
- A canonical digest helper exists and is dead code (`SignStatus::digest_bytes`, `sign_bidirectional.rs:54` — zero callers): apparent incomplete refactor.
- Verified by demo test (2026-07-16): two `PendingRequests` holding the same request, differing only by 1 second of `unix_timestamp_indexed` clock skew — or only by the `is_proposer` flag — produce entirely different digests. (The proper inverted regression tests live on the digest-fix branch.)

## Reproduce Exhibit A yourself

```
resource.type="k8s_container"
resource.labels.cluster_name="dev"
resource.labels.container_name="multichain"
jsonPayload.message="created checkpoint"
```
Any recent window; group by `(jsonPayload.chain, jsonPayload.block)` and compare `jsonPayload.signId` across `resource.labels.pod_name`.

## Origin (git)

Born nearly-right, broken in a refactor, feature shipped on the broken form:

1. **2026-05-29, PR #830** — checkpoints introduced; the digest decoded entries and hashed canonical bytes (`sign_id + status.digest_bytes()`).
2. **2026-06-04, `cae9bbaa`** — `Checkpoint` moved to `mpc-primitives`, `BacklogEntry` stayed in `mpc-node`, so the decode-based digest couldn't come along; replaced with hashing the raw CBOR. Timestamps + all per-node state silently entered the hash; `digest_bytes()` has been dead code since.
3. **2026-06-19, PR #847** — the NEAR consensus loop shipped on top. The feature (27 days old) only ever agreed at empty/quiescent boundaries in its first days — hence the frozen values.

## Fix and status

Hash only what every node derives identically from the chain: `(version-tag, chain, height, sorted request-ids)` — the full entry bytes stay in the checkpoint for recovery, they just leave the hash. Exhibit A's Ethereum data shows this is sufficient: the id-sets already agree 7/7.

**The core change already exists**: `origin/xiangyi/fix-checkpoint-digest-consensus` (`5e0ceedb`, 2026-07-13) drops the raw bytes from the hash and inverts the tests. **Do not deploy it bare**: the old-format digest is still stored on NEAR, and upgraded nodes that can't match it hang forever in the peer-fetch regression loop (which runs before any watchdog) — a full-cluster brick. Two migration options: (a) node-side legacy-digest fallback when matching the stored value (~30 lines, zero on-chain coordination — the mainnet-grade pattern); (b) devnet shortcut: `near call <contract> reset_checkpoint '{"chains":["Canton","Ethereum"]}' --accountId <contract>` (the `#[private]` admin method already in the contract, `lib.rs:1113`) — clears the stored value, alignment short-circuits, and even already-hanging nodes self-recover the moment the value empties. Keep node Redis so the last replay is ~29k blocks instead of from offset 0.

Follow-ups that turn "unfrozen" into "clean" (design + rationale in `consensus-freeze-findings.md`): un-gate indexing from the 32-checkpoint cap (today it halts the chain pipeline — all 7 nodes cycle `pendingCheckpoints: 32` watchdog restarts on both chains); make verified settlement events remove backlog entries regardless of phase (closes the replay-zombie factory); idempotent insert on replay; and drain the ~18 fossil deposits via height-based expiry and/or offset-anchored ACS reconciliation. Full root-cause writeup and layered fix design: `consensus-freeze-findings.md`.
