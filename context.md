# Latency work context

Branch: `improve.latency`. Goal: cut **triple**, **presignature**, and especially **full signature e2e** latency (Solana indexing → generation → RPC respond). Signature generation itself is already fast enough; remaining work is the rest of the pipeline.

## Constraint

**Solana stays finalized-only.** Do not index/sign `confirmed` or use geyser/WS to beat finality. The finalized pointer trails tip by up to ~13s (`primitives/src/chain.rs`). That is a floor for user-submit → respond. Docs’ “~4s Solana avg” is **already-finalized → respond**, not user-submit → respond.

User-submit → on-chain respond ≈ **13s finality + ~4s node path**. Do not sell sub-13s e2e without changing commitment.

## Latency budget (happy path, stockpile full)

| Stage | Happy path | Floor | Cuttable |
|---|---|---|---|
| Finality (user tx → finalized) | ~13s trail | ~13s | **no** |
| Indexer poll after new finalized | 0–400ms now (was 1s) | ~400ms frontier | small |
| Organize | ~0 if mesh live | 0 | p99 permit wait |
| Posit | 0 if invite size = t; else ≤50ms slack | 1 mesh RTT | yes |
| Presig peek/fetch | Redis RTT | Redis | poll 500/250ms if empty |
| cait-sith generation | ~1–2s | CPU + mesh RTTs | not the target |
| Publish (`confirmed` send) | ~0.2–0.8s | RPC RTT | retry 1s if first send fails |
| Failover observe | not happy path | finality+15s | p99 only |

## Decisions

- Optimize **all three** (triple / presig / sign e2e), ranked; implement sign p50 first, then p99, keep generation as-is for later e2e cuts.
- Start-at-`t` instead of waiting 500ms for extra Accepts. Original wait was intentional (late accepters burn a round). Compromise: **short slack after t**, not 500ms from Propose.
- Slack is **50ms after t is reached**, and **skipped when invite set is already size t** (extras cannot arrive; totality starts immediately).
- A/B for measurement: `set_wait_for_accept_gather(true)` restores the old 500ms-from-Propose wait (`test-feature` only).

## What landed

### Sign p50

1. **Posit starts at t + slack** (`protocol/request/posit.rs`, `mod.rs`)
   - Production: start when `t` accepts + 50ms slack for extra holders, or immediately on totality / size-t invite.
   - Deliberator Waiting-for-Start floor still `2 * ACCEPT_POSIT_TIMEOUT` (500ms × 2) so Accept stays binding.
   - Tests: `advance_starts_at_threshold_without_waiting_for_totality`, `advance_includes_accepts_arriving_during_slack`, `advance_skips_slack_when_invite_set_is_threshold`.
2. **Solana poll 1s → 400ms** (`chain-solana/src/config.rs`, CLI `MPC_SOL_POLL_INTERVAL_MS` default 400). Still `get_slot_finalized`. Matches ~400ms finalized frontier.
3. **Outbox flush on enqueue** (`protocol/message/outbox.rs`): drain `try_recv` then publish; wait on `contract.wait_participants()` instead of a 10ms tick. Avoids stuck messages when participants are unset.
4. **Publish first-retry 5s → 1s** (`rpc/mod.rs` `PUBLISH_MIN_DELAY`). Happy path is still one send. Failover observe-margin test still holds (`DEFAULT_OBSERVE_MARGIN` 15s > 1s).

Storage wait/notify (replace 500/250/200ms polls) was **skipped** — not on the full-stockpile happy path.

### Sign p99

1. Prefer a presig with **> t active holders** (one extra `peek_mine`) so one `MissingArtifact` is less likely to burn a threshold-sized round (`organize.rs`).
2. Round 0 **20s → 5s** (`ORGANIZE_POSIT_TIMEOUT`). Dead first proposer is cheaper. Later rounds still 2s × 1.15 to 600s.
3. Proposer cap **4 → 8** (`MAX_CONCURRENT_PROPOSERS`).
4. After mesh/permit/presig, **reset posit budget** to a full `round_timeout(r)` so organize waits don’t eat Propose→Start.

### Measurement harness (fixture, not Solana e2e)

- Extra Accepts delayed 300ms on the slowest third (`MpcFixtureBuilder::with_delayed_extra_accepts`).
- `test_sign_p50_improves_on_3_and_8_node_clusters` (`integration-tests/tests/cases/mpc.rs`), `#[serial]`.
- Results (start-at-t vs old 500ms gather; extra Accepts delayed 300ms):

| Cluster | Before | After |
|---|---|---|
| 3-node t=2 | 319ms | 13ms |
| 8-node t=5 | 465ms | 60ms |

That gain is the gather timeout. Solana poll and outbox flush are **not** in this fixture (in-process mock, no indexer).

## Tradeoffs (start-at-t)

- Late accepters after slack still miss `START`, sit in Waiting-for-Start, bump `r+1`, may reserve another presig.
- Generation often runs at exactly `t` if extras miss slack — one drop during cait-sith fails the round.
- At invite size `t`, one `MissingArtifact` still aborts (`rejects > n-t`). Holder-slack peek only helps when some presigs have extras.

## Remaining e2e (generation is not the bottleneck)

**Solana / intake (biggest user-visible remainder, given finalized-only):**

- ~13s finality trail — do not change.
- 0–400ms poll after a new finalized slot — WS/geyser ruled out.
- Catchup gate: live signs dropped until `CatchupCompleted` (`stream/mod.rs`).
- Solana `getSignaturesForAddress` vs `getSlot` split-brain (`indexer.rs` TODO / #777).
- Solana `indexing` metric is 0 (no block timestamp) — Grafana step histograms needed for real p50/p99.

**Posit / organize:**

- Permit wait still charged against organize timeout (budget is reset only after a presig is reserved). Burst can still burn a round if the slot never arrives.
- `Waiting for participants` is unbounded and eats the round (`posit_state_machine.md` §8.7).
- Mesh `active` gated on sync (120s broadcast, 1s ping). Watch-channel TODO: `sync/mod.rs`.

**Publish:**

- Failover observe = chain finality + 15s (`publish_failover.rs`). Slow path only.
- Solana publisher is fire-and-forget `confirmed` send — no extra confirm wait on happy path.

**Stockpile (only when the pool is empty — then it *is* the sign tail):**

- Presig `poke()` on the async runtime (triples already `spawn_blocking`).
- Presig reject `MissingArtifact` instead of waiting for triples.
- Redis `len`/`contains` on the 100ms stockpile tick.
- Storage polls: organize 500ms, sign fetch 250ms, triple fetch 200ms.

Highest remaining leverage: catchup/mesh active, permit vs budget, Grafana breakdown of `multichain_sign_request_latency_sec{chain=solana,step=*}`.

## Key files

- `chain-signatures/node/src/protocol/request/{mod,posit,organize}.rs` — posit, slack, round timeout, proposer cap, presig peek
- `chain-signatures/node/src/protocol/message/outbox.rs` — flush on enqueue
- `chain-signatures/node/src/rpc/mod.rs` — publish retry; `wait_participants`
- `chain-signatures/chain-solana/src/{config,indexer,client}.rs` — poll 400ms, finalized indexer, confirmed publish
- `doc/protocol_properties.md`, `doc/posit_state_machine.md` — L1 / round schedule
- `integration-tests/tests/cases/mpc.rs` — 3/8-node p50 A/B
- `integration-tests/src/mpc_fixture/{builder,fixture_tasks}.rs` — delayed extra Accepts

## A/B / test knobs

- `mpc_node::protocol::request::set_wait_for_accept_gather(true)` — old 500ms-from-Propose gather (`test-feature`).
- `MpcFixtureBuilder::with_delayed_extra_accepts(Duration)` — delay Accepts from the highest third of participants.

Do not run cluster `just reset` / checkpoint wipe. No `git commit` unless asked.
