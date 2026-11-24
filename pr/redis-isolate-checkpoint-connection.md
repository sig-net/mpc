## Description

Follow-up to the merged-pool refactor (`redis-skip-recycle-ping`). That refactor replaced up to 20 sockets per storage handle with a single multiplexed `redis::aio::ConnectionManager` per pool. A paired 3-repeat checkpoint A/B against the pre-refactor base showed `concurrent_take_triple_with_checkpoint` p50 +66.5%, p95 +81.2%, goodput -40.0%, and `checkpoint_read` p50 +12.8%, goodput -9.2%. The plausible cause is head-of-line blocking: ~30 MB checkpoint GET/SET payloads share the same multiplexed socket as the small, latency-sensitive artifact commands, so a large checkpoint transfer stalls unrelated work.

This PR gives checkpoint storage its own `redis_pool::Pool` (and therefore its own multiplexed `ConnectionManager`), separate from the artifact pool, in both the production node (`StorageHandles::new`) and the benchmark harness (`SimulatedParticipant::checkpoint_pool`). Triples, presignatures and the Midnight DUST checkpoint stay on the existing artifact pool. Key layout, Lua scripts, command sequences and timeouts are unchanged; only the connection used for checkpoint commands differs. The benchmark harness mirrors the production split so its measurements reflect production behavior. This branch is based on `redis-skip-recycle-ping` (parent commit `20002d99`), so it includes that branch's changes. See `doc/redis-connection-pooling.md` for the design and tradeoffs.

When opening the PR, use a `!` in the title (e.g. `perf(redis)!: ...`) because the Operator box is ticked.

## Breaking changes

<!--
Tick `None` or every type that applies. For each breaking type, replace
[details here] with what breaks and what users must do. This text is copied into the release notes.
Code behind an `unstable-*` feature or a disabled gate is not breaking.

Mark breaking PRs with `!` in the title (e.g. `feat(node)!: ...`) so the
squash commit records it in git history. CI checks the section against the title.

Network–Applications: only additive changes (new flows) are allowed.
-->

- [ ] None
- [ ] Node–Node: [details here]
- [ ] Contract–Node: [details here]
- [ ] Contract state: [details here]
- [ ] Network–Applications: [details here]
- [x] Operator (flags, env vars, config, storage migration): no flags, env vars or stored data change. Each node/participant now opens **one additional multiplexed Redis TCP connection** (two total: one for artifacts, one for checkpoints) instead of one. The pool concurrency bound applies per pool, so the effective in-flight limit for Redis commands across a node can double. Operators should account for one extra Redis client connection per node and per benchmark participant; existing Redis `maxmemory`/`maxclients` sizing should be checked. The diagnostics `Pool:` line still reports one shared connection per pool.

## Design

<!-- Tick exactly one and replace the [link]. Non-trivial changes need a design doc in doc/. -->

- [ ] Trivial: no design decision involved (CI, tests, tooling, dependencies, refactor without behaviour change)
- [ ] Follows the existing design in [doc/](https://github.com/sig-net/mpc/tree/develop/doc)
- [x] Adds or changes the design; docs updated in this PR or in: [doc/redis-connection-pooling.md](../doc/redis-connection-pooling.md)
- [ ] Non-trivial, but this area has no design doc yet; tracked in: [issue link]

## Performance results

Benchmark command (identical settings to the parent and baseline runs, with the external Cargo target dir used for build artifacts):

```sh
mkdir -p tmp
set -o pipefail
CARGO_TARGET_DIR=/private/var/folders/9r/zs_bh5_90rj11vlw571bfs8c0000gn/T/opencode/redis-bench-target cargo run --release -p integration-tests --bin redis-bench -- --redis-url redis://default:bench@127.0.0.1:6399 --allow-external-redis --json-out tmp/redis-isolate-checkpoint-connection.json --csv-out tmp/redis-isolate-checkpoint-connection.csv 2>&1 | tee tmp/redis-isolate-checkpoint-connection-run.log
```

- Local standalone Redis 8.4.0 at `redis://default:bench@127.0.0.1:6399` (same server as the parent run). `PING` returned `PONG` immediately before the run; no `BUSY` events occurred during the run and Redis was still healthy afterwards.
- Commits compared: **parent `20002d99ef77dcf11192a831e64349780638ee55`** (`redis-skip-recycle-ping`, `tmp/redis-skip-recycle-ping-final.csv`) vs this branch (`tmp/redis-isolate-checkpoint-connection.csv`). This parent comparison is **primary** because it isolates this change. Baseline `ff9bb300833a15ada23529b172c67e45ac90a0c0` (`continuous.redis.bench`, `tmp/baseline.csv`) is shown for context only.
- New run: release build, full 46-operation suite, ~1m07s of benchmark log timestamps (`2026-11-24T19:22:27Z` → `19:23:34Z`), all 46 records exported, `cargo run` exit 0.
- **Lower latency (p50/p95, ms) and higher goodput (operations/sec) are better.** Deltas are signed `(new − parent) / parent` using CSV values verbatim: negative p50/p95 (faster) and positive goodput (more work) are improvements. `n/a` means the CSV had no percentile (too few samples).

| Operation | Parent p50 | New p50 | Δp50 | Parent p95 | New p95 | Δp95 | Parent goodput/s | New goodput/s | Δgoodput/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `concurrent_insert_triple` | 0.37 | 0.38 | +2.7% | 0.84 | 0.52 | -38.1% | 27717.3 | 29787.5 | +7.5% |
| `concurrent_take_triple` | 0.22 | 0.23 | +4.5% | 0.26 | 0.37 | +42.3% | 53865.4 | 48043.2 | -10.8% |
| `concurrent_insert_triple_no_poll` | 0.36 | 0.36 | +0.0% | 0.39 | 0.50 | +28.2% | 33146.6 | 31507.5 | -4.9% |
| `concurrent_take_triple_no_poll` | 0.23 | 0.32 | +39.1% | 0.36 | 1.08 | +200.0% | 48366.4 | 25758.6 | -46.7% |
| `concurrent_insert_triple_with_poll` | 0.35 | 0.35 | +0.0% | 0.42 | 0.51 | +21.4% | 33203.4 | 31971.2 | -3.7% |
| `concurrent_take_triple_with_poll` | 0.22 | 0.22 | +0.0% | 0.27 | 0.35 | +29.6% | 53157.4 | 50479.4 | -5.0% |
| `concurrent_insert_triple_no_checkpoint` | 0.37 | 0.35 | -5.4% | 1.00 | 0.42 | -58.0% | 25385.7 | 33914.2 | +33.6% |
| `concurrent_take_triple_no_checkpoint` | 0.22 | 0.22 | +0.0% | 0.26 | 0.29 | +11.5% | 53781.2 | 54510.3 | +1.4% |
| `concurrent_insert_triple_with_checkpoint` | 207.70 | 68.49 | -67.0% | 361.94 | 142.74 | -60.6% | 54.1 | 157.9 | +191.9% |
| `concurrent_take_triple_with_checkpoint` | 122.25 | 34.30 | -71.9% | 250.73 | 77.57 | -69.1% | 90.0 | 318.4 | +253.8% |
| `checkpoint_write` | 143.59 | 208.09 | +44.9% | 223.62 | 377.72 | +68.9% | 78.7 | 53.9 | -31.5% |
| `checkpoint_read` | 247.02 | 341.03 | +38.1% | 385.14 | 621.51 | +61.4% | 48.2 | 33.4 | -30.7% |
| `remove_outdated_storm` | 6.12 | 8.93 | +45.9% | 7.88 | 19.66 | +149.5% | 1592.1 | 1077.2 | -32.3% |
| `peek_mine_contended` | 0.09 | 0.12 | +33.3% | 0.20 | 0.22 | +10.0% | 7162.3 | 7135.4 | -0.4% |
| `commit_proposal` | 0.10 | 0.09 | -10.0% | 0.15 | 0.19 | +26.7% | 5439.7 | 5027.2 | -7.6% |
| `saturated_insert_triple` | 0.71 | 0.75 | +5.6% | 1.08 | 1.09 | +0.9% | 12139.7 | 12000.0 | -1.2% |
| `saturated_peek_mine` | 2.21 | 1.37 | -38.0% | 4.68 | 2.42 | -48.3% | 4496.2 | 32707.1 | +627.4% |
| `saturated_take_triple` | 0.77 | 0.55 | -28.6% | 2.32 | 0.91 | -60.8% | 60456.1 | 12539.9 | -79.3% |
| `clear_triples_storm` | 3.22 | 4.24 | +31.7% | 4.34 | 5.92 | +36.4% | 2782.2 | 2318.3 | -16.7% |
| `clear_presigs_storm` | 3.20 | 4.28 | +33.8% | 4.33 | 6.94 | +60.3% | 2810.0 | 2259.7 | -19.6% |
| `mixed_insert_triple` | 0.76 | 0.95 | +25.0% | 1.36 | 1.52 | +11.8% | 7066.6 | 6498.6 | -8.0% |
| `mixed_presig_peek_triple` | 0.33 | 0.40 | +21.2% | 0.75 | 0.75 | +0.0% | 7066.6 | 6498.6 | -8.0% |
| `mixed_presig_commit_triple` | 0.37 | 0.42 | +13.5% | 0.72 | 0.75 | +4.2% | 7066.6 | 6498.6 | -8.0% |
| `mixed_insert_presig` | 0.64 | 0.80 | +25.0% | 1.43 | 1.39 | -2.8% | 7066.6 | 6498.6 | -8.0% |
| `mixed_sign_peek_presig` | 0.51 | 0.56 | +9.8% | 0.79 | 0.85 | +7.6% | 3533.3 | 3249.3 | -8.0% |
| `mixed_sign_commit_presig` | 0.49 | 0.52 | +6.1% | 0.78 | 0.82 | +5.1% | 3533.3 | 3249.3 | -8.0% |
| `mixed_sign_take_presig` | 0.42 | 0.45 | +7.1% | 0.73 | 0.76 | +4.1% | 28266.3 | 25994.4 | -8.0% |
| `sync_update_triples` | 3.56 | 4.01 | +12.6% | 4.24 | 4.38 | +3.3% | 1441.2 | 1387.6 | -3.7% |
| `sync_update_presigs` | 4.10 | 4.21 | +2.7% | 4.20 | 4.49 | +6.9% | 1441.2 | 1387.6 | -3.7% |
| `sync_prune_triples` | 7.00 | 7.00 | +0.0% | 7.28 | 7.57 | +4.0% | 867.6 | 845.3 | -2.6% |
| `sync_prune_presigs` | 6.71 | 6.84 | +1.9% | 6.90 | 7.43 | +7.7% | 867.6 | 845.3 | -2.6% |
| `insert_under_client_kill` | 0.36 | 0.37 | +2.8% | 0.39 | 0.40 | +2.6% | 32721.7 | 31942.2 | -2.4% |
| `take_under_client_kill` | 0.22 | 0.23 | +4.5% | 0.26 | 0.27 | +3.8% | 53127.8 | 51615.6 | -2.8% |
| `take_post_reconnect` | 0.23 | 0.23 | +0.0% | 0.26 | 0.26 | +0.0% | 52870.4 | 53046.7 | +0.3% |
| `deep_peek_mine` | 2.29 | 2.34 | +2.2% | 2.94 | 3.00 | +2.0% | 723.1 | 719.9 | -0.4% |
| `deep_commit` | 2.19 | 2.22 | +1.4% | 2.36 | 2.40 | +1.7% | 373.4 | 368.7 | -1.3% |
| `presig_stockpile_peek` | 0.83 | 1.00 | +20.5% | 1.10 | 1.24 | +12.7% | 1705.2 | 1072.9 | -37.1% |
| `presig_stockpile_commit` | 0.28 | 0.10 | -64.3% | 0.89 | 0.91 | +2.2% | 1278.9 | 1005.9 | -21.3% |
| `churn_peek_mine` | 0.14 | 0.12 | -14.3% | 0.20 | 0.19 | -5.0% | 1.6 | 1.6 | +0.0% |
| `churn_commit` | 0.44 | 0.53 | +20.5% | n/a | n/a | n/a | 0.8 | 0.8 | +0.0% |
| `take_contended` | 0.16 | 0.12 | -25.0% | 0.19 | 0.23 | +21.1% | 6182.8 | 5958.7 | -3.6% |
| `large_argv_sync` | 4.64 | 5.64 | +21.6% | 5.09 | 6.39 | +25.5% | 212.8 | 167.5 | -21.3% |
| `large_outdated_prune` | 3.98 | 4.92 | +23.6% | 4.40 | 11.05 | +151.1% | 249.1 | 166.7 | -33.1% |
| `in_memory_insert` | 0.37 | 0.36 | -2.7% | 0.40 | 0.65 | +62.5% | 32163.7 | 26964.5 | -16.2% |
| `aof_fsync_insert` | 8.05 | 10.98 | +36.4% | 11.07 | 15.96 | +44.2% | 1393.6 | 1042.7 | -25.2% |
| `bgsave_concurrent_take` | 9.04 | 6.82 | -24.6% | 10.26 | 8.04 | -21.6% | 1287.9 | 1865.0 | +44.8% |

The six checkpoint-scenario operations, first against the parent (primary) and then against the original baseline (context):

| Operation | Δp50 vs parent | Δp95 vs parent | Δgoodput vs parent | Δp50 vs baseline | Δp95 vs baseline | Δgoodput vs baseline |
|---|---:|---:|---:|---:|---:|---:|
| `concurrent_insert_triple_no_checkpoint` | -5.4% | -58.0% | +33.6% | -44.4% | -40.0% | +79.3% |
| `concurrent_take_triple_no_checkpoint` | +0.0% | +11.5% | +1.4% | -35.3% | -25.6% | +57.9% |
| `concurrent_insert_triple_with_checkpoint` | -67.0% | -60.6% | +191.9% | -61.6% | -43.3% | +143.3% |
| `concurrent_take_triple_with_checkpoint` | -71.9% | -69.1% | +253.8% | -62.3% | -47.2% | +154.1% |
| `checkpoint_write` | +44.9% | +68.9% | -31.5% | -30.0% | -6.1% | +36.5% |
| `checkpoint_read` | +38.1% | +61.4% | -30.7% | +95.6% | +106.8% | -48.6% |

Failures / unknown outcomes (new run vs parent and baseline):

| Operation | Parent failures | New failures | Parent unknown | New unknown |
|---|---:|---:|---:|---:|
| `peek_mine_contended` | 0 | 0 | 121 | 112 |
| `commit_proposal` | 0 | 0 | 19 | 26 |
| `saturated_peek_mine` | 0 | 0 | 31 | 57 |
| `insert_under_client_kill` | 10 | 5 | 0 | 0 |
| `take_under_client_kill` | 0 | 0 | 12 | 12 |
| `deep_peek_mine` | 0 | 0 | 178 | 177 |
| `deep_commit` | 0 | 0 | 59 | 60 |
| `presig_stockpile_peek` | 0 | 0 | 100 | 136 |
| `presig_stockpile_commit` | 0 | 0 | 25 | 4 |
| `take_contended` | 0 | 0 | 180 | 180 |
| **Total (all 46 operations)** | **10** | **5** | **725** | **764** |

Failures and unknown outcomes are excluded from latency percentiles (successes only). Hard failures fell from 10 to 5, all in `insert_under_client_kill` (the scenario severs live client connections); unknown totals shifted between operations as usual for contention/empty-stockpile outcomes.

### Improvements

- **The mixed checkpoint scenarios the A/B flagged are now much faster than the parent.** `concurrent_insert_triple_with_checkpoint` p50 207.70 → 68.49 ms (-67.0%), p95 361.94 → 142.74 ms (-60.6%), goodput 54.1 → 157.9/s (+191.9%); `concurrent_take_triple_with_checkpoint` p50 122.25 → 34.30 ms (-71.9%), p95 250.73 → 77.57 ms (-69.1%), goodput 90.0 → 318.4/s (+253.8%). These are far larger than the run-to-run spread, and they directly reverse the paired A/B regressions for the with-checkpoint mixes (also -61.6%/-62.3% p50 vs the original baseline).
- The `no_checkpoint` control scenario also improved (`concurrent_insert_triple_no_checkpoint` p95 1.00 → 0.42 ms, goodput +33.6%), but because that scenario issues no checkpoint commands it is more likely run-to-run variance than an effect of this change.
- Hard failures halved (10 → 5), with no change to the client-kill logic; this is likely noise rather than a consequence of pool isolation.

### Regressions / noise

- **Isolation did not improve the standalone checkpoint operations, which are slower than the parent:** `checkpoint_write` p50 143.59 → 208.09 ms (+44.9%), p95 +68.9%, goodput -31.5%; `checkpoint_read` p50 247.02 → 341.03 ms (+38.1%), p95 +61.4%, goodput -30.7%. `checkpoint_read` is also still materially worse than the original baseline (p50 +95.6%, p95 +106.8%, goodput -48.6%). The hypothesis that a separate socket helps checkpoint traffic itself is **not supported** by this run; the benefit is confined to artifact traffic running alongside checkpoints.
- **Broad slower-than-parent readings are mostly run-to-run noise.** 39 of 46 operations have at least one metric worse by >1%. These include operations that never touch checkpoints (`aof_fsync_insert` p50 +36.4%, `large_argv_sync` +21.6%, `clear_triples_storm` +31.7%, `concurrent_take_triple_no_poll` p95 +200.0%) and even an in-memory operation (`in_memory_insert` p95 +62.5%) — none of which can be causally affected by giving checkpoints a second connection. The consistent modest slowdown across unrelated, disk- and scheduler-bound scenarios indicates this run was under different system load; only the 60–70% improvements in the with-checkpoint mixes stand out from that spread.
- **Full list of operations with any metric slower than the parent** (>1% threshold; the table above has all 46 values): `concurrent_insert_triple` (p50 +2.7%, p95 -38.1%, goodput +7.5%); `concurrent_take_triple` (p50 +4.5%, p95 +42.3%, goodput -10.8%); `concurrent_insert_triple_no_poll` (p50 +0.0%, p95 +28.2%, goodput -4.9%); `concurrent_take_triple_no_poll` (p50 +39.1%, p95 +200.0%, goodput -46.7%); `concurrent_insert_triple_with_poll` (p50 +0.0%, p95 +21.4%, goodput -3.7%); `concurrent_take_triple_with_poll` (p50 +0.0%, p95 +29.6%, goodput -5.0%); `concurrent_take_triple_no_checkpoint` (p50 +0.0%, p95 +11.5%, goodput +1.4%); `checkpoint_write` (p50 +44.9%, p95 +68.9%, goodput -31.5%); `checkpoint_read` (p50 +38.1%, p95 +61.4%, goodput -30.7%); `remove_outdated_storm` (p50 +45.9%, p95 +149.5%, goodput -32.3%); `peek_mine_contended` (p50 +33.3%, p95 +10.0%, goodput -0.4%); `commit_proposal` (p50 -10.0%, p95 +26.7%, goodput -7.6%); `saturated_insert_triple` (p50 +5.6%, p95 +0.9%, goodput -1.2%); `saturated_take_triple` (p50 -28.6%, p95 -60.8%, goodput -79.3%); `clear_triples_storm` (p50 +31.7%, p95 +36.4%, goodput -16.7%); `clear_presigs_storm` (p50 +33.8%, p95 +60.3%, goodput -19.6%); `mixed_insert_triple` (p50 +25.0%, p95 +11.8%, goodput -8.0%); `mixed_presig_peek_triple` (p50 +21.2%, p95 +0.0%, goodput -8.0%); `mixed_presig_commit_triple` (p50 +13.5%, p95 +4.2%, goodput -8.0%); `mixed_insert_presig` (p50 +25.0%, p95 -2.8%, goodput -8.0%); `mixed_sign_peek_presig` (p50 +9.8%, p95 +7.6%, goodput -8.0%); `mixed_sign_commit_presig` (p50 +6.1%, p95 +5.1%, goodput -8.0%); `mixed_sign_take_presig` (p50 +7.1%, p95 +4.1%, goodput -8.0%); `sync_update_triples` (p50 +12.6%, p95 +3.3%, goodput -3.7%); `sync_update_presigs` (p50 +2.7%, p95 +6.9%, goodput -3.7%); `sync_prune_triples` (p50 +0.0%, p95 +4.0%, goodput -2.6%); `sync_prune_presigs` (p50 +1.9%, p95 +7.7%, goodput -2.6%); `insert_under_client_kill` (p50 +2.8%, p95 +2.6%, goodput -2.4%); `take_under_client_kill` (p50 +4.5%, p95 +3.8%, goodput -2.8%); `deep_peek_mine` (p50 +2.2%, p95 +2.0%, goodput -0.4%); `deep_commit` (p50 +1.4%, p95 +1.7%, goodput -1.3%); `presig_stockpile_peek` (p50 +20.5%, p95 +12.7%, goodput -37.1%); `presig_stockpile_commit` (p50 -64.3%, p95 +2.2%, goodput -21.3%); `churn_commit` (p50 +20.5%, p95 n/a, goodput +0.0%); `take_contended` (p50 -25.0%, p95 +21.1%, goodput -3.6%); `large_argv_sync` (p50 +21.6%, p95 +25.5%, goodput -21.3%); `large_outdated_prune` (p50 +23.6%, p95 +151.1%, goodput -33.1%); `in_memory_insert` (p50 -2.7%, p95 +62.5%, goodput -16.2%); `aof_fsync_insert` (p50 +36.4%, p95 +44.2%, goodput -25.2%).
- Operations with very small sample counts (`churn_commit` p95/p99 are `n/a`, `take_contended` and `presig_stockpile_commit` have ~60 samples) have correspondingly noisy percentiles.

### Motivation / tradeoff

Motivation: the paired 3-repeat checkpoint A/B against the pre-refactor base showed `concurrent_take_triple_with_checkpoint` p50 +66.5%, p95 +81.2%, goodput -40.0% and `checkpoint_read` p50 +12.8%, goodput -9.2%, plausibly from ~30 MB checkpoint GET/SET traffic sharing one multiplexed socket with artifact commands. This run confirms the fix for the mixed-workload case (p50 -67%/-72%, goodput +192%/+254% vs parent) but **not** for standalone checkpoint reads/writes, which got slower. The tradeoff is one extra multiplexed TCP connection per node/participant in exchange for removing head-of-line blocking between checkpoint and artifact traffic; key layout, Lua scripts, command sequences and timeouts are unchanged. A second paired 3-repeat A/B is advisable before merge to separate the checkpoint_read regression from run-to-run noise.
