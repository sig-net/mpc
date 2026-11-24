## Description

Replaces `deadpool-redis 0.18`'s pool in the node's Redis storage layer with a lightweight pool-like wrapper around a single multiplexed `redis::aio::ConnectionManager`. deadpool pipelines `UNWATCH` + `PING` on every checkout of an idle connection, costing one extra round trip per storage operation; the new wrapper pays no per-checkout RTT. A semaphore sized from the configured maximum pool size preserves the concurrency bound, and a checked-out `Connection` holds a permit and dereferences to the manager, so all existing `AsyncCommands`, pipelines and `Script::invoke_async(&mut conn)` call sites are unchanged. Redis key layout, Lua scripts, command sequences and error handling are unchanged; connection recovery now uses `ConnectionManager`'s best-effort single-attempt reconnect. The checkout wait timeout bounds the whole checkout (permit plus lazy connection setup), and the diagnostics waiting counter uses a drop guard so cancelled checkouts cannot leak it. See `doc/redis-connection-pooling.md` for the design and tradeoffs.

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
- [x] Operator (flags, env vars, config, storage migration): no flags, env vars or stored data change. Operational behavior does change: each storage/participant now holds one multiplexed Redis TCP connection instead of up to `max_size` pooled sockets, there is no per-checkout `PING` liveness probe, and the diagnostics `Pool:` line now reports one shared connection (`active=1` after first checkout, `available` = free permits) instead of deadpool's idle/active socket counts.

## Design

<!-- Tick exactly one and replace the [link]. Non-trivial changes need a design doc in doc/. -->

- [ ] Trivial: no design decision involved (CI, tests, tooling, dependencies, refactor without behaviour change)
- [ ] Follows the existing design in [doc/](https://github.com/sig-net/mpc/tree/develop/doc)
- [x] Adds or changes the design; docs updated in this PR or in: [doc/redis-connection-pooling.md](../doc/redis-connection-pooling.md)
- [ ] Non-trivial, but this area has no design doc yet; tracked in: [issue link]

## Performance results

Benchmark command (identical settings to the baseline, with the external Cargo target dir used for build artifacts):

```sh
mkdir -p tmp
set -o pipefail
CARGO_TARGET_DIR=/private/var/folders/9r/zs_bh5_90rj11vlw571bfs8c0000gn/T/opencode/redis-bench-target cargo run --release -p integration-tests --bin redis-bench -- --redis-url redis://default:bench@127.0.0.1:6399 --allow-external-redis --json-out tmp/redis-skip-recycle-ping-final.json --csv-out tmp/redis-skip-recycle-ping-final.csv 2>&1 | tee tmp/redis-skip-recycle-ping-final-run.log
```

- Local Redis 8.4.0 standalone server at `redis://default:bench@127.0.0.1:6399` (same server as the baseline).
- Commits compared: baseline `ff9bb300833a15ada23529b172c67e45ac90a0c0` (`continuous.redis.bench`) vs this branch `redis-skip-recycle-ping` (single commit on top of that base). `tmp/baseline.csv` vs `tmp/redis-skip-recycle-ping-final.csv`.
- New run: release build + full suite ~2m18s of benchmark log timestamps (46 records, all scenarios completed; `cargo run` exit 0). The earlier exploratory run of this branch (~2m01s) differed in timing; all numbers below are from the FINAL run.
- **Lower latency (p50/p95, in ms) and higher goodput (operations/sec) are better.** Deltas use CSV values verbatim; `n/a` means the CSV had no percentile (too few samples).

| Operation | Baseline p50 | New p50 | Δ p50 | Baseline p95 | New p95 | Δ p95 | Baseline goodput/s | New goodput/s | Δ goodput/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `concurrent_insert_triple` | 0.63 | 0.37 | -41.3% | 0.71 | 0.84 | +18.3% | 18741.1 | 27717.3 | +47.9% |
| `concurrent_take_triple` | 0.36 | 0.22 | -38.9% | 0.64 | 0.26 | -59.4% | 30614.5 | 53865.4 | +75.9% |
| `concurrent_insert_triple_no_poll` | 0.64 | 0.36 | -43.8% | 0.85 | 0.39 | -54.1% | 17674.6 | 33146.6 | +87.5% |
| `concurrent_take_triple_no_poll` | 0.34 | 0.23 | -32.4% | 0.41 | 0.36 | -12.2% | 34171.6 | 48366.4 | +41.5% |
| `concurrent_insert_triple_with_poll` | 0.62 | 0.35 | -43.5% | 0.68 | 0.42 | -38.2% | 19177.2 | 33203.4 | +73.1% |
| `concurrent_take_triple_with_poll` | 0.34 | 0.22 | -35.3% | 0.40 | 0.27 | -32.5% | 34485.4 | 53157.4 | +54.1% |
| `concurrent_insert_triple_no_checkpoint` | 0.63 | 0.37 | -41.3% | 0.70 | 1.00 | +42.9% | 18918.6 | 25385.7 | +34.2% |
| `concurrent_take_triple_no_checkpoint` | 0.34 | 0.22 | -35.3% | 0.39 | 0.26 | -33.3% | 34523.5 | 53781.2 | +55.8% |
| `concurrent_insert_triple_with_checkpoint` | 178.15 | 207.70 | +16.6% | 251.76 | 361.94 | +43.8% | 64.9 | 54.1 | -16.6% |
| `concurrent_take_triple_with_checkpoint` | 90.99 | 122.25 | +34.4% | 146.80 | 250.73 | +70.8% | 125.3 | 90.0 | -28.2% |
| `checkpoint_write` | 297.35 | 143.59 | -51.7% | 402.23 | 223.62 | -44.4% | 39.5 | 78.7 | +99.2% |
| `checkpoint_read` | 174.36 | 247.02 | +41.7% | 300.47 | 385.14 | +28.2% | 65.0 | 48.2 | -25.8% |
| `remove_outdated_storm` | 7.29 | 6.12 | -16.0% | 13.74 | 7.88 | -42.6% | 1459.0 | 1592.1 | +9.1% |
| `peek_mine_contended` | 0.30 | 0.09 | -70.0% | 0.33 | 0.20 | -39.4% | 2993.4 | 7162.3 | +139.3% |
| `commit_proposal` | 0.31 | 0.10 | -67.7% | 0.35 | 0.15 | -57.1% | 2952.4 | 5439.7 | +84.2% |
| `saturated_insert_triple` | 1.60 | 0.71 | -55.6% | 2.04 | 1.08 | -47.1% | 10320.8 | 12139.7 | +17.6% |
| `saturated_peek_mine` | 2.54 | 2.21 | -13.0% | 3.01 | 4.68 | +55.5% | 4723.0 | 4496.2 | -4.8% |
| `saturated_take_triple` | 0.99 | 0.77 | -22.2% | 1.26 | 2.32 | +84.1% | 11506.2 | 60456.1 | +425.4% |
| `clear_triples_storm` | 4.64 | 3.22 | -30.6% | 4.85 | 4.34 | -10.5% | 2514.3 | 2782.2 | +10.7% |
| `clear_presigs_storm` | 4.66 | 3.20 | -31.3% | 4.85 | 4.33 | -10.7% | 2514.1 | 2810.0 | +11.8% |
| `mixed_insert_triple` | 1.55 | 0.76 | -51.0% | 1.69 | 1.36 | -19.5% | 4736.1 | 7066.6 | +49.2% |
| `mixed_presig_peek_triple` | 0.58 | 0.33 | -43.1% | 0.88 | 0.75 | -14.8% | 4736.1 | 7066.6 | +49.2% |
| `mixed_presig_commit_triple` | 0.57 | 0.37 | -35.1% | 0.88 | 0.72 | -18.2% | 4736.1 | 7066.6 | +49.2% |
| `mixed_insert_presig` | 1.11 | 0.64 | -42.3% | 1.64 | 1.43 | -12.8% | 4736.1 | 7066.6 | +49.2% |
| `mixed_sign_peek_presig` | 0.78 | 0.51 | -34.6% | 0.90 | 0.79 | -12.2% | 2368.1 | 3533.3 | +49.2% |
| `mixed_sign_commit_presig` | 0.77 | 0.49 | -36.4% | 0.90 | 0.78 | -13.3% | 2368.1 | 3533.3 | +49.2% |
| `mixed_sign_take_presig` | 0.57 | 0.42 | -26.3% | 0.87 | 0.73 | -16.1% | 18944.4 | 28266.3 | +49.2% |
| `sync_update_triples` | 4.36 | 3.56 | -18.3% | 4.51 | 4.24 | -6.0% | 1360.2 | 1441.2 | +6.0% |
| `sync_update_presigs` | 4.03 | 4.10 | +1.7% | 5.19 | 4.20 | -19.1% | 1360.2 | 1441.2 | +6.0% |
| `sync_prune_triples` | 7.27 | 7.00 | -3.7% | 7.40 | 7.28 | -1.6% | 835.8 | 867.6 | +3.8% |
| `sync_prune_presigs` | 6.87 | 6.71 | -2.3% | 8.25 | 6.90 | -16.4% | 835.8 | 867.6 | +3.8% |
| `insert_under_client_kill` | 0.63 | 0.36 | -42.9% | 0.74 | 0.39 | -47.3% | 18497.6 | 32721.7 | +76.9% |
| `take_under_client_kill` | 0.35 | 0.22 | -37.1% | 0.40 | 0.26 | -35.0% | 33616.1 | 53127.8 | +58.0% |
| `take_post_reconnect` | 0.35 | 0.23 | -34.3% | 0.39 | 0.26 | -33.3% | 34365.0 | 52870.4 | +53.8% |
| `deep_peek_mine` | 2.55 | 2.29 | -10.2% | 3.12 | 2.94 | -5.8% | 382.4 | 723.1 | +89.1% |
| `deep_commit` | 2.44 | 2.19 | -10.2% | 2.62 | 2.36 | -9.9% | 326.9 | 373.4 | +14.2% |
| `presig_stockpile_peek` | 0.97 | 0.83 | -14.4% | 1.14 | 1.10 | -3.5% | 1502.1 | 1705.2 | +13.5% |
| `presig_stockpile_commit` | 0.79 | 0.28 | -64.6% | 1.11 | 0.89 | -19.8% | 1502.1 | 1278.9 | -14.9% |
| `churn_peek_mine` | 0.23 | 0.14 | -39.1% | 0.50 | 0.20 | -60.0% | 1.6 | 1.6 | +0.0% |
| `churn_commit` | 0.54 | 0.44 | -18.5% | n/a | n/a | n/a | 0.8 | 0.8 | +0.0% |
| `take_contended` | 0.27 | 0.16 | -40.7% | 0.55 | 0.19 | -65.5% | 2818.1 | 6182.8 | +119.4% |
| `large_argv_sync` | 5.34 | 4.64 | -13.1% | 8.14 | 5.09 | -37.5% | 168.7 | 212.8 | +26.1% |
| `large_outdated_prune` | 4.87 | 3.98 | -18.3% | 7.02 | 4.40 | -37.3% | 174.2 | 249.1 | +43.0% |
| `in_memory_insert` | 0.69 | 0.37 | -46.4% | 1.46 | 0.40 | -72.6% | 14909.7 | 32163.7 | +115.7% |
| `aof_fsync_insert` | 16.12 | 8.05 | -50.1% | 24.01 | 11.07 | -53.9% | 723.4 | 1393.6 | +92.6% |
| `bgsave_concurrent_take` | 13.95 | 9.04 | -35.2% | 15.95 | 10.26 | -35.7% | 880.0 | 1287.9 | +46.4% |

Failures / unknown outcomes (failures are hard errors; unknown means the storage returned no value):

| Operation | Baseline failures | New failures | Baseline unknown | New unknown |
|---|---:|---:|---:|---:|
| `peek_mine_contended` | 0 | 0 | 127 | 121 |
| `commit_proposal` | 0 | 0 | 1 | 19 |
| `saturated_peek_mine` | 0 | 0 | 10 | 31 |
| `insert_under_client_kill` | 7 | 10 | 0 | 0 |
| `take_under_client_kill` | 0 | 0 | 4 | 12 |
| `deep_peek_mine` | 0 | 0 | 238 | 178 |
| `deep_commit` | 0 | 0 | 9 | 59 |
| `presig_stockpile_peek` | 0 | 0 | 92 | 100 |
| `presig_stockpile_commit` | 0 | 0 | 0 | 25 |
| **Total (all 46 operations)** | **7** | **10** | **661** | **725** |

Failures and unknown outcomes are excluded from latency percentiles (successes only). **Hard failures rose from 7 to 10 in the final run**, all in `insert_under_client_kill` (an earlier exploratory run of this branch recorded 3): the scenario severs 12 live client connections and the in-flight commands fail with `Connection reset by peer` before the best-effort single-attempt reconnect. No wrong values were observed, but this increase is real in the final measurement and must be considered before merge (see Regressions). Unknown totals rose 661 → 725 and shifted between operations (e.g. `deep_peek_mine` 238→178, `deep_commit` 9→59); these are expected "no value" outcomes whose counts depend on scheduling.

### Improvements

- Hot artifact paths: `concurrent_take_triple` p50 0.36 → 0.22 ms (-38.9%), p95 0.64 → 0.26 ms (-59.4%), goodput 30614.5 → 53865.4/s (+75.9%); `concurrent_insert_triple_no_poll` p50 0.64 → 0.36 ms (-43.8%), goodput 17674.6 → 33146.6/s (+87.5%).
- Proposer/contention paths: `peek_mine_contended` p50 0.30 → 0.09 ms (-70.0%), `commit_proposal` p50 0.31 → 0.10 ms (-67.7%), `take_contended` p50 0.27 → 0.16 ms (-40.7%).
- Client-kill paths: `insert_under_client_kill` p50 0.63 → 0.36 ms (-42.9%) and `take_post_reconnect` p50 0.35 → 0.23 ms (-34.3%); recovery works, but hard failures in the kill scenario increased (7 → 10 in this run — see Regressions).
- Checkpoint write and persistence: `checkpoint_write` p50 297.35 → 143.59 ms (-51.7%), goodput 39.5 → 78.7/s (+99.2%); `aof_fsync_insert` p50 16.12 → 8.05 ms (-50.1%); `bgsave_concurrent_take` p50 13.95 → 9.04 ms (-35.2%).
- Broad gains in mixed stockpile, sync, prune and storm scenarios (typically -10% to -45% p50, +3% to +50% goodput).

### Regressions / correctness risks

- **Slower operations / possible head-of-line blocking:** checkpoint-heavy mixes regressed in the final run: `checkpoint_read` p50 174.36 → 247.02 ms (+41.7%), p95 +28.2%, goodput -25.8%; `concurrent_take_triple_with_checkpoint` p50 90.99 → 122.25 ms (+34.4%), p95 +70.8%, goodput -28.2%; `concurrent_insert_triple_with_checkpoint` p50 +16.6%, p95 +43.8%, goodput -16.6%; `sync_update_presigs` p50 +1.7% (p95 -19.1%); `concurrent_insert_triple` and `concurrent_insert_triple_no_checkpoint` p95 +18.3% and +42.9% despite much better p50. Replacing up to `max_size` sockets with one multiplexed connection is a **plausible cause of head-of-line blocking** when checkpoint and artifact traffic overlap. That cause is **unvalidated** by these numbers, and these mixes should be A/B'd against deadpool before merge. Server-side AOF/BGSAVE timing may also contribute, but the regressions are not attributed purely to run-to-run variance.
- **Loss of recycle liveness check / more hard failures:** deadpool's per-checkout `PING` caught a dead socket before a real command. Now the first real command fails and `ConnectionManager` makes a best-effort single-attempt reconnect; a command can fail once before recovery. In the final run `insert_under_client_kill` had **10 failures vs the baseline's 7** (an earlier run of this branch had 3) with `Connection reset by peer` at the kill; no wrong values were observed, but the increase needs A/B confirmation and monitoring before merge.
- **Loss of `UNWATCH` cleanup:** no node or benchmark code uses Redis `WATCH`/`MULTI`, so there is no transaction state left on a reused socket. If `WATCH` is introduced later, this design needs an explicit cleanup or fresh connection.
- **Multiplexing instead of parallel sockets:** all permits on a pool share one TCP connection. A blocked/slow response or saturated loopback can affect all concurrent checkouts (head-of-line blocking, as discussed above), unlike deadpool's independent sockets; semaphore limits still bound concurrency and the response timeout (5s) still applies. The checkout wait timeout now also bounds lazy connection setup.
- **Pool-status semantics:** the diagnostics `Pool:` line changed from deadpool's socket counts to one multiplexed connection (`max` = permit limit, `active` = 1 after init, `available` = free connection slots, 0 after `close()`). Operators watching that line need the new interpretation. `close()` and wait/response timeouts are preserved.
- **Unknown outcomes:** total unknown rose 661 → 725 (see table). These are nondeterministic contention/empty-stockpile outcomes, not wrong values.
- **Dependency cleanup:** `deadpool-redis` remains declared in `Cargo.toml` though no code uses it; removing it is a harmless follow-up.

### Motivation / tradeoff

Motivation: `deadpool-redis 0.18`'s `Manager::recycle` pipelines `UNWATCH` + `PING` for every checkout of an idle connection (1 extra RTT per operation), and no newer version makes this configurable. A local microbenchmark measured pooled `get()` + PING at ~151 us median versus ~79 us median for a directly reused `MultiplexedConnection` PING (~72-112 us saved per checkout). The tradeoff is giving up proactive per-checkout liveness detection (and `UNWATCH` cleanup, unused here) in exchange for the removed RTT; best-effort single-attempt reconnect plus existing timeouts and retries bound the failure mode.
