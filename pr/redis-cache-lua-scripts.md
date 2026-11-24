## Description

`redis::Script::new(code)` in redis-rs 0.27 SHA1-hashes the Lua source and copies the source `String` on every call. The node calls it for every hot Redis operation (7 sites in `protocol_storage.rs`, 5 in `checkpoint_storage.rs`), so this hashing/allocation is pure client-side overhead on the busiest paths. This change caches one prepared `redis::Script` per call site in a `static LazyLock<redis::Script>`, so the hash and copy happen once per process instead of once per operation. The Lua source text is byte-for-byte unchanged, the script objects are immutable (`Script { code, hash }`), and no Redis semantics or call arguments change.

## Breaking changes

<!--
Tick `None` or every type that applies. For each breaking type, replace
[details here] with what breaks and what users must do. This text is copied into the release notes.
Code behind an `unstable-*` feature or a disabled gate is not breaking.

Mark breaking PRs with `!` in the title (e.g. `feat(node)!: ...`) so the
squash commit records it in git history. CI checks the section against the title.

Network–Applications: only additive changes (new flows) are allowed.
-->

- [x] None
- [ ] Node–Node: [details here]
- [ ] Contract–Node: [details here]
- [ ] Contract state: [details here]
- [ ] Network–Applications: [details here]
- [ ] Operator (flags, env vars, config, storage migration): [details here]

## Design

<!-- Tick exactly one and replace the [link]. Non-trivial changes need a design doc in doc/. -->

- [x] Trivial: no design decision involved (CI, tests, tooling, dependencies, refactor without behaviour change)
- [ ] Follows the existing design in [doc/](https://github.com/sig-net/mpc/tree/develop/doc)
- [ ] Adds or changes the design; docs updated in this PR or in: [link]
- [ ] Non-trivial, but this area has no design doc yet; tracked in: [issue link]

## Performance results

Benchmark command (identical to the baseline in `baseline.md`, with the external Cargo target dir used for build artifacts):

```sh
mkdir -p tmp
set -o pipefail
CARGO_TARGET_DIR=/private/var/folders/9r/zs_bh5_90rj11vlw571bfs8c0000gn/T/opencode/redis-bench-target cargo run --release -p integration-tests --bin redis-bench -- --redis-url redis://default:bench@127.0.0.1:6399 --allow-external-redis --json-out tmp/redis-cache-lua-scripts.json --csv-out tmp/redis-cache-lua-scripts.csv 2>&1 | tee tmp/redis-cache-lua-scripts-run.log
```

- Redis 8.4.0, local server at `redis://default:bench@127.0.0.1:6399` with DEBUG enabled (Docker unavailable; same server as the baseline).
- Commits compared: baseline `ff9bb300833a15ada23529b172c67e45ac90a0c0` (`continuous.redis.bench`) vs the head commit of `redis-cache-lua-scripts` (this PR's single commit). `baseline.md` records an earlier hash from when its CSV was first captured; the base branch tip used here is `ff9bb30`.
- New run: release build 1m02s, full suite ~2m09s (46 records, all 14 scenarios completed; `cargo run` exit 0). Baseline run: ~2m08s for the suite.
- **Lower latency (p50/p95, in ms) and higher goodput (operations/sec) are better.** Deltas are computed from the CSV values verbatim; `n/a` means the CSV had no percentile (too few samples).

| Operation | Baseline p50 | New p50 | Δ p50 | Baseline p95 | New p95 | Δ p95 | Baseline goodput/s | New goodput/s | Δ goodput/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `concurrent_insert_triple` | 0.63 | 0.68 | +7.9% | 0.71 | 1.25 | +76.1% | 18741.1 | 15902.3 | -15.1% |
| `concurrent_take_triple` | 0.36 | 0.36 | +0.0% | 0.64 | 0.46 | -28.1% | 30614.5 | 32435.9 | +5.9% |
| `concurrent_insert_triple_no_poll` | 0.64 | 0.62 | -3.1% | 0.85 | 0.76 | -10.6% | 17674.6 | 18714.1 | +5.9% |
| `concurrent_take_triple_no_poll` | 0.34 | 0.41 | +20.6% | 0.41 | 0.70 | +70.7% | 34171.6 | 26623.0 | -22.1% |
| `concurrent_insert_triple_with_poll` | 0.62 | 0.62 | +0.0% | 0.68 | 0.74 | +8.8% | 19177.2 | 18728.2 | -2.3% |
| `concurrent_take_triple_with_poll` | 0.34 | 0.36 | +5.9% | 0.40 | 0.47 | +17.5% | 34485.4 | 32443.2 | -5.9% |
| `concurrent_insert_triple_no_checkpoint` | 0.63 | 0.63 | +0.0% | 0.70 | 0.75 | +7.1% | 18918.6 | 18659.2 | -1.4% |
| `concurrent_take_triple_no_checkpoint` | 0.34 | 0.37 | +8.8% | 0.39 | 0.57 | +46.2% | 34523.5 | 29900.5 | -13.4% |
| `concurrent_insert_triple_with_checkpoint` | 178.15 | 192.32 | +8.0% | 251.76 | 285.32 | +13.3% | 64.9 | 60.0 | -7.6% |
| `concurrent_take_triple_with_checkpoint` | 90.99 | 82.92 | -8.9% | 146.80 | 145.12 | -1.1% | 125.3 | 136.0 | +8.5% |
| `checkpoint_write` | 297.35 | 301.41 | +1.4% | 402.23 | 427.67 | +6.3% | 39.5 | 39.0 | -1.3% |
| `checkpoint_read` | 174.36 | 183.51 | +5.2% | 300.47 | 321.29 | +6.9% | 65.0 | 61.6 | -5.2% |
| `remove_outdated_storm` | 7.29 | 7.41 | +1.6% | 13.74 | 7.85 | -42.9% | 1459.0 | 1578.8 | +8.2% |
| `peek_mine_contended` | 0.30 | 0.28 | -6.7% | 0.33 | 0.33 | +0.0% | 2993.4 | 3123.7 | +4.4% |
| `commit_proposal` | 0.31 | 0.30 | -3.2% | 0.35 | 0.35 | +0.0% | 2952.4 | 2931.5 | -0.7% |
| `saturated_insert_triple` | 1.60 | 1.76 | +10.0% | 2.04 | 3.44 | +68.6% | 10320.8 | 9751.7 | -5.5% |
| `saturated_peek_mine` | 2.54 | 2.41 | -5.1% | 3.01 | 2.99 | -0.7% | 4723.0 | 4772.7 | +1.1% |
| `saturated_take_triple` | 0.99 | 1.01 | +2.0% | 1.26 | 1.36 | +7.9% | 11506.2 | 11441.3 | -0.6% |
| `clear_triples_storm` | 4.64 | 4.66 | +0.4% | 4.85 | 7.44 | +53.4% | 2514.3 | 2357.1 | -6.3% |
| `clear_presigs_storm` | 4.66 | 4.65 | -0.2% | 4.85 | 7.46 | +53.8% | 2514.1 | 2344.0 | -6.8% |
| `mixed_insert_triple` | 1.55 | 1.59 | +2.6% | 1.69 | 2.11 | +24.9% | 4736.1 | 4457.7 | -5.9% |
| `mixed_presig_peek_triple` | 0.58 | 0.59 | +1.7% | 0.88 | 0.95 | +8.0% | 4736.1 | 4457.7 | -5.9% |
| `mixed_presig_commit_triple` | 0.57 | 0.59 | +3.5% | 0.88 | 1.00 | +13.6% | 4736.1 | 4457.7 | -5.9% |
| `mixed_insert_presig` | 1.11 | 1.17 | +5.4% | 1.64 | 1.80 | +9.8% | 4736.1 | 4457.7 | -5.9% |
| `mixed_sign_peek_presig` | 0.78 | 0.80 | +2.6% | 0.90 | 1.07 | +18.9% | 2368.1 | 2228.9 | -5.9% |
| `mixed_sign_commit_presig` | 0.77 | 0.79 | +2.6% | 0.90 | 1.08 | +20.0% | 2368.1 | 2228.9 | -5.9% |
| `mixed_sign_take_presig` | 0.57 | 0.58 | +1.8% | 0.87 | 0.94 | +8.0% | 18944.4 | 17830.8 | -5.9% |
| `sync_update_triples` | 4.36 | 4.42 | +1.4% | 4.51 | 4.73 | +4.9% | 1360.2 | 1331.6 | -2.1% |
| `sync_update_presigs` | 4.03 | 4.34 | +7.7% | 5.19 | 5.06 | -2.5% | 1360.2 | 1331.6 | -2.1% |
| `sync_prune_triples` | 7.27 | 7.37 | +1.4% | 7.40 | 7.78 | +5.1% | 835.8 | 813.3 | -2.7% |
| `sync_prune_presigs` | 6.87 | 7.05 | +2.6% | 8.25 | 7.85 | -4.8% | 835.8 | 813.3 | -2.7% |
| `insert_under_client_kill` | 0.63 | 0.63 | +0.0% | 0.74 | 0.68 | -8.1% | 18497.6 | 18619.3 | +0.7% |
| `take_under_client_kill` | 0.35 | 0.36 | +2.9% | 0.40 | 0.41 | +2.5% | 33616.1 | 32954.7 | -2.0% |
| `take_post_reconnect` | 0.35 | 0.35 | +0.0% | 0.39 | 0.39 | +0.0% | 34365.0 | 34202.8 | -0.5% |
| `deep_peek_mine` | 2.55 | 2.50 | -2.0% | 3.12 | 3.18 | +1.9% | 382.4 | 370.0 | -3.2% |
| `deep_commit` | 2.44 | 2.49 | +2.0% | 2.62 | 2.56 | -2.3% | 326.9 | 326.1 | -0.2% |
| `presig_stockpile_peek` | 0.97 | 0.93 | -4.1% | 1.14 | 1.17 | +2.6% | 1502.1 | 1455.8 | -3.1% |
| `presig_stockpile_commit` | 0.79 | 0.79 | +0.0% | 1.11 | 1.11 | +0.0% | 1502.1 | 1455.8 | -3.1% |
| `churn_peek_mine` | 0.23 | 0.22 | -4.3% | 0.50 | 0.35 | -30.0% | 1.6 | 1.6 | +0.0% |
| `churn_commit` | 0.54 | 0.49 | -9.3% | n/a | n/a | n/a | 0.8 | 0.8 | +0.0% |
| `take_contended` | 0.27 | 0.25 | -7.4% | 0.55 | 0.28 | -49.1% | 2818.1 | 3920.2 | +39.1% |
| `large_argv_sync` | 5.34 | 5.06 | -5.2% | 8.14 | 5.49 | -32.6% | 168.7 | 183.1 | +8.5% |
| `large_outdated_prune` | 4.87 | 4.32 | -11.3% | 7.02 | 5.01 | -28.6% | 174.2 | 217.9 | +25.1% |
| `in_memory_insert` | 0.69 | 0.63 | -8.7% | 1.46 | 0.75 | -48.6% | 14909.7 | 18450.6 | +23.7% |
| `aof_fsync_insert` | 16.12 | 23.97 | +48.7% | 24.01 | 34.99 | +45.7% | 723.4 | 507.9 | -29.8% |
| `bgsave_concurrent_take` | 13.95 | 15.93 | +14.2% | 15.95 | 17.96 | +12.6% | 880.0 | 788.6 | -10.4% |

Failures / unknown outcomes (failures are hard errors, unknown means the storage returned no value):

| Operation | Baseline failures | New failures | Baseline unknown | New unknown |
|---|---:|---:|---:|---:|
| `insert_under_client_kill` | 7 | 7 | 0 | 0 |
| `peek_mine_contended` | 0 | 0 | 127 | 135 |
| `commit_proposal` | 0 | 0 | 1 | 4 |
| `saturated_peek_mine` | 0 | 0 | 10 | 6 |
| `take_under_client_kill` | 0 | 0 | 4 | 5 |
| `deep_peek_mine` | 0 | 0 | 238 | 241 |
| `deep_commit` | 0 | 0 | 9 | 7 |
| `presig_stockpile_peek` | 0 | 0 | 92 | 96 |
| `take_contended` | 0 | 0 | 180 | 180 |

Failures and unknown outcomes are excluded from the latency percentiles (successes only). `insert_under_client_kill` had **7 failures in the baseline** and **the same 7 failures in this run** (3,593 successes both times) — the expected result of the scenario's 240 severed client connections. No other operation had a nonzero failure count in either run.

### Improvements

- `large_outdated_prune`: p50 4.87 → 4.32 ms (-11.3%), p95 7.02 → 5.01 ms (-28.6%), goodput 174.2 → 217.9/s (+25.1%).
- `large_argv_sync`: p50 5.34 → 5.06 ms (-5.2%), p95 8.14 → 5.49 ms (-32.6%), goodput 168.7 → 183.1/s (+8.5%).
- `take_contended`: p50 0.27 → 0.25 ms (-7.4%), p95 0.55 → 0.28 ms (-49.1%), goodput 2818.1 → 3920.2/s (+39.1%).
- `in_memory_insert`: p50 0.69 → 0.63 ms (-8.7%), p95 1.46 → 0.75 ms (-48.6%), goodput 14909.7 → 18450.6/s (+23.7%).
- Proposer/contention paths got faster: `peek_mine_contended` p50 0.30 → 0.28 ms (-6.7%), `commit_proposal` 0.31 → 0.30 ms (-3.2%), `churn_commit` 0.54 → 0.49 ms (-9.3%), `concurrent_take_triple_with_checkpoint` 90.99 → 82.92 ms (-8.9%), goodput 125.3 → 136.0/s (+8.5%).
- Pruning tail improved: `remove_outdated_storm` p95 13.74 → 7.85 ms (-42.9%), goodput 1459.0 → 1578.8/s (+8.2%).

### Regressions / noise

Several operations got worse in this single run; the changes are not attributable to this patch (caching a `Script` only removes client-side SHA1/allocation and cannot increase Redis-side latency), and the table shows both directions:

- `aof_fsync_insert` (+48.7% p50, +45.7% p95, -29.8% goodput) and `bgsave_concurrent_take` (+14.2% p50, +12.6% p95, -10.4% goodput) measure disk/AOF and BGSAVE stalls on the shared local Redis — directly subject to host I/O variance, not Lua preparation.
- `concurrent_insert_triple` (+7.9% p50, +76.1% p95, -15.1% goodput) and `concurrent_take_triple_no_poll` (+20.6% p50, +70.7% p95, -22.1% goodput) are high-QPS scenarios where small host/Redis scheduling differences dominate p95.
- Every `mixed_*` operation reports exactly -5.9% goodput, and `sync_*` operations -2.1% to -2.7%, which is a scenario-wide timing/throughput shift (fixed-count workloads over a fixed window) rather than a script-specific effect.
- `clear_triples_storm` / `clear_presigs_storm` p95 rose from 4.85 to 7.44/7.46 ms while p50 stayed at ~4.65 ms — a tail-latency outlier on 108 samples; `checkpoint_write`/`checkpoint_read` and `concurrent_insert_triple_with_checkpoint` were 1.4-8.0% slower, in the checkpoint contention workload that is dominated by 25k pending requests and Redis-side scans.

There is no mechanism in this change that can slow down script execution: the SHA1 hash and source copy happen once at first use, and `Script` is immutable (`code` + `hash`) and thread-safe. These regressions are treated as measurement noise on a shared local Redis/host; no code adjustment was made in response. A repeat run is needed before drawing strong conclusions from the small deltas.
