## Description

Demote two per-artifact **success** events in `chain-signatures/node/src/storage/protocol_storage.rs` from `INFO` to `DEBUG`:

- `take`: `tracing::info!(id, ?elapsed, "took artifact")` → `tracing::debug!(...)`
- `commit_reserved`: `tracing::info!(id, ?elapsed, "committed reservation, took artifact")` → `tracing::debug!(...)`

Message text and fields are unchanged; all `warn!`/`error!` events are untouched.

Motivation: this environment exports `RUST_LOG=info,workspaces=warn` globally. A 2-minute baseline run emitted **29,219** `took artifact` and **2,050** `committed reservation, took artifact` formatted log lines. That formatting/I/O happens on the thread inside the storage API call the harness times (and in the client process, not the Redis server). `INFO` is a common production log level, so demoting these high-volume success events to `DEBUG` removes real client-side overhead while keeping the diagnostic available when `DEBUG` is enabled. No Redis commands, key layout, or server-side execution change.

## Breaking changes

- [x] None
- [ ] Node–Node: [details here]
- [ ] Contract–Node: [details here]
- [ ] Contract state: [details here]
- [ ] Network–Applications: [details here]
- [ ] Operator (flags, env vars, config, storage migration): [details here]

## Design

- [x] Trivial: no design decision involved (CI, tests, tooling, dependencies, refactor without behaviour change)
- [ ] Follows the existing design in [doc/](https://github.com/sig-net/mpc/tree/develop/doc)
- [ ] Adds or changes the design; docs updated in this PR or in: [link]
- [ ] Non-trivial, but this area has no design doc yet; tracked in: [issue link]

## Performance results

**Command (identical for baseline and this branch):**

```
mkdir -p tmp
set -o pipefail
CARGO_TARGET_DIR=/private/var/folders/9r/zs_bh5_90rj11vlw571bfs8c0000gn/T/opencode/redis-bench-target cargo run --release -p integration-tests --bin redis-bench -- --redis-url redis://default:bench@127.0.0.1:6399 --allow-external-redis --json-out tmp/redis-debug-artifact-success-logs.json --csv-out tmp/redis-debug-artifact-success-logs.csv 2>&1 | tee tmp/redis-debug-artifact-success-logs-run.log
```

- Local Redis **8.4.0** standalone server on port 6399 (`PING` verified before each run), full 15-scenario / 46-operation suite.
- Baseline: `ff9bb300833a15ada23529b172c67e45ac90a0c0` (`continuous.redis.bench`, `tmp/baseline.csv`). New: this branch, one commit on top of that baseline (`tmp/redis-debug-artifact-success-logs.csv`, second/warm run of two identical runs).
- Lower latency and higher goodput are better. Δ = (new − baseline) / baseline, verbatim CSV values; signed % deltas.
- Failures and unknown/indeterminate outcomes are excluded from latency percentiles. Successful-sample counts are unchanged (46 rows, 1 iteration each). Failures were 0 everywhere except `insert_under_client_kill` (7 → 8); unknown counts moved only slightly: `peek_mine_contended` 127 → 134, `commit_proposal` 1 → 3, `saturated_peek_mine` 10 → 1, `take_under_client_kill` 4 → 6, `deep_commit` 9 → 10, `presig_stockpile_peek` 92 → 85; unchanged for `deep_peek_mine` (238) and `take_contended` (180).

| Operation | Baseline p50 | New p50 | Δ p50 | Baseline p95 | New p95 | Δ p95 | Baseline goodput/s | New goodput/s | Δ goodput/s |
|---|---|---|---|---|---|---|---|---|---|
| concurrent_insert_triple | 0.63 | 0.67 | +6.3% | 0.71 | 1.33 | +87.3% | 18741.1 | 16179.7 | -13.7% |
| concurrent_take_triple | 0.36 | 0.38 | +5.6% | 0.64 | 0.42 | -34.4% | 30614.5 | 31587.8 | +3.2% |
| concurrent_insert_triple_no_poll | 0.64 | 0.66 | +3.1% | 0.85 | 0.71 | -16.5% | 17674.6 | 18089.5 | +2.3% |
| concurrent_take_triple_no_poll | 0.34 | 0.38 | +11.8% | 0.41 | 0.43 | +4.9% | 34171.6 | 31050.9 | -9.1% |
| concurrent_insert_triple_with_poll | 0.62 | 0.66 | +6.5% | 0.68 | 0.71 | +4.4% | 19177.2 | 18097.7 | -5.6% |
| concurrent_take_triple_with_poll | 0.34 | 0.38 | +11.8% | 0.40 | 0.42 | +5.0% | 34485.4 | 31363.8 | -9.1% |
| concurrent_insert_triple_no_checkpoint | 0.63 | 0.68 | +7.9% | 0.70 | 1.45 | +107.1% | 18918.6 | 15634.5 | -17.4% |
| concurrent_take_triple_no_checkpoint | 0.34 | 0.38 | +11.8% | 0.39 | 0.42 | +7.7% | 34523.5 | 31578.2 | -8.5% |
| concurrent_insert_triple_with_checkpoint | 178.15 | 130.15 | -26.9% | 251.76 | 172.50 | -31.5% | 64.9 | 90.0 | +38.7% |
| concurrent_take_triple_with_checkpoint | 90.99 | 75.70 | -16.8% | 146.80 | 114.01 | -22.3% | 125.3 | 154.3 | +23.1% |
| checkpoint_write | 297.35 | 226.72 | -23.8% | 402.23 | 312.60 | -22.3% | 39.5 | 51.5 | +30.4% |
| checkpoint_read | 174.36 | 135.73 | -22.2% | 300.47 | 222.55 | -25.9% | 65.0 | 84.3 | +29.7% |
| remove_outdated_storm | 7.29 | 7.61 | +4.4% | 13.74 | 9.77 | -28.9% | 1459.0 | 1449.5 | -0.7% |
| peek_mine_contended | 0.30 | 0.28 | -6.7% | 0.33 | 0.31 | -6.1% | 2993.4 | 3194.7 | +6.7% |
| commit_proposal | 0.31 | 0.29 | -6.5% | 0.35 | 0.32 | -8.6% | 2952.4 | 3049.5 | +3.3% |
| saturated_insert_triple | 1.60 | 1.52 | -5.0% | 2.04 | 1.92 | -5.9% | 10320.8 | 10515.8 | +1.9% |
| saturated_peek_mine | 2.54 | 2.46 | -3.1% | 3.01 | 2.87 | -4.7% | 4723.0 | 4806.0 | +1.8% |
| saturated_take_triple | 0.99 | 1.02 | +3.0% | 1.26 | 1.19 | -5.6% | 11506.2 | 59844.6 | +420.1% |
| clear_triples_storm | 4.64 | 4.86 | +4.7% | 4.85 | 5.26 | +8.5% | 2514.3 | 2377.6 | -5.4% |
| clear_presigs_storm | 4.66 | 4.85 | +4.1% | 4.85 | 5.29 | +9.1% | 2514.1 | 2368.1 | -5.8% |
| mixed_insert_triple | 1.55 | 1.59 | +2.6% | 1.69 | 1.89 | +11.8% | 4736.1 | 4323.1 | -8.7% |
| mixed_presig_peek_triple | 0.58 | 0.65 | +12.1% | 0.88 | 1.03 | +17.0% | 4736.1 | 4323.1 | -8.7% |
| mixed_presig_commit_triple | 0.57 | 0.63 | +10.5% | 0.88 | 0.99 | +12.5% | 4736.1 | 4323.1 | -8.7% |
| mixed_insert_presig | 1.11 | 1.28 | +15.3% | 1.64 | 1.85 | +12.8% | 4736.1 | 4323.1 | -8.7% |
| mixed_sign_peek_presig | 0.78 | 0.81 | +3.8% | 0.90 | 1.00 | +11.1% | 2368.1 | 2161.5 | -8.7% |
| mixed_sign_commit_presig | 0.77 | 0.79 | +2.6% | 0.90 | 0.97 | +7.8% | 2368.1 | 2161.5 | -8.7% |
| mixed_sign_take_presig | 0.57 | 0.63 | +10.5% | 0.87 | 1.00 | +14.9% | 18944.4 | 17292.3 | -8.7% |
| sync_update_triples | 4.36 | 4.47 | +2.5% | 4.51 | 4.88 | +8.2% | 1360.2 | 1280.1 | -5.9% |
| sync_update_presigs | 4.03 | 4.18 | +3.7% | 5.19 | 6.42 | +23.7% | 1360.2 | 1280.1 | -5.9% |
| sync_prune_triples | 7.27 | 7.49 | +3.0% | 7.40 | 8.84 | +19.5% | 835.8 | 757.5 | -9.4% |
| sync_prune_presigs | 6.87 | 7.54 | +9.8% | 8.25 | 10.06 | +21.9% | 835.8 | 757.5 | -9.4% |
| insert_under_client_kill | 0.63 | 0.62 | -1.6% | 0.74 | 0.66 | -10.8% | 18497.6 | 18810.9 | +1.7% |
| take_under_client_kill | 0.35 | 0.36 | +2.9% | 0.40 | 0.41 | +2.5% | 33616.1 | 32683.5 | -2.8% |
| take_post_reconnect | 0.35 | 0.36 | +2.9% | 0.39 | 0.48 | +23.1% | 34365.0 | 31614.3 | -8.0% |
| deep_peek_mine | 2.55 | 2.58 | +1.2% | 3.12 | 3.21 | +2.9% | 382.4 | 382.3 | -0.0% |
| deep_commit | 2.44 | 2.44 | +0.0% | 2.62 | 2.56 | -2.3% | 326.9 | 320.6 | -1.9% |
| presig_stockpile_peek | 0.97 | 0.92 | -5.2% | 1.14 | 1.18 | +3.5% | 1502.1 | 1568.5 | +4.4% |
| presig_stockpile_commit | 0.79 | 0.78 | -1.3% | 1.11 | 1.11 | +0.0% | 1502.1 | 1568.5 | +4.4% |
| churn_peek_mine | 0.23 | 0.25 | +8.7% | 0.50 | 2.04 | +308.0% | 1.6 | 1.6 | +0.0% |
| churn_commit | 0.54 | 0.46 | -14.8% | n/a | n/a | n/a | 0.8 | 0.8 | +0.0% |
| take_contended | 0.27 | 0.26 | -3.7% | 0.55 | 0.34 | -38.2% | 2818.1 | 3674.6 | +30.4% |
| large_argv_sync | 5.34 | 4.92 | -7.9% | 8.14 | 5.42 | -33.4% | 168.7 | 197.5 | +17.1% |
| large_outdated_prune | 4.87 | 4.19 | -14.0% | 7.02 | 4.71 | -32.9% | 174.2 | 232.3 | +33.4% |
| in_memory_insert | 0.69 | 0.65 | -5.8% | 1.46 | 0.70 | -52.1% | 14909.7 | 18202.4 | +22.1% |
| aof_fsync_insert | 16.12 | 18.00 | +11.7% | 24.01 | 20.97 | -12.7% | 723.4 | 708.6 | -2.0% |
| bgsave_concurrent_take | 13.95 | 10.01 | -28.2% | 15.95 | 11.09 | -30.5% | 880.0 | 1189.6 | +35.2% |

### Improvements (take / commit_reserved hot paths)

- `concurrent_take_triple_with_checkpoint`: p50 90.99 → 75.70 ms (**−16.8%**), p95 146.80 → 114.01 ms (**−22.3%**), goodput 125.3 → 154.3/s (**+23.1%**).
- `take_contended`: p50 0.27 → 0.26 ms (−3.7%), p95 0.55 → 0.34 ms (**−38.2%**), goodput 2818.1 → 3674.6/s (**+30.4%**).
- `bgsave_concurrent_take`: p50 13.95 → 10.01 ms (**−28.2%**), p95 15.95 → 11.09 ms (**−30.5%**), goodput 880.0 → 1189.6/s (**+35.2%**).
- `commit_proposal`: p50 0.31 → 0.29 ms (−6.5%), p95 0.35 → 0.32 ms (−8.6%), goodput 2952.4 → 3049.5/s (+3.3%).
- `concurrent_take_triple`: p95 0.64 → 0.42 ms (−34.4%), goodput 30614.5 → 31587.8/s (+3.2%).
- `presig_stockpile_commit`: p50 0.79 → 0.78 ms (−1.3%), goodput 1502.1 → 1568.5/s (+4.4%).
- `deep_commit`: p95 2.62 → 2.56 ms (−2.3%), p50 unchanged at 2.44 ms.
- `saturated_take_triple`: p95 1.26 → 1.19 ms (−5.6%) — see the goodput caveat below.

### Regressions / noise

- Several take/commit operations were **slower** in this run: `mixed_sign_take_presig` p50 0.57 → 0.63 ms (+10.5%), `mixed_sign_commit_presig` p50 +2.6%, `mixed_presig_commit_triple` p50 +10.5%, `take_under_client_kill` p50 +2.9%, `take_post_reconnect` p50 +2.9% / p95 +23.1%, `saturated_take_triple` p50 +3.0%. Non-take operations also moved both ways (e.g. `concurrent_insert_triple` p50 +6.3%, `aof_fsync_insert` p50 +11.7%), which points to run-to-run noise rather than a change caused by this patch.
- Confirmation run: two identical full-suite runs were executed (the table is the second, warm run). On the first run the same ops often moved the other way, e.g. `commit_proposal` p50 0.32 ms (+3.2%) vs 0.29 ms here, `presig_stockpile_commit` 0.95 ms (+20.3%) vs 0.78 ms here, `take_contended` 0.50 ms (+85.2%) vs 0.26 ms here, `deep_commit` 2.05 ms (−16.0%) vs 2.44 ms here. Sub-millisecond deltas should be read as noise; prior A/B runs in this environment show the same ±10–20% spread.
- `saturated_take_triple` goodput 11506.2 → 59844.6/s (+420.1%) is a harness artifact, not a real gain: the baseline row contains a 253 ms max sample (p99 253.00 ms) that inflates the baseline wall time, while the new row's max is 1.63 ms. Same successful sample count (3600) in both.
- `churn_commit` p95 and `churn_peek_mine` p95 are extremely low-sample operations (1.6 goodput/s) and swing by hundreds of percent; ignore those percentiles.
- The large `checkpoint_*` / `sync_*` / `large_*` improvements appear in both runs but are not on the `take`/`commit_reserved` path (e.g. `checkpoint_write` p50 −23.8%, `checkpoint_read` −22.2%). They are reported for completeness, not attributed to this change.

### Transparency / scope

- This is a **client-side** overhead optimization, not a Redis server-side one. No Redis command, key layout, TTL, Lua script, or server execution changed.
- Benchmark visibility depends entirely on the log level: `RUST_LOG=info,workspaces=warn` was exported in the shell for both runs (verified). With `RUST_LOG=warn` (or higher), neither baseline nor patched binary would emit these lines and no latency difference is expected.
- Deterministic outcome — log volume from the two runs (same suite, same settings):

  | | baseline | patched |
  |---|---|---|
  | `took artifact` lines | 29,219 | 0 |
  | `committed reservation, took artifact` lines | 2,050 | 0 |
  | run log lines | 30,861 | 543 |
  | run log size | 5,836,271 bytes (5.6 MB) | 87,283 bytes (85 KB) |

  Warn/error lines (e.g. `failed to take artifact`) are still emitted at `WARN` and are unchanged.
- Runtime: each full suite took roughly 2 minutes; the first patched run additionally spent 1m01s compiling release artifacts. Checks: `CARGO_TARGET_DIR=... cargo check -p mpc-node --all-features`, `cargo fmt --all -- --check`, and `git diff --stat` (1 file, 2 lines) all passed.
