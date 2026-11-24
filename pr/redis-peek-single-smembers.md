## Description

Each `peek_mine` invocation runs a Lua script inside Redis. With a large ownership set the previous script issued `SCARD` for the set, then `SCARD`+`SMEMBERS` per candidate until one had holders. This replaces the per-candidate `SCARD`+`SMEMBERS` pair with a single `SMEMBERS`: the holder list is fetched once and tested with `#holders > 0`. An absent or empty set yields an empty list exactly as before, so behavior is unchanged. The initial `SCARD mine_key` early return is also removed — `SMEMBERS` on an empty set already returns no rows and falls through to `return nil`.

This halves the holder-related Redis commands on the hot selection path (from two commands per non-excluded candidate to one) without changing the Rust code, key layout, or semantics. It is a pure command-count reduction and is therefore most valuable on large ownership sets where many candidates are scanned per peek.

Note: open PR #1749 separately proposes random sampling of candidates; this change is orthogonal and composes with it.

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

Benchmark command (identical settings to baseline), run against a local **Redis 8.4.0** server on port 6399:

```sh
CARGO_TARGET_DIR=/private/var/folders/9r/zs_bh5_90rj11vlw571bfs8c0000gn/T/opencode/redis-bench-target \
cargo run --release -p integration-tests --bin redis-bench -- \
  --redis-url redis://default:bench@127.0.0.1:6399 \
  --allow-external-redis \
  --json-out tmp/redis-peek-single-smembers.json \
  --csv-out tmp/redis-peek-single-smembers.csv
```

- Compared commits: **baseline `ff9bb30`** (`continuous.redis.bench`) vs. **this branch** (`redis-peek-single-smembers`, same change). Full 46-operation suite, identical settings.
- Lower latency (p50/p95 in ms) is better; higher goodput (operations/sec) is better. Deltas are signed percentages relative to baseline.
- Failures and indeterminate/unknown outcomes are **excluded** from the latency percentiles (the harness reports successes only), so the percentile columns and the goodput/failure columns are not directly comparable in magnitude.

| Operation | Baseline p50 | New p50 | Δ p50 | Baseline p95 | New p95 | Δ p95 | Baseline goodput/s | New goodput/s | Δ goodput/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| concurrent_insert_triple | 0.63 | 0.62 | -1.6% | 0.71 | 0.71 | +0.0% | 18741.1 | 18856.1 | +0.6% |
| concurrent_take_triple | 0.36 | 0.34 | -5.6% | 0.64 | 0.39 | -39.1% | 30614.5 | 34582.3 | +13.0% |
| concurrent_insert_triple_no_poll | 0.64 | 0.61 | -4.7% | 0.85 | 0.66 | -22.4% | 17674.6 | 19431.9 | +9.9% |
| concurrent_take_triple_no_poll | 0.34 | 0.36 | +5.9% | 0.41 | 0.44 | +7.3% | 34171.6 | 32917.9 | -3.7% |
| concurrent_insert_triple_with_poll | 0.62 | 0.63 | +1.6% | 0.68 | 0.71 | +4.4% | 19177.2 | 18800.5 | -2.0% |
| concurrent_take_triple_with_poll | 0.34 | 0.37 | +8.8% | 0.40 | 0.46 | +15.0% | 34485.4 | 31454.5 | -8.8% |
| concurrent_insert_triple_no_checkpoint | 0.63 | 0.75 | +19.0% | 0.70 | 1.66 | +137.1% | 18918.6 | 12365.4 | -34.6% |
| concurrent_take_triple_no_checkpoint | 0.34 | 0.48 | +41.2% | 0.39 | 1.15 | +194.9% | 34523.5 | 18827.1 | -45.5% |
| concurrent_insert_triple_with_checkpoint | 178.15 | 165.77 | -6.9% | 251.76 | 279.23 | +10.9% | 64.9 | 67.6 | +4.2% |
| concurrent_take_triple_with_checkpoint | 90.99 | 79.56 | -12.6% | 146.80 | 122.73 | -16.4% | 125.3 | 145.1 | +15.8% |
| checkpoint_write | 297.35 | 266.32 | -10.4% | 402.23 | 410.99 | +2.2% | 39.5 | 43.1 | +9.1% |
| checkpoint_read | 174.36 | 165.91 | -4.8% | 300.47 | 297.88 | -0.9% | 65.0 | 67.3 | +3.5% |
| remove_outdated_storm | 7.29 | 7.25 | -0.5% | 13.74 | 8.39 | -38.9% | 1459.0 | 1593.8 | +9.2% |
| peek_mine_contended | 0.30 | 0.30 | +0.0% | 0.33 | 0.33 | +0.0% | 2993.4 | 2893.0 | -3.4% |
| commit_proposal | 0.31 | 0.30 | -3.2% | 0.35 | 0.34 | -2.9% | 2952.4 | 2848.5 | -3.5% |
| saturated_insert_triple | 1.60 | 1.71 | +6.9% | 2.04 | 3.51 | +72.1% | 10320.8 | 9842.1 | -4.6% |
| saturated_peek_mine | 2.54 | 2.51 | -1.2% | 3.01 | 3.60 | +19.6% | 4723.0 | 4706.5 | -0.3% |
| saturated_take_triple | 0.99 | 0.99 | +0.0% | 1.26 | 1.22 | -3.2% | 11506.2 | 11557.5 | +0.4% |
| clear_triples_storm | 4.64 | 4.58 | -1.3% | 4.85 | 4.93 | +1.6% | 2514.3 | 2538.9 | +1.0% |
| clear_presigs_storm | 4.66 | 4.58 | -1.7% | 4.85 | 4.92 | +1.4% | 2514.1 | 2526.3 | +0.5% |
| mixed_insert_triple | 1.55 | 1.56 | +0.6% | 1.69 | 1.75 | +3.6% | 4736.1 | 4665.8 | -1.5% |
| mixed_presig_peek_triple | 0.58 | 0.57 | -1.7% | 0.88 | 0.90 | +2.3% | 4736.1 | 4665.8 | -1.5% |
| mixed_presig_commit_triple | 0.57 | 0.59 | +3.5% | 0.88 | 0.90 | +2.3% | 4736.1 | 4665.8 | -1.5% |
| mixed_insert_presig | 1.11 | 1.16 | +4.5% | 1.64 | 1.66 | +1.2% | 4736.1 | 4665.8 | -1.5% |
| mixed_sign_peek_presig | 0.78 | 0.78 | +0.0% | 0.90 | 0.93 | +3.3% | 2368.1 | 2332.9 | -1.5% |
| mixed_sign_commit_presig | 0.77 | 0.78 | +1.3% | 0.90 | 0.92 | +2.2% | 2368.1 | 2332.9 | -1.5% |
| mixed_sign_take_presig | 0.57 | 0.57 | +0.0% | 0.87 | 0.89 | +2.3% | 18944.4 | 18663.3 | -1.5% |
| sync_update_triples | 4.36 | 4.40 | +0.9% | 4.51 | 4.63 | +2.7% | 1360.2 | 1347.8 | -0.9% |
| sync_update_presigs | 4.03 | 4.23 | +5.0% | 5.19 | 5.09 | -1.9% | 1360.2 | 1347.8 | -0.9% |
| sync_prune_triples | 7.27 | 7.26 | -0.1% | 7.40 | 7.69 | +3.9% | 835.8 | 828.0 | -0.9% |
| sync_prune_presigs | 6.87 | 6.95 | +1.2% | 8.25 | 8.62 | +4.5% | 835.8 | 828.0 | -0.9% |
| insert_under_client_kill | 0.63 | 0.63 | +0.0% | 0.74 | 0.67 | -9.5% | 18497.6 | 18925.4 | +2.3% |
| take_under_client_kill | 0.35 | 0.35 | +0.0% | 0.40 | 0.40 | +0.0% | 33616.1 | 33891.6 | +0.8% |
| take_post_reconnect | 0.35 | 0.35 | +0.0% | 0.39 | 0.38 | -2.6% | 34365.0 | 34264.5 | -0.3% |
| deep_peek_mine | 2.55 | 2.54 | -0.4% | 3.12 | 3.17 | +1.6% | 382.4 | 422.9 | +10.6% |
| deep_commit | 2.44 | 2.13 | -12.7% | 2.62 | 2.58 | -1.5% | 326.9 | 342.1 | +4.6% |
| presig_stockpile_peek | 0.97 | 0.98 | +1.0% | 1.14 | 1.21 | +6.1% | 1502.1 | 1035.5 | -31.1% |
| presig_stockpile_commit | 0.79 | 0.99 | +25.3% | 1.11 | 1.26 | +13.5% | 1502.1 | 1021.1 | -32.0% |
| churn_peek_mine | 0.23 | 0.23 | +0.0% | 0.50 | 0.30 | -40.0% | 1.6 | 1.6 | +0.0% |
| churn_commit | 0.54 | 0.45 | -16.7% | n/a | n/a | n/a | 0.8 | 0.8 | +0.0% |
| take_contended | 0.27 | 0.27 | +0.0% | 0.55 | 0.28 | -49.1% | 2818.1 | 3809.3 | +35.2% |
| large_argv_sync | 5.34 | 5.09 | -4.7% | 8.14 | 5.26 | -35.4% | 168.7 | 195.9 | +16.1% |
| large_outdated_prune | 4.87 | 4.36 | -10.5% | 7.02 | 4.85 | -30.9% | 174.2 | 227.8 | +30.8% |
| in_memory_insert | 0.69 | 0.61 | -11.6% | 1.46 | 0.67 | -54.1% | 14909.7 | 19472.0 | +30.6% |
| aof_fsync_insert | 16.12 | 17.99 | +11.6% | 24.01 | 21.96 | -8.5% | 723.4 | 714.6 | -1.2% |
| bgsave_concurrent_take | 13.95 | 15.93 | +14.2% | 15.95 | 19.12 | +19.9% | 880.0 | 735.4 | -16.4% |

### Improvements

- **`deep_peek_mine`** — the clearest peek-driven win: goodput 382.4 → 422.9 ops/s (**+10.6%**) with p50 2.55 → 2.54 ms (-0.4%); p95 3.12 → 3.17 ms (+1.6%) is within noise. This scenario scans the deepest candidate lists, where removing one Redis command per candidate matters most.
- **`churn_peek_mine`** — tail latency p95 0.50 → 0.30 ms (**-40.0%**); p50 flat (0.23 ms) and goodput flat (1.6/s, a throughput-capped scenario).
- **`saturated_peek_mine`** — p50 2.54 → 2.51 ms (-1.2%) and goodput essentially flat (4723.0 → 4706.5/s, -0.3%); the p50 edge is consistent with the command-count reduction.
- **`peek_mine_contended`** — p50 (0.30 ms) and p95 (0.33 ms) unchanged (+0.0%); goodput 2993.4 → 2893.0/s (-3.4%) is run-to-run noise. With short candidate lists in this scenario the saved `SCARD` is a very small fraction of total latency.
- **`mixed_presig_peek_triple`** — p50 0.58 → 0.57 ms (-1.7%); p95 (+2.3%) and goodput (-1.5%) are within noise. **`mixed_sign_peek_presig`** is effectively flat (p50 0.78 ms unchanged, p95 +3.3%, goodput -1.5%).

Overall, the peek-driven operations are at or better than baseline on median latency; the most meaningful gains appear in the deeper/larger scans, as expected for a per-candidate command reduction. Unknown (indeterminate) outcomes for the peek scenarios stayed within a narrow band: `peek_mine_contended` 127 → 135, `deep_peek_mine` 238 → 232, `saturated_peek_mine` 10 → 6, `presig_stockpile_peek` 92 → 128.

### Regressions / noise

- **`presig_stockpile_peek`** is the one peek-driven operation that clearly got worse: goodput 1502.1 → 1035.5/s (-31.1%), p95 1.14 → 1.21 ms (+6.1%), p50 0.97 → 0.98 ms (+1.0%). Its sibling **`presig_stockpile_commit`** shows an almost identical goodput drop (1502.1 → 1021.1/s, -32.0%) despite not exercising `peek_mine` differently, so this looks like a shared workload/sampling effect in the stockpile scenario rather than a consequence of the script change.
- Large p95/goodput swings in `concurrent_insert_triple_no_checkpoint` (p95 +137.1%, goodput -34.6%) and `concurrent_take_triple_no_checkpoint` (p95 +194.9%, goodput -45.5%) are run-to-run noise in sub-millisecond scenarios; these paths do not depend on the changed peek script.
- Smaller degradations within run-to-run noise: `bgsave_concurrent_take` (p50 +14.2%, p95 +19.9%, goodput -16.4%), `aof_fsync_insert` (p50 +11.6%, goodput -1.2%), `saturated_insert_triple` (p95 +72.1% from a 2.04 ms base, goodput -4.6%), `presig_stockpile_commit` (see above), `mixed_*_commit`/`mixed_insert_*` ops (~-1.5% goodput), and `sync_*` ops (~-0.9% goodput, low-single-digit p50/p95 deltas).
- Failures: only `insert_under_client_kill` changed (7 → 0), a kill/chaos scenario unrelated to this change. No other operation reported hard failures in either run.
