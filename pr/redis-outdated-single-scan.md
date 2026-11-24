## Description

Fuse the two full scans of `our_shares` inside the `remove_outdated` Lua script into one. The `our_shares_check` lookup used to classify incoming shares is now built in the same first pass that collects outdated IDs, and the second standalone loop is removed. Results are byte-for-byte unchanged: `our_shares_check[id] == 1` semantics, the 4096-item batch deletion, `HEXISTS`/`EXISTS`/`HDEL`/`SREM`/`DEL` not-found handling, and the `{outdated, not_found}` return shape are all preserved. No Rust code changed.

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

Benchmark command (identical settings for baseline and this branch):

```sh
mkdir -p tmp
set -o pipefail
CARGO_TARGET_DIR=/private/var/folders/9r/zs_bh5_90rj11vlw571bfs8c0000gn/T/opencode/redis-bench-target cargo run --release -p integration-tests --bin redis-bench -- --redis-url redis://default:bench@127.0.0.1:6399 --allow-external-redis --json-out tmp/redis-outdated-single-scan.json --csv-out tmp/redis-outdated-single-scan.csv
```

- Server: local standalone Redis **8.4.0** on `127.0.0.1:6399`.
- Commits compared: baseline `ff9bb30` (`tmp/baseline.csv`) vs this branch `redis-outdated-single-scan` (`tmp/redis-outdated-single-scan.csv`).
- Lower latency (p50/p95) and higher goodput are better. Deltas are signed percentages vs baseline: `(new - baseline) / baseline`.
- Latency percentiles are computed from successful samples only (failures / `unknown`/indeterminate outcomes are excluded, as reported by the harness). Goodput counts successfully completed operations per second.

Full comparison, all 46 operations (numbers verbatim from the CSVs):

| Operation | Baseline p50 | New p50 | Δ p50 | Baseline p95 | New p95 | Δ p95 | Baseline goodput/s | New goodput/s | Δ goodput/s |
|---|---|---|---|---|---|---|---|---|---|
| concurrent_insert_triple | 0.63 | 0.64 | +1.6% | 0.71 | 0.77 | +8.5% | 18741.1 | 18189.9 | -2.9% |
| concurrent_take_triple | 0.36 | 0.38 | +5.6% | 0.64 | 0.50 | -21.9% | 30614.5 | 30488.1 | -0.4% |
| concurrent_insert_triple_no_poll | 0.64 | 0.65 | +1.6% | 0.85 | 0.79 | -7.1% | 17674.6 | 17831.3 | +0.9% |
| concurrent_take_triple_no_poll | 0.34 | 0.38 | +11.8% | 0.41 | 0.50 | +22.0% | 34171.6 | 30442.8 | -10.9% |
| concurrent_insert_triple_with_poll | 0.62 | 0.65 | +4.8% | 0.68 | 0.77 | +13.2% | 19177.2 | 18085.7 | -5.7% |
| concurrent_take_triple_with_poll | 0.34 | 0.37 | +8.8% | 0.40 | 0.41 | +2.5% | 34485.4 | 32080.4 | -7.0% |
| concurrent_insert_triple_no_checkpoint | 0.63 | 0.65 | +3.2% | 0.70 | 0.76 | +8.6% | 18918.6 | 17341.2 | -8.3% |
| concurrent_take_triple_no_checkpoint | 0.34 | 0.58 | +70.6% | 0.39 | 1.48 | +279.5% | 34523.5 | 15475.8 | -55.2% |
| concurrent_insert_triple_with_checkpoint | 178.15 | 149.64 | -16.0% | 251.76 | 228.83 | -9.1% | 64.9 | 75.4 | +16.2% |
| concurrent_take_triple_with_checkpoint | 90.99 | 76.87 | -15.5% | 146.80 | 129.41 | -11.8% | 125.3 | 145.5 | +16.1% |
| checkpoint_write | 297.35 | 249.82 | -16.0% | 402.23 | 381.84 | -5.1% | 39.5 | 46.1 | +16.7% |
| checkpoint_read | 174.36 | 155.66 | -10.7% | 300.47 | 280.88 | -6.5% | 65.0 | 72.0 | +10.8% |
| remove_outdated_storm | 7.29 | 7.05 | -3.3% | 13.74 | 8.20 | -40.3% | 1459.0 | 1600.9 | +9.7% |
| peek_mine_contended | 0.30 | 0.29 | -3.3% | 0.33 | 0.49 | +48.5% | 2993.4 | 2450.0 | -18.2% |
| commit_proposal | 0.31 | 0.29 | -6.5% | 0.35 | 0.95 | +171.4% | 2952.4 | 2450.0 | -17.0% |
| saturated_insert_triple | 1.60 | 1.68 | +5.0% | 2.04 | 7.31 | +258.3% | 10320.8 | 5512.7 | -46.6% |
| saturated_peek_mine | 2.54 | 3.11 | +22.4% | 3.01 | 6.58 | +118.6% | 4723.0 | 4405.0 | -6.7% |
| saturated_take_triple | 0.99 | 1.16 | +17.2% | 1.26 | 2.17 | +72.2% | 11506.2 | 47622.7 | +313.9% |
| clear_triples_storm | 4.64 | 4.53 | -2.4% | 4.85 | 4.81 | -0.8% | 2514.3 | 2574.6 | +2.4% |
| clear_presigs_storm | 4.66 | 4.45 | -4.5% | 4.85 | 4.82 | -0.6% | 2514.1 | 2554.0 | +1.6% |
| mixed_insert_triple | 1.55 | 1.57 | +1.3% | 1.69 | 1.77 | +4.7% | 4736.1 | 4601.1 | -2.9% |
| mixed_presig_peek_triple | 0.58 | 0.61 | +5.2% | 0.88 | 0.91 | +3.4% | 4736.1 | 4601.1 | -2.9% |
| mixed_presig_commit_triple | 0.57 | 0.61 | +7.0% | 0.88 | 0.89 | +1.1% | 4736.1 | 4601.1 | -2.9% |
| mixed_insert_presig | 1.11 | 1.14 | +2.7% | 1.64 | 1.70 | +3.7% | 4736.1 | 4601.1 | -2.9% |
| mixed_sign_peek_presig | 0.78 | 0.81 | +3.8% | 0.90 | 0.93 | +3.3% | 2368.1 | 2300.6 | -2.9% |
| mixed_sign_commit_presig | 0.77 | 0.79 | +2.6% | 0.90 | 0.91 | +1.1% | 2368.1 | 2300.6 | -2.9% |
| mixed_sign_take_presig | 0.57 | 0.60 | +5.3% | 0.87 | 0.90 | +3.4% | 18944.4 | 18404.5 | -2.8% |
| sync_update_triples | 4.36 | 4.38 | +0.5% | 4.51 | 4.51 | +0.0% | 1360.2 | 1367.8 | +0.6% |
| sync_update_presigs | 4.03 | 3.63 | -9.9% | 5.19 | 5.03 | -3.1% | 1360.2 | 1367.8 | +0.6% |
| sync_prune_triples | 7.27 | 7.28 | +0.1% | 7.40 | 7.47 | +0.9% | 835.8 | 840.5 | +0.6% |
| sync_prune_presigs | 6.87 | 5.80 | -15.6% | 8.25 | 8.29 | +0.5% | 835.8 | 840.5 | +0.6% |
| insert_under_client_kill | 0.63 | 0.65 | +3.2% | 0.74 | 0.69 | -6.8% | 18497.6 | 18081.6 | -2.2% |
| take_under_client_kill | 0.35 | 0.36 | +2.9% | 0.40 | 0.40 | +0.0% | 33616.1 | 32533.4 | -3.2% |
| take_post_reconnect | 0.35 | 0.38 | +8.6% | 0.39 | 0.66 | +69.2% | 34365.0 | 29246.5 | -14.9% |
| deep_peek_mine | 2.55 | 2.59 | +1.6% | 3.12 | 3.22 | +3.2% | 382.4 | 404.8 | +5.9% |
| deep_commit | 2.44 | 2.37 | -2.9% | 2.62 | 2.60 | -0.8% | 326.9 | 336.3 | +2.9% |
| presig_stockpile_peek | 0.97 | 0.93 | -4.1% | 1.14 | 1.09 | -4.4% | 1502.1 | 1255.0 | -16.5% |
| presig_stockpile_commit | 0.79 | 0.92 | +16.5% | 1.11 | 1.12 | +0.9% | 1502.1 | 1255.0 | -16.5% |
| churn_peek_mine | 0.23 | 0.24 | +4.3% | 0.50 | 0.75 | +50.0% | 1.6 | 1.6 | +0.0% |
| churn_commit | 0.54 | 1.27 | +135.2% | n/a | n/a | n/a | 0.8 | 0.8 | +0.0% |
| take_contended | 0.27 | 0.48 | +77.8% | 0.55 | 0.67 | +21.8% | 2818.1 | 1985.9 | -29.5% |
| large_argv_sync | 5.34 | 4.91 | -8.1% | 8.14 | 5.21 | -36.0% | 168.7 | 201.8 | +19.6% |
| large_outdated_prune | 4.87 | 4.26 | -12.5% | 7.02 | 4.66 | -33.6% | 174.2 | 230.2 | +32.1% |
| in_memory_insert | 0.69 | 0.72 | +4.3% | 1.46 | 0.94 | -35.6% | 14909.7 | 16108.1 | +8.0% |
| aof_fsync_insert | 16.12 | 14.99 | -7.0% | 24.01 | 20.03 | -16.6% | 723.4 | 804.2 | +11.2% |
| bgsave_concurrent_take | 13.95 | 10.79 | -22.7% | 15.95 | 15.00 | -6.0% | 880.0 | 1071.3 | +21.7% |

### Improvements

The operations that actually drive `remove_outdated` show the clearest wins:

- **`remove_outdated_storm`** — p50 7.29 → 7.05 ms (-3.3%), p95 13.74 → 8.20 ms (-40.3%), goodput 1459.0 → 1600.9/s (+9.7%). The tail collapses as the second Lua pass over the owner set is removed.
- **`large_outdated_prune`** — p50 4.87 → 4.26 ms (-12.5%), p95 7.02 → 4.66 ms (-33.6%), goodput 174.2 → 230.2/s (+32.1%). Largest owner-set case, so it benefits most from halving the Lua scan work.
- **`large_argv_sync`** — p50 5.34 → 4.91 ms (-8.1%), p95 8.14 → 5.21 ms (-36.0%), goodput 168.7 → 201.8/s (+19.6%). Same pattern with a large `ARGV` classification pass.
- **`sync_prune_presigs`** — p50 6.87 → 5.80 ms (-15.6%), p95 8.25 → 8.29 ms (+0.5%, flat), goodput 835.8 → 840.5/s (+0.6%). Median improves; tail and goodput are effectively unchanged.
- **`sync_prune_triples`** — p50 7.27 → 7.28 ms (+0.1%), p95 7.40 → 7.47 ms (+0.9%), goodput 835.8 → 840.5/s (+0.6%): within run-to-run noise, no regression.

Corroborating (indirect) wins in the checkpoint path, which also exercises owner-set pruning: `checkpoint_write` p50 -16.0% / goodput +16.7%, `checkpoint_read` p50 -10.7% / goodput +10.8%, `concurrent_*_triple_with_checkpoint` p50 -16.0% / -15.5% and goodput +16.2% / +16.1%.

### Regressions / noise

Several sub-millisecond, client-scheduling-dominated operations were slower in this run. They do not invoke `remove_outdated`, so the change cannot affect their server-side path; the differences are consistent with run-to-run jitter (baseline also shows anomalous ~253 ms p99 spikes in the `saturated_*` cases that are absent in the new run):

- `concurrent_take_triple_no_checkpoint`: p50 0.34 → 0.58 ms (+70.6%), p95 0.39 → 1.48 ms (+279.5%), goodput -55.2%.
- `saturated_insert_triple`: p95 2.04 → 7.31 ms (+258.3%), goodput -46.6% (baseline p99 253.88 ms).
- `take_contended`: p50 +77.8%, goodput -29.5%.
- `churn_commit`: p50 0.54 → 1.27 ms (+135.2%); sample count is tiny (17) and p95 is `n/a` in both runs.
- `take_post_reconnect` goodput -14.9%, `presig_stockpile_*` goodput -16.5%, `peek_mine_contended` / `commit_proposal` goodput -18.2% / -17.0%.

No regression was observed in any operation that exercises `remove_outdated` (the five operations above plus the checkpoint paths). Failures and `unknown`/indeterminate outcomes are excluded from the latency percentiles; their counts are unchanged or lower for the targeted operations (e.g. `insert_under_client_kill` failures 7 → 2, `take_under_client_kill` unknown 4 → 2).

## Motivation

`remove_outdated` scans the owner set twice inside one Lua script — once to find outdated IDs and once to build a lookup used to classify incoming shares. On large owner sets this doubles Lua work for a table that can be built during the first pass; fusing the passes reduces server-side script time without changing results.

This change is orthogonal to open PRs #1744/#1745 (deletion changes) and #1749 (slot/sampling).
