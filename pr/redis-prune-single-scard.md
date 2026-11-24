## Description

State-sync holder updates call `remove_holder_and_prune` once per artifact (triples and presignatures). Inside its Lua script, each owned ID previously issued `SISMEMBER` (owner guard), `EXISTS` (holder-key presence), `SREM` (remove peer), and `SCARD` (post-removal holder count) — four holder-key/owner-key commands before the pruning decision.

This change restructures that loop to use one `SCARD` before the removal and derives the post-removal count from `SREM`'s return value:

- `SCARD` returns 0 both when the holders key is absent and when the set is empty, so it replaces `EXISTS` for the "no holders" case.
- `SREM` returns the number of members actually removed (0 or 1 here); subtracting it from the pre-removal `SCARD` yields the same post-removal count without issuing a second `SCARD`.

This removes 2 of the 4 Redis commands per holder ID (`EXISTS` and the second `SCARD`) on the hot sync path, with identical results. The owner-membership guard, `{removed, updated}` return values, threshold comparison, and `DEL holders_key` are all preserved. No Rust code, key layout, or semantics change.

Orthogonal to open PR #1744 (replacing `DEL` with `UNLINK` during prune) and PR #1749 (slot/sampling for state sync); this change composes with both.

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
mkdir -p tmp
set -o pipefail
CARGO_TARGET_DIR=/private/var/folders/9r/zs_bh5_90rj11vlw571bfs8c0000gn/T/opencode/redis-bench-target \
cargo run --release -p integration-tests --bin redis-bench -- \
  --redis-url redis://default:bench@127.0.0.1:6399 \
  --allow-external-redis \
  --json-out tmp/redis-prune-single-scard.json \
  --csv-out tmp/redis-prune-single-scard.csv
```

- Compared commits: **baseline `ff9bb30`** (`continuous.redis.bench`) vs. **this branch** (`redis-prune-single-scard`). Full 46-operation suite, identical settings; benchmark wall time ~2m03s.
- Lower latency (p50/p95 in ms) is better; higher goodput (operations/sec) is better. Deltas are signed percentages relative to baseline, with baseline/new numbers verbatim from the CSVs.
- Failures and indeterminate/unknown outcomes are **excluded** from the latency percentiles (the harness reports successes only), so the percentile columns and the goodput/failure columns are not directly comparable in magnitude.

| Operation | Baseline p50 | New p50 | Δ p50 | Baseline p95 | New p95 | Δ p95 | Baseline goodput/s | New goodput/s | Δ goodput/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `concurrent_insert_triple` | 0.63 | 0.65 | +3.2% | 0.71 | 1.17 | +64.8% | 18741.1 | 16692.8 | -10.9% |
| `concurrent_take_triple` | 0.36 | 0.36 | +0.0% | 0.64 | 0.47 | -26.6% | 30614.5 | 31824.4 | +4.0% |
| `concurrent_insert_triple_no_poll` | 0.64 | 0.65 | +1.6% | 0.85 | 0.70 | -17.6% | 17674.6 | 18317.5 | +3.6% |
| `concurrent_take_triple_no_poll` | 0.34 | 0.37 | +8.8% | 0.41 | 0.41 | +0.0% | 34171.6 | 32112.8 | -6.0% |
| `concurrent_insert_triple_with_poll` | 0.62 | 0.64 | +3.2% | 0.68 | 0.69 | +1.5% | 19177.2 | 18517.6 | -3.4% |
| `concurrent_take_triple_with_poll` | 0.34 | 0.37 | +8.8% | 0.40 | 0.40 | +0.0% | 34485.4 | 32455.1 | -5.9% |
| `concurrent_insert_triple_no_checkpoint` | 0.63 | 0.65 | +3.2% | 0.70 | 1.40 | +100.0% | 18918.6 | 15792.2 | -16.5% |
| `concurrent_take_triple_no_checkpoint` | 0.34 | 0.37 | +8.8% | 0.39 | 0.40 | +2.6% | 34523.5 | 32601.5 | -5.6% |
| `concurrent_insert_triple_with_checkpoint` | 178.15 | 170.47 | -4.3% | 251.76 | 270.73 | +7.5% | 64.9 | 66.2 | +2.0% |
| `concurrent_take_triple_with_checkpoint` | 90.99 | 83.67 | -8.0% | 146.80 | 143.11 | -2.5% | 125.3 | 133.7 | +6.7% |
| `checkpoint_write` | 297.35 | 282.61 | -5.0% | 402.23 | 418.17 | +4.0% | 39.5 | 41.0 | +3.8% |
| `checkpoint_read` | 174.36 | 173.75 | -0.3% | 300.47 | 308.56 | +2.7% | 65.0 | 64.3 | -1.1% |
| `remove_outdated_storm` | 7.29 | 7.78 | +6.7% | 13.74 | 22.22 | +61.7% | 1459.0 | 978.2 | -33.0% |
| `peek_mine_contended` | 0.30 | 0.33 | +10.0% | 0.33 | 0.37 | +12.1% | 2993.4 | 2437.6 | -18.6% |
| `commit_proposal` | 0.31 | 0.35 | +12.9% | 0.35 | 0.41 | +17.1% | 2952.4 | 2398.3 | -18.8% |
| `saturated_insert_triple` | 1.60 | 2.52 | +57.5% | 2.04 | 34.93 | +1612.3% | 10320.8 | 3643.4 | -64.7% |
| `saturated_peek_mine` | 2.54 | 2.62 | +3.1% | 3.01 | 3.27 | +8.6% | 4723.0 | 23064.0 | +388.3% |
| `saturated_take_triple` | 0.99 | 1.19 | +20.2% | 1.26 | 1.98 | +57.1% | 11506.2 | 10991.8 | -4.5% |
| `clear_triples_storm` | 4.64 | 4.61 | -0.6% | 4.85 | 5.65 | +16.5% | 2514.3 | 2477.3 | -1.5% |
| `clear_presigs_storm` | 4.66 | 4.63 | -0.6% | 4.85 | 5.67 | +16.9% | 2514.1 | 2477.0 | -1.5% |
| `mixed_insert_triple` | 1.55 | 1.57 | +1.3% | 1.69 | 1.77 | +4.7% | 4736.1 | 4600.2 | -2.9% |
| `mixed_presig_peek_triple` | 0.58 | 0.59 | +1.7% | 0.88 | 0.93 | +5.7% | 4736.1 | 4600.2 | -2.9% |
| `mixed_presig_commit_triple` | 0.57 | 0.58 | +1.8% | 0.88 | 0.92 | +4.5% | 4736.1 | 4600.2 | -2.9% |
| `mixed_insert_presig` | 1.11 | 1.15 | +3.6% | 1.64 | 1.69 | +3.0% | 4736.1 | 4600.2 | -2.9% |
| `mixed_sign_peek_presig` | 0.78 | 0.81 | +3.8% | 0.90 | 0.94 | +4.4% | 2368.1 | 2300.1 | -2.9% |
| `mixed_sign_commit_presig` | 0.77 | 0.79 | +2.6% | 0.90 | 0.92 | +2.2% | 2368.1 | 2300.1 | -2.9% |
| `mixed_sign_take_presig` | 0.57 | 0.57 | +0.0% | 0.87 | 0.91 | +4.6% | 18944.4 | 18400.8 | -2.9% |
| `sync_update_triples` | 4.36 | 3.94 | -9.6% | 4.51 | 4.40 | -2.4% | 1360.2 | 1523.6 | +12.0% |
| `sync_update_presigs` | 4.03 | 3.46 | -14.1% | 5.19 | 4.39 | -15.4% | 1360.2 | 1523.6 | +12.0% |
| `sync_prune_triples` | 7.27 | 6.70 | -7.8% | 7.40 | 7.49 | +1.2% | 835.8 | 881.3 | +5.4% |
| `sync_prune_presigs` | 6.87 | 6.20 | -9.8% | 8.25 | 8.17 | -1.0% | 835.8 | 881.3 | +5.4% |
| `insert_under_client_kill` | 0.63 | 0.70 | +11.1% | 0.74 | 0.79 | +6.8% | 18497.6 | 16679.1 | -9.8% |
| `take_under_client_kill` | 0.35 | 0.39 | +11.4% | 0.40 | 0.45 | +12.5% | 33616.1 | 29883.4 | -11.1% |
| `take_post_reconnect` | 0.35 | 0.37 | +5.7% | 0.39 | 0.42 | +7.7% | 34365.0 | 32017.7 | -6.8% |
| `deep_peek_mine` | 2.55 | 2.60 | +2.0% | 3.12 | 3.22 | +3.2% | 382.4 | 389.1 | +1.8% |
| `deep_commit` | 2.44 | 2.45 | +0.4% | 2.62 | 2.63 | +0.4% | 326.9 | 327.3 | +0.1% |
| `presig_stockpile_peek` | 0.97 | 0.96 | -1.0% | 1.14 | 1.18 | +3.5% | 1502.1 | 1154.0 | -23.2% |
| `presig_stockpile_commit` | 0.79 | 0.91 | +15.2% | 1.11 | 1.19 | +7.2% | 1502.1 | 1139.9 | -24.1% |
| `churn_peek_mine` | 0.23 | 0.24 | +4.3% | 0.50 | 1.83 | +266.0% | 1.6 | 1.6 | +0.0% |
| `churn_commit` | 0.54 | 1.40 | +159.3% | n/a | n/a | n/a | 0.8 | 0.8 | +0.0% |
| `take_contended` | 0.27 | 0.49 | +81.5% | 0.55 | 0.63 | +14.5% | 2818.1 | 2028.0 | -28.0% |
| `large_argv_sync` | 5.34 | 5.12 | -4.1% | 8.14 | 5.37 | -34.0% | 168.7 | 195.2 | +15.7% |
| `large_outdated_prune` | 4.87 | 4.31 | -11.5% | 7.02 | 5.30 | -24.5% | 174.2 | 222.7 | +27.8% |
| `in_memory_insert` | 0.69 | 0.65 | -5.8% | 1.46 | 0.69 | -52.7% | 14909.7 | 18197.1 | +22.0% |
| `aof_fsync_insert` | 16.12 | 11.92 | -26.1% | 24.01 | 14.96 | -37.7% | 723.4 | 1051.7 | +45.4% |
| `bgsave_concurrent_take` | 13.95 | 13.02 | -6.7% | 15.95 | 15.17 | -4.9% | 880.0 | 959.1 | +9.0% |

### Improvements

- **`sync_update_triples`** — directly exercises the changed script (holder update path): p50 4.36 → 3.94 ms (**-9.6%**), p95 4.51 → 4.40 ms (-2.4%), goodput 1360.2 → 1523.6/s (**+12.0%**).
- **`sync_update_presigs`** — the same path for presignatures: p50 4.03 → 3.46 ms (**-14.1%**), p95 5.19 → 4.39 ms (**-15.4%**), goodput 1360.2 → 1523.6/s (**+12.0%**).
- **`sync_prune_triples` / `sync_prune_presigs`** — the below-threshold branch of the same script: p50 7.27 → 6.70 ms (-7.8%) and 6.87 → 6.20 ms (-9.8%); p95 is flat (+1.2% / -1.0%); goodput 835.8 → 881.3/s (+5.4%) for both.
- **`large_argv_sync`** — p50 5.34 → 5.12 ms (-4.1%), p95 8.14 → 5.37 ms (**-34.0%**), goodput 168.7 → 195.2/s (**+15.7%**). Caveat: this scenario calls `remove_outdated`, not `remove_holder_and_prune`, so its gain cannot be caused by this change; it is reported for completeness and reflects run-to-run/environment variation (the sibling `large_outdated_prune` shows a similar -11.5% p50 / +27.8% goodput).
- All four state-sync operations that actually call the changed script improved on median latency and goodput, which is the expected shape for a per-ID command-count reduction.

### Regressions / noise

- No operation that calls the changed script regressed materially: the only negative signal is `sync_prune_triples` p95 +1.2% (7.40 → 7.49 ms), within noise.
- The run had broad host-level noise on unrelated paths. Largest swings: `saturated_insert_triple` (p50 +57.5%, p95 +1612.3% from 2.04 → 34.93 ms, goodput -64.7%), `churn_commit` (p50 +159.3%, 17 samples), `take_contended` (p50 +81.5%, goodput -28.0%), `churn_peek_mine` (p95 +266.0%, 32 samples), `remove_outdated_storm` (p95 +61.7%, goodput -33.0%), `saturated_take_triple` (p50 +20.2%), `concurrent_insert_triple_no_checkpoint` (p95 +100.0%), `concurrent_insert_triple` (p95 +64.8%), and `presig_stockpile_commit` (p50 +15.2%, goodput -24.1%). None of these call `remove_holder_and_prune`.
- Smaller degradations within noise: `peek_mine_contended`, `commit_proposal`, `insert_under_client_kill`, `take_under_client_kill` (p50 ~+10–13%, goodput ~-10–19%); `clear_triples_storm` / `clear_presigs_storm` (p95 ~+16.5% with flat p50); all `mixed_*` operations (goodput -2.9%, a shared scenario-level denominator); `saturated_peek_mine` goodput +388.3% while p50 is +3.1% — a denominator/sampling artifact, not a script effect.
- Failures/unknown: `insert_under_client_kill` failures 7 → 8 (chaos scenario); indeterminate outcomes drifted in `peek_mine_contended` 127 → 138, `presig_stockpile_peek` 92 → 118, `deep_commit` 9 → 10, `take_under_client_kill` 4 → 5, and `deep_peek_mine` 238 → 237. These outcomes are excluded from the latency percentiles and are unrelated to the changed script.
