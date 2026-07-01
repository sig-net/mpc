# Stress Progress Report

## 2026-05-15

### Added

- B-2 burst spike scenario in local stress harness.
- CI-lite burst spike test covering warmup, spike, recovery.
- Dedicated GitHub Actions workflow for stress CI.
- Remaining-gap tracker in `doc/stress-tasks.md`.

### Issue found

- Existing `burst` scenario was not spec-grade burst testing.
- Old behavior ran one request batch plus one snapshot.
- Result: no warmup baseline, no explicit spike stage, no recovery proof. Spec B-2 could not be validated, CI could not catch regressions in post-spike recovery.

### Fix

- Added `BurstSpikeConfig` with three explicit phases: `warmup`, `spike`, `recovery`.
- `StressHarness::run_burst_spike` now records per-phase batches plus before/after snapshots.
- `StressScenario::Burst` now routes through this staged scenario, so bench runs keep same env var while gaining spec-aligned behavior.

### Why fix works

- Warmup batch gives pre-spike healthy baseline.
- Spike batch drives concurrent burst as separate measured event.
- Recovery batch proves system returns to lower steady-state behavior instead of only surviving burst moment.
- Batch labels and snapshots make regressions visible in JSON/CSV artifacts and CI assertions.

### Validation target

- `cargo test -p integration-tests --test lib test_stress_b2_burst_spike_ci -- --nocapture`

### Validation result

- Passed locally on 2026-05-15.
- Result: `1 passed; 0 failed; 77 filtered out`.

### Next likely slice

- Stress workflow artifact upload for JSON/CSV outputs.
- Threshold assertion helpers shared by all stress tests.
- A-3 indexer latency.

## 2026-05-15 C-2

### Added

- `pipeline-contention` scenario in local stress harness and bench entrypoint.
- CI-lite C-2 test covering signing load plus concurrent triple and presignature refill pressure.

### Issue found

- Harness could test signing, triple pressure, and overload separately, but not prove both refill pipelines were active during signing.
- Result: contention regressions between signature work and background artifact generation could hide.

### Fix

- Added `PipelineContentionConfig` and `StressHarness::run_pipeline_contention`.
- Increased C-2 stockpile targets and request load so the combined phase lasts long enough to observe protocol contention.
- Added durable historical triple/presignature generator counters to the stable `/state` surface.
- Switched C-2 overlap detection from transient in-flight counters on flaky endpoints to historical generator counts observed while the sign batch is still active.

### Why fix works

- One batch keeps signature execution active.
- `/state` now carries durable generator history, so short-lived refill protocols do not need to be sampled in the exact millisecond they are running.
- The harness refuses to count post-batch generator activity, so the observed refill work is constrained to the actual contention window.
- Recovery check proves the cluster can restock enough artifacts after the combined phase.

### Validation result

- `cargo test -p integration-tests --test lib test_stress_c2_pipeline_contention_ci -- --nocapture`
- Passed locally on 2026-05-15.
- Result: `1 passed; 0 failed; 80 filtered out`.

## 2026-05-15 B-3

### Added

- `overload-node-degradation` scenario in local stress harness.
- CI-lite B-3 test covering warmup -> hard-killed-node overload -> recovery.

### Issue found

- Harness had overload coverage plus node fault controls, but no single scenario combining both.
- Result: regressions in degraded-node backlog handling would slip through even though both ingredients existed separately.

### Fix

- Added `OverloadNodeDegradationConfig` and `StressHarness::run_overload_with_node_degradation`.
- Added `StressHarness::run_overload_with_node_restart` for hard kill/restart semantics in CI-lite.

### Why fix works

- Warmup proves healthy baseline.
- Degraded batch applies overload while one node process is actually down, exercising threshold behavior with fewer live participants.
- Recovery batch proves cluster returns to healthy request handling after the restarted node rejoins.

### Validation result

- `cargo test -p integration-tests --test lib test_stress_b3_overload_node_degradation_ci -- --nocapture`
- Passed locally on 2026-05-15.
- Result: `1 passed; 0 failed; 80 filtered out`.

## 2026-05-15 C-3

### Added

- `queue-backpressure` scenario in local stress harness and bench entrypoint.
- C-3 fairness test scaffold with completion-order tracking for queued sign requests.
- Contract-backed request sequence capture in stress outcomes so FIFO checks can use contract acceptance order instead of client submission order.

### Issue found

- Near-empty triple runs do create refill pressure, but queued requests do not drain in strict FIFO order.
- Result: older requests can be overtaken once new presignatures become available, so the spec's no-starvation/FIFO expectation is not yet met.

### Root cause

- Signature proposers race independently for presignatures.
- The proposer path polls `take_mine()` in a loop, and storage pops owned presignatures with Redis `SPOP`, so there is no request-age reservation or FIFO handoff between queued sign requests.
- A follow-up check ruled out the earlier harness-ordering hypothesis: the ignored C-3 test still fails when completions are compared against the contract's monotonic request sequence rather than client submission order.

### Status

- Scenario code is landed for continued investigation.
- Harness artifacts now include contract request sequence for each request outcome, which makes future fairness experiments measurable against the actual accepted queue order.
- Test is intentionally ignored until the signature protocol gains a fair presignature allocation path for older queued requests.

### Validation result

- `cargo test -p integration-tests --test lib test_stress_c3_queue_backpressure_ci -- --nocapture`
- Failed locally on 2026-05-15 with `request completions should drain in FIFO order` before being moved to ignored status.

## 2026-05-15 C-1

### Added

- `triple-depletion` scenario in local stress harness and bench entrypoint.
- CI-lite C-1 test proving stockpile ready -> depleted -> recovered path.
- Stress doc updates for new scenario/test coverage.

### Issue found

- Harness had no way to prove triple stockpile exhaustion happened during active signing.
- Result: spec C-1 stayed doc-only. Regressions like never-depleting stockpile, dead wait on refill, or silent recovery failure would not be caught.

### Fix

- Added `TripleDepletionConfig` and `StressHarness::run_triple_depletion`.
- Disabled default harness prestockpile for this scenario so the test controls stockpile behavior instead of inheriting unrelated presignature warmup.
- Reused existing wait helpers to ensure initial triples/presignatures exist.
- Stored cloneable node state snapshots and used durable triple-generator history on `/state` plus `/state` recovery checks.

### Why fix works

- Default prestockpile was root issue for early failures: it forced unrelated presignature stockpiling before C-1 even started.
- `/bench/metrics` was too flaky for depletion assertions under pressure; `/state` is the stable observability surface for these CI-lite checks.
- Refill pressure is now observable from durable triple-generator history on `/state`, which means short-lived generator activity does not need to be sampled at the exact instant it is running.
- Recovery is verified from `/state`, so test catches refill stalls instead of only checking request success.
- Small config (`min_triples = 1`, `max_triples = 2`, generation/introduction capped to `1`) makes depletion pressure deterministic enough for CI-lite runs.

### Validation result

- `cargo test -p integration-tests --test lib test_stress_c1_triple_depletion_ci -- --nocapture`
- Passed locally on 2026-05-15.
- Result: `1 passed; 0 failed; 80 filtered out`.