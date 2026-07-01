# Stress Tasks

Remaining gaps after current stress harness work.

## Ready now

- A-3 indexer latency scenario: add controllable delayed block/event delivery in local harness, assert no duplicate request execution, capture lag-specific reason codes.
- C-3 queue backpressure with near-empty triple store: scenario scaffold exists (`queue-backpressure`), and the harness now records contract acceptance sequence; FIFO still fails against that true queue order, so the remaining gap is protocol-side fairness.
- C-4 soak test: nightly-only long run with sampled metrics artifacts and trend checks.
- D-1 below-threshold partition: split mesh into 4/4 equivalent local groups, assert clean failure/no signature until heal.
- D-2 packet loss: extend fault proxy beyond latency/block to probabilistic drops, add loss sweep assertions.

## Cross-cutting gaps

- Acceptance threshold assertions: move spec pass bars into machine-checked helpers instead of shape-only assertions.
- Observability depth: include triple store depth, in-flight protocol counts, peer connectivity, queue depth in stress snapshots or explicit metrics artifacts.
- Artifact review tooling: summarize JSON/CSV into stable markdown or JUnit-style output for CI.
- Staging promotion runbook: document how local scenarios map to 8-node staging runs and required env/config.
- Contract/indexer backlog limits: answer open questions in spec with measured values or code references.

## Landed in first slice

- B-2 burst spike now covered in harness/test/CI. Warmup -> spike -> recovery batches replace one-shot burst run so recovery behavior becomes observable.
- B-3 overload + node degradation now covered in harness/test/CI-lite with hard kill/restart semantics.
- C-1 triple depletion now covered in harness/test/CI. Scenario disables default prestockpile, waits for stocked triples, observes active refill pressure under load, then proves stockpile recovery.
- C-2 all phases concurrent now covered in harness/test/CI. Scenario uses sustained signing load plus durable generator-history counters on `/state` to prove triple generation and presignature generation both occur during the active contention window.