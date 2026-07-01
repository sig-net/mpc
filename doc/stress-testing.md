# Stress Test Specification: Sig.Network MPC

**Version:** 1.0
**Repo:** [sig-net/mpc](https://github.com/sig-net/mpc)
**Status:** Draft

---

## Overview

This document specifies a comprehensive stress testing plan for the Sig.Network MPC system. The goal is to validate the network's behavior under adversarial load conditions across three primary axes:

1. **Timeout and latency degradation** — what happens when the network is slow or individual nodes are sluggish
2. **Backlog overload** — what happens when sign requests pile up faster than they can be consumed
3. **Signature pipeline congestion** — what happens when triple generation, presignature generation, and signature protocols are all competing for resources simultaneously

The network today handles up to **16 concurrent requests** with an average response time of ~4 seconds. The 8-node network requires a threshold of 5 to produce valid signatures. Each signature consumes **two triples per node**, and generating a single triple takes ~30 seconds at worst-case (or ~2 seconds when parallelized). These numbers form the baseline for all stress scenarios below.

---

## 1. Scope and Components Under Test

### 1.1 Components

| Component | Role |
|---|---|
| MPC Node (`mpc-node`) | Core signing participant; runs triple/presignature/signature protocols |
| Smart Contract (`mpc-contract`) | Orchestrates `sign`, `respond`, `vote_*`, `state`, `config` calls |
| Indexer | Picks up `sign` events from the contract and forwards to the signature pipeline |
| P2P Mesh | Routes inter-node messages for protocol rounds |
| Triple Store | Stockpile of pre-generated beaver triples consumed per signature |

### 1.2 Out of Scope

- Foreign chain relay (sending a signature from NEAR to Ethereum/Bitcoin/etc.)
- Key resharing / node join/leave ceremonies (covered separately in protocol conformance tests)
- Smart contract correctness (covered by unit tests on the contract itself)

---

## 2. Test Environment

### 2.1 Baseline Configuration

Run all tests against a local multi-node testnet first (using `integration-tests`), then promote passing scenarios to a staging deployment matching production hardware.

```
Nodes:          8 (matching mainnet)
Threshold:      5-of-8
Hardware:       Default prod hardware config per node
Network:        Simulated via tc/netem for latency/loss injection
Contract:       Deployed to localnet or testnet
Indexer:        One per node (or shared provider, matching prod config)
```

### 2.2 Tooling

- **Load generator:** Custom Rust binary (extend `bench.sh` / `integration-tests` bench harness) or a script calling `sign` on the contract in parallel
- **Network fault injection:** Linux `tc netem` or a proxy like `toxiproxy` placed in front of inter-node connections
- **Observability:** Prometheus metrics from each node + contract `system_load` view call, aggregated in Grafana
- **Failure classification:** Each test run must record — for every sign request — whether the result was `success`, `timeout`, `dropped`, or `error(type)`

### 2.3 Building for Bench

```sh
# From repo root
cd chain-signatures/
cargo build -p mpc-contract --release --features "bench" --target wasm32-unknown-unknown
cargo build -p mpc-node --release --features "bench"

cd ../integration-tests
MPC_TEST_BUILD_DISABLED=1 cargo bench
```

All new stress scenarios should be integrated into this bench harness so they are reproducible in CI.

### 2.4 Current Local Harness

Current repo now includes local stress harness in `integration-tests/src/stress.rs` and bench entrypoint in `integration-tests/benches/stress.rs`.

Local runs on **macOS** and **Ubuntu** use built-in TCP fault proxies instead of `tc netem`, so latency and node-isolation scenarios can run without Linux-only traffic control.

Supported scenario names today:

- `burst`
- `global-latency`
- `single-node-straggler`
- `steady-overload`
- `overload-node-degradation`
- `queue-backpressure`
- `pipeline-contention`
- `triple-depletion`

Common env vars:

- `MPC_STRESS_SCENARIO` — scenario name
- `MPC_STRESS_NODES` — node count
- `MPC_STRESS_THRESHOLD` — threshold
- `MPC_STRESS_TOTAL_REQUESTS` — requests per batch or per stage base
- `MPC_STRESS_CONCURRENCY` — concurrent sign requests
- `MPC_STRESS_LATENCY_MS` — extra global latency for `burst`
- `MPC_STRESS_REPORT_PATH` — JSON artifact path
- `MPC_STRESS_CSV_PATH` — per-request CSV artifact path

Example commands from repo root:

```sh
cargo bench -p integration-tests --bench stress --no-run

MPC_STRESS_SCENARIO=burst \
MPC_STRESS_TOTAL_REQUESTS=32 \
MPC_STRESS_CONCURRENCY=8 \
MPC_STRESS_REPORT_PATH=target/stress/burst.json \
MPC_STRESS_CSV_PATH=target/stress/burst.csv \
cargo bench -p integration-tests --bench stress

MPC_STRESS_SCENARIO=global-latency \
MPC_STRESS_TOTAL_REQUESTS=16 \
MPC_STRESS_CONCURRENCY=8 \
MPC_STRESS_REPORT_PATH=target/stress/global-latency.json \
MPC_STRESS_CSV_PATH=target/stress/global-latency.csv \
cargo bench -p integration-tests --bench stress

MPC_STRESS_SCENARIO=single-node-straggler \
MPC_STRESS_TOTAL_REQUESTS=50 \
MPC_STRESS_CONCURRENCY=8 \
MPC_STRESS_REPORT_PATH=target/stress/straggler.json \
MPC_STRESS_CSV_PATH=target/stress/straggler.csv \
cargo bench -p integration-tests --bench stress

MPC_STRESS_SCENARIO=steady-overload \
MPC_STRESS_TOTAL_REQUESTS=32 \
MPC_STRESS_REPORT_PATH=target/stress/overload.json \
MPC_STRESS_CSV_PATH=target/stress/overload.csv \
cargo bench -p integration-tests --bench stress
```

Per-request CSV columns:

- `batch_label`
- `request_index`
- `latency_ms`
- `status` where status is `success|timeout|dropped|error`
- `reason_code` for stable machine-readable classification such as `local_timeout`, `contract_timeout`, `request_collision`, `request_limit_exceeded`
- `detail`

CI-lite scenario tests currently implemented in `integration-tests/tests/cases/stress.rs`:

- A-1 global latency sweep
- A-2 single-node straggler
- B-1 steady overload
- B-2 burst spike
- B-3 overload + node degradation
- C-1 triple depletion
- C-2 pipeline contention

Run one test at time from repo root:

```sh
cargo test -p integration-tests --test lib test_stress_a1_global_latency_ci -- --nocapture
cargo test -p integration-tests --test lib test_stress_a2_single_node_straggler_ci -- --nocapture
cargo test -p integration-tests --test lib test_stress_b1_steady_overload_ci -- --nocapture
cargo test -p integration-tests --test lib test_stress_b2_burst_spike_ci -- --nocapture
cargo test -p integration-tests --test lib test_stress_b3_overload_node_degradation_ci -- --nocapture
cargo test -p integration-tests --test lib test_stress_c1_triple_depletion_ci -- --nocapture
cargo test -p integration-tests --test lib test_stress_c2_pipeline_contention_ci -- --nocapture
```

---

## 3. Test Categories

---

### Category A: Timeout and Latency Stress

These tests explore what happens when the network experiences degraded latency, either globally or on a subset of nodes.

#### A-1: Global High Latency

**Goal:** Establish the latency threshold at which signature requests begin to fail or exceed SLA.

**Setup:**
- Inject symmetric latency on all inter-node links using `tc netem delay`.
- Send a steady stream of sign requests at the current 16-request concurrency limit.

**Procedure:**

| Step | Latency Added | Duration |
|---|---|---|
| Baseline | 0 ms | 2 min |
| Low | 50 ms | 2 min |
| Medium | 200 ms | 2 min |
| High | 500 ms | 2 min |
| Severe | 1000 ms | 2 min |
| Recovery | 0 ms (restore) | 2 min |

**Pass criteria:**
- At 0–200 ms added latency: ≥ 99% of sign requests complete successfully within 10s
- At 500 ms: ≥ 90% complete; no permanent hangs (all either succeed or fail cleanly with an error, not indefinite blocking)
- At 1000 ms: the node mesh should detect degradation via liveness checks; sign requests should return a clean failure rather than hanging
- On recovery: throughput and latency return to baseline within 60 seconds

**What to watch for:**
- Protocol round timeouts that leave orphaned presignature state
- Triple consumption without corresponding signature completion (leaked triples)
- Nodes that don't reconnect to the mesh after latency normalizes
- Contract `sign` calls that remain pending indefinitely because `respond` was never called

---

#### A-2: Single Node Latency (Straggler)

**Goal:** Test threshold robustness when one non-leader node is severely degraded but the remaining n-1 nodes are healthy.

**Setup:**
- Pick one node (not the current "initiating" node for signature rounds).
- Inject 2000 ms latency on all of that node's connections only.
- Send 50 sign requests at a moderate rate (8 concurrent).

**Pass criteria:**
- Signatures still complete successfully using the remaining 7 nodes (threshold = 5, so 7 healthy nodes should be sufficient)
- Completion time increases by no more than 3× baseline
- No errors on the healthy nodes due to the slow peer

**What to watch for:**
- Whether the slow node's messages are waited on longer than necessary
- Whether the protocol implementation correctly handles "slow but alive" vs "dead" nodes differently
- Buffer bloat on the slow node's inbound queue

---

#### A-3: Indexer Latency / Block Delivery Delay

**Goal:** Test behavior when sign events from the contract arrive at nodes with significant delay (simulating a slow indexing provider).

**Setup:**
- Throttle the indexer feed to each node to deliver blocks with 5s, 10s, and 30s delay.
- Ensure sign requests are submitted to the contract at a normal rate.

**Pass criteria:**
- Sign requests eventually complete (the pipeline drains) as long as the indexer catches up
- No duplicate signature attempts for the same request ID
- Node logs clearly indicate "waiting for block delivery" vs "processing"

**What to watch for:**
- Race conditions between two nodes seeing the same sign event at different times
- Whether the ordering of sign events is preserved or if out-of-order delivery causes state corruption

---

### Category B: Backlog Overload

These tests drive the request queue well beyond the node's processing capacity to find where the system degrades gracefully vs. collapses.

#### B-1: Request Flood — Steady State Overload

**Goal:** Determine maximum stable throughput and characterize behavior when the backlog exceeds processing capacity.

**Procedure:**
1. Start with 16 concurrent sign requests (current max supported).
2. Ramp to 32, 64, 128 concurrent requests in 30-second steps.
3. Hold at each level for 2 minutes.
4. Ramp back down.

**Metrics to record at each level:**
- Requests in flight at any given moment
- Median and P99 completion time
- Number of sign requests that expire at the contract level (contract-side timeout)
- Triple store depth (how many pre-generated triples remain)
- CPU and memory per node

**Pass criteria:**
- At 32 concurrent: system queues excess requests; latency increases but no crashes
- At 64–128 concurrent: the contract's backlog limit (if any) is respected; requests are cleanly rejected or queued, not silently dropped
- Triple store does not drain to zero (nodes must be generating new triples fast enough or throttling intake accordingly)
- All nodes remain alive throughout; no OOM kills

**What to watch for:**
- Whether the node has any internal backpressure mechanism signaling it is saturated
- Whether the contract's `sign` function has a configurable queue cap, and what happens when it's hit
- Memory growth on nodes due to unbounded in-memory queuing of pending sign state

---

#### B-2: Burst Spike

**Goal:** Simulate a sudden, sharp spike in demand (e.g., a large airdrop or a burst of cross-chain activity).

**Procedure:**
- Run the network at 8 concurrent requests (half capacity) for 5 minutes.
- Send 200 sign requests simultaneously within a 1-second window.
- Monitor recovery back to steady state.

**Pass criteria:**
- No node panics or crashes from the sudden burst
- All 200 requests eventually resolve (either succeed or fail with a meaningful error, not hang)
- Recovery to 8-concurrent steady-state performance within 5 minutes of the burst ending

**What to watch for:**
- Memory spikes on nodes receiving many pending requests simultaneously
- Whether the contract's gas limits cause burst transactions to revert
- Whether the indexer can handle a large block of sign events at once without dropping events

---

#### B-3: Sustained Overload with Node Degradation

**Goal:** Combine overload with a node going offline to see if the system can still drain the backlog with fewer participants.

**Procedure:**
1. Flood to 64 concurrent requests.
2. While flooded, kill one node (hard kill, not graceful shutdown).
3. Hold for 3 minutes.
4. Restart the killed node.
5. Monitor re-integration and backlog drain.

**Pass criteria:**
- After node loss, signatures using the remaining 7 nodes (5-of-7 threshold still met) continue to complete
- No sign requests are permanently lost; they either complete or the contract surfaces a clean timeout
- The restarted node re-joins the mesh and begins contributing to new signatures within a reasonable window (target: 60s)

---

### Category C: Signature Pipeline Congestion

This is the most critical category. The signature pipeline has three distinct protocol phases — **triple generation**, **presignature generation**, and **signature execution** — which all compete for compute, memory, and network bandwidth when running simultaneously. The goal is to find the point at which they interfere destructively with each other.

#### C-1: Triple Depletion Under Load

**Goal:** Drive the system hard enough and fast enough that the pre-generated triple stockpile is exhausted, forcing real-time triple generation concurrent with active signing.

**Procedure:**
1. Disable or pause triple pre-generation by holding the triple generator at a low concurrency setting.
2. Issue a large burst of sign requests that consumes the entire stockpile.
3. Observe behavior as triples run out mid-burst (each signature consumes 2 triples per node).
4. Re-enable triple generation at full speed and observe recovery.

**Pass criteria:**
- When triples are exhausted, new sign requests are queued (not silently dropped)
- Triple generation under signing load takes no longer than 60s per triple at worst case
- Sign requests submitted during depletion complete once triples become available
- No partial signature state is left when triples run out mid-protocol

**What to watch for:**
- Deadlock: signing waiting on triples, while triple generation is starved of CPU by signing
- Triples being consumed but not accounted for (leaked on protocol abort)
- Any scenario where the stockpile goes negative or sign requests steal triples from each other

---

#### C-2: All Three Protocol Phases Running Concurrently at Max Parallelism

**Goal:** Force triple generation, presignature generation, and signature execution to all run at maximum configured parallelism simultaneously, then measure interference.

**Procedure:**

Phase A — Baseline each in isolation:
1. Run triple generation only at max parallelism. Record CPU, memory, throughput.
2. Run presignature generation only at max parallelism. Record same.
3. Run signature execution only at max parallelism. Record same.

Phase B — Combined:
4. Simultaneously run all three at their individual max parallelism settings.
5. Hold for 10 minutes.
6. Record resource usage and any failures.

**Pass criteria:**
- Combined CPU usage per node stays below 90% sustained; no thermal throttling
- Signature latency in Phase B does not exceed 3× Phase A (isolation) latency
- Triple generation throughput in Phase B does not fall below 50% of Phase A throughput
- No protocol round failures due to message queue saturation or dropped inter-node messages

**What to watch for:**
- Thread pool starvation: if all Tokio tasks are consumed by triple generation, signing tasks starve and vice versa
- Network bandwidth saturation: triple and presignature protocols are message-heavy; running them together can saturate the inter-node links
- Memory pressure: each protocol instance holds cryptographic state in memory; running all three concurrently multiplies peak memory usage

---

#### C-3: Signature Queue Backpressure with Depleted Triple Store

**Goal:** Specifically test the interaction between a full request backlog and a nearly-empty triple store, which is the worst-case congestion scenario.

**Procedure:**
1. Deliberately run the triple store down to ≤ 5 triples per node (near-empty).
2. Submit 50 sign requests simultaneously.
3. Do not pause triple generation — let it try to refill under load.

**Pass criteria:**
- The system does not deadlock
- Sign requests are served in FIFO order as triples become available (no starvation of older requests)
- Triple generation rate is not reduced by more than 30% compared to an idle system

**What to watch for:**
- Priority inversion: newer sign requests consuming freshly generated triples ahead of older queued requests
- Triple generation being cancelled or aborted because the node decides signing has higher priority

---

#### C-4: Long-Running Pipeline Soak Test

**Goal:** Run all three protocol phases at a moderate but sustained load for an extended period to detect memory leaks, state accumulation, and gradual degradation.

**Procedure:**
- Set concurrency to 50% of max for each protocol phase.
- Run for **6 hours** continuously.
- Sample performance metrics every 5 minutes.

**Pass criteria:**
- Signature success rate does not degrade over time (within ±5% across the 6-hour window)
- Node memory usage does not grow monotonically (no unbounded accumulation of pending protocol state)
- No node restarts or OOM kills during the run
- Triple store depth oscillates around a stable average, not trending to zero

**What to watch for:**
- Pending sign state that is never cleaned up after a timeout
- Growing hashmaps/vecs of in-progress protocol instances
- Log file disk usage (nodes should rotate logs; unbounded logging itself can cause failures)

---

### Category D: Network Partition and Topology Stress

#### D-1: Network Partition (Below Threshold)

**Goal:** Simulate a partition where only 4 nodes can communicate (below the 5-of-8 threshold) and verify the system halts cleanly rather than producing invalid or partial output.

**Procedure:**
- Partition the 8 nodes into two groups: 4 and 4.
- Submit sign requests to both sides.
- After 2 minutes, heal the partition.

**Pass criteria:**
- Neither partition produces a valid signature (threshold not met)
- All pending sign requests on both sides surface a clean error or timeout — no indefinite hang
- After healing, the network re-converges and resumes signing within 60 seconds
- No duplicate or conflicting protocol state remains after healing

---

#### D-2: High Packet Loss

**Goal:** Simulate a degraded network with significant packet loss and verify the protocol's retransmission and retry behavior.

**Procedure:**
- Inject 5%, 15%, and 30% packet loss on all inter-node links using `tc netem loss`.
- At each loss level, run 20 concurrent sign requests for 3 minutes.

**Pass criteria:**
- At 5% loss: ≥ 95% success rate, latency increase ≤ 2×
- At 15% loss: ≥ 70% success rate; no crashes
- At 30% loss: graceful degradation; system does not thrash or produce corrupted state

**What to watch for:**
- Protocol messages being retransmitted but arriving out of order, causing protocol state confusion
- Whether the P2P mesh can sustain liveness pings at 30% loss (node discovery / reachability)

---

## 4. Metrics and Instrumentation

For every test run, capture the following:

**Per-sign-request:**
- Request ID
- Submission timestamp
- Completion timestamp (or timeout timestamp)
- Result: `success` | `timeout` | `dropped` | `error(<code>)`
- Which node initiated the signing round

**Per-node (sampled every 10s):**
- CPU usage
- Memory RSS
- Triple store depth
- In-flight signature protocols count
- In-flight triple generation protocols count
- In-flight presignature protocols count
- Peer mesh connectivity (number of reachable peers)
- P2P message queue depth (inbound and outbound)

**Contract-level (via view calls every 10s):**
- `system_load` response
- `state` (to detect unexpected state transitions)
- Pending sign request count

---

## 5. Acceptance Thresholds

| Scenario | Minimum Pass Bar |
|---|---|
| Baseline (no stress) | 100% success, ≤ 5s median |
| Global latency 200ms | ≥ 99% success, ≤ 10s median |
| Global latency 1000ms | No permanent hangs, all requests resolve (pass or fail) within 30s |
| 2× concurrency overload (32 concurrent) | ≥ 90% success; no crashes |
| 8× concurrency overload (128 concurrent) | No crashes; clean backpressure or rejection |
| Single node killed under load | Remaining 7 nodes continue signing |
| Triple depletion | No deadlock; all queued requests eventually served |
| All 3 pipeline phases concurrent | ≤ 3× baseline latency; no crashes |
| 6-hour soak | No memory growth trend; ≤ ±5% throughput variation |
| Network partition (4/4) | No signatures produced; clean timeout surfaced |

---

## 6. Failure Classification

When a test scenario fails its acceptance threshold, categorize the failure:

- **Hard failure:** Node crash, OOM kill, panic, data corruption, or incorrect signature produced
- **Protocol failure:** A signing round starts but never completes and leaves orphaned state
- **Performance regression:** The system completes all requests but outside the latency/throughput threshold
- **Graceful degradation:** The system correctly queues, throttles, or rejects excess work and recovers cleanly

Only **hard failures** and **protocol failures** block a release. Performance regressions and graceful degradation failures should be filed as issues with severity labels.

---

## 7. Implementation Plan

### 7.1 Phase 1 — Local Harness (Week 1–2)

- Extend the existing `integration-tests` bench harness to support parameterized concurrency (number of simultaneous sign requests)
- Add a `toxiproxy` or `tc netem` wrapper for fault injection that can be controlled programmatically from test code
- Instrument nodes to expose triple store depth and in-flight protocol counts via a metrics endpoint

### 7.2 Phase 2 — Scenario Implementation (Week 3–5)

Implement the following in order of risk (highest risk first):

1. C-1 (Triple Depletion) — highest architectural risk
2. C-2 (All phases concurrent) — most likely to reveal thread/memory issues
3. B-1 (Steady overload) — validates backpressure
4. A-1 (Global latency) — validates timeout handling
5. D-1 (Partition) — validates safety under threshold failure
6. C-4 (Soak test) — run last; requires everything else to be stable

### 7.3 Phase 3 — CI Integration (Week 6)

- Add lighter-weight versions of A-1, B-1, and C-2 to the CI pipeline (shorter duration, lower concurrency)
- Add the full soak test (C-4) to a nightly job

---

## 8. Open Questions

- Does the contract have a configurable limit on pending sign requests in the queue? If not, what is the implicit limit (e.g., storage quota)?
- Is there any built-in backpressure from nodes to the contract when they are saturated, or does the contract accept arbitrarily many sign calls?
- Are triple generation, presignature generation, and signature protocols running in the same Tokio runtime or separate runtimes? This determines whether CPU starvation is possible between them.
- What happens to the in-memory signing state if a node restarts mid-protocol — does it attempt to resume or abort?
- Is the indexer's event ordering guaranteed, or can events arrive out of order? Does the signing pipeline handle out-of-order event delivery?