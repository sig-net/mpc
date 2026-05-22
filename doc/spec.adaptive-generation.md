# Adaptive CPU-Aware Concurrency for Triple & Presignature Generation

**Repo:** `sig-net/mpc`
**Status:** Proposed
**Scope:** `chain-signatures/node/src/protocol/triple.rs`, `chain-signatures/node/src/protocol/presignature.rs`, `chain-signatures/node/src/protocol/consensus.rs`, `chain-signatures/node/src/protocol/mod.rs`, and metrics/config wiring

## Problem

Triple generation and presignature generation are both CPU-heavy background workloads that compete for the same cores. Static concurrency limits are wrong by construction:
- Too high → workloads starve each other; protocol rounds time out or back-pressure into the network layer
- Too low → CPU sits idle; triple buffer drains under signing load, adding latency
The correct limit depends on hardware (core count, clock speed), participant count, and real-time signing pressure — none of which are known at config-write time.

## Goals
- Sustain **50–75% CPU utilization** on triple + presignature generation combined
- Presignatures always have **priority** over triple generation (presigs are on the latency-critical path for signing; triples are speculative buffer)
- No per-machine tuning required at deploy time
- Operator escape hatches remain available (hard caps, opt-out)

### Non-goals

- Controlling CPU used by the NEAR indexer, network I/O, or signing itself
- Per-participant or per-curve tuning
- Kernel-level CPU pinning or cgroups

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                 ConcurrencyController                    │
│                                                          │
│  CpuSampler (shared with hardware metrics)               │
│      │  f64 ∈ [0.0, 1.0]                                 │
│      ▼                                                   │
│  ProportionalAdjuster ──► desired_slots                  │
│      │   (core algorithm, always on)                     │
│      │                                                   │
│      │   [optional] AimdStabilizer                       │
│      │   (wraps ProportionalAdjuster output)             │
│      │                                                   │
│      ▼                                                   │
│  ┌────────────────────────────────────────────────────┐  │
│  │            ConcurrencyArbiter (Mutex)              │  │
│  │ desired_slots                                      │  │
│  │ presig_active / triple_active                      │  │
│  │ waiting_presigs                                    │  │
│  │ Notify                                             │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

Single `desired_slots` value remains only concurrency budget. Actual admission is owned by one arbiter that enforces invariant `presig_active + triple_active <= desired_slots.max(active_total)`. Presignatures have queue priority over triples via `waiting_presigs`, not by optimistic atomics.

## Component Specifications

### 1. `CpuSampler`

Samples aggregate CPU utilization across all logical cores every `sample_interval_ms` (default: 1000 ms).

```rust
/// Returns a value in [0.0, 1.0] representing mean CPU utilization
/// across all logical cores since the last call.
fn sample_cpu() -> f64;
```

**Implementation:** reuse and refactor the existing system metrics sampler in `chain-signatures/node/src/protocol/mod.rs` so one background task samples CPU and publishes to a `watch::Sender<f64>` that both metrics and the adjuster subscribe to. Do not introduce a second independent CPU sampler.

`sysinfo` measures kernel + user time. This is intentional — we want to account for all CPU contention, not just our own user-space cycles.

### 2. `ProportionalAdjuster` (Core Algorithm — always on)

A simple proportional controller that adjusts `desired_slots` toward keeping CPU in `[target_low, target_high]`.

**State:**
```rust
struct ProportionalAdjuster {
    desired_slots: Arc<AtomicUsize>,
    active_total: Arc<AtomicUsize>,
    cfg: AdaptiveConcurrencyConfig,
}
```

**Tick logic** (runs every `sample_interval_ms`):

```rust
fn tick(&self, cpu: f64) {
    let current = self.desired_slots.load(Ordering::Relaxed);
    let active_floor = self.active_total.load(Ordering::Relaxed).max(1);
    let new = if cpu < self.cfg.target_cpu_low {
        // Under-utilized: add one slot
        (current + 1).min(self.cfg.max_slots)
    } else if cpu > self.cfg.target_cpu_high {
        // Over-utilized: remove one slot, but never below in-flight work.
        current.saturating_sub(1).max(active_floor)
    } else {
        current // in the band, hold steady
    };
    self.desired_slots.store(new, Ordering::Relaxed);
}
```

Properties:
- Additive in both directions (+1 / −1 per tick) — intentionally conservative; avoids step-change disruption to in-flight protocols
- Never drops `desired_slots` below total in-flight work — no protocol is forcibly cancelled
- Never exceeds `max_slots` — hard ceiling safety valve

### 3. `ConcurrencyArbiter`

Two lightweight permit APIs are backed by one shared arbiter. Admission must be serialized under one mutex; lock-free optimistic `load`/`fetch_add` is not correct here because it can oversubscribe slots and break presignature priority.

**State:**

```rust
struct ArbiterState {
    desired_slots: usize,
    presig_active: usize,
    triple_active: usize,
    waiting_presigs: usize,
}

struct ConcurrencyArbiter {
    state: Mutex<ArbiterState>,
    notify: Notify,
}
```

#### Acquiring a presignature slot

```rust
impl ConcurrencyArbiter {
    async fn acquire(&self) -> PresigPermit {
        loop {
            let notified = {
                let mut state = self.state.lock().await;
                state.waiting_presigs += 1;

                if state.presig_active + state.triple_active < state.desired_slots {
                    state.waiting_presigs -= 1;
                    state.presig_active += 1;
                    return PresigPermit { ... };
                }

                self.notify.notified()
            };

            notified.await;
        }
    }
}

impl Drop for PresigPermit {
    fn drop(&mut self) {
        let arbiter = self.arbiter.clone();
        tokio::spawn(async move {
            let mut state = arbiter.state.lock().await;
            state.presig_active -= 1;
            drop(state);
            arbiter.notify.notify_waiters();
        });
    }
}
```

#### Acquiring a triple slot

```rust
impl ConcurrencyArbiter {
    async fn acquire_triple(&self) -> TriplePermit {
        loop {
            let notified = {
                let mut state = self.state.lock().await;
                let active_total = state.presig_active + state.triple_active;

                if state.waiting_presigs == 0 && active_total < state.desired_slots {
                    state.triple_active += 1;
                    return TriplePermit { ... };
                }

                self.notify.notified()
            }
            notified.await;
        }
    }
}
```

**Priority guarantee:** if one or more presignatures are waiting, no new triple may start. Existing triples are not cancelled, but next released slot goes to presignature first.

This design removes three correctness bugs in atomic pseudo-semaphore approach:
- `fetch_add` after separate `load` races and can oversubscribe slots
- presignature admission must account for active triples too
- shrinking target budget below total active work creates impossible state unless explicit temporary oversubscription is modeled

### 4. Configuration

```toml
[protocol.adaptive_concurrency]
# Feature gate. When false, existing static logic remains in effect.
enabled = false

# CPU utilization target band (proportion, 0.0–1.0)
target_cpu_low  = 0.50
target_cpu_high = 0.75

# How often to sample CPU and adjust (milliseconds)
sample_interval_ms = 1000

# Hard ceiling on total concurrent operations (triples + presigs combined)
# Defaults to existing protocol.max_concurrent_generation if zero/unset
max_slots = 0  # 0 = auto (num_cpus::get())

# Initial slot count before the adjuster has had time to learn
# Defaults to max(1, min(max_slots, num_logical_cpus / 2))
initial_slots = 0  # 0 = auto

# [optional] AIMD stabilizer — see Phase 2
[protocol.adaptive_concurrency.aimd]
enabled = false
```

`max_concurrent_introduction` stays as separate protection for posit/proposal fan-out. Adaptive concurrency replaces only admission for active generation work currently gated by `protocol.max_concurrent_generation` in triple/presignature spawners.

### 5. `ConcurrencyController` (wiring)

```rust
pub struct ConcurrencyController {
    desired_slots: Arc<AtomicUsize>,
    active_total: Arc<AtomicUsize>,
    arbiter: Arc<ConcurrencyArbiter>,
    adjuster: ProportionalAdjuster,  // or AimdStabilizer wrapping it
    cfg: AdaptiveConcurrencyConfig,
}

impl ConcurrencyController {
    pub fn new(cfg: AdaptiveConcurrencyConfig) -> Self { ... }

    /// Spawns the CPU sampling + adjustment background task.
    pub fn start(&self, cpu_rx: watch::Receiver<f64>) { ... }

    pub fn presig_permits(&self) -> PresigPermits { ... }
    pub fn triple_permits(&self) -> TriplePermits { ... }
}
```

Controller is constructed once when node enters `Running` in `consensus.rs` and passed into both spawners. Existing `protocol.max_concurrent_generation` becomes fallback ceiling and migration bridge. No existing per-workload max fields need migration because codebase does not have them.

## Optional Phase 2: AIMD Stabilizer

> **This is an optional enhancement.** The `ProportionalAdjuster` alone should be sufficient for most deployments. Enable `aimd.enabled = true` if you observe oscillation around the target band.

### Motivation

The proportional adjuster reacts symmetrically: +1 when low, −1 when high. In practice, if adding one slot causes a 5% CPU jump (e.g., you're near the knee of the curve), the adjuster may oscillate — add, overshoot, subtract, undershoot, repeat.

AIMD (Additive Increase / Multiplicative Decrease) breaks this symmetry:
- Increase is gentle and linear (+1 per tick below target) — same as before
- Decrease is aggressive and multiplicative (halve `desired_slots` when above target) — fast convergence from overload

This is the same shape TCP uses for congestion control, and it works for the same reason: gentle exploration of headroom, sharp response to overload.

### `AimdStabilizer`

Wraps `ProportionalAdjuster` and overrides the decrease step:

```rust
struct AimdStabilizer {
    inner: ProportionalAdjuster,
    cfg: AimdConfig,
}

impl AimdStabilizer {
    fn tick(&self, cpu: f64) {
        let current = self.inner.desired_slots.load(Ordering::Relaxed);
        let active_floor = self.inner.active_total
            .load(Ordering::Relaxed).max(1);

        let new = if cpu < self.cfg.target_cpu_low - self.cfg.hysteresis {
            // Under target band: additive increase (same as proportional)
            (current + 1).min(self.cfg.max_slots)
        } else if cpu > self.cfg.target_cpu_high + self.cfg.hysteresis {
            // Over target band: multiplicative decrease (halve, floor at active work)
            (current / 2).max(active_floor)
        } else {
            // Inside hysteresis band: hold steady
            current
        };

        self.inner.desired_slots.store(new, Ordering::Relaxed);
    }
}
```

**Hysteresis band:** a ±`hysteresis` (default: 0.03, i.e. 3%) deadband around the targets prevents reacting to noise. Without it, CPU measurements bouncing between 74% and 76% would cause constant ±1 thrashing even when the system is stable.

**Trade-off vs proportional:**

| Property | Proportional | AIMD |
||||
| Convergence from cold start | Slow (linear ramp) | Slow (same linear ramp up) |
| Recovery from overload | Slow (linear drain) | Fast (halving) |
| Oscillation risk | Moderate | Low (asymmetric) |
| Complexity | Low | Low |
| Best for | Stable load | Bursty / spiky load |

### AIMD Configuration

```toml
[protocol.adaptive_concurrency.aimd]
enabled   = true
hysteresis = 0.03   # ± deadband around target_cpu_low / target_cpu_high
```

`target_cpu_low` and `target_cpu_high` are inherited from the parent `[protocol.adaptive_concurrency]` block — AIMD does not introduce its own target values.



## Integration Points

### Where to acquire permits

```rust
// TripleSpawner::generate_with_id()
self.ongoing.spawn(id, async move {
    let _permit = controller.triple_permits().acquire().await;
    generator.run(epoch).await;
});

// PresignatureSpawner::generate()
self.ongoing.spawn(id.id, async move {
    let _permit = controller.presig_permits().acquire().await;
    generator.run(me, epoch).await;
});
```

Permit must be acquired inside spawned task, not in spawner event loop, so manager stays responsive to messages/posits while work waits for budget. Permit stays held for full protocol lifetime.

### Metrics to expose

All of the following should be emitted as Prometheus gauges/counters:

| Metric | Description |
|||
| `mpc_concurrency_desired_slots` | Current target slot count |
| `mpc_concurrency_presig_active` | In-flight presignature count |
| `mpc_concurrency_triple_active` | In-flight triple count |
| `mpc_concurrency_waiting_presigs` | Presignatures queued for priority admission |
| `mpc_concurrency_waiting_triples` | Triples queued behind budget / presig demand |
| `mpc_cpu_utilization` | Last sampled CPU proportion (from shared sampler) |
| `mpc_concurrency_adjustments_total{direction="up"|"down"|"hold"}` | Adjuster decision counts |

These metrics are the primary observability surface for tuning `target_cpu_low/high` and validating the controller is behaving correctly.



## Migration from Static Limits

Existing config fields:

```toml
# Existing today
protocol.max_concurrent_generation   = 8
protocol.max_concurrent_introduction = 8
```

Migration path:
1. Ship the controller with `enabled = false` default (fall through to existing static logic)
2. When `enabled = true`, resolve `max_slots = 0` to current `protocol.max_concurrent_generation` first, not directly to CPU count, for safe rollout
3. Keep `max_concurrent_introduction` unchanged
4. After observing metrics, decide whether `max_concurrent_generation` remains as fallback-only field or is fully subsumed by `adaptive_concurrency.max_slots`

## Testing Plan

**Unit:**
- `ProportionalAdjuster::tick()` with synthetic CPU values; assert `desired_slots` moves correctly
- `ConcurrencyArbiter` never allows `presig_active + triple_active > desired_slots`
- Waiting presignature blocks new triple admission and gets next released slot first
- `AimdStabilizer::tick()` halves on overload; does not drop below active work floor

**Component / integration:**
- Add focused tests in node crate for controller + arbiter behavior with synthetic load stub
- Add one `integration-tests` MpcFixture case to verify presignature priority under live node scheduling
- Assert `desired_slots` converges to value that keeps stub-CPU in `[0.50, 0.75]`
- Assert presig gets first newly-freed slot when triples are saturating budget

**Load / chaos:**
- Spike signing requests (presig demand) while triple generation is at capacity; assert triple concurrency drops and presig concurrency is unaffected
- Inject CPU noise (random spikes); assert `desired_slots` does not oscillate by more than ±2 per 10 s window with AIMD enabled



## Open Questions

1. **CPU measurement scope:** `sysinfo` measures the whole machine. If the node runs alongside other services (indexer, sidecar), the CPU reading will be inflated. Should we use `/proc/self/stat` (process-scoped) instead? Process-scoped is more accurate for our workload but misses system-level contention.

2. **Slot granularity:** one slot = one protocol session. Is this the right unit? If triple OT extension is itself parallelized internally (via rayon), a single slot may use multiple cores. We may need `slots = protocol_sessions × threads_per_session` accounting.

3. **Cold start:** at startup, `initial_slots` is low and adjuster ramps linearly. Safer default in this repo is `max(1, min(max_slots, num_cpus / 2))`, not `/ 4`, because current generation tasks are already coarse and long-lived.

4. **Cross-node coordination:** each node runs its own controller independently. Since protocols are multi-party, heterogeneous hardware can cause one node to throttle earlier. Monitor per-node `mpc_concurrency_desired_slots` for skew.