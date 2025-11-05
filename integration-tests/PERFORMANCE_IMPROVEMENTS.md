# Integration Tests Performance Improvements

## Summary
After analyzing the integration test setup, identified multiple bottlenecks causing `test_signature_basic` to take ~55 seconds.

## Root Causes

### 1. Excessive Retry Delays
Current retry strategies use very conservative delays suitable for production but overkill for tests:

**`running()` wait** (wait.rs:301-311)
- Current: 3s delay × 50 retries = 150s max
- Typical: Takes 5-10 retries = 15-30s actual

**`nodes_running()` wait** (wait.rs:218-230)
- Current: 3s delay × 20 retries per node = 60s max per node
- Typical: Takes 3-5 retries per node = 9-15s actual per node

**`require_presignatures()` wait** (wait.rs:313-355)
- Current: 5s delay × (expected * 100) retries
- For 16 presigs: 5s × 1600 = 8000s max (!)
- Typical: Takes 20-40 retries = 100-200s actual

### 2. Prestockpile Overhead
**Problem**: By default, spawner pre-generates triples before test starts
- Location: spawner.rs:72 - `prestockpile: Some(Prestockpile { multiplier: 4 })`
- For 3 nodes, min_triples=16: generates 16×4×3 = 192 triples
- Then waits for 16 presignatures to be ready
- Estimated cost: **15-25 seconds**

**Impact on `test_signature_basic`**:
- Test only needs 1 signature (1 presignature)
- Prestockpile generates 16+ presignatures unnecessarily

### 3. Fixed Sleep Delays
Multiple hardcoded sleeps add up:
- `require_node_state` (Joining): 5s sleep after success (wait.rs:237)
- `start_node`: 3s sleep after adding node (lib.rs:206)
- `vote_update`: 3s sleep after voting (cluster/mod.rs:323)

### 4. Sequential Node Startup
Nodes start sequentially rather than in parallel, each waiting for state transitions.

## Proposed Solutions

### Phase 1: Conservative Improvements (Safe for all tests)

#### A. Reduce retry delays
```rust
// wait.rs - running()
let strategy = ConstantBuilder::default()
    .with_delay(std::time::Duration::from_millis(1000))  // was 3000
    .with_max_times(30);  // was 50 (still 30s max)
```

```rust
// wait.rs - require_node_state()
let strategy = ConstantBuilder::default()
    .with_delay(std::time::Duration::from_millis(1000))  // was 3000
    .with_max_times(15);  // was 20 (still 15s max)
```

```rust
// wait.rs - require_presignatures() and require_triples()
let strategy = ConstantBuilder::default()
    .with_delay(std::time::Duration::from_secs(2))  // was 5
    .with_max_times(expected * 50);  // was expected * 100
```

**Expected Impact**: Reduces typical wait times by 40-60% (from 55s to 25-35s)

#### B. Disable prestockpile for basic tests
```rust
// In test_signature_basic:
let nodes = cluster::spawn()
    .disable_prestockpile()  // Add this line
    .await?;
```

**Expected Impact**: Saves 15-25 seconds (from 55s to 30-40s, or 20-25s combined with A)

#### C. Reduce hardcoded sleeps
```rust
// wait.rs:237 - After node joins
tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;  // was 5

// lib.rs:206 - After node start
tokio::time::sleep(std::time::Duration::from_millis(1000)).await;  // was 3000

// cluster/mod.rs:323 - After vote
tokio::time::sleep(std::time::Duration::from_millis(1000)).await;  // was 3000
```

**Expected Impact**: Saves 6-8 seconds

### Phase 2: Aggressive Improvements (Test-only, requires testing)

#### A. Environment-aware retry delays
Add a test mode with faster retries:
```rust
// In wait.rs, add helper:
fn test_retry_strategy(max_times: usize) -> ConstantBuilder {
    let delay_ms = if cfg!(test) { 500 } else { 3000 };
    ConstantBuilder::default()
        .with_delay(std::time::Duration::from_millis(delay_ms))
        .with_max_times(max_times)
}
```

**Expected Impact**: Additional 30-40% reduction in wait times

#### B. Parallel node waits
Instead of waiting for nodes sequentially, wait for all in parallel:
```rust
// In wait.rs - nodes_running()
pub fn nodes_running(mut self) -> Self {
    // Current: Adds sequential wait actions
    // Improved: Could spawn parallel futures
    for id in 0..self.nodes.len() {
        self.actions.push(WaitActions::NodeState(NodeState::Running, id));
    }
    self
}
```

#### C. Smarter prestockpile
Only prestockpile what's needed:
```rust
pub fn auto_prestockpile(mut self) -> Self {
    // Calculate based on test needs rather than fixed multiplier
    self.prestockpile = Some(Prestockpile { multiplier: 1 });
    self
}
```

### Phase 3: Architectural Improvements

#### A. Cached test fixtures
For tests that don't need fresh state, reuse running clusters:
- Keep a pool of ready clusters
- Reset state between tests
- Amortize startup cost

#### B. Faster container startup
- Use container pooling
- Pre-pull images
- Optimize Redis/NEAR sandbox startup

## Implementation Plan

### Step 1: Immediate (Low Risk)
- [ ] Disable prestockpile for `test_signature_basic` and similar simple tests
- [ ] Reduce retry delays from 3s→1s and 5s→2s
- [ ] Reduce max_times from 50→30 for running(), 20→15 for nodes_running()

**Expected Result**: test_signature_basic: 55s → 20-25s

### Step 2: Short Term (Needs Testing)
- [ ] Reduce hardcoded sleeps (5s→2s, 3s→1s)
- [ ] Add test-mode flag for aggressive timeouts (500ms delays)
- [ ] Document which tests can disable prestockpile

**Expected Result**: test_signature_basic: 20-25s → 10-15s

### Step 3: Long Term (Architecture)
- [ ] Implement cluster pooling/caching
- [ ] Parallel node startup where safe
- [ ] Container optimization

**Expected Result**: test_signature_basic: 10-15s → 5-8s

## Files to Modify

1. `integration-tests/src/actions/wait.rs` - Retry strategies
2. `integration-tests/src/cluster/spawner.rs` - Prestockpile defaults
3. `integration-tests/src/lib.rs` - Hardcoded sleeps
4. `integration-tests/src/cluster/mod.rs` - More hardcoded sleeps
5. `integration-tests/tests/cases/mod.rs` - Individual test optimizations

## Testing Strategy

1. Run full integration test suite with changes to ensure no flakiness
2. Monitor for timeout failures in CI
3. If issues arise, can bump delays incrementally
4. Add metrics/logging to measure actual wait times

## Risks

- **Flaky tests**: Reduced timeouts might cause occasional failures on slow machines
  - Mitigation: Use conservative values first, monitor CI, make configurable
- **Hidden timing bugs**: Some sleeps might be covering race conditions
  - Mitigation: Test thoroughly, roll back if issues appear
