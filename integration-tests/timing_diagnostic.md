# Integration Test Performance Diagnostic

## Current Issue
The `test_signature_basic` test takes ~55 seconds despite only performing a single signature.

## Key Areas to Investigate

### 1. Setup Phase Components
Based on code analysis, the setup phase includes:
- **Docker Network**: Creating network (~instant)
- **NEAR Sandbox**: Spawning sandbox (~1-5s)
- **Account Creation**: Creating 3 accounts (~1-3s)
- **Redis Container**: Spawning Redis (~2-5s)
- **Contract Deploy**: Deploying MPC contract (~2-5s)
- **MPC Nodes**: Starting 3 nodes (~5-10s)

### 2. Wait Operations with Long Timeouts
Found several wait operations with potentially slow retry mechanisms:

#### `wait().running()` - Line 303 in spawner.rs
- **Retry Strategy**: 3s delay, 50 max retries = **up to 150 seconds**
- Location: `integration-tests/src/actions/wait.rs:301-311`
```rust
let strategy = ConstantBuilder::default()
    .with_delay(std::time::Duration::from_secs(3))
    .with_max_times(50);
```

#### `wait().nodes_running()`
- Calls `require_node_state` for each node
- **Retry Strategy**: 3s delay, 20 max retries per node = **up to 60 seconds per node**
- Location: `integration-tests/src/actions/wait.rs:218-230`
```rust
let strategy = ConstantBuilder::default()
    .with_delay(std::time::Duration::from_secs(3))
    .with_max_times(20);
```

#### `prestockpile()` - Called by default
- Waits for `min_mine_presignatures` (default 16)
- **Retry Strategy**: 5s delay, expected*100 max retries = **up to 1300 seconds for 16 presigs**
- Location: `integration-tests/src/actions/wait.rs:313-355`
```rust
let strategy = ConstantBuilder::default()
    .with_delay(std::time::Duration::from_secs(5))
    .with_max_times(expected * 100);
```

#### `wait().signable()` in test
- Waits for at least 1 presignature
- **Retry Strategy**: 5s delay, 100 max retries = **up to 500 seconds**
- Location: `integration-tests/src/actions/wait.rs:313-355`

### 3. Prestockpile Overhead
By default, spawner has `prestockpile: Some(Prestockpile { multiplier: 4 })`:
- For min_triples=16, generates 16*4*3 = **192 triples**
- For min_presignatures=16, must wait for nodes to generate **16 presignatures**
- This happens BEFORE test even starts
- Location: `integration-tests/src/cluster/spawner.rs:72`

### 4. Additional Sleep Delays
- `require_node_state` for Joining: **5s sleep** after retry succeeds
- `start_node`: **3s sleep** after adding node
- `vote_update`: **3s sleep** after voting

## Optimization Recommendations

### Quick Wins:

1. **Reduce retry delays** (conservative improvements):
   - `running()`: 3s → 1s (50 retries → ~50s max instead of 150s)
   - `nodes_running()`: 3s → 1s (20 retries → ~20s max instead of 60s)
   - `require_presignatures()`: 5s → 2s (still very safe timeout)

2. **Reduce max retry counts** (for tests that should be fast):
   - `running()`: 50 → 30 (still 90s max with 3s delay, 30s with 1s)
   - `nodes_running()`: 20 → 15 (still 45s max with 3s, 15s with 1s)

3. **Disable prestockpile for basic tests**:
   - `test_signature_basic` doesn't need pre-stockpiled triples
   - Can call `.disable_prestockpile()` on spawner
   - Saves ~10-20 seconds

4. **Reduce hardcoded sleep delays**:
   - Most 3-5s sleeps can be reduced to 1-2s for test environments

### Aggressive Optimizations (test environment only):

1. **Faster polling for tests**:
   - `running()`: 500ms delay, 30 retries = 15s max
   - `nodes_running()`: 500ms delay, 20 retries = 10s max
   - `require_presignatures()`: 1s delay (for generation time)

2. **Parallel waits**: Some waits could be parallelized (e.g., waiting for multiple nodes)

3. **Skip unnecessary waits**: Some waits might be overly conservative for tests

## Expected Improvements

With conservative optimizations (1-2s delays, no prestockpile):
- **Current**: ~55 seconds
- **Optimized**: ~15-25 seconds (60-70% improvement)

With aggressive optimizations (500ms delays):
- **Optimized**: ~10-15 seconds (75-80% improvement)
