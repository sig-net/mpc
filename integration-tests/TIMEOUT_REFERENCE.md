# Integration Tests Timeout Optimizations - Quick Reference

## Summary of Changes

### Optimized for Debug Mode
Since integration tests typically run in debug mode (not `--release`), all timeouts have been aggressively optimized while maintaining safety margins.

## New Timeout Values

| Operation | Old Delay | New Delay | Old Max | New Max | Max Timeout |
|-----------|-----------|-----------|---------|---------|-------------|
| `running()` | 3s | **500ms** | 50 | 40 | 20s |
| `nodes_running()` | 3s | **500ms** | 20 | 30 | 15s |
| `contract_state()` | 3s | **500ms** | 20 | 30 | 15s |
| `presignatures()` | 5s | **1s** | N×100 | N×100 | 100s+ |
| `triples()` | 5s | **1s** | N×100 | N×100 | 100s+ |
| Joining sleep | 5s | **1s** | - | - | - |
| Node startup | 3s | **500ms** | - | - | - |
| Vote operation | 3s | **500ms** | - | - | - |

## Test-Specific Optimizations

### Disabled Prestockpile
The following tests now skip prestockpile (saves 15-25s):
- `test_signature_basic`
- `test_signature_rogue`

To disable prestockpile in other tests:
```rust
let nodes = cluster::spawn().disable_prestockpile().await?;
```

To re-enable with custom multiplier:
```rust
let nodes = cluster::spawn().prestockpile(2).await?;
```

## Performance Expectations

### Debug Mode (without --release)
- **Before**: ~53 seconds
- **After**: ~20-25 seconds
- **Improvement**: ~60% faster

### Release Mode (with --release)
- **Before**: ~30-40 seconds (estimated)
- **After**: ~10-15 seconds (estimated)
- **Improvement**: ~65-70% faster

## When to Adjust

### Increase Timeouts If:
- Tests fail with timeout errors on slower machines
- Running on heavily loaded CI systems
- Running many tests in parallel

### Decrease Timeouts If:
- Tests consistently pass with time to spare
- Using release mode for tests
- Want even faster iteration

## How to Adjust

### Quick Adjustment (Single Test)
If a specific test times out, add extra wait time:
```rust
nodes.wait()
    .min_mine_presignatures(16)  // waits longer
    .await?;
```

### Global Adjustment
Edit `integration-tests/src/actions/wait.rs`:

```rust
// For faster iteration (more aggressive)
.with_delay(std::time::Duration::from_millis(250))

// For safer/slower (more conservative)
.with_delay(std::time::Duration::from_millis(1000))
```

## Debugging Slow Tests

To understand where time is spent:

```rust
let start = std::time::Instant::now();
nodes.wait().running().await?;
println!("Running took: {:?}", start.elapsed());

let start = std::time::Instant::now();
nodes.wait().nodes_running().await?;
println!("Nodes running took: {:?}", start.elapsed());

let start = std::time::Instant::now();
nodes.wait().signable().await?;
println!("Signable took: {:?}", start.elapsed());
```

## Files Modified

1. `integration-tests/src/actions/wait.rs` - All retry strategies
2. `integration-tests/src/lib.rs` - Node startup sleep
3. `integration-tests/src/cluster/mod.rs` - Vote sleep
4. `integration-tests/tests/cases/mod.rs` - Test-specific prestockpile disabling

## Rollback

If issues arise, increase delays in `wait.rs`:
- 500ms → 1000ms for quick operations
- 1s → 2s for generation operations
- Increase max_times if needed

Or selectively revert tests by removing `.disable_prestockpile()`.
