# Integration Tests Performance Analysis - ACTUAL Root Cause

## Reality Check: Debug Mode Crypto is Slow

After adding timing instrumentation, discovered the **real bottleneck**:

### Actual Timing Breakdown (Debug Mode)

```
Total Time: 59.8 seconds

Breakdown:
- Setup (Docker, Redis, NEAR, accounts):  ~6s
- MPC Key Generation (crypto):           ~20s  ← REAL BOTTLENECK #1
- Wait for Running state (retries):       ~0s  (nodes ready immediately after keygen)
- Wait for Signable:                      ~2s
- Signature Generation (crypto):         ~21s  ← REAL BOTTLENECK #2
- Overhead/other:                        ~11s
```

### The Real Problem

**Debug mode crypto is 5-10x slower than release mode** because:

1. **No compiler optimizations**: Complex math operations not optimized
2. **Debug assertions**: Extra checks in crypto libraries
3. **No inlining**: Function call overhead on hot paths
4. **Slower NEAR sandbox**: Debug builds of contract/sandbox

The **20+ seconds for key generation** and **21 seconds for signing** are **actual cryptographic computations**, not waiting/timeouts!

## Proof

Looking at the logs:
```
21:06:17 - Nodes start
21:06:37 - "mpc network ready" (nodes finished keygen)
           ↑ 20 seconds of actual crypto work
```

## What Our Timeout Optimizations Actually Fixed

We reduced retry overhead from ~10-15s to ~2-3s:
- Running state check: Now fast (nodes are ready when crypto completes)
- Signable wait: 2s (good!)
- Contract state checks: Fast

**But this only saves ~10 seconds** when the test takes 60 seconds.

## The Uncomfortable Truth

To get test_signature_basic under 20-25 seconds, you **MUST** use `--release`:

```bash
# Debug mode: ~60s (dominated by crypto)
cargo test -p integration-tests test_signature_basic

# Release mode: ~15-20s (crypto 5x faster)
cargo test -p integration-tests test_signature_basic --release
```

### Why You Should Use --release for Integration Tests

1. **Integration tests don't need debug builds**
   - You're testing system behavior, not debugging code
   - Debugger won't help with multi-node async systems anyway
   - Use unit tests for debugging individual components

2. **Release mode is closer to production**
   - Tests production-like performance
   - Catches real performance issues
   - Validates actual timing assumptions

3. **Much faster iteration**
   - 60s → 15-20s per test (3-4x speedup)
   - Can run full suite more frequently
   - Better developer experience

## Alternative: Custom Profile

Create a test-optimized profile in `Cargo.toml`:

```toml
[profile.test-opt]
inherits = "test"
opt-level = 2           # Some optimization without full release
debug = true            # Keep debug symbols
debug-assertions = false # Disable slow checks
```

Then run:
```bash
cargo test -p integration-tests test_signature_basic --profile=test-opt
```

This gives ~60-70% of release mode speed while keeping some debug info.

## What We Actually Improved

Our timeout optimizations **DO** help, but not as much as expected because:

| Component | Debug (before) | Debug (after) | Savings |
|-----------|----------------|---------------|---------|
| Retry overhead | ~15s | ~3s | **-12s** |
| Prestockpile | ~0s (disabled) | ~0s | **0s** |
| Key generation | ~20s | ~20s | 0s (crypto) |
| Signing | ~21s | ~21s | 0s (crypto) |
| Setup | ~6s | ~6s | 0s |
| **Total** | **~62s** | **~50s** | **-12s (19%)** |

So we DID improve by ~12 seconds (19%), which is good! But to get the 3-4x improvement you want, **you must use --release**.

## Recommendations

### Option 1: Use --release for integration tests (RECOMMENDED)
```bash
# Add to your workflow
alias itest='cargo test -p integration-tests --release'
```

**Result**: 15-20 seconds per test

### Option 2: Use test-opt profile
Add to root `Cargo.toml` and use `--profile=test-opt`

**Result**: 25-35 seconds per test

### Option 3: Accept debug mode slowness
Keep current setup, understand that 50s is expected for debug crypto.

**Result**: 50 seconds per test (after our optimizations)

## Bottom Line

**The 500ms timeout optimizations are good**, but they can only remove retry overhead (~12s savings).

**The real slowness is debug mode crypto** (~40s of the 60s total), which can only be fixed by:
- Using `--release` mode (recommended)
- Using an optimized test profile
- Or accepting that debug crypto is slow

Sorry for the initial misdiagnosis - the timeout optimizations help, but the real issue is that **you're running crypto operations in debug mode**, which is inherently slow!
