//! Benchmarking helpers, gated behind the `bench` feature.
//!
//! Two pieces:
//! - [`rpc_inc`] / [`rpc_snapshot`] / [`rpc_reset`] / [`rpc_total`]: a thread-local
//!   per-method RPC counter, incremented at the source (`RpcEthereumClient::rpc_call`
//!   and the batch `get_blocks` path). The Helios path compiles but never touches this
//!   thread-local, so its counts stay zero there intentionally.
//! - [`StageTimer`]: an RAII `Instant` wrapper that logs a per-stage line on explicit
//!   stop ([`StageTimer::finish`]) or on drop, so callers can additionally roll timings
//!   into a per-block summary line.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// `tracing` target used by all bench instrumentation for filtering / grep
pub const TARGET: &str = "mpc_chain_ethereum::bench";

// Thread-local per-method RPC counter.
thread_local! {
    static RPC_STATS: RefCell<HashMap<&'static str, u64>> =
        RefCell::new(HashMap::new());
}

/// Increment the per-thread counter for `method`. Counted at the source of the RPC.
pub fn rpc_inc(method: &'static str) {
    RPC_STATS.with(|c| {
        *c.borrow_mut().entry(method).or_default() += 1;
    });
}

/// Increment the per-thread counter for `method` by `n` (used by the batch
/// `get_blocks` path).
pub fn rpc_inc_n(method: &'static str, n: u64) {
    if n == 0 {
        return;
    }
    RPC_STATS.with(|c| {
        *c.borrow_mut().entry(method).or_default() += n;
    });
}

/// Snapshot the current thread's per-method counts, sorted by method name for
/// stable log output.
pub fn rpc_snapshot() -> Vec<(&'static str, u64)> {
    let mut v: Vec<(&'static str, u64)> =
        RPC_STATS.with(|c| c.borrow().iter().map(|(k, v)| (*k, *v)).collect());
    v.sort_by_key(|(k, _)| *k);
    v
}

/// Reset the current thread's counters
pub fn rpc_reset() {
    RPC_STATS.with(|c| c.borrow_mut().clear());
}

/// Total RPC count on the current thread (sum across all methods).
pub fn rpc_total() -> u64 {
    RPC_STATS.with(|c| c.borrow().values().sum())
}

/// RAII stage timer. Logs a per-stage line on [`StageTimer::finish`] (explicit stop)
/// or on drop, and exposes [.elapsed()](StageTimer::elapsed) /
/// [.elapsed_ms()](StageTimer::elapsed_ms) for rolling timings into a per-block summary.
pub struct StageTimer {
    label: &'static str,
    start: Instant,
    finished: bool,
}

impl StageTimer {
    pub fn start(label: &'static str) -> Self {
        Self {
            label,
            start: Instant::now(),
            finished: false,
        }
    }

    pub fn label(&self) -> &'static str {
        self.label
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn elapsed_ms(&self) -> u128 {
        self.start.elapsed().as_millis()
    }

    /// Explicit stop: log the per-stage line and return the elapsed duration.
    pub fn finish(mut self) -> Duration {
        self.finished = true;
        let d = self.start.elapsed();
        tracing::info!(
            target: TARGET,
            stage = self.label,
            elapsed_ms = d.as_millis() as u64,
            "stage"
        );
        d
    }
}

impl Drop for StageTimer {
    /// Implicit stop: log the per-stage line if not already finished.
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let d = self.start.elapsed();
        tracing::info!(
            target: TARGET,
            stage = self.label,
            elapsed_ms = d.as_millis() as u64,
            "stage (dropped)"
        );
    }
}
