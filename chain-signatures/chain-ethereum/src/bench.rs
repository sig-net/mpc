//! Benchmarking helpers, gated behind the `bench` feature.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Target for tracing logs emitted by the benchmarking helpers.
pub const TARGET: &str = "mpc_chain_ethereum::bench";

// Global state for benchmarking
static RPC_STATS: Mutex<Option<HashMap<&'static str, u64>>> = Mutex::new(None);
static FETCH_TIME_MS: AtomicU64 = AtomicU64::new(0);
static PROCESS_TIME_MS: AtomicU64 = AtomicU64::new(0);
static BLOCKS_PROCESSED: AtomicU64 = AtomicU64::new(0);
static CATCHUP_START: Mutex<Option<Instant>> = Mutex::new(None);

/// Increment the count of RPC calls for a given method.
pub fn rpc_inc(method: &'static str) {
    let mut guard = RPC_STATS.lock().unwrap();
    *guard.get_or_insert_with(HashMap::new).entry(method).or_default() += 1;
}

/// Increment the count of RPC calls for a given method by `n` (batch calls)
pub fn rpc_inc_n(method: &'static str, n: u64) {
    if n == 0 { return; }
    let mut guard = RPC_STATS.lock().unwrap();
    *guard.get_or_insert_with(HashMap::new).entry(method).or_default() += n;
}

/// Reset all benchmarking metrics to zero (restarting the catchup benchmark).
pub fn rpc_reset() {
    if let Some(m) = RPC_STATS.lock().unwrap().as_mut() {
        m.clear();
    }
    FETCH_TIME_MS.store(0, Ordering::Relaxed);
    PROCESS_TIME_MS.store(0, Ordering::Relaxed);
    BLOCKS_PROCESSED.store(0, Ordering::Relaxed);
    *CATCHUP_START.lock().unwrap() = Some(Instant::now());
}

/// Add the given duration to the total fetch time in milliseconds.
pub fn add_fetch_time(d: Duration) {
    FETCH_TIME_MS.fetch_add(d.as_millis() as u64, Ordering::Relaxed);
}

/// Add the given duration to the total process time in milliseconds.
pub fn add_process_time(d: Duration) {
    PROCESS_TIME_MS.fetch_add(d.as_millis() as u64, Ordering::Relaxed);
}


/// Increment the count of blocks processed by one and return the new count.
pub fn inc_block() -> u64 {
    BLOCKS_PROCESSED.fetch_add(1, Ordering::Relaxed) + 1
}

/// Report the current benchmarking metrics to the tracing log.
pub fn report_metrics(stage: &str) {
    let rpcs: Vec<_> = RPC_STATS.lock().unwrap().as_ref().map(|m| {
        let mut v: Vec<_> = m.iter().map(|(k, v)| (*k, *v)).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }).unwrap_or_default();
    
    let total_rpc: u64 = rpcs.iter().map(|(_, v)| v).sum();
    let fetch_ms = FETCH_TIME_MS.load(Ordering::Relaxed);
    let process_ms = PROCESS_TIME_MS.load(Ordering::Relaxed);
    let blocks = BLOCKS_PROCESSED.load(Ordering::Relaxed);

    let elapsed_sec = CATCHUP_START.lock().unwrap().unwrap_or_else(Instant::now).elapsed().as_secs_f64().max(0.001);

    tracing::info!(
        target: TARGET,
        stage,
        blocks,
        fetch_ms,
        process_ms,
        total_rpc,
        blocks_per_sec = format!("{:.2}", blocks as f64 / elapsed_sec),
        rpc_per_sec = format!("{:.2}", total_rpc as f64 / elapsed_sec),
        rpc_breakdown = ?rpcs,
        "Catchup Benchmark Report"
    );
}
