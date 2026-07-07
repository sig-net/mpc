//! Benchmarking helpers, gated behind the `bench` feature.
//!
//! Only covers the direct-RPC backend
//! (`indexer_eth_direct_rpc::RpcEthereumClient`). The Helios light-client backend
//! (`indexer_eth_helios::HeliosEthereumClient`) is intentionally NOT instrumented

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Target for tracing logs emitted by the benchmarking helpers.
pub const TARGET: &str = "mpc_chain_ethereum::bench";

/// Per-method RPC counters.
/// `logical` is the number of JSON-RPC requests issued for that method;
/// `http` is the number of HTTP round-trips they went in.
#[derive(Default, Clone, Copy)]
struct RpcCount {
    logical: u64,
    http: u64,
}

// Global state for benchmarking.
//
// TODO: this single global set of counters assumes at most one catchup is
// in flight at a time. When concurrent catchups land, consider moving this state onto
// `EthereumIndexer` (per-instance) so each catchup reports independently
static RPC_STATS: Mutex<Option<HashMap<&'static str, RpcCount>>> = Mutex::new(None);
static BATCH_FETCH_NS: AtomicU64 = AtomicU64::new(0);
static REFETCH_NS: AtomicU64 = AtomicU64::new(0);
static PROCESS_TIME_NS: AtomicU64 = AtomicU64::new(0);
static BLOCKS_PROCESSED: AtomicU64 = AtomicU64::new(0);
static CATCHUP_START: Mutex<Option<Instant>> = Mutex::new(None);

/// Increment the logical and HTTP count for a single (non-batched) RPC method
/// by one. One logical request == one HTTP POST.
pub fn rpc_inc(method: &'static str) {
    let mut guard = RPC_STATS.lock().unwrap();
    let c = guard
        .get_or_insert_with(HashMap::new)
        .entry(method)
        .or_default();
    c.logical += 1;
    c.http += 1;
}

/// Increment the logical count for a batched RPC method by `n` and the HTTP
/// count by one (all `n` JSON-RPC entries travel in a single batch POST).
/// Counters reflect attempted requests, not successful ones.
pub fn rpc_inc_n(method: &'static str, n: u64) {
    if n == 0 {
        return;
    }
    let mut guard = RPC_STATS.lock().unwrap();
    let c = guard
        .get_or_insert_with(HashMap::new)
        .entry(method)
        .or_default();
    c.logical += n;
    c.http += 1;
}

/// Reset all benchmarking metrics to zero (restarting the catchup benchmark).
pub fn rpc_reset() {
    let mut stats = RPC_STATS.lock().unwrap();
    if let Some(m) = stats.as_mut() {
        m.clear();
    }
    BATCH_FETCH_NS.store(0, Ordering::Relaxed);
    REFETCH_NS.store(0, Ordering::Relaxed);
    PROCESS_TIME_NS.store(0, Ordering::Relaxed);
    BLOCKS_PROCESSED.store(0, Ordering::Relaxed);
    *CATCHUP_START.lock().unwrap() = Some(Instant::now());
    drop(stats);
}

/// Accumulate time spent in `CatchupIter::fetch_next_batch` — the batched
/// `get_blocks` HTTP POST that pulls the next up-to-32-block chunk from the
/// upstream. This is the main historical-block fetch path. Stored in
/// nanoseconds to preserve sub-millisecond precision.
pub fn add_batch_fetch_time(d: Duration) {
    BATCH_FETCH_NS.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
}

/// Accumulate time spent in the per-block single-block refetch path inside
/// `EthereumIndexer::process_catchup` — fired only when a batch returns
/// `MaybeBlock::Missing` for a block id and the indexer re-asks for that one
/// block via `get_block`. Stored in nanoseconds.
pub fn add_refetch_time(d: Duration) {
    REFETCH_NS.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
}

/// Accumulate time spent in `EthereumIndexer::process_block` (the per-block
/// processing step). `process_block` itself
/// issues RPCs (`eth_getBlockReceipts`, `eth_getTransactionByHash`,
/// `debug_traceTransaction`, `eth_getTransactionCount`), so this bucket
/// includes their latency too. Stored in nanoseconds.
pub fn add_process_time(d: Duration) {
    PROCESS_TIME_NS.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
}

/// Increment the count of blocks processed by one and return the new count.
pub fn inc_block() -> u64 {
    BLOCKS_PROCESSED.fetch_add(1, Ordering::Relaxed) + 1
}

/// Report the current benchmarking metrics
pub fn report_metrics(stage: &str) {
    let rpcs: Vec<_> = RPC_STATS
        .lock()
        .unwrap()
        .as_ref()
        .map(|m| {
            let mut v: Vec<_> = m.iter().map(|(k, v)| (*k, *v)).collect();
            v.sort_by_key(|(k, _)| *k);
            v
        })
        .unwrap_or_default();

    let total_rpc: u64 = rpcs.iter().map(|(_, c)| c.logical).sum();
    let total_http: u64 = rpcs.iter().map(|(_, c)| c.http).sum();
    let batch_fetch_ms = (BATCH_FETCH_NS.load(Ordering::Relaxed) as f64 / 1e6).round() as u64;
    let refetch_ms = (REFETCH_NS.load(Ordering::Relaxed) as f64 / 1e6).round() as u64;
    let per_block_process_ms =
        (PROCESS_TIME_NS.load(Ordering::Relaxed) as f64 / 1e6).round() as u64;
    let blocks = BLOCKS_PROCESSED.load(Ordering::Relaxed);

    let elapsed_sec = CATCHUP_START
        .lock()
        .unwrap()
        .unwrap_or_else(Instant::now)
        .elapsed()
        .as_secs_f64()
        .max(0.001);

    let blocks_per_sec = blocks as f64 / elapsed_sec;
    let rpc_per_sec = total_rpc as f64 / elapsed_sec;
    let http_per_sec = total_http as f64 / elapsed_sec;

    let breakdown = rpcs
        .iter()
        .map(|(method, c)| {
            format!(
                "  {method:<36} {logical:>6} ({http} http)",
                logical = c.logical,
                http = c.http
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let label = format!("{stage}: {blocks} blocks in {elapsed_sec:.2}s");

    tracing::info!(
        target: TARGET,
        "Catchup Benchmark Report\n{label}\n  blocks_per_sec  {blocks_per_sec:.1}\n  rpc_per_sec    {rpc_per_sec:.1}  (http_per_sec {http_per_sec:.1})\n  total_rpc      {total_rpc}  (total_http {total_http})\n  batch_fetch_ms {batch_fetch_ms}\n  refetch_ms     {refetch_ms}\n  process_ms     {per_block_process_ms}\n  rpc_breakdown (logical, http round-trips):\n{breakdown}"
    );
}
