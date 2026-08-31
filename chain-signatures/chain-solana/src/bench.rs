//! Benchmarking helpers, gated behind the `bench` feature.
//!
//! Instruments the catchup path (`catchup_blocks` → `paginate_slots` →
//! `fetch_blocks_for_pages` → `process_catchup_item`) with RPC counters and
//! timing, emitting a `Catchup Benchmark Report` via [`report_metrics`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Target for tracing logs emitted by the benchmarking helpers.
pub const TARGET: &str = "mpc_chain_solana::bench";

/// Per-method RPC counters.
/// `logical` is the number of JSON-RPC requests issued for that method;
/// `http` is the number of HTTP round-trips they went in.
#[derive(Default, Clone, Copy)]
struct RpcCount {
    logical: u64,
    http: u64,
}

// Global state for benchmarking. Assumes at most one catchup in flight at a
// time (same caveat as chain-ethereum's bench module).
static RPC_STATS: Mutex<Option<HashMap<&'static str, RpcCount>>> = Mutex::new(None);
static SIG_FETCH_NS: AtomicU64 = AtomicU64::new(0);
static BATCH_FETCH_NS: AtomicU64 = AtomicU64::new(0);
static REFETCH_NS: AtomicU64 = AtomicU64::new(0);
static PROCESS_TIME_NS: AtomicU64 = AtomicU64::new(0);
static SLOTS_PROCESSED: AtomicU64 = AtomicU64::new(0);
static SIGNATURE_PAGES: AtomicU64 = AtomicU64::new(0);
static SIGNATURES_SCANNED: AtomicU64 = AtomicU64::new(0);
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
    SIG_FETCH_NS.store(0, Ordering::Relaxed);
    BATCH_FETCH_NS.store(0, Ordering::Relaxed);
    REFETCH_NS.store(0, Ordering::Relaxed);
    PROCESS_TIME_NS.store(0, Ordering::Relaxed);
    SLOTS_PROCESSED.store(0, Ordering::Relaxed);
    SIGNATURE_PAGES.store(0, Ordering::Relaxed);
    SIGNATURES_SCANNED.store(0, Ordering::Relaxed);
    *CATCHUP_START.lock().unwrap() = Some(Instant::now());
    drop(stats);
}

/// Accumulate time spent in `order_and_chunk_pages` — the paginated
/// `getSignaturesForAddress` walk-back from the anchor down to the catchup
/// start slot. Stored in nanoseconds.
pub fn add_sig_fetch_time(d: Duration) {
    SIG_FETCH_NS.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
}

/// Accumulate time spent in `SolanaClient::fetch_blocks_for_slots` — the
/// batched `getBlock` POSTs (chunks of 50, 5 concurrent) that pull blocks for
/// the slots that touched the program. Stored in nanoseconds.
pub fn add_batch_fetch_time(d: Duration) {
    BATCH_FETCH_NS.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
}

/// Accumulate time spent in the single-slot refetch path inside
/// `SolanaIndexer::process_catchup_item` — fired only when a batch is missing
/// a slot and the indexer re-asks for it via `get_block`. Stored in
/// nanoseconds.
pub fn add_refetch_time(d: Duration) {
    REFETCH_NS.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
}

/// Accumulate time spent in `SolanaIndexer::process_block` (the per-slot
/// parse + emit step). Stored in nanoseconds.
pub fn add_process_time(d: Duration) {
    PROCESS_TIME_NS.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
}

/// Increment the count of slots processed by one and return the new count.
pub fn inc_slot() -> u64 {
    SLOTS_PROCESSED.fetch_add(1, Ordering::Relaxed) + 1
}

/// Record one fetched signature page holding `scanned` signatures.
pub fn inc_sig_page(scanned: u64) {
    SIGNATURE_PAGES.fetch_add(1, Ordering::Relaxed);
    SIGNATURES_SCANNED.fetch_add(scanned, Ordering::Relaxed);
}

fn ns_to_ms(ns: u64) -> u64 {
    (ns as f64 / 1e6).round() as u64
}

/// Report the current benchmarking metrics.
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
    let sig_fetch_ms = ns_to_ms(SIG_FETCH_NS.load(Ordering::Relaxed));
    let batch_fetch_ms = ns_to_ms(BATCH_FETCH_NS.load(Ordering::Relaxed));
    let refetch_ms = ns_to_ms(REFETCH_NS.load(Ordering::Relaxed));
    let process_ms = ns_to_ms(PROCESS_TIME_NS.load(Ordering::Relaxed));
    let slots = SLOTS_PROCESSED.load(Ordering::Relaxed);
    let sig_pages = SIGNATURE_PAGES.load(Ordering::Relaxed);
    let sigs_scanned = SIGNATURES_SCANNED.load(Ordering::Relaxed);
    // Signatures walked past vs. slots that actually contained program
    // activity: how much of the `getSignaturesForAddress` walk-back is waste.
    let walk_back_overhead = sigs_scanned as f64 / slots.max(1) as f64;

    let elapsed_sec = CATCHUP_START
        .lock()
        .unwrap()
        .unwrap_or_else(Instant::now)
        .elapsed()
        .as_secs_f64()
        .max(0.001);

    let slots_per_sec = slots as f64 / elapsed_sec;
    let rpc_per_sec = total_rpc as f64 / elapsed_sec;
    let http_per_sec = total_http as f64 / elapsed_sec;

    let breakdown = rpcs
        .iter()
        .map(|(method, c)| {
            format!(
                "  {method:<36} {logical:>6} ({http} http)",
                logical = c.logical,
                http = c.http,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let label = format!("{stage}: {slots} slots in {elapsed_sec:.2}s");

    tracing::info!(
        target: TARGET,
        "Catchup Benchmark Report\n{label}\n  slots_per_sec  {slots_per_sec:.1}\n  rpc_per_sec    {rpc_per_sec:.1}  (http_per_sec {http_per_sec:.1})\n  total_rpc      {total_rpc}  (total_http {total_http})\n  sig_fetch_ms   {sig_fetch_ms}\n  batch_fetch_ms {batch_fetch_ms}\n  refetch_ms     {refetch_ms}\n  process_ms     {process_ms}\n  walk_back      {sig_pages} pages, {sigs_scanned} sigs scanned, {slots} active slots ({walk_back_overhead:.1}x overhead)\n  rpc_breakdown (logical, http round-trips):\n{breakdown}"
    );
}
