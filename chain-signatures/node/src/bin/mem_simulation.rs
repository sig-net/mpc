use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use k256::Scalar;
use mpc_node::backlog::{Backlog, BacklogEntry, Checkpoint};
use mpc_node::sign_bidirectional::PublishState;
use mpc_primitives::{Chain, IndexedSignRequest, SignArgs, SignId};
use mpc_utils::task::JoinMap;
use sysinfo::{Pid, ProcessesToUpdate, System as SysSystem};
use tokio_util::time::delay_queue::DelayQueue;

// =========================================================================
// Tracking Allocator
// =========================================================================

struct TrackingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let size = layout.size();
            let total = ALLOCATED.fetch_add(size, Ordering::Relaxed) + size;
            let dealloc = DEALLOCATED.load(Ordering::Relaxed);
            let in_use = total.saturating_sub(dealloc);
            PEAK.fetch_max(in_use, Ordering::Relaxed);
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        DEALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ptr = System.realloc(ptr, layout, new_size);
        if !ptr.is_null() {
            if new_size > layout.size() {
                let diff = new_size - layout.size();
                let total = ALLOCATED.fetch_add(diff, Ordering::Relaxed) + diff;
                let dealloc = DEALLOCATED.load(Ordering::Relaxed);
                let in_use = total.saturating_sub(dealloc);
                PEAK.fetch_max(in_use, Ordering::Relaxed);
            } else {
                let diff = layout.size() - new_size;
                DEALLOCATED.fetch_add(diff, Ordering::Relaxed);
            }
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }
}

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

fn current_heap() -> usize {
    let alloc = ALLOCATED.load(Ordering::Relaxed);
    let dealloc = DEALLOCATED.load(Ordering::Relaxed);
    alloc.saturating_sub(dealloc)
}

fn peak_heap() -> usize {
    PEAK.load(Ordering::Relaxed)
}

fn reset_peak() {
    PEAK.store(current_heap(), Ordering::Relaxed);
}

fn get_process_rss() -> usize {
    let mut sys = SysSystem::new();
    let pid = Pid::from_u32(std::process::id());
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    if let Some(process) = sys.process(pid) {
        process.memory() as usize
    } else {
        0
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn make_sign_request(index: u64) -> Arc<IndexedSignRequest> {
    let mut id_bytes = [0u8; 32];
    id_bytes[0..8].copy_from_slice(&index.to_be_bytes());
    id_bytes[8..16].copy_from_slice(&0xdeadbeef_u64.to_be_bytes());
    let id = SignId::new(id_bytes);

    let mut entropy = [0u8; 32];
    entropy[0..8].copy_from_slice(&index.to_le_bytes());

    let args = SignArgs {
        entropy,
        epsilon: Scalar::from(index + 1),
        payload: Scalar::from(index + 42),
        path: "m/44'/60'/0'/0/0".to_string(),
        key_version: 0,
    };

    Arc::new(IndexedSignRequest::sign(id, args, Chain::Ethereum, 1724000000 + index))
}

#[tokio::main]
async fn main() {
    println!("=================================================================================");
    println!("     MPC-NODE SYSTEM MEMORY USAGE & SCALE BENCHMARK (AFTER LATEST FIXES)        ");
    println!("=================================================================================\n");

    println!("Initial Process RSS: {}", format_bytes(get_process_rss()));
    println!("Initial Heap:        {}\n", format_bytes(current_heap()));

    // =========================================================================
    // PART 1: STATIC SIZES
    // =========================================================================
    println!("=================================================================================");
    println!("PART 1: STRUCT STATIC SIZES");
    println!("=================================================================================");
    println!("{:<35} | {:>15}", "Type / Struct", "Stack Size");
    println!("{:-<35}-+-{:-<15}", "", "");
    println!("{:<35} | {:>15}", "SignId", format!("{} B", std::mem::size_of::<SignId>()));
    println!("{:<35} | {:>15}", "IndexedSignRequest", format!("{} B", std::mem::size_of::<IndexedSignRequest>()));
    println!("{:<35} | {:>15}", "Arc<IndexedSignRequest>", format!("{} B", std::mem::size_of::<Arc<IndexedSignRequest>>()));
    println!("{:<35} | {:>15}", "PublishState", format!("{} B", std::mem::size_of::<PublishState>()));
    println!("{:<35} | {:>15}", "Arc<PublishState>", format!("{} B", std::mem::size_of::<Arc<PublishState>>()));
    println!("{:<35} | {:>15}", "BacklogEntry", format!("{} B", std::mem::size_of::<BacklogEntry>()));
    println!("{:<35} | {:>15}", "Checkpoint", format!("{} B", std::mem::size_of::<Checkpoint>()));

    // =========================================================================
    // PART 2: SCALE BENCHMARKS (10k, 50k, 250k, 1M)
    // =========================================================================
    println!("\n=================================================================================");
    println!("PART 2: SCALE BENCHMARKS & CHECKPOINT RETENTION (10k, 50k, 250k, 1M)");
    println!("=================================================================================");

    for &n in &[10_000, 50_000, 250_000, 1_000_000] {
        println!("\n---------------------------------------------------------------------------------");
        println!(">>> RUNNING SCALE: N = {} REQUESTS", n);
        println!("---------------------------------------------------------------------------------");

        let pre_heap = current_heap();
        reset_peak();
        let t0 = Instant::now();

        // 1. Ingestion
        let mut requests = Vec::with_capacity(n);
        for i in 0..n as u64 {
            requests.push(make_sign_request(i));
        }
        let ingest_time = t0.elapsed();
        let ingest_heap = current_heap().saturating_sub(pre_heap);

        // 2. Backlog Insertion
        let backlog = Backlog::new();
        let t1 = Instant::now();
        for req in &requests {
            backlog.insert(req.clone()).await;
        }
        let insert_time = t1.elapsed();
        let backlog_heap = current_heap().saturating_sub(pre_heap + ingest_heap);

        // 3. Single Checkpoint Creation
        let t2 = Instant::now();
        let cp = backlog.checkpoint(Chain::Ethereum).await.expect("checkpoint");
        let cp_time = t2.elapsed();
        let single_cp_heap = current_heap().saturating_sub(pre_heap + ingest_heap + backlog_heap);

        // 4. Digest
        let t3 = Instant::now();
        let digest = cp.digest();
        let digest_time = t3.elapsed();

        // 5. 32 Pending Checkpoints
        let mut pending_cps = Vec::with_capacity(32);
        pending_cps.push(cp);
        for _ in 1..32 {
            let cp_clone = backlog.checkpoint(Chain::Ethereum).await.expect("checkpoint");
            pending_cps.push(cp_clone);
        }
        let total_32_cps_heap = current_heap().saturating_sub(pre_heap + ingest_heap + backlog_heap);

        println!("1. Ingestion:   {} in {:?} (Heap: {}, {:.1} B/req)", n, ingest_time, format_bytes(ingest_heap), ingest_heap as f64 / n as f64);
        println!("2. Backlog:     Inserted in {:?} (Heap: {}, {:.1} B/req)", insert_time, format_bytes(backlog_heap), backlog_heap as f64 / n as f64);
        println!("3. Checkpoint:  Generated in {:?} (Single CP Heap: {}, {:.1} B/req)", cp_time, format_bytes(single_cp_heap), single_cp_heap as f64 / n as f64);
        println!("4. Digest:      Computed ({:02x}{:02x}...) in {:?}", digest[0], digest[1], digest_time);
        println!("5. 32 CPs Heap: Total for 32 Checkpoints: {} (WAS: {} previously!)", format_bytes(total_32_cps_heap), format_bytes(if n == 10_000 { 395 * 1024 * 1024 } else if n == 50_000 { 1930 * 1024 * 1024 } else if n == 250_000 { 9660 * 1024 * 1024 } else { 38620 * 1024 * 1024 }));
        println!("6. Total System (Backlog + 32 CPs): {}", format_bytes(backlog_heap + total_32_cps_heap));
        println!("   Current Process RSS: {}", format_bytes(get_process_rss()));

        drop(pending_cps);
        drop(backlog);
        drop(requests);
    }

    // =========================================================================
    // PART 3: SIGNATURE SPAWNER & DELAY QUEUE SIMULATION (60k Backlog)
    // =========================================================================
    println!("\n=================================================================================");
    println!("PART 3: SIGNATURE SPAWNER + DELAY QUEUE BENCHMARK (60k REQUESTS)");
    println!("=================================================================================");

    let n = 60_000;
    let mut requests = Vec::with_capacity(n);
    for i in 0..n as u64 {
        requests.push(make_sign_request(i));
    }

    let pre_spawner_heap = current_heap();
    reset_peak();

    let mut requests_map = HashMap::with_capacity(n);
    let mut delay_queue: DelayQueue<SignId> = DelayQueue::new();
    let mut tasks: JoinMap<SignId, Result<(), ()>> = JoinMap::new();

    let t_spawner = Instant::now();
    for req in &requests {
        let sign_id = req.id;
        let is_proposer = Arc::new(AtomicBool::new(false));
        requests_map.insert(sign_id, (
            Arc::clone(req),
            Arc::clone(&is_proposer),
            Arc::new(AtomicUsize::new(0)),
        ));

        // Use DelayQueue instead of spawning 60,000 separate watcher tasks!
        delay_queue.insert(sign_id, Duration::from_secs(3600));

        tasks.spawn(sign_id, async move {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(())
        });
    }
    let spawner_elapsed = t_spawner.elapsed();
    let spawner_heap = current_heap().saturating_sub(pre_spawner_heap);

    println!("Admitted 60,000 requests to Spawner & DelayQueue in {:?}", spawner_elapsed);
    println!("Spawner Net Heap Allocated: {} ({:.1} B/request)", format_bytes(spawner_heap), spawner_heap as f64 / n as f64);
    println!("Spawner Peak Heap:          {}", format_bytes(peak_heap().saturating_sub(pre_spawner_heap)));
    println!("Process Total RSS:          {}", format_bytes(get_process_rss()));

    // Cleanup
    for req in &requests {
        tasks.abort(req.id);
    }
}
