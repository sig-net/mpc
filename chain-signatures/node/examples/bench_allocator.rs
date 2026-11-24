//! Microbenchmark to measure allocator performance under a multi-threaded Tokio runtime.
//! Compares the default system allocator (e.g. glibc ptmalloc on Linux) against jemalloc.
//!
//! # Architecture
//! Simulates high-concurrency cross-thread message passing across Tokio worker threads:
//! - 32 independent MPSC channels with concurrent producer and consumer async tasks.
//! - 15,000 messages per task (480,000 total messages) with varying payload sizes (128B to 16KB).
//! - Buffers are allocated on producer tasks and dropped/freed on consumer tasks across threads,
//!   triggering cross-thread free paths in the memory allocator.
//!
//! # Running
//! Run with jemalloc (default):
//! ```bash
//! cargo run --release -p mpc-node --example bench_allocator
//! ```
//!
//! Run with system allocator:
//! ```bash
//! cargo run --release -p mpc-node --no-default-features --example bench_allocator
//! ```

#[cfg(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    not(target_arch = "wasm32")
))]
#[global_allocator]
static GLOBAL: mpc_node::alloc::Jemalloc = mpc_node::alloc::Jemalloc;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

fn get_peak_rss_mb() -> f64 {
    #[cfg(unix)]
    unsafe {
        let mut rusage = std::mem::zeroed::<libc::rusage>();
        if libc::getrusage(libc::RUSAGE_SELF, &mut rusage) == 0 {
            #[cfg(target_os = "macos")]
            return rusage.ru_maxrss as f64 / (1024.0 * 1024.0); // macOS reports in bytes
            #[cfg(not(target_os = "macos"))]
            return rusage.ru_maxrss as f64 / 1024.0; // Linux reports in kilobytes
        }
    }
    0.0
}

fn get_current_rss_mb() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let mut parts = statm.split_whitespace();
            if let (Some(_virt), Some(rss)) = (parts.next(), parts.next()) {
                if let Ok(pages) = rss.parse::<u64>() {
                    let page_size = unsafe {
                        let sz = libc::sysconf(libc::_SC_PAGESIZE);
                        if sz > 0 {
                            sz as u64
                        } else {
                            4096u64
                        }
                    };
                    return (pages * page_size) as f64 / (1024.0 * 1024.0);
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    #[allow(deprecated)]
    unsafe {
        let mut info = std::mem::zeroed::<libc::mach_task_basic_info>();
        let mut count = (std::mem::size_of::<libc::mach_task_basic_info>()
            / std::mem::size_of::<libc::natural_t>())
            as libc::mach_msg_type_number_t;
        if libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as *mut libc::integer_t,
            &mut count,
        ) == libc::KERN_SUCCESS
        {
            return info.resident_size as f64 / (1024.0 * 1024.0);
        }
    }
    get_peak_rss_mb()
}

#[derive(Clone)]
#[allow(dead_code)]
struct MessagePayload {
    id: u64,
    data: Vec<u8>,
}

#[tokio::main]
async fn main() {
    let allocator_name = if cfg!(all(
        feature = "jemalloc",
        not(target_env = "msvc"),
        not(target_arch = "wasm32")
    )) {
        "tikv-jemallocator (jemalloc)"
    } else {
        "system allocator (glibc / default)"
    };

    println!("============================================================");
    println!(" Allocator Benchmark: {allocator_name}");
    #[cfg(all(
        feature = "jemalloc",
        not(target_env = "msvc"),
        not(target_arch = "wasm32")
    ))]
    {
        let (dirty, muzzy) = mpc_node::alloc::query_decay_ms().expect("query decay");
        println!(" Jemalloc decay: dirty_decay_ms={dirty}, muzzy_decay_ms={muzzy}");
        mpc_node::alloc::verify_configuration().expect("verify decay");
    }
    println!("============================================================");

    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    println!("Worker threads: {num_cpus}");

    const NUM_TASKS: usize = 32;
    const MESSAGES_PER_TASK: usize = 15_000;
    const TOTAL_MESSAGES: usize = NUM_TASKS * MESSAGES_PER_TASK;

    println!("Total cross-thread messages: {TOTAL_MESSAGES} ({NUM_TASKS} channels x {MESSAGES_PER_TASK} msgs)");

    let initial_rss = get_current_rss_mb();
    let counter = Arc::new(AtomicUsize::new(0));
    let bytes_counter = Arc::new(AtomicUsize::new(0));

    let start_time = Instant::now();

    let mut handles = Vec::with_capacity(NUM_TASKS * 2);

    for task_idx in 0..NUM_TASKS {
        let (tx, mut rx) = mpsc::channel::<MessagePayload>(256);
        let counter_clone = Arc::clone(&counter);
        let bytes_clone = Arc::clone(&bytes_counter);

        // Consumer task: receives on worker thread and deallocates (cross-thread free)
        let consumer = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                // Simulate decoding / inspecting data before drop
                let len = msg.data.len();
                bytes_clone.fetch_add(len, Ordering::Relaxed);
                counter_clone.fetch_add(1, Ordering::Relaxed);
                drop(msg);
            }
        });
        handles.push(consumer);

        // Producer task: allocates buffers of varying sizes simulating serialized protocol envelopes
        let producer = tokio::spawn(async move {
            for i in 0..MESSAGES_PER_TASK {
                // Varying payload size from 128 bytes to 16 KiB
                let size = 128 + ((task_idx * 17 + i * 31) % 16384);
                let mut data = Vec::with_capacity(size);
                data.resize(size, (i % 255) as u8);

                let payload = MessagePayload {
                    id: (task_idx * 100_000 + i) as u64,
                    data,
                };

                if tx.send(payload).await.is_err() {
                    break;
                }
            }
        });
        handles.push(producer);
    }

    for h in handles {
        let _ = h.await;
    }

    let elapsed = start_time.elapsed();
    let total_msgs = counter.load(Ordering::Relaxed);
    let total_bytes = bytes_counter.load(Ordering::Relaxed);
    let total_mb = total_bytes as f64 / (1024.0 * 1024.0);
    let throughput_msgs = total_msgs as f64 / elapsed.as_secs_f64();
    let throughput_mb = total_mb / elapsed.as_secs_f64();
    let peak_rss = get_peak_rss_mb();
    let immediate_rss = get_current_rss_mb();

    // Sleep for 2.0s to allow allocator active decay (1000ms configured on jemalloc) to purge dirty pages
    tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
    let post_decay_rss = get_current_rss_mb();
    let purged_mb = (immediate_rss - post_decay_rss).max(0.0);
    let retained_vs_init = post_decay_rss - initial_rss;

    println!("------------------------------------------------------------");
    println!("Elapsed time:       {:.3}s", elapsed.as_secs_f64());
    println!("Throughput:         {:.0} msgs/sec", throughput_msgs);
    println!(
        "Bandwidth:          {:.2} MB/sec ({:.2} MB total)",
        throughput_mb, total_mb
    );
    println!("Initial RSS:        {:.2} MB", initial_rss);
    println!("Peak RSS (high-wm): {:.2} MB", peak_rss);
    println!("Immediate RSS:      {:.2} MB", immediate_rss);
    println!("Post-decay RSS:     {:.2} MB (after 2s idle)", post_decay_rss);
    println!(
        "Purged back to OS:  {:.2} MB (retained above init: {:.2} MB)",
        purged_mb, retained_vs_init
    );
    println!("============================================================");
}
