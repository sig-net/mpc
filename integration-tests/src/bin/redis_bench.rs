use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use clap::Parser;
use k256::elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use mpc_node::protocol::triple::Triple;
use mpc_node::storage::triple_storage::{TriplePair, TripleStorage};
use near_account_id::AccountId;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::GenericImage;

#[derive(Parser, Debug)]
#[command(
    name = "redis-bench",
    about = "Benchmark Redis Lua scripts and storage operations for MPC ProtocolStorage"
)]
struct CliArgs {
    /// Redis connection URL (e.g. redis://127.0.0.1:6379). If omitted, launches a local Docker container.
    #[arg(long)]
    redis_url: Option<String>,

    /// Run only a specific scenario (1-5). If omitted, runs all 5 scenarios.
    #[arg(short, long)]
    scenario: Option<usize>,
}

struct WorkerResult {
    samples: Vec<Duration>,
    successes: usize,
    failures: usize,
}

struct PhaseResult {
    name: String,
    wall_time: Duration,
    successes: usize,
    failures: usize,
    min: Duration,
    p50: Duration,
    p90: Duration,
    p99: Duration,
    max: Duration,
}

impl PhaseResult {
    fn compute(
        name: &str,
        wall_time: Duration,
        successes: usize,
        failures: usize,
        mut samples: Vec<Duration>,
    ) -> Self {
        samples.sort_unstable();
        let (min, p50, p90, p99, max) = if samples.is_empty() {
            (
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
            )
        } else {
            let n = samples.len();
            (
                samples[0],
                samples[n * 50 / 100],
                samples[n * 90 / 100],
                samples[n * 99 / 100],
                samples[n - 1],
            )
        };

        Self {
            name: name.to_string(),
            wall_time,
            successes,
            failures,
            min,
            p50,
            p90,
            p99,
            max,
        }
    }

    fn print_header() {
        println!(
            "{:<32} | {:>10} | {:>7} | {:>5} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9}",
            "Phase", "Wall Time", "Success", "Fail", "Min", "p50", "p90", "p99", "Max"
        );
        println!(
            "{:-<32}-+-{:-<10}-+-{:-<7}-+-{:-<5}-+-{:-<9}-+-{:-<9}-+-{:-<9}-+-{:-<9}-+-{:-<9}",
            "", "", "", "", "", "", "", "", ""
        );
    }

    fn print_row(&self) {
        println!(
            "{:<32} | {:>10} | {:>7} | {:>5} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9}",
            self.name,
            format_duration(self.wall_time),
            self.successes,
            self.failures,
            format_duration(self.min),
            format_duration(self.p50),
            format_duration(self.p90),
            format_duration(self.p99),
            format_duration(self.max),
        );
    }
}

fn format_duration(d: Duration) -> String {
    let micros = d.as_micros();
    if micros < 1000 {
        format!("{micros}µs")
    } else if micros < 1_000_000 {
        format!("{:.2}ms", d.as_secs_f64() * 1000.0)
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}

/// Single helper owning spawn, barrier synchronization, and sample collection.
async fn run_phase<F, Fut>(name: &str, num_workers: usize, worker_factory: F) -> PhaseResult
where
    F: Fn(usize, Arc<tokio::sync::Barrier>) -> Fut,
    Fut: Future<Output = WorkerResult> + Send + 'static,
{
    let barrier = Arc::new(tokio::sync::Barrier::new(num_workers + 1));
    let mut handles = Vec::with_capacity(num_workers);

    for worker_idx in 0..num_workers {
        let b = Arc::clone(&barrier);
        let fut = worker_factory(worker_idx, b);
        handles.push(tokio::spawn(fut));
    }

    barrier.wait().await;
    let start = Instant::now();

    let mut all_samples = Vec::new();
    let mut total_successes = 0;
    let mut total_failures = 0;

    for handle in handles {
        match handle.await {
            Ok(res) => {
                all_samples.extend(res.samples);
                total_successes += res.successes;
                total_failures += res.failures;
            }
            Err(err) => {
                eprintln!("Worker panicked: {err}");
                total_failures += 1;
            }
        }
    }

    let wall_time = start.elapsed();
    PhaseResult::compute(
        name,
        wall_time,
        total_successes,
        total_failures,
        all_samples,
    )
}

fn create_pool(redis_url: &str, max_size: usize) -> deadpool_redis::Pool {
    let mut cfg = deadpool_redis::Config::from_url(redis_url);
    cfg.pool = Some(deadpool_redis::PoolConfig::new(max_size));
    cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("valid redis pool config")
}

fn dummy_pair(id: u64, participants: &[Participant]) -> TriplePair {
    let triple = Triple {
        share: TripleShare {
            a: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            b: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            c: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
        },
        public: TriplePub {
            big_a: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_b: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_c: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            participants: participants.to_vec(),
            threshold: 2,
        },
    };

    TriplePair {
        id,
        triple0: triple.clone(),
        triple1: triple,
        holders: Some(participants.to_vec()),
    }
}

async fn populate_stockpile(
    storage: &TripleStorage,
    owner: Participant,
    holders: &[Participant],
    start_id: u64,
    count: usize,
) -> Vec<u64> {
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let id = start_id + i as u64;
        let pair = dummy_pair(id, holders);
        if let Some(mut slot) = storage.create_slot(id, owner).await {
            if slot.insert(pair, owner).await {
                ids.push(id);
            }
        }
    }
    ids
}

/// SCENARIO 1: Batch size scaling of remove_outdated
async fn bench_remove_outdated(storage: &TripleStorage, owner: Participant, peers: &[Participant]) {
    println!("\n=== Scenario 1: Batch size of remove_outdated ===");
    PhaseResult::print_header();

    let batch_sizes = [50, 500, 2000, 5000];
    let mut base_id = 100_000u64;

    for &batch_size in &batch_sizes {
        storage.clear().await;
        let all_ids = populate_stockpile(storage, owner, peers, base_id, batch_size).await;
        base_id += batch_size as u64 + 100;

        // Phase A: All items present (0 outdated). Measures ARGV encoding, Redis table scan, and unpack across B elements.
        let storage_clone = storage.clone();
        let ids_clone = all_ids.clone();
        let phase_name = format!("remove_outdated_sync_{batch_size}");
        let res_sync = run_phase(&phase_name, 1, move |_worker_idx, barrier| {
            let s = storage_clone.clone();
            let ids = ids_clone.clone();
            async move {
                barrier.wait().await;
                let start = Instant::now();
                let outcome = s.remove_outdated(owner, &ids).await;
                let elapsed = start.elapsed();
                match outcome {
                    Ok(_) => WorkerResult {
                        samples: vec![elapsed],
                        successes: 1,
                        failures: 0,
                    },
                    Err(_) => WorkerResult {
                        samples: vec![elapsed],
                        successes: 0,
                        failures: 1,
                    },
                }
            }
        })
        .await;
        res_sync.print_row();

        // Phase B: Keep 10% of items, pruning 90% in Lua. Measures Lua SREM, HDEL, DEL unpack under deletion pressure.
        let keep_count = (batch_size / 10).max(1);
        let remaining_ids: Vec<u64> = all_ids[..keep_count].to_vec();
        let storage_clone2 = storage.clone();
        let phase_name = format!("remove_outdated_prune_{batch_size}");
        let res_prune = run_phase(&phase_name, 1, move |_worker_idx, barrier| {
            let s = storage_clone2.clone();
            let r_ids = remaining_ids.clone();
            async move {
                barrier.wait().await;
                let start = Instant::now();
                let outcome = s.remove_outdated(owner, &r_ids).await;
                let elapsed = start.elapsed();
                match outcome {
                    Ok(_) => WorkerResult {
                        samples: vec![elapsed],
                        successes: 1,
                        failures: 0,
                    },
                    Err(_) => WorkerResult {
                        samples: vec![elapsed],
                        successes: 0,
                        failures: 1,
                    },
                }
            }
        })
        .await;
        res_prune.print_row();
    }

    storage.clear().await;
}

/// SCENARIO 2: Batch size scaling of clear
async fn bench_clear(storage: &TripleStorage, owner: Participant, peers: &[Participant]) {
    println!("\n=== Scenario 2: Batch size of clear ===");
    PhaseResult::print_header();

    let sizes = [100, 1000, 5000];
    let mut base_id = 200_000u64;

    for &size in &sizes {
        storage.clear().await;
        populate_stockpile(storage, owner, peers, base_id, size).await;
        base_id += size as u64 + 100;

        let storage_clone = storage.clone();
        let phase_name = format!("clear_{size}_items");
        let res = run_phase(&phase_name, 1, move |_worker_idx, barrier| {
            let s = storage_clone.clone();
            async move {
                barrier.wait().await;
                let start = Instant::now();
                let ok = s.clear().await;
                let elapsed = start.elapsed();
                if ok {
                    WorkerResult {
                        samples: vec![elapsed],
                        successes: 1,
                        failures: 0,
                    }
                } else {
                    WorkerResult {
                        samples: vec![elapsed],
                        successes: 0,
                        failures: 1,
                    }
                }
            }
        })
        .await;
        res.print_row();
    }
}

/// SCENARIO 3: peek_mine versus exclusion-list size
async fn bench_peek_mine_exclusions(
    storage: &TripleStorage,
    owner: Participant,
    peers: &[Participant],
) {
    println!("\n=== Scenario 3: peek_mine versus exclusion-list size ===");
    PhaseResult::print_header();

    let stockpile_size = 2000;
    storage.clear().await;
    let all_ids = populate_stockpile(storage, owner, peers, 300_000, stockpile_size).await;

    let exclusion_counts = [0, 200, 1000, 1950];
    let iterations = 100;

    for &excl_count in &exclusion_counts {
        let excluded: Vec<u64> = all_ids[..excl_count].to_vec();
        let storage_clone = storage.clone();
        let phase_name = format!("peek_mine_excl_{excl_count}");

        let res = run_phase(&phase_name, 1, move |_worker_idx, barrier| {
            let s = storage_clone.clone();
            let excl = excluded.clone();
            async move {
                barrier.wait().await;
                let mut samples = Vec::with_capacity(iterations);
                let mut successes = 0;
                let mut failures = 0;
                for _ in 0..iterations {
                    let start = Instant::now();
                    let opt = s.peek_mine(&excl).await;
                    let elapsed = start.elapsed();
                    samples.push(elapsed);
                    if opt.is_some() {
                        successes += 1;
                    } else {
                        failures += 1;
                    }
                }
                WorkerResult {
                    samples,
                    successes,
                    failures,
                }
            }
        })
        .await;
        res.print_row();
    }

    storage.clear().await;
}

/// SCENARIO 4: Pool saturation on one node
async fn bench_pool_saturation(redis_url: &str, owner: Participant, peers: &[Participant]) {
    println!("\n=== Scenario 4: Pool saturation on one node ===");
    PhaseResult::print_header();

    let account_id: AccountId = "node0.near".parse().unwrap();
    let num_workers = 50;
    let calls_per_worker = 20;

    // Sub-case A: 10 connections in pool vs 50 concurrent workers
    {
        let pool_10 = create_pool(redis_url, 10);
        let storage_10 = TriplePair::storage(&pool_10, &account_id);
        storage_10.set_me(owner);
        storage_10.clear().await;
        populate_stockpile(&storage_10, owner, peers, 400_000, 500).await;

        let res = run_phase(
            "pool_saturated_10conn_50w",
            num_workers,
            move |_worker_idx, barrier| {
                let s = storage_10.clone();
                async move {
                    barrier.wait().await;
                    let mut samples = Vec::with_capacity(calls_per_worker);
                    let mut successes = 0;
                    let mut failures = 0;
                    for _ in 0..calls_per_worker {
                        let start = Instant::now();
                        let opt = s.peek_mine(&[]).await;
                        let elapsed = start.elapsed();
                        samples.push(elapsed);
                        if opt.is_some() {
                            successes += 1;
                        } else {
                            failures += 1;
                        }
                    }
                    WorkerResult {
                        samples,
                        successes,
                        failures,
                    }
                }
            },
        )
        .await;
        res.print_row();
    }

    // Sub-case B: 50 connections in pool for 50 concurrent workers
    {
        let pool_50 = create_pool(redis_url, 50);
        let storage_50 = TriplePair::storage(&pool_50, &account_id);
        storage_50.set_me(owner);
        storage_50.clear().await;
        populate_stockpile(&storage_50, owner, peers, 450_000, 500).await;

        let res = run_phase(
            "pool_adequate_50conn_50w",
            num_workers,
            move |_worker_idx, barrier| {
                let s = storage_50.clone();
                async move {
                    barrier.wait().await;
                    let mut samples = Vec::with_capacity(calls_per_worker);
                    let mut successes = 0;
                    let mut failures = 0;
                    for _ in 0..calls_per_worker {
                        let start = Instant::now();
                        let opt = s.peek_mine(&[]).await;
                        let elapsed = start.elapsed();
                        samples.push(elapsed);
                        if opt.is_some() {
                            successes += 1;
                        } else {
                            failures += 1;
                        }
                    }
                    WorkerResult {
                        samples,
                        successes,
                        failures,
                    }
                }
            },
        )
        .await;
        res.print_row();
    }
}

/// SCENARIO 5: Persistence stall overlap
async fn bench_persistence_overlap(
    pool: &deadpool_redis::Pool,
    storage: &TripleStorage,
    owner: Participant,
    peers: &[Participant],
) {
    println!("\n=== Scenario 5: Persistence stall overlap ===");
    PhaseResult::print_header();

    let num_workers = 10;
    let calls_per_worker = 50;

    // Pre-populate 5,000 items to give Redis a non-trivial dataset to snapshot
    storage.clear().await;
    populate_stockpile(storage, owner, peers, 500_000, 5000).await;

    // Phase A: Baseline in-memory execution (appendonly no)
    {
        if let Ok(mut conn) = pool.get().await {
            let _: Result<(), _> = deadpool_redis::redis::cmd("CONFIG")
                .arg("SET")
                .arg("appendonly")
                .arg("no")
                .query_async(&mut conn)
                .await;
        }

        let storage_clone = storage.clone();
        let peers_vec = peers.to_vec();
        let res_base = run_phase(
            "in_memory_baseline",
            num_workers,
            move |worker_idx, barrier| {
                let s = storage_clone.clone();
                let p = peers_vec.clone();
                async move {
                    barrier.wait().await;
                    let mut samples = Vec::with_capacity(calls_per_worker);
                    let mut successes = 0;
                    let mut failures = 0;
                    let start_id = 600_000 + (worker_idx * calls_per_worker) as u64;
                    for i in 0..calls_per_worker {
                        let id = start_id + i as u64;
                        let pair = dummy_pair(id, &p);
                        let start = Instant::now();
                        if let Some(mut slot) = s.create_slot(id, owner).await {
                            if slot.insert(pair, owner).await {
                                successes += 1;
                            } else {
                                failures += 1;
                            }
                        } else {
                            failures += 1;
                        }
                        samples.push(start.elapsed());
                    }
                    WorkerResult {
                        samples,
                        successes,
                        failures,
                    }
                }
            },
        )
        .await;
        res_base.print_row();
    }

    // Phase B: Overlapping BGSAVE background snapshot
    {
        let pool_clone = pool.clone();
        let storage_clone = storage.clone();
        let peers_vec = peers.to_vec();
        let res_bgsave = run_phase(
            "overlapping_bgsave",
            num_workers,
            move |worker_idx, barrier| {
                let s = storage_clone.clone();
                let p_pool = pool_clone.clone();
                let p = peers_vec.clone();
                async move {
                    barrier.wait().await;
                    if worker_idx == 0 {
                        tokio::spawn(async move {
                            if let Ok(mut conn) = p_pool.get().await {
                                let _: Result<(), _> = deadpool_redis::redis::cmd("BGSAVE")
                                    .query_async(&mut conn)
                                    .await;
                            }
                        });
                    }

                    let mut samples = Vec::with_capacity(calls_per_worker);
                    let mut successes = 0;
                    let mut failures = 0;
                    let start_id = 700_000 + (worker_idx * calls_per_worker) as u64;
                    for i in 0..calls_per_worker {
                        let id = start_id + i as u64;
                        let pair = dummy_pair(id, &p);
                        let start = Instant::now();
                        if let Some(mut slot) = s.create_slot(id, owner).await {
                            if slot.insert(pair, owner).await {
                                successes += 1;
                            } else {
                                failures += 1;
                            }
                        } else {
                            failures += 1;
                        }
                        samples.push(start.elapsed());
                    }
                    WorkerResult {
                        samples,
                        successes,
                        failures,
                    }
                }
            },
        )
        .await;
        res_bgsave.print_row();
    }

    // Phase C: Real AOF disk fsync (appendfsync always)
    {
        if let Ok(mut conn) = pool.get().await {
            let _: Result<(), _> = deadpool_redis::redis::cmd("CONFIG")
                .arg("SET")
                .arg("appendonly")
                .arg("yes")
                .query_async(&mut conn)
                .await;
            let _: Result<(), _> = deadpool_redis::redis::cmd("CONFIG")
                .arg("SET")
                .arg("appendfsync")
                .arg("always")
                .query_async(&mut conn)
                .await;
        }

        let storage_clone = storage.clone();
        let peers_vec = peers.to_vec();
        let res_aof = run_phase(
            "aof_always_fsync",
            num_workers,
            move |worker_idx, barrier| {
                let s = storage_clone.clone();
                let p = peers_vec.clone();
                async move {
                    barrier.wait().await;
                    let mut samples = Vec::with_capacity(calls_per_worker);
                    let mut successes = 0;
                    let mut failures = 0;
                    let start_id = 800_000 + (worker_idx * calls_per_worker) as u64;
                    for i in 0..calls_per_worker {
                        let id = start_id + i as u64;
                        let pair = dummy_pair(id, &p);
                        let start = Instant::now();
                        if let Some(mut slot) = s.create_slot(id, owner).await {
                            if slot.insert(pair, owner).await {
                                successes += 1;
                            } else {
                                failures += 1;
                            }
                        } else {
                            failures += 1;
                        }
                        samples.push(start.elapsed());
                    }
                    WorkerResult {
                        samples,
                        successes,
                        failures,
                    }
                }
            },
        )
        .await;
        res_aof.print_row();

        if let Ok(mut conn) = pool.get().await {
            let _: Result<(), _> = deadpool_redis::redis::cmd("CONFIG")
                .arg("SET")
                .arg("appendonly")
                .arg("no")
                .query_async(&mut conn)
                .await;
        }
    }

    storage.clear().await;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    let (redis_url, _container) = if let Some(url) = args.redis_url {
        println!("Connecting to external Redis at {url}");
        (url, None)
    } else {
        println!("Starting Redis 7 container via testcontainers...");
        let container = GenericImage::new("redis", "7.4.2")
            .with_exposed_port(6379.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .start()
            .await?;
        let port = container.get_host_port_ipv4(6379u16).await?;
        let url = format!("redis://127.0.0.1:{port}");
        println!("Redis container ready on {url}");
        (url, Some(container))
    };

    let pool = create_pool(&redis_url, 32);
    let account_id: AccountId = "node0.near".parse().unwrap();
    let storage = TriplePair::storage(&pool, &account_id);
    let owner = Participant::from(0);
    storage.set_me(owner);
    let peers = vec![
        Participant::from(0),
        Participant::from(1),
        Participant::from(2),
    ];

    let scenario = args.scenario;

    if scenario.is_none() || scenario == Some(1) {
        bench_remove_outdated(&storage, owner, &peers).await;
    }
    if scenario.is_none() || scenario == Some(2) {
        bench_clear(&storage, owner, &peers).await;
    }
    if scenario.is_none() || scenario == Some(3) {
        bench_peek_mine_exclusions(&storage, owner, &peers).await;
    }
    if scenario.is_none() || scenario == Some(4) {
        bench_pool_saturation(&redis_url, owner, &peers).await;
    }
    if scenario.is_none() || scenario == Some(5) {
        bench_persistence_overlap(&pool, &storage, owner, &peers).await;
    }

    println!("\nBenchmark run complete.");
    Ok(())
}
