use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use integration_tests::redis_harness::diagnostics::LatencySummary;
use integration_tests::redis_harness::{RedisHarness, RedisHarnessConfig};

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum BenchScenario {
    All,
    Baseline,
    Polling,
    Storm,
    Proposer,
    Saturation,
    Clear,
    Mixed,
    SyncPrune,
    ClientKill,
    DeepStockpile,
    ReservationChurn,
    ConflictedTake,
}

impl std::fmt::Display for BenchScenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_possible_value().unwrap().get_name())
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "redis-bench",
    about = "Redis Latency & Stress Benchmark Harness (Pure Redis Container - No MPC Nodes, NEAR, or Blockchains)"
)]
struct Args {
    /// Benchmark scenario to run: 'all', 'baseline', 'polling', 'storm', 'proposer', 'saturation', 'clear', 'mixed', 'sync_prune', 'client_kill', 'deep_stockpile', 'reservation_churn', 'conflicted_take'
    #[arg(short, long, value_enum, default_value_t = BenchScenario::All)]
    scenario: BenchScenario,

    /// Number of simulated participants interacting with Redis (e.g. 12 matching devnet)
    #[arg(short, long, alias = "nodes", default_value_t = 12)]
    participants: usize,

    /// Number of items (triples/presignatures) per participant
    #[arg(short, long, default_value_t = 300)]
    items: usize,

    /// Connection pool max size constraint (default: 8; 0 for unbounded deadpool default)
    #[arg(long, default_value_t = 8)]
    pool_size: usize,

    /// Duration of periodic blocking spikes on Redis in milliseconds (default: 250ms)
    #[arg(long, default_value_t = 250)]
    spike_ms: u64,

    /// Simulated proposer deliberation hold time in milliseconds for Scenario 11 (default: 15ms)
    #[arg(long, default_value_t = 15)]
    deliberation_ms: u64,

    /// Total stockpile size for Scenario 10 Deep Stockpile Seek (default: max(items * 10, 2000))
    #[arg(long)]
    deep_stockpile: Option<usize>,

    /// Number of excluded IDs for Scenario 10 Deep Stockpile Seek (default: 85% of stockpile for near-exhaustion tail)
    #[arg(long)]
    deep_exclusions: Option<usize>,

    /// Number of seeks per worker in Scenario 10 Deep Stockpile Seek (default: 50)
    #[arg(long, default_value_t = 50)]
    deep_seeks: usize,

    /// Optional external Redis URL (e.g. redis://127.0.0.1:6379). If omitted, spawns an isolated Redis container.
    #[arg(long)]
    redis_url: Option<String>,

    /// Disable flushing Redis between scenarios (by default, FLUSHDB runs between scenarios for isolation).
    #[arg(long)]
    no_flush: bool,

    /// Optional output file path for exporting results as JSON
    #[arg(long)]
    json_out: Option<PathBuf>,

    /// Optional output file path for exporting results as CSV
    #[arg(long)]
    csv_out: Option<PathBuf>,

    /// Number of repeat runs to perform (default: 1)
    #[arg(long, default_value_t = 1)]
    repeats: usize,

    /// Number of storm/batch rounds for Scenarios 3, 6, and 8 (default: adaptive ceil(100 / participants), e.g. 9 for 12 nodes, 25 for 4 nodes)
    #[arg(long)]
    rounds: Option<usize>,

    /// Explicitly allow destructive operations (FLUSHDB, CLIENT KILL) against external --redis-url
    #[arg(long)]
    allow_destructive: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    integration_tests::utils::init_tracing_log();
    let args = Args::parse();

    if args.redis_url.is_some() && !args.allow_destructive {
        if !args.no_flush {
            anyhow::bail!(
                "Refusing to run default FLUSHDB against external --redis-url without --allow-destructive.\n\
                 Pass --allow-destructive to allow wiping keys, or pass --no-flush to disable FLUSHDB."
            );
        }
        if args.scenario == BenchScenario::All || args.scenario == BenchScenario::ClientKill {
            anyhow::bail!(
                "Refusing to run Scenario 9 (CLIENT KILL) against external --redis-url without --allow-destructive.\n\
                 Pass --allow-destructive to allow severing client connections, or specify a non-destructive scenario."
            );
        }
    }

    let should_flush = !args.no_flush;
    let effective_pool_size = if args.pool_size == 0 {
        None
    } else {
        Some(args.pool_size)
    };

    let adaptive_rounds = 100usize.div_ceil(args.participants.max(1));
    let storm_rounds = args.rounds.unwrap_or(adaptive_rounds).max(1);

    println!("\n=========================================================================");
    println!("     MPC REDIS BENCHMARK HARNESS - ISOLATED CONTAINER BASELINE SUITE     ");
    println!("=========================================================================");
    println!("  Simulated Participants: {}", args.participants);
    println!("  Items per Participant:  {}", args.items);
    println!(
        "  Batch Storm Rounds:     {} ({} total samples)",
        storm_rounds,
        storm_rounds * args.participants
    );
    println!(
        "  Target Redis:           {}",
        args.redis_url
            .as_deref()
            .unwrap_or("Ephemeral Docker Container (redis:7.4.2)")
    );
    println!(
        "  Architecture:           Pure Redis container (Zero nodes / NEAR / chain processes)"
    );
    println!("  Scenario:               {}", args.scenario);
    println!(
        "  Connection Pool Max:    {}",
        match effective_pool_size {
            Some(sz) => sz.to_string(),
            None => "Unbounded".to_string(),
        }
    );
    println!(
        "  Keyspace Isolation:     {}",
        if should_flush {
            "Isolated by default (FLUSHDB between scenarios)"
        } else {
            "Disabled (accumulating keys across scenarios)"
        }
    );
    println!("=========================================================================\n");

    println!("Initializing Redis benchmark harness...");
    let mut config = RedisHarnessConfig::new(args.participants)
        .with_pool_size(effective_pool_size)
        .with_flush_between(should_flush);
    if let Some(ref url) = args.redis_url {
        config = config.with_redis_url(url);
    }
    let harness = RedisHarness::new(config).await?;
    let pool_status = harness.pool.status();
    println!("Connected to Redis at: {}", harness.redis_url);
    println!("Connection pool ready: max_size={}", pool_status.max_size);

    #[derive(serde::Serialize)]
    struct BenchmarkRecord {
        iteration: usize,
        #[serde(flatten)]
        summary: LatencySummary,
    }

    let should_run = |s: BenchScenario| args.scenario == BenchScenario::All || args.scenario == s;
    let mut all_results: Vec<BenchmarkRecord> = Vec::new();

    for iteration in 1..=args.repeats {
        if args.repeats > 1 {
            println!(
                "\n========================================================================="
            );
            println!("               BENCHMARK ITERATION {iteration}/{}", args.repeats);
            println!(
                "=========================================================================\n"
            );
        }

        let mut record = |results: Vec<LatencySummary>| {
            for r in results {
                all_results.push(BenchmarkRecord {
                    iteration,
                    summary: r,
                });
            }
        };

        if should_run(BenchScenario::Baseline) {
            println!(
                "\n>>> Running Scenario 1: Concurrent Insert & Take ({} participants, {} items/participant)",
                args.participants, args.items
            );
            let results = harness.bench_concurrent_insert_and_take(args.items).await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::Polling) {
            println!("\n>>> Running Scenario 2: Stockpile 100ms Polling Contention Comparison");
            println!("    Phase A: Workload WITHOUT background polling...");
            let without_polling = harness
                .bench_polling_contention(args.items / 2, false)
                .await?;

            println!(
                "    Phase B: Workload WITH 100ms background polling (HLEN/SCARD across {} participants)...",
                args.participants
            );
            let with_polling = harness
                .bench_polling_contention(args.items / 2, true)
                .await?;

            println!("\n  Comparison (Without vs. With 100ms Polling Contention):");
            let mut combined = Vec::with_capacity(without_polling.len() + with_polling.len());
            combined.extend(without_polling.into_iter().map(|mut r| {
                r.op_name = format!("{}_no_poll", r.op_name);
                r
            }));
            combined.extend(with_polling.into_iter().map(|mut r| {
                r.op_name = format!("{}_with_poll", r.op_name);
                r
            }));
            harness.report_results(&combined).await?;
            record(combined);
        }

        if should_run(BenchScenario::Storm) {
            let stockpile = (args.items * 2).max(10);
            let prune = stockpile / 2;
            println!(
                "\n>>> Running Scenario 3: `remove_outdated` Pruning Storm ({storm_rounds} rounds, {} items total/round, {} pruned/round)",
                stockpile * args.participants,
                prune * args.participants
            );
            let results = harness
                .bench_remove_outdated_storm(stockpile, prune, storm_rounds)
                .await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::Proposer) {
            let initial_stockpile = args.items.max(50);
            let racers = 4;
            let per_racer = 50;
            println!(
                "\n>>> Running Scenario 4: Proposer Race (`peek_mine` + `commit`) - {racers} racers, {per_racer} proposals each"
            );
            let results = harness
                .bench_proposer_race(0, initial_stockpile, racers, per_racer)
                .await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::Saturation) {
            let tasks_per_p = 5;
            let items_per_task = (args.items / tasks_per_p).max(10);
            let spike_ms = args.spike_ms;
            println!("\n>>> Running Scenario 5: Cascading Saturation & Head-of-Line Blocking (50ms - 6s Grafana conditions)");
            println!(
                "    Simulating {} concurrent tasks across {} participants, 100ms background polling, and periodic {}ms Redis blocking spikes (insert + take)...",
                args.participants * tasks_per_p,
                args.participants,
                spike_ms
            );
            let results = harness
                .bench_cascading_saturation(tasks_per_p, items_per_task, spike_ms, 3)
                .await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::Clear) {
            let stockpile = args.items.max(100);
            println!(
                "\n>>> Running Scenario 6: Mass Epoch Resharing `clear()` Storm ({storm_rounds} rounds, {} participants, {} items/participant/round)",
                args.participants, stockpile
            );
            let results = harness.bench_clear_storm(stockpile, storm_rounds).await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::Mixed) {
            let items = (args.items / 3).max(50);
            println!("\n>>> Running Scenario 7: Realistic Mixed MPC Pipeline Contention (Triples + Presigs + Signers)");
            println!("    Running concurrent triple gen, presig gen, sign requests (takes), and 100ms polling on a shared connection pool...");
            let results = harness.bench_mixed_pipeline(items).await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::SyncPrune) {
            let items = args.items.max(100);
            println!(
                "\n>>> Running Scenario 8: State Sync Peer Drop & Pruning (`remove_holder_and_prune` - {storm_rounds} rounds, {items} items/participant/round)"
            );
            let results = harness.bench_sync_prune_storm(items, storm_rounds).await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::ClientKill) {
            let items = args.items.max(100);
            println!("\n>>> Running Scenario 9: Connection Drop & Reconnection Shock (`CLIENT KILL`)");
            let results = harness.bench_client_kill(items, 30).await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::DeepStockpile) {
            let stockpile = args
                .deep_stockpile
                .unwrap_or_else(|| (args.items * 10).max(100));
            let num_seekers = args.participants.clamp(2, 6);
            let exclusions = args
                .deep_exclusions
                .unwrap_or_else(|| (stockpile * 85) / 100);
            let seeks = args.deep_seeks;
            let coverage = (exclusions as f64 / stockpile as f64) * 100.0;
            println!(
                "\n>>> Running Scenario 10: Large Stockpile Deep-Seek (`peek_mine` with {exclusions} exclusions across {stockpile} items - {coverage:.1}% near-exhaustion tail)"
            );
            let results = harness
                .bench_deep_stockpile_seek(stockpile, num_seekers, exclusions, seeks)
                .await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::ReservationChurn) {
            let stockpile = (args.items * 2).max(50);
            let num_proposers = args.participants.clamp(2, 4);
            let rounds = 25;
            let abort_percent = 40;
            let deliberation_ms = args.deliberation_ms;
            println!(
                "\n>>> Running Scenario 11: Proposer Churn & Aborted Reservation Storm ({rounds} rounds, {abort_percent}% timeout/abort rate, {deliberation_ms}ms deliberation hold)"
            );
            let results = harness
                .bench_reservation_churn_abort(
                    stockpile,
                    num_proposers,
                    rounds,
                    abort_percent,
                    deliberation_ms,
                )
                .await?;
            harness.report_results(&results).await?;
            record(results);
        }

        if should_run(BenchScenario::ConflictedTake) {
            let items = (args.items / 5).max(10);
            let contenders = args.participants.clamp(2, 4);
            println!(
                "\n>>> Running Scenario 12: Conflicted Double-Take Race Storm ({items} items, {contenders} parallel contenders racing per item)"
            );
            let results = harness.bench_conflicted_take(items, contenders).await?;
            harness.report_results(&results).await?;
            record(results);
        }
    }

    if let Some(ref path) = args.json_out {
        let json = serde_json::to_string_pretty(&all_results)?;
        std::fs::write(path, json)?;
        println!(
            "\nExported {} benchmark records to JSON: {}",
            all_results.len(),
            path.display()
        );
    }

    if let Some(ref path) = args.csv_out {
        let mut csv = String::from(
            "iteration,operation,samples,failures,p50_ms,p90_ms,p95_ms,p99_ms,max_ms,attempts_ops_sec,goodput_ops_sec\n",
        );
        for rec in &all_results {
            let r = &rec.summary;
            let fmt_csv = |val: f64, min_samples: usize| -> String {
                if r.count < min_samples {
                    "n/a".to_string()
                } else {
                    format!("{:.2}", val)
                }
            };
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{:.1},{:.1}\n",
                rec.iteration,
                r.op_name,
                r.count,
                r.failures,
                fmt_csv(r.p50_ms, 1),
                fmt_csv(r.p90_ms, 10),
                fmt_csv(r.p95_ms, 20),
                fmt_csv(r.p99_ms, 20),
                fmt_csv(r.max_ms, 1),
                r.attempts_ops_sec,
                r.goodput_ops_sec
            ));
        }
        std::fs::write(path, csv)?;
        println!(
            "Exported {} benchmark records to CSV: {}",
            all_results.len(),
            path.display()
        );
    }

    println!("\n=========================================================================");
    println!("                       BENCHMARK RUN COMPLETE                            ");
    println!("=========================================================================\n");

    if should_flush {
        println!("Performing post-benchmark flush on Redis...");
        if let Err(e) = harness.flush_db().await {
            tracing::warn!("Failed to flush Redis after benchmark run: {e:#}");
        }
    }

    Ok(())
}
