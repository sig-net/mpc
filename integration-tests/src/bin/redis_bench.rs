use clap::{Parser, ValueEnum};
use integration_tests::redis_harness::RedisHarness;

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

    /// Optional connection pool max size constraint (e.g. 8 to simulate production pool saturation)
    #[arg(long)]
    pool_size: Option<usize>,

    /// Duration of periodic blocking spikes on Redis in milliseconds (default: 250ms)
    #[arg(long, default_value_t = 250)]
    spike_ms: u64,

    /// Optional external Redis URL (e.g. redis://127.0.0.1:6379). If omitted, spawns an isolated Redis container.
    #[arg(long)]
    redis_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    integration_tests::utils::init_tracing_log();
    let args = Args::parse();

    println!("\n=========================================================================");
    println!("     MPC REDIS BENCHMARK HARNESS - ISOLATED CONTAINER BASELINE SUITE     ");
    println!("=========================================================================");
    println!("  Simulated Participants: {}", args.participants);
    println!("  Items per Participant:  {}", args.items);
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
    println!("=========================================================================\n");

    println!("Initializing Redis benchmark harness...");
    let harness = match &args.redis_url {
        Some(url) => RedisHarness::from_url(url, args.participants).await?,
        None => {
            RedisHarness::spawn_with_pool_config(
                args.participants,
                args.pool_size,
                Some(std::time::Duration::from_secs(5)),
            )
            .await?
        }
    };
    println!("Connected to Redis at: {}", harness.redis_url);

    let should_run = |s: BenchScenario| args.scenario == BenchScenario::All || args.scenario == s;

    if should_run(BenchScenario::Baseline) {
        println!(
            "\n>>> Running Scenario 1: Concurrent Insert & Take ({} participants, {} items/participant)",
            args.participants, args.items
        );
        let results = harness.bench_concurrent_insert_and_take(args.items).await?;
        harness.report_results(&results).await?;
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
    }

    if should_run(BenchScenario::Storm) {
        let stockpile = (args.items * 2).max(500);
        let prune = stockpile / 2;
        println!(
            "\n>>> Running Scenario 3: `remove_outdated` Pruning Storm ({} items total, {} pruned)",
            stockpile * args.participants,
            prune * args.participants
        );
        let results = harness
            .bench_remove_outdated_storm(stockpile, prune)
            .await?;
        harness.report_results(&results).await?;
    }

    if should_run(BenchScenario::Proposer) {
        let initial_stockpile = args.items.max(200);
        let racers = 4;
        let per_racer = 50;
        println!(
            "\n>>> Running Scenario 4: Proposer Race (`peek_mine` + `commit`) - {racers} racers, {per_racer} proposals each"
        );
        let results = harness
            .bench_proposer_race(0, initial_stockpile, racers, per_racer)
            .await?;
        harness.report_results(&results).await?;
    }

    if should_run(BenchScenario::Saturation) {
        let tasks_per_p = 5;
        let items_per_task = (args.items / tasks_per_p).max(10);
        let spike_ms = args.spike_ms;
        println!("\n>>> Running Scenario 5: Cascading Saturation & Head-of-Line Blocking (50ms - 6s Grafana conditions)");
        println!(
            "    Simulating {} concurrent tasks across {} participants, 100ms background polling, and periodic {}ms Redis blocking spikes...",
            args.participants * tasks_per_p,
            args.participants,
            spike_ms
        );
        let results = harness
            .bench_cascading_saturation(tasks_per_p, items_per_task, spike_ms, 3)
            .await?;
        harness.report_results(&results).await?;
    }

    if should_run(BenchScenario::Clear) {
        let stockpile = args.items.max(100);
        println!(
            "\n>>> Running Scenario 6: Mass Epoch Resharing `clear()` Storm ({} participants, {} items/participant)",
            args.participants, stockpile
        );
        let results = harness.bench_clear_storm(stockpile).await?;
        harness.report_results(&results).await?;
    }

    if should_run(BenchScenario::Mixed) {
        let items = (args.items / 3).max(50);
        println!("\n>>> Running Scenario 7: Realistic Mixed MPC Pipeline Contention (Triples + Presigs + Signers)");
        println!("    Running concurrent triple gen, presig gen, sign requests (takes), and 100ms polling on a shared connection pool...");
        let results = harness.bench_mixed_pipeline(items).await?;
        harness.report_results(&results).await?;
    }

    if should_run(BenchScenario::SyncPrune) {
        let items = args.items.max(100);
        println!(
            "\n>>> Running Scenario 8: State Sync Peer Drop & Pruning (`remove_holder_and_prune`)"
        );
        let results = harness.bench_sync_prune_storm(items).await?;
        harness.report_results(&results).await?;
    }

    if should_run(BenchScenario::ClientKill) {
        let items = args.items.max(100);
        println!("\n>>> Running Scenario 9: Connection Drop & Reconnection Shock (`CLIENT KILL`)");
        let results = harness.bench_client_kill(items, 30).await?;
        harness.report_results(&results).await?;
    }

    if should_run(BenchScenario::DeepStockpile) {
        let stockpile = (args.items * 5).max(1000);
        let num_seekers = args.participants.clamp(2, 6);
        let exclusions = 50;
        let seeks = 20;
        println!(
            "\n>>> Running Scenario 10: Large Stockpile Deep-Seek (`peek_mine` with {exclusions} exclusions across {stockpile} items)"
        );
        let results = harness
            .bench_deep_stockpile_seek(stockpile, num_seekers, exclusions, seeks)
            .await?;
        harness.report_results(&results).await?;
    }

    if should_run(BenchScenario::ReservationChurn) {
        let stockpile = (args.items * 2).max(300);
        let num_proposers = args.participants.clamp(2, 4);
        let rounds = 25;
        let abort_percent = 40;
        println!(
            "\n>>> Running Scenario 11: Proposer Churn & Aborted Reservation Storm ({rounds} rounds, {abort_percent}% timeout/abort rate)"
        );
        let results = harness
            .bench_reservation_churn_abort(stockpile, num_proposers, rounds, abort_percent)
            .await?;
        harness.report_results(&results).await?;
    }

    if should_run(BenchScenario::ConflictedTake) {
        let items = (args.items / 5).max(30);
        let contenders = args.participants.clamp(2, 4);
        println!(
            "\n>>> Running Scenario 12: Conflicted Double-Take Race Storm ({items} items, {contenders} parallel contenders racing per item)"
        );
        let results = harness.bench_conflicted_take(items, contenders).await?;
        harness.report_results(&results).await?;
    }

    println!("\n=========================================================================");
    println!("                       BENCHMARK RUN COMPLETE                            ");
    println!("=========================================================================\n");

    Ok(())
}
