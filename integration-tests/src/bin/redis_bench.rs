use clap::Parser;
use integration_tests::redis_harness::{print_summary_header, RedisHarness};

#[derive(Parser, Debug)]
#[command(
    name = "redis-bench",
    about = "Redis Latency & Stress Benchmark Harness (Pure Redis Container - No MPC Nodes, NEAR, or Blockchains)"
)]
struct Args {
    /// Benchmark scenario to run: 'all', 'baseline', 'storm', 'polling', 'proposer', 'saturation'
    #[arg(short, long, default_value = "all")]
    scenario: String,

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
    println!("  Architecture:           Pure Redis container (Zero nodes / NEAR / chain processes)");
    println!("  Scenario:               {}", args.scenario);
    println!("=========================================================================\n");

    println!("Initializing Redis benchmark harness...");
    let harness = match &args.redis_url {
        Some(url) => RedisHarness::from_url(url, args.participants).await?,
        None => RedisHarness::spawn_with_pool_config(
            args.participants,
            args.pool_size,
            Some(std::time::Duration::from_secs(5)),
        ).await?,
    };
    println!("Connected to Redis at: {}", harness.redis_url);

    let run_all = args.scenario == "all";

    if run_all || args.scenario == "baseline" {
        println!("\n>>> Running Scenario 1: Concurrent Insert & Take ({} participants, {} items/participant)", args.participants, args.items);
        let results = harness.bench_concurrent_insert_and_take(args.items).await?;
        print_summary_header();
        for r in &results {
            r.print_row();
        }
        harness.print_diagnostics().await?;
    }

    if run_all || args.scenario == "polling" {
        println!("\n>>> Running Scenario 2: Stockpile 100ms Polling Contention Comparison");
        println!("    Phase A: Workload WITHOUT background polling...");
        let without_polling = harness.bench_polling_contention(args.items / 2, false).await?;

        println!("    Phase B: Workload WITH 100ms background polling (HLEN/SCARD across {} participants)...", args.participants);
        let with_polling = harness.bench_polling_contention(args.items / 2, true).await?;

        println!("\n  Comparison (Without vs. With 100ms Polling Contention):");
        print_summary_header();
        for mut r in without_polling {
            r.op_name = format!("{}_no_poll", r.op_name);
            r.print_row();
        }
        for mut r in with_polling {
            r.op_name = format!("{}_with_poll", r.op_name);
            r.print_row();
        }
        harness.print_diagnostics().await?;
    }

    if run_all || args.scenario == "storm" {
        let stockpile = (args.items * 2).max(500);
        let prune = stockpile / 2;
        println!("\n>>> Running Scenario 3: `remove_outdated` Pruning Storm ({} items total, {} pruned)", stockpile * args.participants, prune * args.participants);
        let result = harness.bench_remove_outdated_storm(stockpile, prune).await?;
        print_summary_header();
        result.print_row();
        harness.print_diagnostics().await?;
    }

    if run_all || args.scenario == "proposer" {
        let initial_stockpile = args.items.max(200);
        let racers = 4;
        let per_racer = 50;
        println!("\n>>> Running Scenario 4: Proposer Race (`peek_mine` + `commit`) - {} racers, {} proposals each", racers, per_racer);
        let results = harness.bench_proposer_race(0, initial_stockpile, racers, per_racer).await?;
        print_summary_header();
        for r in &results {
            r.print_row();
        }
        harness.print_diagnostics().await?;
    }

    if run_all || args.scenario == "saturation" {
        let tasks_per_p = 5;
        let items_per_task = (args.items / tasks_per_p).max(10);
        let spike_ms = args.spike_ms;
        println!("\n>>> Running Scenario 5: Cascading Saturation & Head-of-Line Blocking (50ms - 6s Grafana conditions)");
        println!("    Simulating {} concurrent tasks across {} participants, 100ms background polling, and periodic {}ms Redis blocking spikes...", args.participants * tasks_per_p, args.participants, spike_ms);
        let results = harness.bench_cascading_saturation(tasks_per_p, items_per_task, spike_ms, 3).await?;
        print_summary_header();
        for r in &results {
            r.print_row();
        }
        harness.print_diagnostics().await?;
    }

    println!("\n=========================================================================");
    println!("                       BENCHMARK RUN COMPLETE                            ");
    println!("=========================================================================\n");

    Ok(())
}
