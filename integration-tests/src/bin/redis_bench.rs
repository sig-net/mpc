use clap::Parser;
use integration_tests::redis_harness::{print_summary_header, RedisHarnessCluster};

#[derive(Parser, Debug)]
#[command(
    name = "redis-bench",
    about = "Redis Latency & Stress Benchmark Harness for Chain Signatures MPC Nodes"
)]
struct Args {
    /// Benchmark scenario to run: 'all', 'baseline', 'storm', 'polling', 'proposer'
    #[arg(short, long, default_value = "all")]
    scenario: String,

    /// Number of simulated MPC nodes interacting with Redis (e.g. 12 matching devnet)
    #[arg(short, long, default_value_t = 12)]
    nodes: usize,

    /// Number of items (triples/presignatures) per node
    #[arg(short, long, default_value_t = 300)]
    items: usize,

    /// Optional external Redis URL (e.g. redis://127.0.0.1:6379). If omitted, spawns a testcontainer.
    #[arg(long)]
    redis_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    integration_tests::utils::init_tracing_log();
    let args = Args::parse();

    println!("\n=========================================================================");
    println!("     MPC REDIS BENCHMARK HARNESS - BASELINE LATENCY & STRESS SUITE       ");
    println!("=========================================================================");
    println!("  Simulated Nodes:     {}", args.nodes);
    println!("  Items per Node:      {}", args.items);
    println!(
        "  Target Redis:        {}",
        args.redis_url
            .as_deref()
            .unwrap_or("Ephemeral Docker Container (redis:7.4.2)")
    );
    println!("  Scenario:            {}", args.scenario);
    println!("=========================================================================\n");

    println!("Initializing harness cluster...");
    let cluster = match &args.redis_url {
        Some(url) => RedisHarnessCluster::from_url(url, args.nodes).await?,
        None => RedisHarnessCluster::spawn(args.nodes).await?,
    };
    println!("Connected to Redis at: {}", cluster.redis_url);

    let run_all = args.scenario == "all";

    if run_all || args.scenario == "baseline" {
        println!("\n>>> Running Scenario 1: Concurrent Insert & Take ({} nodes, {} items/node)", args.nodes, args.items);
        let results = cluster.bench_concurrent_insert_and_take(args.items).await?;
        print_summary_header();
        for r in &results {
            r.print_row();
        }
        cluster.print_diagnostics().await?;
    }

    if run_all || args.scenario == "polling" {
        println!("\n>>> Running Scenario 2: Stockpile 100ms Polling Contention Comparison");
        println!("    Phase A: Workload WITHOUT background polling...");
        let without_polling = cluster.bench_polling_contention(args.items / 2, false).await?;

        println!("    Phase B: Workload WITH 100ms background polling (HLEN/SCARD across {} nodes)...", args.nodes);
        let with_polling = cluster.bench_polling_contention(args.items / 2, true).await?;

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
        cluster.print_diagnostics().await?;
    }

    if run_all || args.scenario == "storm" {
        let stockpile = (args.items * 2).max(500);
        let prune = stockpile / 2;
        println!("\n>>> Running Scenario 3: `remove_outdated` Pruning Storm ({} items total, {} pruned)", stockpile * args.nodes, prune * args.nodes);
        let result = cluster.bench_remove_outdated_storm(stockpile, prune).await?;
        print_summary_header();
        result.print_row();
        cluster.print_diagnostics().await?;
    }

    if run_all || args.scenario == "proposer" {
        let initial_stockpile = args.items.max(200);
        let racers = 4;
        let per_racer = 50;
        println!("\n>>> Running Scenario 4: Proposer Race (`peek_mine` + `commit`) - {} racers, {} proposals each", racers, per_racer);
        let results = cluster.bench_proposer_race(0, initial_stockpile, racers, per_racer).await?;
        print_summary_header();
        for r in &results {
            r.print_row();
        }
        cluster.print_diagnostics().await?;
    }

    println!("\n=========================================================================");
    println!("                       BENCHMARK RUN COMPLETE                            ");
    println!("=========================================================================\n");

    Ok(())
}
