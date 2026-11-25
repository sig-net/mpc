use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use integration_tests::memory_harness::{
    print_memory_summary_header, print_memory_summary_row, MemoryHarness, MemoryHarnessConfig,
    MemorySummary,
};

#[cfg(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    not(target_arch = "wasm32")
))]
#[global_allocator]
static GLOBAL: mpc_node::alloc::Jemalloc = mpc_node::alloc::Jemalloc;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum MemoryBenchScenario {
    All,
    OrphanInbox,
    BurstPosit,
    GeneratorSurge,
}

impl std::fmt::Display for MemoryBenchScenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_possible_value().unwrap().get_name())
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "memory-bench",
    about = "MPC Node Memory Benchmark & Leak Detection Harness"
)]
struct Args {
    /// Benchmark scenario to execute.
    #[arg(short, long, value_enum, default_value_t = MemoryBenchScenario::All)]
    scenario: MemoryBenchScenario,

    /// Number of simulated MPC network participants (default: 8).
    #[arg(short, long, default_value_t = 8)]
    participants: usize,

    /// Threshold for agreement (default: 2/3 + 1).
    #[arg(short, long)]
    threshold: Option<usize>,

    /// Number of items/operations per batch.
    #[arg(short, long, default_value_t = 500)]
    items: usize,

    /// Number of burst posit messages for posit flooding scenario.
    #[arg(long, default_value_t = 5_000)]
    burst_posits: usize,

    /// Number of concurrent generator tasks for generator surge scenario.
    #[arg(long, default_value_t = 40)]
    surge_generators: usize,

    /// Payload size in bytes per protocol message in inbox scenarios.
    #[arg(long, default_value_t = 8192)]
    payload_bytes: usize,

    /// Post-teardown wait in milliseconds for allocator decay reclamation.
    #[arg(long, default_value_t = 1500)]
    decay_wait_ms: u64,

    /// High-water mark memory sample interval in milliseconds (default: 10ms).
    #[arg(long, default_value_t = 10)]
    sample_ms: u64,

    /// Maximum allowed memory leak/retained delta in Megabytes (default: 20MB).
    #[arg(long, default_value_t = 20)]
    max_leak_mb: u64,

    /// Number of times to repeat the benchmark scenario (default: 1).
    #[arg(long, default_value_t = 1)]
    repeats: usize,

    /// PRNG seed for reproducible scenario generation (default: 42).
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Print machine-readable JSON output.
    #[arg(long)]
    json: bool,

    /// Optional path to write JSON benchmark report to.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Optional path to write CSV benchmark metrics to.
    #[arg(long)]
    csv_out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut config = MemoryHarnessConfig::new(args.participants)
        .with_sample_interval(Duration::from_millis(args.sample_ms))
        .with_max_allowed_leak(args.max_leak_mb * 1024 * 1024)
        .with_items_per_batch(args.items)
        .with_posit_burst_count(args.burst_posits)
        .with_surge_generators(args.surge_generators)
        .with_payload_bytes(args.payload_bytes)
        .with_decay_wait(Duration::from_millis(args.decay_wait_ms))
        .with_seed(args.seed);

    if let Some(t) = args.threshold {
        config = config.with_threshold(t);
    }

    let allocator_name = if cfg!(all(
        feature = "jemalloc",
        not(target_env = "msvc"),
        not(target_arch = "wasm32")
    )) {
        "tikv-jemallocator (jemalloc)"
    } else {
        "system allocator (default)"
    };

    if !args.json {
        println!("==========================================================================================");
        println!("                         MPC NODE MEMORY BENCHMARK HARNESS                                ");
        println!("==========================================================================================");
        println!("Allocator:          {allocator_name}");
        #[cfg(all(
            feature = "jemalloc",
            not(target_env = "msvc"),
            not(target_arch = "wasm32")
        ))]
        {
            if let Ok((dirty, muzzy)) = mpc_node::alloc::query_decay_ms() {
                println!("Jemalloc Decay:     dirty_decay_ms={dirty}, muzzy_decay_ms={muzzy}");
            }
        }
        println!("Participants:       {}", config.num_participants);
        println!("Threshold:          {}", config.threshold);
        println!("Items / Batch:      {}", config.items_per_batch);
        println!("Payload Bytes:      {}", config.payload_bytes);
        println!("Posit Burst:        {}", config.posit_burst_count);
        println!("Surge Generators:   {}", config.surge_generators);
        println!("Decay Wait:         {:?}", config.decay_wait);
        println!("Sampling Interval:  {:?}", config.sample_interval);
        println!("Max Leak Allowed:   {} MB", args.max_leak_mb);
        println!("Repeats:            {}", args.repeats);
        println!("PRNG Seed:          {}", config.seed);
        println!("Scenario:           {}", args.scenario);
        println!("==========================================================================================\n");
    }

    let harness = MemoryHarness::new(config).await?;

    if !args.json {
        print_memory_summary_header();
    }

    let mut all_summaries: Vec<MemorySummary> = Vec::new();

    for rep in 0..args.repeats {
        let iteration = rep + 1;
        if !args.json && args.repeats > 1 {
            println!("--- Run {} of {} ---", iteration, args.repeats);
        }

        let run_summaries = match args.scenario {
            MemoryBenchScenario::All => harness.bench_all_iter(iteration, !args.json).await?,
            MemoryBenchScenario::OrphanInbox => {
                let s = harness
                    .bench_orphan_inbox_accumulation_iter(iteration)
                    .await?;
                if !args.json {
                    print_memory_summary_row(&s);
                }
                vec![s]
            }
            MemoryBenchScenario::BurstPosit => {
                let s = harness.bench_burst_posit_flood_iter(iteration).await?;
                if !args.json {
                    print_memory_summary_row(&s);
                }
                vec![s]
            }
            MemoryBenchScenario::GeneratorSurge => {
                let s = harness
                    .bench_generator_concurrency_surge_iter(iteration)
                    .await?;
                if !args.json {
                    print_memory_summary_row(&s);
                }
                vec![s]
            }
        };

        all_summaries.extend(run_summaries);
    }

    let json_str = serde_json::to_string_pretty(&all_summaries)?;

    if args.json {
        println!("{json_str}");
    }

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &json_str)?;
        if !args.json {
            println!("\nBenchmark results written to: {}", path.display());
        }
    }

    if let Some(path) = args.csv_out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut csv_content = MemorySummary::to_csv_header();
        for s in &all_summaries {
            csv_content.push_str(&s.to_csv_row());
        }
        std::fs::write(&path, csv_content)?;
        if !args.json {
            println!("CSV results written to: {}", path.display());
        }
    }

    let any_failed = all_summaries.iter().any(|s| !s.passed_leak_check);
    if any_failed {
        eprintln!(
            "\nERROR: One or more scenarios exceeded the maximum allowed memory leak threshold!"
        );
        anyhow::bail!("Memory benchmark leak check failed");
    }

    Ok(())
}
