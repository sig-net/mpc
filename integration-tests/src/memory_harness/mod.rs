pub mod config;
pub mod diagnostics;
pub mod gate;
pub mod participant;
pub mod scenarios;

use anyhow::Context as _;

pub use config::MemoryHarnessConfig;
pub use diagnostics::{
    format_bytes, print_memory_summary_header, print_memory_summary_row, HighWaterMarkTracker,
    MemorySnapshot, MemorySummary,
};
pub use gate::StartingGate;
pub use participant::SimulatedParticipant;
pub use scenarios::MemoryScenarios;

/// Memory Benchmark Harness for measuring MPC node memory footprint and leak vectors.
pub struct MemoryHarness {
    pub config: MemoryHarnessConfig,
    pub participants: Vec<SimulatedParticipant>,
    pub baseline_rss: u64,
}

impl MemoryHarness {
    /// Initialize the memory benchmark harness from a configuration.
    pub async fn new(config: MemoryHarnessConfig) -> anyhow::Result<Self> {
        config.validate()?;

        let mut participants = Vec::with_capacity(config.num_participants);
        for i in 0..config.num_participants {
            let idx = u32::try_from(i).context("participant index exceeds u32::MAX")?;
            participants.push(SimulatedParticipant::try_new(idx)?);
        }

        let baseline_rss = MemorySnapshot::current().rss_bytes;

        Ok(Self {
            config,
            participants,
            baseline_rss,
        })
    }

    /// Scenario 1: Orphan Inbox Subscriber Channel Accumulation
    pub async fn bench_orphan_inbox_accumulation(&self) -> anyhow::Result<MemorySummary> {
        self.bench_orphan_inbox_accumulation_iter(1).await
    }

    pub async fn bench_orphan_inbox_accumulation_iter(
        &self,
        iteration: usize,
    ) -> anyhow::Result<MemorySummary> {
        MemoryScenarios::bench_orphan_inbox_accumulation(
            &self.config,
            &self.participants,
            iteration,
            self.baseline_rss,
        )
        .await
    }

    /// Scenario 2: Burst Posit Queue Flood
    pub async fn bench_burst_posit_flood(&self) -> anyhow::Result<MemorySummary> {
        self.bench_burst_posit_flood_iter(1).await
    }

    pub async fn bench_burst_posit_flood_iter(
        &self,
        iteration: usize,
    ) -> anyhow::Result<MemorySummary> {
        MemoryScenarios::bench_burst_posit_flood(
            &self.config,
            &self.participants,
            iteration,
            self.baseline_rss,
        )
        .await
    }

    /// Scenario 3: Generator Concurrency Surge
    pub async fn bench_generator_concurrency_surge(&self) -> anyhow::Result<MemorySummary> {
        self.bench_generator_concurrency_surge_iter(1).await
    }

    pub async fn bench_generator_concurrency_surge_iter(
        &self,
        iteration: usize,
    ) -> anyhow::Result<MemorySummary> {
        MemoryScenarios::bench_generator_concurrency_surge(
            &self.config,
            &self.participants,
            iteration,
            self.baseline_rss,
        )
        .await
    }

    /// Run all 3 in-process benchmark scenarios and return their memory summaries.
    pub async fn bench_all(&self, verbose: bool) -> anyhow::Result<Vec<MemorySummary>> {
        self.bench_all_iter(1, verbose).await
    }

    /// Run all 3 in-process benchmark scenarios for a specific iteration.
    pub async fn bench_all_iter(
        &self,
        iteration: usize,
        verbose: bool,
    ) -> anyhow::Result<Vec<MemorySummary>> {
        let mut summaries = Vec::new();

        if verbose {
            println!("\n>>> Running Scenario 1: Orphan Inbox Channel Accumulation (iteration {iteration})...");
        }
        let s1 = self.bench_orphan_inbox_accumulation_iter(iteration).await?;
        if verbose {
            print_memory_summary_row(&s1);
        }
        summaries.push(s1);

        if verbose {
            println!(">>> Running Scenario 2: Burst Posit Queue Flood (iteration {iteration})...");
        }
        let s2 = self.bench_burst_posit_flood_iter(iteration).await?;
        if verbose {
            print_memory_summary_row(&s2);
        }
        summaries.push(s2);

        if verbose {
            println!(
                ">>> Running Scenario 3: Generator Concurrency Surge (iteration {iteration})..."
            );
        }
        let s3 = self
            .bench_generator_concurrency_surge_iter(iteration)
            .await?;
        if verbose {
            print_memory_summary_row(&s3);
        }
        summaries.push(s3);

        Ok(summaries)
    }
}
