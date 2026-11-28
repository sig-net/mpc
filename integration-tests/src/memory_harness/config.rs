use std::time::Duration;

#[derive(Clone, Debug)]
pub struct MemoryHarnessConfig {
    /// Number of simulated network participants.
    pub num_participants: usize,
    /// Threshold of participants needed for agreement.
    pub threshold: usize,
    /// Sampling interval for background high-water mark memory tracking.
    pub sample_interval: Duration,
    /// Maximum allowed memory growth/leak for leak detection assertions (in bytes).
    pub max_allowed_leak_bytes: u64,
    /// Number of items/operations per scenario batch.
    pub items_per_batch: usize,
    /// Number of burst posit messages for posit flooding scenario.
    pub posit_burst_count: usize,
    /// Number of concurrent generator tasks to trigger in generator surge scenario.
    pub surge_generators: usize,
    /// Payload size in bytes per protocol message in inbox scenarios.
    pub payload_bytes: usize,
    /// Duration to wait after teardown so allocator decay can reclaim dirty pages.
    pub decay_wait: Duration,
    /// Deterministic PRNG seed for reproducible scenario runs.
    pub seed: u64,
}

impl Default for MemoryHarnessConfig {
    fn default() -> Self {
        Self::new(8)
    }
}

impl MemoryHarnessConfig {
    pub fn new(num_participants: usize) -> Self {
        let threshold = if num_participants < 2 {
            1
        } else {
            (num_participants * 2) / 3 + 1
        };
        Self {
            num_participants,
            threshold,
            sample_interval: Duration::from_millis(10),
            max_allowed_leak_bytes: 20 * 1024 * 1024, // 20 MB default threshold
            items_per_batch: 500,
            posit_burst_count: 5_000,
            surge_generators: 40,
            payload_bytes: 8192,
            decay_wait: Duration::from_millis(1500),
            seed: 42,
        }
    }

    /// Validate the harness configuration parameters.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.num_participants >= 2,
            "benchmark requires at least 2 participants (got {})",
            self.num_participants
        );
        anyhow::ensure!(
            self.threshold >= 1,
            "threshold must be at least 1 (got {})",
            self.threshold
        );
        anyhow::ensure!(
            self.threshold <= self.num_participants,
            "threshold ({}) cannot exceed number of participants ({})",
            self.threshold,
            self.num_participants
        );
        anyhow::ensure!(
            self.items_per_batch > 0 && self.items_per_batch <= 500_000,
            "items_per_batch ({}) must be between 1 and 500,000 to ensure ID stride isolation",
            self.items_per_batch
        );
        anyhow::ensure!(
            self.posit_burst_count > 0 && self.posit_burst_count <= 500_000,
            "posit_burst_count ({}) must be between 1 and 500,000 to ensure ID stride isolation",
            self.posit_burst_count
        );
        anyhow::ensure!(
            self.surge_generators > 0,
            "surge_generators must be greater than 0"
        );
        anyhow::ensure!(
            self.payload_bytes > 0,
            "payload_bytes must be greater than 0"
        );
        anyhow::ensure!(
            !self.sample_interval.is_zero(),
            "sample_interval cannot be zero"
        );
        Ok(())
    }

    pub fn with_threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    pub fn with_sample_interval(mut self, interval: Duration) -> Self {
        self.sample_interval = interval;
        self
    }

    pub fn with_max_allowed_leak(mut self, bytes: u64) -> Self {
        self.max_allowed_leak_bytes = bytes;
        self
    }

    pub fn with_items_per_batch(mut self, items: usize) -> Self {
        self.items_per_batch = items;
        self
    }

    pub fn with_posit_burst_count(mut self, count: usize) -> Self {
        self.posit_burst_count = count;
        self
    }

    pub fn with_surge_generators(mut self, count: usize) -> Self {
        self.surge_generators = count;
        self
    }

    pub fn with_payload_bytes(mut self, bytes: usize) -> Self {
        self.payload_bytes = bytes;
        self
    }

    pub fn with_decay_wait(mut self, wait: Duration) -> Self {
        self.decay_wait = wait;
        self
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }
}
