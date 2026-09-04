use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Current time in seconds since the UNIX epoch.
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Elapsed time since the given unix timestamp (seconds) to now.
pub fn unix_elapsed(unix_timestamp: u64) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Duration::from_secs(now.saturating_sub(unix_timestamp))
}

/// Tracks a remaining time budget, useful for bounding an operation's duration.
pub struct TimeoutBudget {
    started: Instant,
    timeout: Duration,
}

impl TimeoutBudget {
    pub fn new(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    /// Returns the remaining time in the budget, or `Duration::ZERO` if exhausted.
    pub fn remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.started.elapsed())
    }

    /// Returns true if the budget is exhausted.
    /// Resets the budget with a new timeout.
    pub fn reset(&mut self, timeout: Duration) {
        self.started = Instant::now();
        self.timeout = timeout;
    }
}
