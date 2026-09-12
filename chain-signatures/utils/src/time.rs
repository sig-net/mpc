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

/// Elapsed time since the given unix timestamp, or `None` when that timestamp
/// is in the future.
///
/// Unlike [`unix_elapsed`], which saturates a future timestamp to zero, this
/// keeps "no time has passed" distinguishable from "this timestamp cannot be
/// measured against our clock". Timestamps that travel between nodes inside
/// checkpoints carry the originating node's clock, so skew can put one ahead of
/// ours; observing that as zero would land in the bottom histogram bucket and
/// bias the metric invisibly, whereas skipping it shows up honestly as a lower
/// sample count.
pub fn unix_elapsed_checked(unix_timestamp: u64) -> Option<Duration> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.checked_sub(unix_timestamp).map(Duration::from_secs)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A future timestamp must be unmeasurable rather than zero: `unix_elapsed`
    /// saturates, which is what makes a skewed peer's timestamp look like an
    /// instantaneous round trip.
    #[test]
    fn unix_elapsed_checked_rejects_future_timestamps() {
        let now = current_unix_timestamp();

        assert_eq!(unix_elapsed_checked(now + 60), None);
        assert_eq!(unix_elapsed(now + 60), Duration::ZERO);

        assert_eq!(unix_elapsed_checked(now), Some(Duration::ZERO));
        assert!(unix_elapsed_checked(now - 5) >= Some(Duration::from_secs(5)));
    }
}
