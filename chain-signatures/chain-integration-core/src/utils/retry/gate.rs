use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;

use super::classify::is_provider_throttled;

const RATE_LIMIT_BASE_COOLDOWN: Duration = Duration::from_secs(1);
const RATE_LIMIT_MAX_COOLDOWN: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX_JITTER: Duration = Duration::from_millis(500);
const MAX_PENALTY_LEVEL: u32 = 10;

/// Shared cooldown gate: callers wait out a window that failures extend.
#[derive(Clone)]
pub struct SharedBackoff {
    /// Inner state is shared across all clones of this instance to avoid per-instance fragmentation
    inner: Arc<SharedBackoffInner>,
}

struct SharedBackoffInner {
    /// Epoch millis until which all requests should wait.
    limited_until_ms: AtomicU64,
    /// Exponential penalty level, used to compute the cooldown duration.
    penalty_level: AtomicU32,
    /// Base cooldown duration for the first penalty level.
    base_cooldown: Duration,
    /// Maximum cooldown duration for the highest penalty level.
    max_cooldown: Duration,
}

impl Default for SharedBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedBackoff {
    pub fn new() -> Self {
        Self::with_cooldowns(RATE_LIMIT_BASE_COOLDOWN, RATE_LIMIT_MAX_COOLDOWN)
    }

    pub fn with_cooldowns(base_cooldown: Duration, max_cooldown: Duration) -> Self {
        Self {
            inner: Arc::new(SharedBackoffInner {
                limited_until_ms: AtomicU64::new(0),
                penalty_level: AtomicU32::new(0),
                base_cooldown,
                max_cooldown,
            }),
        }
    }

    /// Extends the global cooldown window after a failure callers should back
    /// off from (e.g. a 429). Concurrent reports grow the penalty but only ever
    /// extend the window, never shorten it. Returns the cooldown that was applied.
    pub fn extend_cooldown(&self) -> Duration {
        let level = self.inner.penalty_level.fetch_add(1, Ordering::Relaxed);
        self.inner
            .penalty_level
            .fetch_min(MAX_PENALTY_LEVEL, Ordering::Relaxed);
        let cooldown = self.cooldown_for_level(level);
        self.inner
            .limited_until_ms
            .fetch_max(now_ms() + cooldown.as_millis() as u64, Ordering::Relaxed);
        cooldown
    }

    /// Resets the penalty level once the cooldown window has fully elapsed
    pub fn report_success(&self) {
        if self.remaining() > Duration::ZERO {
            return;
        }
        self.inner.penalty_level.store(0, Ordering::Relaxed);
    }

    /// Extends the cooldown if `err` looks like provider throttling (429/402).
    /// Returns the applied cooldown, or `None` when the error is not a
    /// throttle
    pub fn engage_if_throttled(&self, err: &anyhow::Error) -> Option<Duration> {
        is_provider_throttled(err).then(|| self.extend_cooldown())
    }

    /// Sleeps until the global cooldown window has elapsed, plus random jitter
    /// so callers parked on the same window don't all fire at once.
    pub async fn wait(&self) {
        let remaining = self.remaining();
        if remaining.is_zero() {
            return;
        }
        let jitter_cap = (remaining / 2).min(RATE_LIMIT_MAX_JITTER);
        let jitter = rand::thread_rng().gen_range(Duration::ZERO..=jitter_cap);
        tokio::time::sleep(remaining + jitter).await;
    }

    /// Time left in the current cooldown window, zero if not limited.
    pub fn remaining(&self) -> Duration {
        let ms = self
            .inner
            .limited_until_ms
            .load(Ordering::Relaxed)
            .saturating_sub(now_ms());
        Duration::from_millis(ms)
    }

    fn cooldown_for_level(&self, level: u32) -> Duration {
        let millis = (self.inner.base_cooldown.as_millis() as u64)
            .saturating_mul(1u64 << level.min(MAX_PENALTY_LEVEL));
        Duration::from_millis(millis).min(self.inner.max_cooldown)
    }
}

/// Runs a single call under `gate`: waits out any engaged cooldown, resets the
/// penalty level on success, and extends the window when the error looks like
/// provider throttling (429/402). Single attempt — the caller owns retries.
pub async fn run_gated<T, F>(
    gate: &SharedBackoff,
    operation: &'static str,
    call: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    gate.wait().await;
    match call.await {
        Ok(value) => {
            gate.report_success();
            Ok(value)
        }
        Err(err) => {
            if let Some(cooldown) = gate.engage_if_throttled(&err) {
                tracing::warn!(
                    operation,
                    error = %format_args!("{err:#}"),
                    ?cooldown,
                    "provider throttled (429/402), engaging shared cooldown"
                );
            }
            Err(err)
        }
    }
}

/// Attaches the exhaustion context to a failed retry chain without
/// re-stringifying the error, so typed causes survive for outer gates.
#[doc(hidden)]
pub fn exhausted(e: anyhow::Error, attempts: u32) -> anyhow::Error {
    e.context(format!("exhausted after {} attempts", attempts))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_success_keeps_escalation_while_window_active() {
        let gate = SharedBackoff::with_cooldowns(Duration::from_secs(1), Duration::from_secs(60));
        let base = gate.extend_cooldown();

        gate.report_success();

        // a success landing inside the active window must not de-escalate
        assert_eq!(
            gate.extend_cooldown(),
            base * 2,
            "success during an active window must keep the penalty level"
        );
    }

    #[test]
    fn report_success_resets_escalation_after_window_elapses() {
        let gate = SharedBackoff::with_cooldowns(Duration::from_secs(1), Duration::from_secs(60));
        let base = gate.extend_cooldown();
        gate.extend_cooldown();

        // simulate the window having elapsed
        gate.inner.limited_until_ms.store(0, Ordering::Relaxed);
        gate.report_success();

        assert_eq!(
            gate.extend_cooldown(),
            base,
            "success after the window elapsed must reset escalation"
        );
    }

    #[test]
    fn shared_backoff_rate_limit_cooldown_grows_and_caps() {
        let sb =
            SharedBackoff::with_cooldowns(Duration::from_millis(100), Duration::from_millis(400));
        assert_eq!(sb.extend_cooldown(), Duration::from_millis(100));
        assert_eq!(sb.extend_cooldown(), Duration::from_millis(200));
        assert_eq!(sb.extend_cooldown(), Duration::from_millis(400));
        assert_eq!(sb.extend_cooldown(), Duration::from_millis(400));
    }

    #[test]
    fn shared_backoff_shorter_cooldown_does_not_shorten_window() {
        let sb = SharedBackoff::with_cooldowns(Duration::from_millis(100), Duration::from_secs(60));
        sb.extend_cooldown();
        let long = sb.extend_cooldown();
        // simulate the level having been reset
        sb.inner.penalty_level.store(0, Ordering::Relaxed);
        let short = sb.extend_cooldown();
        assert!(short < long);
        assert!(sb.remaining() > short);
    }

    #[tokio::test]
    async fn wait_blocks_until_cooldown_elapses() {
        let sb = SharedBackoff::with_cooldowns(Duration::from_millis(80), Duration::from_secs(60));
        let t = std::time::Instant::now();
        sb.wait().await;
        assert!(t.elapsed() < Duration::from_millis(50));

        sb.extend_cooldown();
        let t = std::time::Instant::now();
        sb.wait().await;
        assert!(t.elapsed() >= Duration::from_millis(80));
    }
}
