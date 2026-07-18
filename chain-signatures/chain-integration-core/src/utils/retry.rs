use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use backon::ExponentialBuilder;
use rand::Rng;

// Re-export the retry macros
pub use crate::{retry_rpc, retry_rpc_gated};

const RATE_LIMIT_BASE_COOLDOWN: Duration = Duration::from_secs(1);
const RATE_LIMIT_MAX_COOLDOWN: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX_JITTER: Duration = Duration::from_millis(500);
const MAX_PENALTY_LEVEL: u32 = 10;

/// Shared, 429-aware cooldown gate.
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

    /// Extends the global cooldown window after an observed 429. Concurrent
    /// reports grow the penalty but only ever extend the window, never shorten
    /// it. Returns the cooldown that was applied.
    pub fn report_rate_limited(&self) -> Duration {
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

    /// Resets the penalty level after a successful call.
    pub fn report_success(&self) {
        self.inner.penalty_level.store(0, Ordering::Relaxed);
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Returns true if the error looks like an HTTP 429 (rate limited).
pub fn is_rate_limited(e: &anyhow::Error) -> bool {
    contains_status_code(&e.to_string(), "429")
}

/// Configuration for retrying RPC calls with exponential backoff.
#[derive(Clone, Copy)]
pub struct RetryConfig {
    pub min_delay: Duration,
    pub max_delay: Duration,
    pub max_times: usize,
    pub jitter: bool,
}

impl RetryConfig {
    /// Builds an [`ExponentialBuilder`] from this configuration.
    pub fn build(self) -> ExponentialBuilder {
        let mut b = ExponentialBuilder::default()
            .with_min_delay(self.min_delay)
            .with_max_delay(self.max_delay)
            .with_max_times(self.max_times);
        if self.jitter {
            b = b.with_jitter();
        }
        b
    }
}

/// Returns true if `s` contains `code` as a standalone number, i.e. not
/// embedded in a longer digit run. Prevents ports, slots, or request ids from
/// being mistaken for HTTP status codes (e.g. "127.0.0.1:40329" contains "403").
fn contains_status_code(s: &str, code: &str) -> bool {
    let bytes = s.as_bytes();
    let mut start = 0;
    while let Some(pos) = s[start..].find(code) {
        let i = start + pos;
        let end = i + code.len();
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
        let after_ok = end >= bytes.len() || !bytes[end].is_ascii_digit();
        if before_ok && after_ok {
            return true;
        }
        start = i + 1;
    }
    false
}

/// Helper to identify whether an RPC error should be retried.
/// Protects against endlessly retrying terminal client errors (4xx).
pub fn is_retryable(e: &anyhow::Error) -> bool {
    let s = e.to_string();
    // 408 Request Timeout and 429 Too Many Requests are retryable.
    if contains_status_code(&s, "408") || contains_status_code(&s, "429") {
        return true;
    }
    // Other 4xx errors are generally client errors and should not be retried.
    if contains_status_code(&s, "400")
        || contains_status_code(&s, "401")
        || contains_status_code(&s, "403")
        || contains_status_code(&s, "404")
        || contains_status_code(&s, "405")
    {
        return false;
    }
    true
}

/// Wraps an async RPC call with a timeout and [`backon`] exponential-backoff retry strategy.
///
/// # Forms
///
/// ## 1. Standard — named operation, structured [`tracing::warn`] on every retry
/// ```ignore
/// retry_rpc!(timeout, strategy, "op_name", { code })
/// ```
///
/// ## 2. Full — named operation, custom notify closure
/// ```ignore
/// retry_rpc!(timeout, strategy, "op_name", |attempt, err, sleep| { notify }, { code })
/// ```
///
/// # Parameters
///
/// | Parameter  | Type                  | Description                                              |
/// |------------|-----------------------|----------------------------------------------------------|
/// | `timeout`  | [`Duration`]          | Per-attempt deadline. Timeout counts as a retryable error|
/// | `strategy` | [`RetryConfig`]       | Retry policy |
/// | `op_name`  | `&str`                | Logged as `operation=` in tracing spans                  |
/// | `attempt`  | injected `u32`        | 1-indexed retry count, available inside `notify`         |
/// | `err`      | injected `&anyhow::Error` | The error that triggered this retry                  |
/// | `sleep`    | injected [`Duration`] | How long backon will sleep before the next attempt       |
/// | `code`     | `{ async block }`     | The fallible async operation. Must return `anyhow::Result<T>` |
///
/// # Return value
///
/// Returns `anyhow::Result<T>` — either the first successful value or the last
/// error after all retries are exhausted.
///
/// # Examples
///
/// ## Standard form (most common)
/// ```ignore
/// // Retries up to strategy.max_times, logs each failure via tracing::warn!
/// let slot: u64 = retry_rpc!(SOL_RPC_TIMEOUT, self.retry_strategy, "get_slot", {
///     self.rpc_client.get_slot().await.map_err(anyhow::Error::from)
/// })?;
/// ```
///
/// ## Full form (custom retry logging)
/// ```ignore
/// let block = retry_rpc!(
///     ETH_RPC_TIMEOUT,
///     self.retry_strategy,
///     "get_block",
///     |attempt, err, sleep| {
///         tracing::error!(attempt, error = %err, retry_in = ?sleep, "get_block failed");
///     },
///     {
///         client.get_block(block_id).await
///     }
/// )?;
/// ```
#[macro_export]
macro_rules! retry_rpc {
    // Standard form: op_name string, default structured logging
    ($timeout:expr, $strategy:expr, $op_name:literal, { $($code:tt)* }) => {{
        let mut attempt_counter: u32 = 0;
        let op = || async {
            let fut = async { $($code)* };
            match tokio::time::timeout($timeout, fut).await {
                Ok(Ok(res)) => Ok(res),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow::anyhow!("Operation timed out after {:?}", $timeout)),
            }
        };
        use $crate::backon::Retryable as _;
        op.retry(&$strategy.build())
            // Retry only if the error is retryable (e.g., not a 4xx client error)
            .when(|e: &anyhow::Error| $crate::utils::retry::is_retryable(e))
            // Log each retry attempt with structured tracing
            .notify(|err: &anyhow::Error, sleep: std::time::Duration| {
                attempt_counter += 1;
                tracing::warn!(
                    operation = $op_name,
                    attempt = attempt_counter,
                    error = %err,
                    retry_in = ?sleep,
                    "RPC call failed, retrying"
                );
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e} (exhausted after {} attempts)", attempt_counter + 1))
    }};

    // Full form: custom notify closure, no op_name
    ($timeout:expr, $strategy:expr, |$attempt:ident, $err:ident, $sleep:ident| $notify:block, { $($code:tt)* }) => {{
        let mut attempt_counter: u32 = 0;
        let op = || async {
            let fut = async { $($code)* };
            match tokio::time::timeout($timeout, fut).await {
                Ok(Ok(res)) => Ok(res),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow::anyhow!("Operation timed out after {:?}", $timeout)),
            }
        };
        use $crate::backon::Retryable as _;
        op.retry(&$strategy.build())
            // Retry only if the error is retryable (e.g., not a 4xx client error)
            .when(|e: &anyhow::Error| $crate::utils::retry::is_retryable(e))
            // Log each retry attempt with the user-provided notify closure
            .notify(|$err: &anyhow::Error, $sleep: std::time::Duration| {
                attempt_counter += 1;
                let $attempt = attempt_counter;
                $notify
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e} (exhausted after {} attempts)", attempt_counter + 1))
    }};
}

/// Like [`retry_rpc!`], but gates every attempt on a shared 429 cooldown
/// ([`SharedBackoff`]): each attempt waits out the global cooldown before
/// firing, a 429 extends the shared window, and a success resets the penalty.
/// Prevents retry storms when an endpoint starts rate-limiting. Per-call
/// backoff still applies on top.
///
/// # Forms
///
/// ## 1. Standard — named operation, structured [`tracing::warn`] on every retry
/// ```ignore
/// retry_rpc_gated!(timeout, strategy, shared, "op_name", { code })
/// ```
///
/// ## 2. Full — custom notify closure
/// ```ignore
/// retry_rpc_gated!(timeout, strategy, shared, |attempt, err, sleep| { notify }, { code })
/// ```
///
/// See [`retry_rpc!`] for the other parameters; `shared` is a [`SharedBackoff`]
/// handle cloned across all call sites hitting the same endpoint.
#[macro_export]
macro_rules! retry_rpc_gated {
    // Standard form: op_name string, default structured logging
    ($timeout:expr, $strategy:expr, $shared:expr, $op_name:literal, { $($code:tt)* }) => {{
        let shared = &$shared;
        let mut attempt_counter: u32 = 0;
        let op = || async {
            shared.wait().await;
            let fut = async { $($code)* };
            match tokio::time::timeout($timeout, fut).await {
                Ok(Ok(res)) => {
                    shared.report_success();
                    Ok(res)
                }
                Ok(Err(e)) => {
                    if $crate::utils::retry::is_rate_limited(&e) {
                        let cooldown = shared.report_rate_limited();
                        tracing::warn!(
                            operation = $op_name,
                            ?cooldown,
                            "rate limited (429), engaging global cooldown"
                        );
                    }
                    Err(e)
                }
                Err(_) => Err(anyhow::anyhow!("Operation timed out after {:?}", $timeout)),
            }
        };
        use $crate::backon::Retryable as _;
        op.retry(&$strategy.build())
            .when(|e: &anyhow::Error| $crate::utils::retry::is_retryable(e))
            .notify(|err: &anyhow::Error, sleep: std::time::Duration| {
                attempt_counter += 1;
                tracing::warn!(
                    operation = $op_name,
                    attempt = attempt_counter,
                    error = %err,
                    retry_in = ?sleep,
                    "RPC call failed, retrying"
                );
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e} (exhausted after {} attempts)", attempt_counter + 1))
    }};

    // Full form: custom notify closure
    ($timeout:expr, $strategy:expr, $shared:expr, |$attempt:ident, $err:ident, $sleep:ident| $notify:block, { $($code:tt)* }) => {{
        let shared = &$shared;
        let mut attempt_counter: u32 = 0;
        let op = || async {
            shared.wait().await;
            let fut = async { $($code)* };
            match tokio::time::timeout($timeout, fut).await {
                Ok(Ok(res)) => {
                    shared.report_success();
                    Ok(res)
                }
                Ok(Err(e)) => {
                    if $crate::utils::retry::is_rate_limited(&e) {
                        let cooldown = shared.report_rate_limited();
                        tracing::warn!(?cooldown, "rate limited (429), engaging global cooldown");
                    }
                    Err(e)
                }
                Err(_) => Err(anyhow::anyhow!("Operation timed out after {:?}", $timeout)),
            }
        };
        use $crate::backon::Retryable as _;
        op.retry(&$strategy.build())
            .when(|e: &anyhow::Error| $crate::utils::retry::is_retryable(e))
            .notify(|$err: &anyhow::Error, $sleep: std::time::Duration| {
                attempt_counter += 1;
                let $attempt = attempt_counter;
                $notify
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e} (exhausted after {} attempts)", attempt_counter + 1))
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_errors_are_not_retryable() {
        for code in ["400", "401", "403", "404", "405"] {
            let e = anyhow::anyhow!(
                "HTTP status client error ({code} Some Reason) for url (http://127.0.0.1:1234/)"
            );
            assert!(!is_retryable(&e), "{code} should not be retryable");
        }
    }

    #[test]
    fn shared_backoff_rate_limit_cooldown_grows_and_caps() {
        let sb =
            SharedBackoff::with_cooldowns(Duration::from_millis(100), Duration::from_millis(400));
        assert_eq!(sb.report_rate_limited(), Duration::from_millis(100));
        assert_eq!(sb.report_rate_limited(), Duration::from_millis(200));
        assert_eq!(sb.report_rate_limited(), Duration::from_millis(400));
        assert_eq!(sb.report_rate_limited(), Duration::from_millis(400));
    }

    #[test]
    fn shared_backoff_shorter_cooldown_does_not_shorten_window() {
        let sb = SharedBackoff::with_cooldowns(Duration::from_millis(100), Duration::from_secs(60));
        sb.report_rate_limited();
        let long = sb.report_rate_limited();
        sb.report_success();
        let short = sb.report_rate_limited();
        assert!(short < long);
        assert!(sb.remaining() > short);
    }

    #[test]
    fn shared_backoff_success_resets_penalty() {
        let sb = SharedBackoff::with_cooldowns(Duration::from_millis(100), Duration::from_secs(60));
        sb.report_rate_limited();
        sb.report_rate_limited();
        sb.report_success();
        assert_eq!(sb.report_rate_limited(), Duration::from_millis(100));
    }

    #[test]
    fn detects_rate_limit_errors() {
        assert!(is_rate_limited(&anyhow::anyhow!(
            "HTTP status client error (429 Too Many Requests) for url (http://x/)"
        )));
        // Port 42900 contains "429"; the 500 must not be mistaken for rate limiting.
        assert!(!is_rate_limited(&anyhow::anyhow!(
            "HTTP status server error (500) for url (http://127.0.0.1:42900/)"
        )));
        assert!(!is_rate_limited(&anyhow::anyhow!(
            "HTTP status client error (403 Forbidden)"
        )));
    }

    #[tokio::test]
    async fn wait_blocks_until_cooldown_elapses() {
        let sb = SharedBackoff::with_cooldowns(Duration::from_millis(80), Duration::from_secs(60));
        let t = std::time::Instant::now();
        sb.wait().await;
        assert!(t.elapsed() < Duration::from_millis(50));

        sb.report_rate_limited();
        let t = std::time::Instant::now();
        sb.wait().await;
        assert!(t.elapsed() >= Duration::from_millis(80));
    }

    fn gated_test_config() -> RetryConfig {
        RetryConfig {
            min_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            max_times: 2,
            jitter: false,
        }
    }

    #[tokio::test]
    async fn macro_engages_global_cooldown_on_429() {
        let shared =
            SharedBackoff::with_cooldowns(Duration::from_millis(50), Duration::from_millis(200));
        let calls = Arc::new(AtomicU32::new(0));
        let start = std::time::Instant::now();

        // Spawn two concurrent tasks that will each hit the 429 and trigger the shared cooldown.
        let mut handles = Vec::new();
        for _ in 0..2 {
            let shared = shared.clone();
            let calls = calls.clone();
            handles.push(tokio::spawn(async move {
                let attempts = calls.clone();
                let _: anyhow::Result<()> = retry_rpc_gated!(
                    Duration::from_secs(5),
                    gated_test_config(),
                    shared,
                    "test_op",
                    {
                        attempts.fetch_add(1, Ordering::Relaxed);
                        Err(anyhow::anyhow!(
                            "HTTP status client error (429 Too Many Requests)"
                        ))
                    }
                );
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // (1 initial + max_times retries) per op
        assert_eq!(calls.load(Ordering::Relaxed), 6); 
        // Without the gate, 6 calls with 1-5ms backoff finish in ~20ms.
        assert!(start.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn macro_reports_success_after_429() {
        let shared =
            SharedBackoff::with_cooldowns(Duration::from_millis(50), Duration::from_millis(200));
        let calls = Arc::new(AtomicU32::new(0));
        let attempts = calls.clone();
        let start = std::time::Instant::now();

        // The first attempt returns a 429, the second attempt succeeds.
        let res: anyhow::Result<u32> = retry_rpc_gated!(
            Duration::from_secs(5),
            gated_test_config(),
            shared,
            "test_op",
            {
                if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    Err(anyhow::anyhow!(
                        "HTTP status client error (429 Too Many Requests)"
                    ))
                } else {
                    Ok(42)
                }
            }
        );
        assert_eq!(res.unwrap(), 42);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        // The retry had to wait out the cooldown window set by the first attempt.
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn retryable_errors() {
        for msg in [
            // Regression: port 40329 contains "403"; the 500 must still be retried.
            "HTTP status server error (500 Internal Server Error) for url (http://127.0.0.1:40329/)",
            // Digits embedded in longer numbers (ports, slots) are not status codes.
            "server error (500) for url (http://host:14290/)",
            "error at slot 14005",
            // 408/429 are explicitly retryable.
            "HTTP status client error (408 Request Timeout)",
            "HTTP status client error (429 Too Many Requests)",
        ] {
            assert!(is_retryable(&anyhow::anyhow!(msg)), "{msg:?} should be retryable");
        }
    }
}
