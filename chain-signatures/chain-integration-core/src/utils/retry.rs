use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use backon::ExponentialBuilder;
use rand::Rng;

use alloy::transports::{
    RpcError as AlloyRpcError, TransportError as AlloyTransportError, TransportErrorKind,
};
use http::StatusCode;

// Re-export the retry macros
pub use crate::{retry_op, retry_rpc};

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

/// Whether an HTTP status makes an RPC call worth retrying: 408/429 are
/// transient, 402 stays retryable (pairs with the cooldown gate — providers
/// refill credits on their own schedule), 5xx are the server's fault, and
/// everything else — other 4xx, but also redirects — is terminal. A redirect
/// loop never fixes itself by retrying, so it must not be retried to exhaustion.
pub fn http_status_retryable(status: StatusCode) -> bool {
    if matches!(
        status,
        StatusCode::PAYMENT_REQUIRED | StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
    ) {
        return true;
    }
    status.is_server_error()
}

/// Typed RPC failure chain for classifying errors in the retry logic.
// TODO: once every chain client attaches typed failures, the string-matching
// fallbacks in `is_retryable`/`is_provider_throttled` get deleted.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct RpcFailure {
    /// Human-readable error message.
    message: String,
    /// HTTP status code associated with the failure, if any.
    status: Option<StatusCode>,
    /// Whether this failure is considered terminal.
    terminal: bool,
}

impl RpcFailure {
    /// Constructs a new `RpcFailure` with the given HTTP status and message.
    /// The verdict is derived from the status via [`http_status_retryable`].
    pub fn with_status(status: StatusCode, message: String) -> Self {
        Self::with_verdict(status, !http_status_retryable(status), message)
    }

    /// Constructs a new `RpcFailure` with an explicit verdict, for cases where
    /// a chain error code overrules the status (e.g. a concurrent-submission
    /// 409 that is worth retrying). Throttle detection still reads the status.
    pub fn with_verdict(status: StatusCode, terminal: bool, message: String) -> Self {
        Self {
            message,
            status: Some(status),
            terminal,
        }
    }

    /// Constructs a new terminal `RpcFailure` with the given message.
    pub fn terminal(message: String) -> Self {
        Self {
            message,
            status: None,
            terminal: true,
        }
    }

    /// Constructs a new retryable `RpcFailure` with the given message.
    pub fn retryable(message: String) -> Self {
        Self {
            message,
            status: None,
            terminal: false,
        }
    }

    /// Returns the HTTP status code associated with this failure, if any.
    pub fn status(&self) -> Option<StatusCode> {
        self.status
    }
    /// Returns true if this failure is considered terminal.
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }
}

/// Typed signals from one walk of the anyhow chain: the first [`RpcFailure`]`/
/// its verdict, and the first typed HTTP status (on a [`RpcFailure`] or an
/// alloy transport error wrapping an HTTP response).
fn typed_signals(e: &anyhow::Error) -> (Option<&RpcFailure>, Option<StatusCode>) {
    e.chain().fold((None, None), |(failure, status), cause| {
        (
            failure.or_else(|| cause.downcast_ref::<RpcFailure>()),
            status.or_else(|| cause_status(cause)),
        )
    })
}

/// HTTP status carried by a single error cause, if any.
fn cause_status(cause: &(dyn std::error::Error + 'static)) -> Option<StatusCode> {
    if let Some(failure) = cause.downcast_ref::<RpcFailure>() {
        return failure.status;
    }
    let err = cause.downcast_ref::<AlloyTransportError>()?;
    let AlloyRpcError::Transport(TransportErrorKind::HttpError(http)) = err else {
        return None;
    };
    StatusCode::from_u16(http.status).ok()
}

/// Returns true if the error looks like the provider throttling us: HTTP 429
/// (rate limited) or 402 (payment required, e.g. exhausted credits).
fn is_provider_throttled(e: &anyhow::Error) -> bool {
    // Typed status is authoritative over body text (if present).
    if let Some(status) = typed_signals(e).1 {
        return status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::PAYMENT_REQUIRED;
    }
    // TODO: last-resort fallback for chains surfacing statuses only as text;
    // Delete once every chain client attaches typed statuses.
    // `{:#}` renders the full context chain — a 429 can sit under `with_context`
    let s = format!("{e:#}");
    contains_status_code(&s, "429") || contains_status_code(&s, "402")
}

/// Configuration for retrying RPC calls with exponential backoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        // alphanumeric boundaries: hex/base58 runs (…a429f…) must not read as status codes
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let after_ok = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();
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
    // Explicit typed verdict wins over any message text; otherwise the first
    // typed HTTP status decides.
    let (failure, status) = typed_signals(e);
    if let Some(f) = failure {
        return !f.terminal;
    }
    if let Some(status) = status {
        return http_status_retryable(status);
    }

    // TODO: last-resort fallback for chains surfacing statuses only as text;
    // Delete once every chain client attaches typed statuses.
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

/// Wraps an async call with a timeout and [`backon`] exponential-backoff retry strategy.
/// Use for retries that are not RPC-shaped (RPC calls should prefer [`retry_rpc!`],
/// which gates on the shared per-chain cooldown).
///
/// # Forms
///
/// ## 1. Standard — named operation, structured [`tracing::warn`] on every retry
/// ```ignore
/// retry_op!(timeout, strategy, "op_name", { code })
/// ```
///
/// ## 2. Full — named operation, custom notify closure
/// ```ignore
/// retry_op!(timeout, strategy, "op_name", |attempt, err, sleep| { notify }, { code })
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
/// let slot: u64 = retry_op!(SOL_RPC_TIMEOUT, self.retry_strategy, "get_slot", {
///     self.rpc_client.get_slot().await.map_err(anyhow::Error::from)
/// })?;
/// ```
///
/// ## Full form (custom retry logging)
/// ```ignore
/// let block = retry_op!(
///     RPC_TIMEOUT,
///     self.retry_strategy,
///     "get_block",
///     |attempt, err, sleep| {
///         tracing::error!(attempt, error = %format_args!("{err:#}"), retry_in = ?sleep, "get_block failed");
///     },
///     {
///         client.get_block(block_id).await
///     }
/// )?;
/// ```
#[macro_export]
macro_rules! retry_op {
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
                    error = %format_args!("{err:#}"),
                    retry_in = ?sleep,
                    "call failed, retrying"
                );
            })
            .await
            .map_err(|e| $crate::utils::retry::exhausted(e, attempt_counter + 1))
    }};

    // Full form: op_name string, custom notify closure
    ($timeout:expr, $strategy:expr, $op_name:literal, |$attempt:ident, $err:ident, $sleep:ident| $notify:block, { $($code:tt)* }) => {{
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
            .map_err(|e| $crate::utils::retry::exhausted(e, attempt_counter + 1))
    }};
}

/// Like [`retry_op!`], but gates every attempt on a shared cooldown
/// ([`SharedBackoff`]): each attempt waits out the global cooldown before
/// firing, a 429 or 402 extends the shared window, and a success resets the
/// penalty. Prevents retry storms when an endpoint starts rate-limiting or runs
/// out of credits. Per-call backoff still applies on top.
///
/// # Forms
///
/// ## 1. Standard — named operation, structured [`tracing::warn`] on every retry
/// ```ignore
/// retry_rpc!(timeout, strategy, shared, "op_name", { code })
/// ```
///
/// ## 2. Full — named operation, custom notify closure
/// ```ignore
/// retry_rpc!(timeout, strategy, shared, "op_name", |attempt, err, sleep| { notify }, { code })
/// ```
///
/// See [`retry_op!`] for the other parameters; `shared` is a [`SharedBackoff`]
/// handle cloned across all call sites hitting the same endpoint.
#[macro_export]
macro_rules! retry_rpc {
    // Standard form: op_name string, default structured logging
    ($timeout:expr, $strategy:expr, $shared:expr, $op_name:literal, { $($code:tt)* }) => {{
        let shared = &$shared;
        let mut attempt_counter: u32 = 0;
        let op = || async {
            $crate::utils::retry::run_gated(shared, $op_name, async {
                tokio::time::timeout($timeout, async { $($code)* })
                    .await
                    .map_err(|_| anyhow::anyhow!("Operation timed out after {:?}", $timeout))?
            })
            .await
        };
        use $crate::backon::Retryable as _;
        op.retry(&$strategy.build())
            .when(|e: &anyhow::Error| $crate::utils::retry::is_retryable(e))
            .notify(|err: &anyhow::Error, sleep: std::time::Duration| {
                attempt_counter += 1;
                tracing::warn!(
                    operation = $op_name,
                    attempt = attempt_counter,
                    error = %format_args!("{err:#}"),
                    retry_in = ?sleep,
                    "RPC call failed, retrying"
                );
            })
            .await
            .map_err(|e| $crate::utils::retry::exhausted(e, attempt_counter + 1))
    }};

    // Full form: op_name string, custom notify closure
    ($timeout:expr, $strategy:expr, $shared:expr, $op_name:literal, |$attempt:ident, $err:ident, $sleep:ident| $notify:block, { $($code:tt)* }) => {{
        let shared = &$shared;
        let mut attempt_counter: u32 = 0;
        let op = || async {
            $crate::utils::retry::run_gated(shared, $op_name, async {
                tokio::time::timeout($timeout, async { $($code)* })
                    .await
                    .map_err(|_| anyhow::anyhow!("Operation timed out after {:?}", $timeout))?
            })
            .await
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
            .map_err(|e| $crate::utils::retry::exhausted(e, attempt_counter + 1))
    }};
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

    #[test]
    fn detects_provider_throttling_errors() {
        assert!(is_provider_throttled(&anyhow::anyhow!(
            "HTTP status client error (429 Too Many Requests) for url (http://x/)"
        )));
        assert!(is_provider_throttled(&anyhow::anyhow!(
            "rpc: the server returned a non-OK (200) status code: [402 Payment Required]"
        )));
        // Port 42900 contains "429"; the 500 must not be mistaken for throttling.
        assert!(!is_provider_throttled(&anyhow::anyhow!(
            "HTTP status server error (500) for url (http://127.0.0.1:42900/)"
        )));
        assert!(!is_provider_throttled(&anyhow::anyhow!(
            "HTTP status client error (403 Forbidden)"
        )));
        // a 429 underneath `with_context` still engages (full chain scanned)
        assert!(is_provider_throttled(
            &anyhow::anyhow!(
                "HTTP status client error (429 Too Many Requests) for url (http://x/)"
            )
            .context("submitting the midnight respond intent built over the chain at 0x9c1f")
        ));
        // hex fragments must not read as throttles (alphanumeric boundaries)
        assert!(!is_provider_throttled(&anyhow::anyhow!(
            "submitting the midnight respond intent built over the chain at 0xa429f"
        )));
        assert!(!is_provider_throttled(&anyhow::anyhow!(
            "no spendable dust for transfer c402e5819d2b"
        )));
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
                let _: anyhow::Result<()> = retry_rpc!(
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
    async fn macro_engages_global_cooldown_on_402() {
        let shared =
            SharedBackoff::with_cooldowns(Duration::from_millis(50), Duration::from_millis(200));
        let _: anyhow::Result<()> = retry_rpc!(
            Duration::from_secs(5),
            RetryConfig {
                max_times: 0,
                ..gated_test_config()
            },
            shared,
            "test_op",
            {
                Err(anyhow::anyhow!(
                    "rpc: the server returned a non-OK (200) status code: [402 Payment Required]"
                ))
            }
        );
        assert!(shared.remaining() > Duration::ZERO);
    }

    #[tokio::test]
    async fn macro_reports_success_after_429() {
        let shared =
            SharedBackoff::with_cooldowns(Duration::from_millis(50), Duration::from_millis(200));
        let calls = Arc::new(AtomicU32::new(0));
        let attempts = calls.clone();
        let start = std::time::Instant::now();

        // The first attempt returns a 429, the second attempt succeeds.
        let res: anyhow::Result<u32> = retry_rpc!(
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

    #[test]
    fn http_status_retryable_table() {
        let status = |n: u16| StatusCode::from_u16(n).unwrap();
        // 402 pairs with the cooldown gate (credit refill), 408/429 are transient by definition
        for n in [402, 408, 429] {
            assert!(http_status_retryable(status(n)), "{n} should be retryable");
        }
        // every other 4xx is a client error another attempt cannot fix, and
        // redirects (a redirect loop cannot be retried out of) are terminal too
        for n in [400, 401, 403, 404, 405, 409, 410, 422, 499, 301, 308] {
            assert!(!http_status_retryable(status(n)), "{n} should be terminal");
        }
        // 5xx default to retryable
        for n in [500, 502, 503, 504, 599] {
            assert!(http_status_retryable(status(n)), "{n} should be retryable");
        }
    }

    #[test]
    fn rpc_failure_verdict_is_authoritative_over_message_text() {
        // with_status derives the verdict from the status, not the message
        let throttled: anyhow::Error = RpcFailure::with_status(
            StatusCode::TOO_MANY_REQUESTS,
            "nothing suspicious in this text".into(),
        )
        .into();
        assert!(is_retryable(&throttled));
        assert!(is_provider_throttled(&throttled));

        // 409 is terminal by status, even though the body text mentions 429
        let terminal: anyhow::Error = RpcFailure::with_status(
            StatusCode::CONFLICT,
            "conflict; body says 429 retry now".into(),
        )
        .into();
        assert!(!is_retryable(&terminal));
        assert!(!is_provider_throttled(&terminal));

        // status-less verdicts work in both directions
        let explicit_terminal: anyhow::Error =
            RpcFailure::terminal("already accepted".into()).into();
        assert!(!is_retryable(&explicit_terminal));
        let explicit_retryable: anyhow::Error =
            RpcFailure::retryable("transient downstream hiccup".into()).into();
        assert!(is_retryable(&explicit_retryable));
        // no status → no throttle signal
        assert!(!is_provider_throttled(&explicit_retryable));
    }

    #[test]
    fn rpc_failure_under_context_still_classifies() {
        // context wrappers must not hide the typed carrier
        let err = anyhow::Error::new(RpcFailure::with_status(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limited".into(),
        ))
        .context("submitting transaction");
        assert!(is_retryable(&err));
        assert!(is_provider_throttled(&err));
    }

    #[test]
    fn alloy_http_error_classifies_typed() {
        // simulate alloy HTTP errors and check their classification
        let alloy_http_error = |status: u16| {
            let kind = TransportErrorKind::HttpError(alloy::transports::HttpError {
                status,
                body: String::new(),
            });
            let err: AlloyTransportError = AlloyRpcError::Transport(kind);
            anyhow::Error::new(err)
        };
        assert!(is_retryable(&alloy_http_error(429)));
        assert!(is_provider_throttled(&alloy_http_error(429)));
        assert!(!is_retryable(&alloy_http_error(404)));
        assert!(!is_provider_throttled(&alloy_http_error(404)));
        // 409 arrives typed from alloy transports and classifies as terminal
        assert!(!is_retryable(&alloy_http_error(409)));
        // a synthetic invalid status cannot become a StatusCode, so the typed
        // path yields no status and the default (retryable) applies
        assert!(is_retryable(&alloy_http_error(0)));
    }
}
