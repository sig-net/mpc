use std::time::Duration;

use backon::ExponentialBuilder;

// Re-export the retry_rpc macro
pub use crate::retry_rpc;

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
