// TODO: this should be moved somewhere so that it can be re-used by both indexer crates and the node crate

use std::time::Duration;

use backon::ExponentialBuilder;

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

/// Helper to identify whether an RPC error should be retried.
/// Protects against endlessly retrying terminal client errors (4xx).
pub fn is_retryable(e: &anyhow::Error) -> bool {
    let s = e.to_string();
    // 408 Request Timeout and 429 Too Many Requests are retryable.
    if s.contains("408") || s.contains("429") {
        return true;
    }
    // Other 4xx errors are generally client errors and should not be retried.
    if s.contains("400")
        || s.contains("401")
        || s.contains("403")
        || s.contains("404")
        || s.contains("405")
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
        use backon::Retryable;
        op.retry(&$strategy.build())
            // Retry only if the error is retryable (e.g., not a 4xx client error)
            .when(|e: &anyhow::Error| crate::util::retry::is_retryable(e))
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
        use backon::Retryable;
        op.retry(&$strategy.build())
            // Retry only if the error is retryable (e.g., not a 4xx client error)
            .when(|e: &anyhow::Error| crate::util::retry::is_retryable(e))
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

pub(crate) use retry_rpc;
