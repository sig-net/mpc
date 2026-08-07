pub use mpc_utils::retry::{is_rate_limited, is_retryable, RetryConfig, SharedBackoff};

// Re-export the retry macros so callers can import them from `utils::retry`.
pub use crate::{retry_rpc, retry_rpc_gated};

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
///     RPC_TIMEOUT,
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
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

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
}
