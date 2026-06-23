use backon::ExponentialBuilder;

/// Configuration for retrying RPC calls with exponential backoff.
#[derive(Clone, Copy)]
pub struct RetryConfig {
    min_delay: Duration,
    max_delay: Duration,
    max_times: usize,
    jitter: bool,
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

/// Wraps an async RPC call with a timeout and [`backon`] exponential-backoff retry strategy.
///
/// # Forms
///
/// ## 1. Bare — no operation name, silent on retry
/// ```ignore
/// retry_rpc!(timeout, strategy, { code })
/// ```
///
/// ## 2. Standard — named operation, structured [`tracing::warn`] on every retry
/// ```ignore
/// retry_rpc!(timeout, strategy, "op_name", { code })
/// ```
///
/// ## 3. Full — named operation, custom notify closure
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
/// ## Bare form (fire-and-forget, no logging)
/// ```ignore
/// let slot: u64 = retry_rpc!(SOL_RPC_TIMEOUT, self.retry_strategy, {
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
    // Bare form: no op_name
    ($timeout:expr, $strategy:expr, { $($code:tt)* }) => {
        $crate::retry_rpc!($timeout, $strategy, "rpc", { $($code)* })
    };

    // Standard form: op_name with default structured logging
    ($timeout:expr, $strategy:expr, $op_name:expr, { $($code:tt)* }) => {{
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
        op.retry($strategy.build())
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
    }};

    // Full form: custom notify
    ($timeout:expr, $strategy:expr, $op_name:expr, |$attempt:ident, $err:ident, $sleep:ident| $notify:block, { $($code:tt)* }) => {{
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
        op.retry($strategy.build())
            .notify(|$err: &anyhow::Error, $sleep: std::time::Duration| {
                attempt_counter += 1;
                let $attempt = attempt_counter;
                $notify
            })
            .await
    }};
}
