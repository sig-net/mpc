// TODO: move to mpc-indexer-core
/// A universal macro to wrap any asynchronous RPC call with a timeout and a `backon` retry strategy.
#[macro_export]
macro_rules! retry_rpc {
    ($op_name:expr, $timeout:expr, $strategy:expr, $code:expr) => {{
        let fetch_op = || async {
            // Wrap the code block in an async block to evaluate the Future lazily
            let fut = async { $code };
            match tokio::time::timeout($timeout, fut).await {
                Ok(Ok(res)) => Ok(res),
                Ok(Err(e)) => Err(anyhow::anyhow!("RPC Error: {e}")),
                Err(_) => Err(anyhow::anyhow!("Request timed out")),
            }
        };

        use backon::Retryable;
        use anyhow::Context;
        fetch_op
            .retry($strategy)
            .notify(|err: &anyhow::Error, dur: std::time::Duration| {
                tracing::warn!(
                    operation = %$op_name,
                    "RPC call failed: {err}; retrying in {dur:?}"
                );
            })
            .await
            .context(format!("{} exhausted", $op_name))
    }};
}
