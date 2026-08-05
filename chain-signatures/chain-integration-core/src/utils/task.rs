use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

/// Aborts the wrapped task on drop, preventing a leaked background task when
/// the owner (e.g. an indexer `run()` loop) is dropped or cancelled.
pub struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Extension methods on [`CancellationToken`] for cancellation-aware waiting.
pub trait CancellationTokenExt {
    /// Waits up to `dur`, returning early if the token is cancelled.
    /// Returns `true` if cancellation occurred during the wait.
    fn cancelled_within(&self, dur: Duration) -> impl Future<Output = bool> + Send;
}

impl CancellationTokenExt for CancellationToken {
    async fn cancelled_within(&self, dur: Duration) -> bool {
        tokio::select! {
            _ = self.cancelled() => true,
            _ = sleep(dur) => false,
        }
    }
}

/// Retries `process` with `delay` backoff until it returns `Ok(())` or `cancel`
/// fires. Each failure is logged at WARN with `label` identifying the operation.
pub async fn retry_until_ok<F, Fut>(
    cancel: &CancellationToken,
    delay: Duration,
    label: &str,
    process: F,
) where
    F: Fn() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            result = process() => match result {
                Ok(()) => return,
                Err(err) => tracing::warn!(?err, "{label} failed; retrying"),
            },
        }
        if cancel.cancelled_within(delay).await {
            return;
        }
    }
}

/// Same as `retry_until_ok`, but returns Option<T> when the operation returns `Ok(Some(T))`, and continues retrying on `Ok(None)`.
pub async fn retry_until_some<T, F, Fut>(
    cancel: &CancellationToken,
    delay: Duration,
    label: &str,
    poll: F,
) -> Option<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = anyhow::Result<Option<T>>>,
{
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return None,
            result = poll() => match result {
                Ok(Some(value)) => return Some(value),
                Ok(None) => {}
                Err(err) => tracing::warn!(?err, "{label} not ready; retrying"),
            },
        }
        if cancel.cancelled_within(delay).await {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn retry_until_some_returns_value_when_ready() {
        let cancel = CancellationToken::new();
        let val = retry_until_some(&cancel, Duration::from_millis(1), "test", || async {
            Ok::<_, anyhow::Error>(Some(42u64))
        })
        .await;
        assert_eq!(val, Some(42));
    }

    #[tokio::test]
    async fn retry_until_some_retries_on_none_then_yields_value() {
        let cancel = CancellationToken::new();
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();
        let val = retry_until_some(&cancel, Duration::from_millis(1), "test", move || {
            let count = count_clone.clone();
            async move {
                if count.fetch_add(1, Ordering::Relaxed) < 2 {
                    Ok(None)
                } else {
                    Ok(Some(7u64))
                }
            }
        })
        .await;
        assert_eq!(val, Some(7));
        assert_eq!(count.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn retry_until_some_retries_on_error() {
        let cancel = CancellationToken::new();
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();
        let val = retry_until_some(&cancel, Duration::from_millis(1), "test", move || {
            let count = count_clone.clone();
            async move {
                if count.fetch_add(1, Ordering::Relaxed) == 0 {
                    Err(anyhow::anyhow!("boom"))
                } else {
                    Ok(Some(1u64))
                }
            }
        })
        .await;
        assert_eq!(val, Some(1));
    }

    #[tokio::test]
    async fn retry_until_some_returns_none_on_cancel() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_clone.cancel();
        });
        let val = retry_until_some(&cancel, Duration::from_millis(50), "test", || async {
            Ok::<_, anyhow::Error>(None::<u64>)
        })
        .await;
        assert!(val.is_none());
    }
}
