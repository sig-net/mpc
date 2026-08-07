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
    // `Ok(())` -> `Some(())` (done), `Err` retries with backoff.
    retry_until_some(cancel, delay, label, || async { process().await.map(Some) }).await;
}

/// Retries `poll` with `delay` backoff until it returns `Ok(Some(T))` or `cancel`
/// fires. Each failure is logged at WARN with `label` identifying the operation.
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
                Err(err) => tracing::warn!(?err, "{label} failed; retrying"),
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

    #[tokio::test]
    async fn retry_until_ok_retries_on_error_then_succeeds() {
        let cancel = CancellationToken::new();
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();
        retry_until_ok(&cancel, Duration::from_millis(1), "test", move || {
            let count = count_clone.clone();
            async move {
                if count.fetch_add(1, Ordering::Relaxed) == 0 {
                    Err(anyhow::anyhow!("boom"))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn retry_until_ok_stops_on_cancel() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_clone.cancel();
        });
        retry_until_ok(&cancel, Duration::from_millis(50), "test", move || {
            let count = count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                Err::<(), anyhow::Error>(anyhow::anyhow!("always fails"))
            }
        })
        .await;
        // The task should have been retried at least once before cancellation.
        assert!(count.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn cancelled_within_returns_false_when_duration_elapses() {
        let cancel = CancellationToken::new();
        let started = std::time::Instant::now();
        let cancelled = cancel.cancelled_within(Duration::from_millis(30)).await;
        assert!(!cancelled);
        // `sleep` never returns early, so the full duration must have elapsed.
        assert!(started.elapsed() >= Duration::from_millis(30));
    }

    #[tokio::test]
    async fn cancelled_within_returns_true_when_cancelled_during_wait() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel_clone.cancel();
        });
        let started = std::time::Instant::now();
        let cancelled = cancel.cancelled_within(Duration::from_millis(500)).await;
        assert!(cancelled);
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn abort_on_drop_aborts_the_wrapped_task() {
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();
        let handle = tokio::spawn(async move {
            loop {
                count_clone.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        {
            let guard = AbortOnDrop(handle);
            tokio::time::sleep(Duration::from_millis(35)).await;
            assert!(
                count.load(Ordering::Relaxed) >= 2,
                "task should have incremented before drop"
            );
            drop(guard);
        }

        // After dropping the guard, the wrapped task must stop running.
        let after_drop = count.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            count.load(Ordering::Relaxed),
            after_drop,
            "wrapped task kept running after AbortOnDrop was dropped"
        );
    }
}
