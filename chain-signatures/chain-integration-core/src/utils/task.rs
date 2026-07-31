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
