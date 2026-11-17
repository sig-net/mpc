use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Barrier;

/// A synchronized starting gate for benchmark tasks.
///
/// Ensures all `worker_count` worker tasks are fully scheduled and queued at the gate
/// before releasing them simultaneously and starting the wall-clock timer.
#[derive(Clone, Debug)]
pub struct StartingGate {
    barrier: Arc<Barrier>,
}

impl StartingGate {
    /// Create a gate for `worker_count` worker tasks.
    ///
    /// The internal barrier is sized to `worker_count + 1` to accommodate the orchestrator thread.
    pub fn new(worker_count: usize) -> Self {
        Self {
            barrier: Arc::new(Barrier::new(worker_count + 1)),
        }
    }

    /// Obtain a clone of the underlying barrier handle to pass to worker tasks.
    pub fn barrier(&self) -> Arc<Barrier> {
        self.barrier.clone()
    }

    /// Obtain the barrier wrapped in `Some(...)` for functions expecting `Option<Arc<Barrier>>`.
    pub fn optional_barrier(&self) -> Option<Arc<Barrier>> {
        Some(self.barrier.clone())
    }

    /// Release all worker tasks simultaneously and return the start `Instant`.
    pub async fn start(&self) -> Instant {
        let start = Instant::now();
        self.barrier.wait().await;
        start
    }
}
