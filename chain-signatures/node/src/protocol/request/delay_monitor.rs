//! Background monitor tracking signature requests exceeding their expected response time.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use mpc_primitives::{Chain, ChainConfig as _, SignId};
use mpc_utils::time::unix_elapsed;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::time::delay_queue::{DelayQueue, Key};

struct WatchEntry {
    key: Key,
    chain: Chain,
    unix_timestamp_indexed: u64,
    expected_response_time_secs: u64,
    is_proposer: Arc<AtomicBool>,
}

enum DelayCommand {
    Watch {
        sign_id: SignId,
        chain: Chain,
        unix_timestamp_indexed: u64,
        expected_response_time_secs: u64,
        deadline: Instant,
        is_proposer: Arc<AtomicBool>,
    },
    Unwatch {
        sign_id: SignId,
        reason: &'static str,
    },
}

/// A single-task monitor that alerts when signature requests exceed their expected response time.
#[derive(Debug)]
pub struct DelayMonitor {
    tx: mpsc::UnboundedSender<DelayCommand>,
    handle: JoinHandle<()>,
}

impl Drop for DelayMonitor {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl DelayMonitor {
    /// Spawns the single background delay monitor task.
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = tokio::spawn(Self::run(rx));
        Self { tx, handle }
    }

    /// Registers a sign request to be watched for deadline expiration.
    pub fn watch(
        &self,
        sign_id: SignId,
        chain: Chain,
        unix_timestamp_indexed: u64,
        remaining_time: Duration,
        is_proposer: Arc<AtomicBool>,
    ) {
        if remaining_time == Duration::ZERO {
            return;
        }
        let expected_response_time_secs = chain.expected_response_time_secs();
        let deadline = Instant::now() + remaining_time;
        let _ = self.tx.send(DelayCommand::Watch {
            sign_id,
            chain,
            unix_timestamp_indexed,
            expected_response_time_secs,
            deadline,
            is_proposer,
        });
    }

    /// Unwatches a completed or aborted sign request with a reason.
    pub fn unwatch(&self, sign_id: SignId, reason: &'static str) {
        let _ = self.tx.send(DelayCommand::Unwatch { sign_id, reason });
    }

    async fn run(mut rx: mpsc::UnboundedReceiver<DelayCommand>) {
        let mut entries: HashMap<SignId, WatchEntry> = HashMap::new();
        let mut queue: DelayQueue<SignId> = DelayQueue::new();

        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else {
                        break;
                    };
                    Self::handle_command(cmd, &mut entries, &mut queue);
                }
                Some(expired) = queue.next(), if !queue.is_empty() => {
                    let sign_id = expired.into_inner();
                    let Some(entry) = entries.remove(&sign_id) else {
                        continue;
                    };
                    let elapsed = unix_elapsed(entry.unix_timestamp_indexed);
                    tracing::warn!(
                        ?sign_id,
                        chain = ?entry.chain,
                        elapsed_secs = elapsed.as_secs(),
                        expected_secs = entry.expected_response_time_secs,
                        "signature request delayed beyond expected response time"
                    );

                    if entry.is_proposer.load(Ordering::Relaxed) {
                        crate::metrics::requests::SIGN_REQUEST_DELAYED
                            .with_label_values(&[entry.chain.as_str()])
                            .inc();
                    }
                }
            }
        }
    }

    fn handle_command(
        cmd: DelayCommand,
        entries: &mut HashMap<SignId, WatchEntry>,
        queue: &mut DelayQueue<SignId>,
    ) {
        match cmd {
            DelayCommand::Watch {
                sign_id,
                chain,
                unix_timestamp_indexed,
                expected_response_time_secs,
                deadline,
                is_proposer,
            } => {
                if let Some(old) = entries.remove(&sign_id) {
                    queue.remove(&old.key);
                }
                let key = queue.insert_at(sign_id, deadline);
                entries.insert(
                    sign_id,
                    WatchEntry {
                        key,
                        chain,
                        unix_timestamp_indexed,
                        expected_response_time_secs,
                        is_proposer,
                    },
                );
            }
            DelayCommand::Unwatch { sign_id, reason } => {
                if let Some(old) = entries.remove(&sign_id) {
                    queue.remove(&old.key);
                    tracing::info!(?sign_id, reason = %reason, "unwatching delayed request");
                } else {
                    tracing::debug!(?sign_id, reason = %reason, "no delayed request to unwatch");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sign_id(byte: u8) -> SignId {
        SignId::new([byte; 32])
    }

    fn read_delayed_metric(chain: Chain) -> u64 {
        crate::metrics::requests::SIGN_REQUEST_DELAYED
            .with_label_values(&[chain.as_str()])
            .get() as u64
    }

    #[tokio::test]
    async fn test_delay_monitor_emits_metric_when_proposer_exceeds_deadline() {
        let monitor = DelayMonitor::spawn();
        let chain = Chain::Ethereum;
        let initial_metric = read_delayed_metric(chain);

        let sign_id = sample_sign_id(1);
        let is_proposer = Arc::new(AtomicBool::new(true));

        monitor.watch(
            sign_id,
            chain,
            0,
            Duration::from_millis(20),
            Arc::clone(&is_proposer),
        );

        // Before deadline: metric unchanged
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(read_delayed_metric(chain) - initial_metric, 0);

        // Past deadline: metric increments
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(read_delayed_metric(chain) - initial_metric, 1);
    }

    #[tokio::test]
    async fn test_delay_monitor_non_proposer_does_not_increment_metric() {
        let monitor = DelayMonitor::spawn();
        let chain = Chain::Solana;
        let initial_metric = read_delayed_metric(chain);

        let sign_id = sample_sign_id(2);
        let is_proposer = Arc::new(AtomicBool::new(false));

        monitor.watch(
            sign_id,
            chain,
            0,
            Duration::from_millis(20),
            Arc::clone(&is_proposer),
        );

        // Advance past deadline
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(read_delayed_metric(chain), initial_metric);
    }

    #[tokio::test]
    async fn test_delay_monitor_cancellation_prevents_metric() {
        let monitor = DelayMonitor::spawn();
        let chain = Chain::NEAR;
        let initial_metric = read_delayed_metric(chain);

        let sign_id = sample_sign_id(3);
        let is_proposer = Arc::new(AtomicBool::new(true));

        monitor.watch(
            sign_id,
            chain,
            0,
            Duration::from_millis(30),
            Arc::clone(&is_proposer),
        );

        // Unwatch before deadline
        tokio::time::sleep(Duration::from_millis(5)).await;
        monitor.unwatch(sign_id, "test completion");

        // Wait past original deadline
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(read_delayed_metric(chain), initial_metric);
    }

    #[tokio::test]
    async fn test_delay_monitor_handles_multiple_requests_in_deadline_order() {
        let monitor = DelayMonitor::spawn();
        let chain = Chain::Canton;
        let initial_metric = read_delayed_metric(chain);

        let id1 = sample_sign_id(10);
        let id2 = sample_sign_id(20);
        let id3 = sample_sign_id(30);

        let is_proposer1 = Arc::new(AtomicBool::new(true));
        let is_proposer2 = Arc::new(AtomicBool::new(true));
        let is_proposer3 = Arc::new(AtomicBool::new(true));

        // Register with different deadlines: id2 (15ms), id1 (40ms), id3 (80ms)
        monitor.watch(id1, chain, 0, Duration::from_millis(40), is_proposer1);
        monitor.watch(id2, chain, 0, Duration::from_millis(15), is_proposer2);
        monitor.watch(id3, chain, 0, Duration::from_millis(80), is_proposer3);

        // After 25ms -> id2 expired (+1), id1 & id3 still active
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(read_delayed_metric(chain) - initial_metric, 1);

        // Unwatch id3 before it expires
        monitor.unwatch(id3, "test abort");

        // After 30ms more (total 55ms) -> id1 expired (+1)
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(read_delayed_metric(chain) - initial_metric, 2);

        // After 50ms more (total 105ms) -> id3 was cancelled, no further increment
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(read_delayed_metric(chain) - initial_metric, 2);
    }

    #[tokio::test]
    async fn test_delay_monitor_zero_remaining_time_ignored() {
        let monitor = DelayMonitor::spawn();
        let sign_id = sample_sign_id(99);
        let is_proposer = Arc::new(AtomicBool::new(true));

        monitor.watch(sign_id, Chain::Ethereum, 0, Duration::ZERO, is_proposer);
    }
}
