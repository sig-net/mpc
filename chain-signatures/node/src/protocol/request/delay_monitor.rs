//! Background monitor tracking signature requests exceeding their expected response time.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use mpc_primitives::{Chain, ChainConfig as _, RequestId, RequestKind};
use mpc_utils::time::unix_elapsed;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::time::delay_queue::{DelayQueue, Key};

struct DelayEntry {
    key: Key,
    chain: Chain,
    kind: RequestKind,
    unix_timestamp_indexed: u64,
    expected_response_time_secs: u64,
    is_proposer: Arc<AtomicBool>,
}

enum DelayCommand {
    Watch {
        request_id: RequestId,
        chain: Chain,
        kind: RequestKind,
        unix_timestamp_indexed: u64,
        expected_response_time_secs: u64,
        deadline: Instant,
        is_proposer: Arc<AtomicBool>,
    },
    Unwatch {
        request_id: RequestId,
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
        request_id: RequestId,
        chain: Chain,
        kind: RequestKind,
        unix_timestamp_indexed: u64,
        remaining_time: Duration,
        is_proposer: Arc<AtomicBool>,
    ) {
        if remaining_time == Duration::ZERO {
            tracing::warn!(?request_id, "trying to watch for zero budget sign task");
            return;
        }
        let expected_response_time_secs = chain.expected_response_time_secs();
        let deadline = Instant::now() + remaining_time;
        let _ = self.tx.send(DelayCommand::Watch {
            request_id,
            chain,
            kind,
            unix_timestamp_indexed,
            expected_response_time_secs,
            deadline,
            is_proposer,
        });
    }

    /// Unwatches a completed or aborted sign request with a reason.
    pub fn unwatch(&self, request_id: RequestId, reason: &'static str) {
        let _ = self.tx.send(DelayCommand::Unwatch { request_id, reason });
    }

    async fn run(mut rx: mpsc::UnboundedReceiver<DelayCommand>) {
        let mut entries: HashMap<RequestId, DelayEntry> = HashMap::new();
        let mut queue: DelayQueue<RequestId> = DelayQueue::new();

        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else {
                        break;
                    };
                    Self::handle_command(cmd, &mut entries, &mut queue);
                }
                Some(expired) = queue.next(), if !queue.is_empty() => {
                    let request_id = expired.into_inner();
                    let Some(entry) = entries.remove(&request_id) else {
                        continue;
                    };
                    let elapsed = unix_elapsed(entry.unix_timestamp_indexed);
                    tracing::warn!(
                        ?request_id,
                        chain = ?entry.chain,
                        kind = entry.kind.as_str(),
                        elapsed_secs = elapsed.as_secs(),
                        expected_secs = entry.expected_response_time_secs,
                        "signature request delayed beyond expected response time"
                    );

                    if entry.is_proposer.load(Ordering::Relaxed) {
                        crate::metrics::requests::SIGN_REQUEST_DELAYED
                            .with_label_values(&[entry.chain.as_str(), entry.kind.as_str()])
                            .inc();
                    }
                }
            }
        }

        tracing::info!("delay monitor shutting down");
    }

    fn handle_command(
        cmd: DelayCommand,
        entries: &mut HashMap<RequestId, DelayEntry>,
        queue: &mut DelayQueue<RequestId>,
    ) {
        match cmd {
            DelayCommand::Watch {
                request_id,
                chain,
                kind,
                unix_timestamp_indexed,
                expected_response_time_secs,
                deadline,
                is_proposer,
            } => {
                if let Some(old) = entries.remove(&request_id) {
                    queue.remove(&old.key);
                }
                let key = queue.insert_at(request_id, deadline);
                entries.insert(
                    request_id,
                    DelayEntry {
                        key,
                        chain,
                        kind,
                        unix_timestamp_indexed,
                        expected_response_time_secs,
                        is_proposer,
                    },
                );
            }
            DelayCommand::Unwatch { request_id, reason } => {
                if let Some(old) = entries.remove(&request_id) {
                    queue.remove(&old.key);
                    tracing::info!(?request_id, %reason, "unwatching delayed request");
                } else {
                    tracing::debug!(?request_id, %reason, "no delayed request to unwatch");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request_id(byte: u8) -> RequestId {
        RequestId::new([byte; 32])
    }

    fn read_delayed_metric(chain: Chain, kind: RequestKind) -> u64 {
        crate::metrics::requests::SIGN_REQUEST_DELAYED
            .with_label_values(&[chain.as_str(), kind.as_str()])
            .get() as u64
    }

    #[tokio::test]
    async fn test_delay_monitor_emits_metric_when_proposer_exceeds_deadline() {
        let monitor = DelayMonitor::spawn();
        let chain = Chain::Ethereum;
        let kind = RequestKind::Sign;
        let initial_metric = read_delayed_metric(chain, kind);

        let request_id = sample_request_id(1);
        let is_proposer = Arc::new(AtomicBool::new(true));

        monitor.watch(
            request_id,
            chain,
            kind,
            0,
            Duration::from_millis(20),
            Arc::clone(&is_proposer),
        );

        // Before deadline: metric unchanged
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(read_delayed_metric(chain, kind) - initial_metric, 0);

        // Past deadline: metric increments
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(read_delayed_metric(chain, kind) - initial_metric, 1);
    }

    #[tokio::test]
    async fn test_delay_monitor_non_proposer_does_not_increment_metric() {
        let monitor = DelayMonitor::spawn();
        let chain = Chain::Solana;
        let kind = RequestKind::SignBidirectional;
        let initial_metric = read_delayed_metric(chain, kind);

        let request_id = sample_request_id(2);
        let is_proposer = Arc::new(AtomicBool::new(false));

        monitor.watch(
            request_id,
            chain,
            kind,
            0,
            Duration::from_millis(20),
            Arc::clone(&is_proposer),
        );

        // Advance past deadline
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(read_delayed_metric(chain, kind), initial_metric);
    }

    #[tokio::test]
    async fn test_delay_monitor_cancellation_prevents_metric() {
        let monitor = DelayMonitor::spawn();
        let chain = Chain::NEAR;
        let kind = RequestKind::Sign;
        let initial_metric = read_delayed_metric(chain, kind);

        let request_id = sample_request_id(3);
        let is_proposer = Arc::new(AtomicBool::new(true));

        monitor.watch(
            request_id,
            chain,
            kind,
            0,
            Duration::from_millis(30),
            Arc::clone(&is_proposer),
        );

        // Unwatch before deadline
        tokio::time::sleep(Duration::from_millis(5)).await;
        monitor.unwatch(request_id, "test completion");

        // Wait past original deadline
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(read_delayed_metric(chain, kind), initial_metric);
    }

    #[tokio::test]
    async fn test_delay_monitor_handles_multiple_requests_in_deadline_order() {
        let monitor = DelayMonitor::spawn();
        let chain = Chain::Canton;
        let kind = RequestKind::RespondBidirectional;
        let initial_metric = read_delayed_metric(chain, kind);

        let id1 = sample_request_id(10);
        let id2 = sample_request_id(20);
        let id3 = sample_request_id(30);

        let is_proposer1 = Arc::new(AtomicBool::new(true));
        let is_proposer2 = Arc::new(AtomicBool::new(true));
        let is_proposer3 = Arc::new(AtomicBool::new(true));

        // Register with different deadlines: id2 (15ms), id1 (40ms), id3 (80ms)
        monitor.watch(id1, chain, kind, 0, Duration::from_millis(40), is_proposer1);
        monitor.watch(id2, chain, kind, 0, Duration::from_millis(15), is_proposer2);
        monitor.watch(id3, chain, kind, 0, Duration::from_millis(80), is_proposer3);

        // After 25ms -> id2 expired (+1), id1 & id3 still active
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(read_delayed_metric(chain, kind) - initial_metric, 1);

        // Unwatch id3 before it expires
        monitor.unwatch(id3, "test abort");

        // After 30ms more (total 55ms) -> id1 expired (+1)
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(read_delayed_metric(chain, kind) - initial_metric, 2);

        // After 50ms more (total 105ms) -> id3 was cancelled, no further increment
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(read_delayed_metric(chain, kind) - initial_metric, 2);
    }

    #[tokio::test]
    async fn test_delay_monitor_counts_each_kind_separately() {
        let monitor = DelayMonitor::spawn();
        let chain = Chain::Hydration;
        let leg1 = RequestKind::SignBidirectional;
        let leg2 = RequestKind::RespondBidirectional;
        let initial_leg1 = read_delayed_metric(chain, leg1);
        let initial_leg2 = read_delayed_metric(chain, leg2);

        monitor.watch(
            sample_request_id(40),
            chain,
            leg1,
            0,
            Duration::from_millis(20),
            Arc::new(AtomicBool::new(true)),
        );
        monitor.watch(
            sample_request_id(41),
            chain,
            leg2,
            0,
            Duration::from_millis(20),
            Arc::new(AtomicBool::new(true)),
        );

        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(read_delayed_metric(chain, leg1) - initial_leg1, 1);
        assert_eq!(read_delayed_metric(chain, leg2) - initial_leg2, 1);
    }

    #[tokio::test]
    async fn test_delay_monitor_zero_remaining_time_ignored() {
        let monitor = DelayMonitor::spawn();
        let request_id = sample_request_id(99);
        let is_proposer = Arc::new(AtomicBool::new(true));

        monitor.watch(
            request_id,
            Chain::Ethereum,
            RequestKind::Sign,
            0,
            Duration::ZERO,
            is_proposer,
        );
    }
}
