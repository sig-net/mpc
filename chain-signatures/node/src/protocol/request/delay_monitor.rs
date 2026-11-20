//! Counts each admitted request leg once on this node: in time if its response
//! is observed on chain before its deadline, delayed otherwise.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::Duration;

use futures_util::StreamExt;
use lru::LruCache;
use mpc_primitives::{Chain, ChainConfig as _, RequestKind, SignId};
use mpc_utils::time::unix_elapsed;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::time::delay_queue::{DelayQueue, Key};

use crate::metrics::requests::{
    record_request_latency_since, SignRequestStep, SIGN_REQUEST_DELAYED,
};

/// How many late, unanswered legs are remembered.
const MAX_LATE: usize = 8192;

type Leg = (SignId, RequestKind);

/// Where and when this node indexed a leg; its latency runs from here.
#[derive(Clone, Copy)]
struct Indexed {
    chain: Chain,
    unix_timestamp: u64,
}

struct Watched {
    key: Key,
    indexed: Indexed,
}

enum DelayCommand {
    Watch {
        leg: Leg,
        indexed: Indexed,
        deadline: Instant,
    },
    Responded(Leg),
    AbortChain(Chain),
}

/// The deadline of a request indexed at `unix_timestamp_indexed`, `None` if it
/// lies before the earliest representable instant.
fn deadline(unix_timestamp_indexed: u64, expected: Duration) -> Option<Instant> {
    let now = Instant::now();
    let elapsed = unix_elapsed(unix_timestamp_indexed);
    match expected.checked_sub(elapsed) {
        Some(left) => Some(now + left),
        None => now.checked_sub(elapsed - expected),
    }
}

/// A single-task monitor counting each request leg as in time or delayed.
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

    /// Watches a leg until its response is observed or its chain's expected
    /// response time passes. A deadline already passed counts at once, unless it
    /// passed before this monitor started: the node was not running to see it.
    pub fn watch(
        &self,
        sign_id: SignId,
        kind: RequestKind,
        chain: Chain,
        unix_timestamp_indexed: u64,
    ) {
        let expected = Duration::from_secs(chain.expected_response_time_secs());
        if let Some(deadline) = deadline(unix_timestamp_indexed, expected) {
            self.watch_until(sign_id, kind, chain, unix_timestamp_indexed, deadline);
        }
    }

    fn watch_until(
        &self,
        sign_id: SignId,
        kind: RequestKind,
        chain: Chain,
        unix_timestamp_indexed: u64,
        deadline: Instant,
    ) {
        let _ = self.tx.send(DelayCommand::Watch {
            leg: (sign_id, kind),
            indexed: Indexed {
                chain,
                unix_timestamp: unix_timestamp_indexed,
            },
            deadline,
        });
    }

    /// The leg's response was observed on chain.
    pub fn responded(&self, sign_id: SignId, kind: RequestKind) {
        let _ = self.tx.send(DelayCommand::Responded((sign_id, kind)));
    }

    /// Stops watching the chain's legs without counting them; they are watched
    /// again when re-admitted.
    pub fn abort_chain(&self, chain: Chain) {
        let _ = self.tx.send(DelayCommand::AbortChain(chain));
    }

    async fn run(mut rx: mpsc::UnboundedReceiver<DelayCommand>) {
        let mut state = DelayState {
            started: Instant::now(),
            watched: HashMap::new(),
            queue: DelayQueue::new(),
            late: LruCache::new(NonZeroUsize::new(MAX_LATE).unwrap()),
        };

        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else {
                        break;
                    };
                    state.handle_command(cmd);
                }
                Some(expired) = state.queue.next(), if !state.queue.is_empty() => {
                    state.delayed(expired.into_inner());
                }
            }
        }

        tracing::info!("delay monitor shutting down");
    }
}

/// The monitor task's state.
struct DelayState {
    started: Instant,
    watched: HashMap<Leg, Watched>,
    queue: DelayQueue<Leg>,
    /// Legs counted as delayed and not answered yet: a re-admitted one is not
    /// counted again, and its response records `expired`.
    late: LruCache<Leg, Indexed>,
}

impl DelayState {
    fn handle_command(&mut self, cmd: DelayCommand) {
        match cmd {
            DelayCommand::Watch {
                leg,
                indexed,
                deadline,
            } => {
                if self.late.contains(&leg) || self.watched.contains_key(&leg) {
                    return;
                }
                if deadline < self.started {
                    let (sign_id, _) = leg;
                    tracing::debug!(?sign_id, "deadline passed before the node started");
                    return;
                }
                let key = self.queue.insert_at(leg, deadline.max(Instant::now()));
                self.watched.insert(leg, Watched { key, indexed });
            }
            DelayCommand::Responded(leg) => self.responded(leg),
            DelayCommand::AbortChain(chain) => {
                let queue = &mut self.queue;
                self.watched.retain(|_, watched| {
                    if watched.indexed.chain != chain {
                        return true;
                    }
                    queue.remove(&watched.key);
                    false
                });
            }
        }
    }

    fn responded(&mut self, leg: Leg) {
        let (_, kind) = leg;
        let (indexed, status) = if let Some(watched) = self.watched.remove(&leg) {
            self.queue.remove(&watched.key);
            (watched.indexed, "in_time")
        } else if let Some(indexed) = self.late.pop(&leg) {
            (indexed, "expired")
        } else {
            return;
        };
        record_request_latency_since(
            indexed.chain,
            SignRequestStep::Total,
            status,
            kind,
            indexed.unix_timestamp,
        );
    }

    fn delayed(&mut self, leg: Leg) {
        let Some(watched) = self.watched.remove(&leg) else {
            return;
        };
        let (sign_id, kind) = leg;
        let Indexed {
            chain,
            unix_timestamp,
        } = watched.indexed;
        tracing::warn!(
            ?sign_id,
            ?chain,
            kind = kind.as_str(),
            elapsed_secs = unix_elapsed(unix_timestamp).as_secs(),
            "signature request delayed beyond expected response time"
        );
        self.late.put(leg, watched.indexed);
        SIGN_REQUEST_DELAYED
            .with_label_values(&[chain.as_str(), kind.as_str()])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::requests::{delayed_count, request_latency_count};

    fn sign_id(byte: u8) -> SignId {
        SignId::new([byte; 32])
    }

    fn total(chain: Chain, kind: RequestKind, status: &str) -> u64 {
        request_latency_count(chain, SignRequestStep::Total, status, kind)
    }

    fn after(millis: u64) -> Instant {
        Instant::now() + Duration::from_millis(millis)
    }

    async fn settle(millis: u64) {
        tokio::time::sleep(Duration::from_millis(millis)).await;
    }

    // Each test uses its own chain and kind: the metrics are process-wide.

    #[tokio::test(start_paused = true)]
    async fn a_leg_past_its_deadline_counts_as_delayed_once() {
        let (chain, kind) = (Chain::Ethereum, RequestKind::Sign);
        let before = delayed_count(chain, kind);
        let monitor = DelayMonitor::spawn();

        monitor.watch_until(sign_id(1), kind, chain, 0, after(20));
        settle(10).await;
        assert_eq!(delayed_count(chain, kind) - before, 0);
        settle(20).await;
        assert_eq!(delayed_count(chain, kind) - before, 1);

        // Re-admission, e.g. after a rebase, does not count it again.
        monitor.watch_until(sign_id(1), kind, chain, 0, after(0));
        settle(10).await;
        assert_eq!(delayed_count(chain, kind) - before, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_response_before_the_deadline_counts_as_in_time() {
        let (chain, kind) = (Chain::Solana, RequestKind::Sign);
        let (delayed_before, in_time_before) =
            (delayed_count(chain, kind), total(chain, kind, "in_time"));
        let monitor = DelayMonitor::spawn();

        monitor.watch_until(sign_id(2), kind, chain, 0, after(20));
        settle(5).await;
        monitor.responded(sign_id(2), kind);
        settle(30).await;

        assert_eq!(total(chain, kind, "in_time") - in_time_before, 1);
        assert_eq!(delayed_count(chain, kind) - delayed_before, 0);

        // A replayed response does not count again.
        monitor.responded(sign_id(2), kind);
        settle(5).await;
        assert_eq!(total(chain, kind, "in_time") - in_time_before, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_response_records_its_latency_as_expired() {
        let (chain, kind) = (Chain::Canton, RequestKind::Sign);
        let (delayed_before, expired_before) =
            (delayed_count(chain, kind), total(chain, kind, "expired"));
        let monitor = DelayMonitor::spawn();

        monitor.watch_until(sign_id(3), kind, chain, 0, after(10));
        settle(20).await;
        monitor.responded(sign_id(3), kind);
        monitor.responded(sign_id(3), kind);
        settle(5).await;

        assert_eq!(delayed_count(chain, kind) - delayed_before, 1);
        assert_eq!(total(chain, kind, "expired") - expired_before, 1);
        assert_eq!(total(chain, kind, "in_time"), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn an_answered_leg_is_forgotten() {
        let (chain, kind) = (Chain::Canton, RequestKind::SignBidirectional);
        let before = delayed_count(chain, kind);
        let monitor = DelayMonitor::spawn();

        monitor.watch_until(sign_id(9), kind, chain, 0, after(10));
        settle(20).await;
        monitor.responded(sign_id(9), kind);
        settle(1).await;
        assert_eq!(delayed_count(chain, kind) - before, 1);

        // An answered request is never requeued, so nothing is kept to stop a recount.
        monitor.watch_until(sign_id(9), kind, chain, 0, after(0));
        settle(1).await;
        assert_eq!(delayed_count(chain, kind) - before, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_leg_admitted_after_its_deadline_counts_at_once() {
        let (chain, kind) = (Chain::Hydration, RequestKind::RespondBidirectional);
        let before = delayed_count(chain, kind);
        let monitor = DelayMonitor::spawn();
        settle(50).await;

        // Its deadline passed while the node was running.
        monitor.watch_until(
            sign_id(4),
            kind,
            chain,
            0,
            Instant::now() - Duration::from_millis(10),
        );
        settle(1).await;
        assert_eq!(delayed_count(chain, kind) - before, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_deadline_before_the_node_started_is_not_counted() {
        let (chain, kind) = (Chain::Midnight, RequestKind::RespondBidirectional);
        let deadline = Instant::now();
        settle(10).await;
        let before = delayed_count(chain, kind);
        let monitor = DelayMonitor::spawn();

        monitor.watch_until(sign_id(5), kind, chain, 0, deadline);
        settle(10).await;
        assert_eq!(delayed_count(chain, kind) - before, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn each_leg_is_counted_separately() {
        let chain = Chain::Midnight;
        let (leg1, leg2) = (RequestKind::SignBidirectional, RequestKind::Sign);
        let (leg1_before, leg2_in_time_before) =
            (delayed_count(chain, leg1), total(chain, leg2, "in_time"));
        let monitor = DelayMonitor::spawn();

        monitor.watch_until(sign_id(6), leg1, chain, 0, after(20));
        monitor.watch_until(sign_id(6), leg2, chain, 0, after(20));
        monitor.responded(sign_id(6), leg2);
        settle(30).await;

        assert_eq!(delayed_count(chain, leg1) - leg1_before, 1);
        assert_eq!(total(chain, leg2, "in_time") - leg2_in_time_before, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn aborting_a_chain_drops_its_watches_uncounted() {
        let kind = RequestKind::SignBidirectional;
        let (aborted, kept) = (Chain::Solana, Chain::Ethereum);
        let (aborted_before, kept_before) =
            (delayed_count(aborted, kind), delayed_count(kept, kind));
        let monitor = DelayMonitor::spawn();

        monitor.watch_until(sign_id(7), kind, aborted, 0, after(20));
        monitor.watch_until(sign_id(8), kind, kept, 0, after(20));
        monitor.abort_chain(aborted);
        settle(30).await;

        assert_eq!(delayed_count(aborted, kind) - aborted_before, 0);
        assert_eq!(delayed_count(kept, kind) - kept_before, 1);

        // Re-admitted after the rebase, it is watched again.
        monitor.watch_until(sign_id(7), kind, aborted, 0, after(0));
        settle(1).await;
        assert_eq!(delayed_count(aborted, kind) - aborted_before, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_leg_is_not_recounted_after_its_chain_is_aborted() {
        let (chain, kind) = (Chain::Ethereum, RequestKind::RespondBidirectional);
        let before = delayed_count(chain, kind);
        let monitor = DelayMonitor::spawn();

        monitor.watch_until(sign_id(11), kind, chain, 0, after(10));
        settle(20).await;
        monitor.abort_chain(chain);
        monitor.watch_until(sign_id(11), kind, chain, 0, after(0));
        settle(10).await;

        assert_eq!(delayed_count(chain, kind) - before, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_duplicate_watch_keeps_the_first_deadline() {
        let (chain, kind) = (Chain::Solana, RequestKind::RespondBidirectional);
        let before = delayed_count(chain, kind);
        let monitor = DelayMonitor::spawn();

        monitor.watch_until(sign_id(12), kind, chain, 0, after(20));
        monitor.watch_until(sign_id(12), kind, chain, 0, after(100));
        settle(30).await;

        assert_eq!(delayed_count(chain, kind) - before, 1);
    }
}
