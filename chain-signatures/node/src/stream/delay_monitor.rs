//! Counts a leg from indexing until this node observes its response or its deadline passes.

use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lru::LruCache;
use mpc_primitives::{Chain, ChainConfig as _, IndexedSignRequest, RequestKind, SignId};
use mpc_utils::time::unix_elapsed;
use tokio::sync::watch;
use tokio::time::{sleep_until, Instant};

use crate::metrics::requests::{
    record_request_latency_since, SignRequestStep, SIGN_REQUEST_DELAYED,
};

const MAX_LATE: usize = 8192;
type Leg = (Chain, SignId, RequestKind);

#[derive(Debug)]
struct Watched {
    deadline: Instant,
    indexed: u64,
}

#[derive(Debug)]
struct State {
    watched: HashMap<Leg, Watched>,
    deadlines: BTreeSet<(Instant, Leg)>,
    // Remember unanswered late legs across a rebase and for their eventual latency.
    late: LruCache<Leg, u64>,
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

/// Shared by this node's streams. The last sender dropping stops the deadline task.
#[derive(Clone, Debug)]
pub struct DelayMonitor {
    started: Instant,
    state: Arc<Mutex<State>>,
    earlier_deadline: watch::Sender<()>,
}

impl DelayMonitor {
    pub fn spawn() -> Self {
        let (earlier_deadline, changed) = watch::channel(());
        let state = Arc::new(Mutex::new(State {
            watched: HashMap::new(),
            deadlines: BTreeSet::new(),
            late: LruCache::new(NonZeroUsize::new(MAX_LATE).unwrap()),
        }));
        tokio::spawn(Self::run(state.clone(), changed));
        Self {
            started: Instant::now(),
            state,
            earlier_deadline,
        }
    }

    pub(crate) fn watch(&self, request: &IndexedSignRequest) {
        self.watch_if(request, || true);
    }

    pub(crate) fn watch_if(&self, request: &IndexedSignRequest, enabled: impl FnOnce() -> bool) {
        let indexed = request
            .unix_timestamp_indexed
            .unwrap_or_else(mpc_utils::time::current_unix_timestamp);
        let expected = Duration::from_secs(request.chain.expected_response_time_secs());
        if let Some(deadline) = deadline(indexed, expected) {
            self.register(
                (request.chain, request.id, request.request_kind()),
                indexed,
                deadline,
                enabled,
            );
        }
    }

    #[cfg(test)]
    fn watch_until(
        &self,
        id: SignId,
        kind: RequestKind,
        chain: Chain,
        indexed: u64,
        deadline: Instant,
    ) {
        self.register((chain, id, kind), indexed, deadline, || true);
    }

    // Check the source catch-up flag under the same lock as abort_chain: a racing
    // second leg is either registered before the abort or skipped after the flag clears.
    fn register(&self, leg: Leg, indexed: u64, deadline: Instant, enabled: impl FnOnce() -> bool) {
        let mut state = self.state.lock().unwrap();
        if !enabled()
            || deadline < self.started
            || state.late.contains(&leg)
            || state.watched.contains_key(&leg)
        {
            return;
        }
        if deadline <= Instant::now() {
            state.late.put(leg, indexed);
            drop(state);
            record_delayed(leg, indexed);
            return;
        }
        let wake = state
            .deadlines
            .first()
            .is_none_or(|(first, _)| deadline < *first);
        state.watched.insert(leg, Watched { deadline, indexed });
        state.deadlines.insert((deadline, leg));
        if wake {
            self.earlier_deadline.send_replace(());
        }
    }

    pub(crate) fn responded(&self, chain: Chain, id: SignId, kind: RequestKind) {
        let leg = (chain, id, kind);
        let mut state = self.state.lock().unwrap();
        let (indexed, status) = if let Some(watch) = state.watched.remove(&leg) {
            state.deadlines.remove(&(watch.deadline, leg));
            let in_time = Instant::now() < watch.deadline;
            drop(state);
            if in_time {
                (watch.indexed, "in_time")
            } else {
                record_delayed(leg, watch.indexed);
                (watch.indexed, "expired")
            }
        } else if let Some(indexed) = state.late.pop(&leg) {
            drop(state);
            (indexed, "expired")
        } else {
            return;
        };
        record_request_latency_since(chain, SignRequestStep::Total, status, kind, indexed);
    }

    pub(crate) fn abort_chain(&self, chain: Chain) {
        let mut state = self.state.lock().unwrap();
        let State {
            watched, deadlines, ..
        } = &mut *state;
        watched.retain(|leg, watch| {
            if leg.0 != chain {
                return true;
            }
            deadlines.remove(&(watch.deadline, *leg));
            false
        });
    }

    async fn run(state: Arc<Mutex<State>>, mut changed: watch::Receiver<()>) {
        loop {
            // A catch-up burst can leave many deadlines ready in the same scheduler turn.
            tokio::task::consume_budget().await;
            let next = {
                let mut state = state.lock().unwrap();
                let next = state.deadlines.first().copied();
                if let Some((deadline, leg)) = next {
                    if deadline <= Instant::now() {
                        state.deadlines.pop_first();
                        let watched = state
                            .watched
                            .remove(&leg)
                            .expect("queued deadline has a watch");
                        state.late.put(leg, watched.indexed);
                        drop(state);
                        record_delayed(leg, watched.indexed);
                        continue;
                    }
                }
                next
            };
            if let Some((deadline, _)) = next {
                tokio::select! {
                    _ = sleep_until(deadline) => continue,
                    changed = changed.changed() => if changed.is_err() { break; }
                }
            } else if changed.changed().await.is_err() {
                break;
            }
        }
    }
}

fn record_delayed((chain, sign_id, kind): Leg, indexed: u64) {
    tracing::warn!(
        ?sign_id,
        ?chain,
        kind = kind.as_str(),
        elapsed_secs = unix_elapsed(indexed).as_secs(),
        "signature request delayed beyond expected response time"
    );
    SIGN_REQUEST_DELAYED
        .with_label_values(&[chain.as_str(), kind.as_str()])
        .inc();
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
        monitor.responded(chain, sign_id(2), kind);
        settle(30).await;

        assert_eq!(total(chain, kind, "in_time") - in_time_before, 1);
        assert_eq!(delayed_count(chain, kind) - delayed_before, 0);

        // A replayed response does not count again.
        monitor.responded(chain, sign_id(2), kind);
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
        monitor.responded(chain, sign_id(3), kind);
        monitor.responded(chain, sign_id(3), kind);
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
        monitor.responded(chain, sign_id(9), kind);
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
        monitor.responded(chain, sign_id(6), leg2);
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
        monitor.watch_until(sign_id(7), kind, kept, 0, after(20));
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

    #[tokio::test(start_paused = true)]
    async fn response_at_deadline_before_timer_runs_counts_as_late() {
        let (chain, kind) = (Chain::Tron, RequestKind::RespondBidirectional);
        let (late, expired) = (delayed_count(chain, kind), total(chain, kind, "expired"));
        let monitor = DelayMonitor::spawn();
        let id = sign_id(13);
        monitor.watch_until(id, kind, chain, 0, Instant::now());
        monitor.responded(chain, id, kind);
        assert_eq!(delayed_count(chain, kind) - late, 1);
        assert_eq!(total(chain, kind, "expired") - expired, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_last_handle_releases_pending_watches() {
        let monitor = DelayMonitor::spawn();
        let state = Arc::downgrade(&monitor.state);
        monitor.watch_until(
            sign_id(14),
            RequestKind::Sign,
            Chain::NEAR,
            0,
            after(60_000),
        );
        tokio::task::yield_now().await;
        drop(monitor);
        tokio::task::yield_now().await;
        assert!(state.upgrade().is_none());
    }
}
