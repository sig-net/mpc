use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use super::triple::{TripleId, TripleManager};

/// Amount of time to wait before we can say that the protocol is stuck.
const STUCK_TIMEOUT_THRESHOLD: Duration = Duration::from_secs(120);

/// While being stuck, report the stuck every interval. This should not be higher than STUCK_TIMEOUT_THRESHOLD
/// due to how they're coupled in the following code.
const STUCK_COUNT_REPORT_INTERVAL: Duration = Duration::from_secs(30);

pub struct StuckMonitor {
    triple_manager: Arc<RwLock<TripleManager>>,
    last_checked_triples: HashSet<TripleId>,
    last_changed_timestamp: Instant,
    stuck_interval_timestamp: Instant,
}

impl StuckMonitor {
    pub async fn new(triple_manager: &Arc<RwLock<TripleManager>>) -> Self {
        Self {
            triple_manager: triple_manager.clone(),
            last_checked_triples: triple_manager
                .read()
                .await
                .triples
                .keys()
                .cloned()
                .collect(),
            last_changed_timestamp: Instant::now(),
            stuck_interval_timestamp: Instant::now(),
        }
    }

    pub async fn check(&mut self) {
        let triple_manager = self.triple_manager.read().await;
        let latest_triples: HashSet<_> = triple_manager.triples.keys().cloned().collect();
        if triple_manager.has_min_triples() {
            drop(triple_manager);
            self.reset(latest_triples);
            return;
        }

        let diff = latest_triples
            .difference(&self.last_checked_triples)
            .collect::<HashSet<_>>();
        if diff.len() > 0 {
            drop(triple_manager);
            self.reset(latest_triples);
            return;
        }

        if self.last_changed_timestamp.elapsed() >= STUCK_TIMEOUT_THRESHOLD
            && self.stuck_interval_timestamp.elapsed() >= STUCK_COUNT_REPORT_INTERVAL
        {
            self.stuck_interval_timestamp = Instant::now();

            tracing::warn!(
                // ?latest_triples,
                // generators = ?triple_manager.generators.keys().collect::<Vec<_>>(),
                // queued = ?triple_manager.queued,
                // ongoing = ?triple_manager.ongoing,
                ?triple_manager,
                "protocol is stuck for the last {} seconds",
                self.last_changed_timestamp.elapsed().as_secs(),
            );
        }
    }

    fn reset(&mut self, latest_triples: HashSet<TripleId>) {
        self.last_checked_triples = latest_triples;
        self.last_changed_timestamp = Instant::now();
    }
}
