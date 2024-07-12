use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::triple::{TripleId, TripleManager};

/// Amount of iterations before we can say that the protocol is stuck.
const ADVANCEMENT_THRESHOLD: usize = 20;

pub struct StuckMonitor {
    triple_manager: Arc<RwLock<TripleManager>>,
    last_checked_triples: HashSet<TripleId>,
    last_changed_count: usize,
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
            last_changed_count: 0,
        }
    }

    pub async fn advance_then_check(&mut self) {
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

        self.last_changed_count += 1;
        if self.last_changed_count == ADVANCEMENT_THRESHOLD {
            tracing::warn!(
                // ?latest_triples,
                // generators = ?triple_manager.generators.keys().collect::<Vec<_>>(),
                // queued = ?triple_manager.queued,
                // ongoing = ?triple_manager.ongoing,
                ?diff,
                ?triple_manager,
                "protocol is stuck for the last {} iterations",
                self.last_changed_count
            );
        } else if self.last_changed_count > ADVANCEMENT_THRESHOLD {
            tracing::error!(
                ?diff,
                "protocol is stuck for the last {} iterations",
                self.last_changed_count
            );
        }
    }

    fn reset(&mut self, latest_triples: HashSet<TripleId>) {
        self.last_checked_triples = latest_triples;
        self.last_changed_count = 0;
    }
}
