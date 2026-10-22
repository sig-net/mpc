use mpc_primitives::{Chain, ChainEvent};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Interface for a chain indexer that owns its full catchup + live loop.
///
/// Implementations emit the ordered event sequence (catchup events →
/// [`ChainEvent::CatchupCompleted`] → live events) on `events_tx`, resuming from
/// the chain's persisted progress and its own current tip. `cancel` is honoured
/// for supervisor-driven kill+restart on regression/watchdog.
///
/// `CatchupCompleted` gates second-leg signing on the node, so it must mean the
/// node has seen everything the chain has published; [`CatchupGate`] decides
/// when that holds.
#[async_trait::async_trait]
pub trait ChainIndexer: Send + Sync + 'static {
    const CHAIN: Chain;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()>;
}

/// Where an indexer stands after a fresh head reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Catchup {
    /// The head is further ahead than the tolerance: index up to it and read again.
    Behind,
    /// The first reading within tolerance: emit [`ChainEvent::CatchupCompleted`].
    Completed,
    /// Caught up already: wait for new blocks.
    Live,
}

/// Decides when catchup is complete. The head moves while an indexer closes the
/// gap, so the head read at startup is not the boundary: catchup is complete
/// once a reading taken after a round of indexing is within `tolerance` blocks
/// of the last indexed height.
pub struct CatchupGate {
    tolerance: u64,
    caught_up: bool,
}

impl CatchupGate {
    /// `tolerance` is zero on chains whose block interval dwarfs a round of
    /// indexing; a chain whose blocks arrive about as fast as a round takes
    /// allows a few.
    pub fn new(tolerance: u64) -> Self {
        Self {
            tolerance,
            caught_up: false,
        }
    }

    /// `gap` is the fresh head minus the last indexed height.
    pub fn observe(&mut self, gap: u64) -> Catchup {
        if gap > self.tolerance {
            Catchup::Behind
        } else if self.caught_up {
            Catchup::Live
        } else {
            self.caught_up = true;
            Catchup::Completed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_once_on_the_first_reading_within_tolerance() {
        let mut gate = CatchupGate::new(0);
        assert_eq!(gate.observe(2), Catchup::Behind);
        assert_eq!(gate.observe(0), Catchup::Completed);
        assert_eq!(gate.observe(0), Catchup::Live);
        assert_eq!(gate.observe(3), Catchup::Behind);
        assert_eq!(gate.observe(0), Catchup::Live);
    }

    #[test]
    fn tolerance_is_inclusive() {
        let mut gate = CatchupGate::new(10);
        assert_eq!(gate.observe(11), Catchup::Behind);
        assert_eq!(gate.observe(10), Catchup::Completed);
    }
}
