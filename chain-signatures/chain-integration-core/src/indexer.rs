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

/// What an indexer should do after a fresh head reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Catchup {
    /// The head is further ahead than the tolerance: index up to `to` and observe again.
    Index { to: u64 },
    /// Within tolerance. `first_time` marks the reading that completes catchup:
    /// emit [`ChainEvent::CatchupCompleted`].
    UpToDate { first_time: bool },
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
    /// `tolerance` comes from [`mpc_primitives::ChainConfig::catchup_tolerance`].
    pub fn new(tolerance: u64) -> Self {
        Self {
            tolerance,
            caught_up: false,
        }
    }

    pub fn observe(&mut self, head: u64, last_indexed: u64) -> Catchup {
        if head.saturating_sub(last_indexed) > self.tolerance {
            Catchup::Index { to: head }
        } else {
            let first_time = !self.caught_up;
            self.caught_up = true;
            Catchup::UpToDate { first_time }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_once_on_the_first_reading_within_tolerance() {
        let mut gate = CatchupGate::new(0);
        assert_eq!(gate.observe(7, 5), Catchup::Index { to: 7 });
        assert_eq!(gate.observe(7, 7), Catchup::UpToDate { first_time: true });
        assert_eq!(gate.observe(7, 7), Catchup::UpToDate { first_time: false });
        assert_eq!(gate.observe(10, 7), Catchup::Index { to: 10 });
        assert_eq!(
            gate.observe(10, 10),
            Catchup::UpToDate { first_time: false }
        );
    }

    #[test]
    fn tolerance_is_inclusive() {
        let mut gate = CatchupGate::new(10);
        assert_eq!(gate.observe(11, 0), Catchup::Index { to: 11 });
        assert_eq!(gate.observe(10, 0), Catchup::UpToDate { first_time: true });
    }

    #[test]
    fn a_head_behind_the_indexed_height_is_up_to_date() {
        let mut gate = CatchupGate::new(0);
        assert_eq!(gate.observe(4, 5), Catchup::UpToDate { first_time: true });
    }
}
