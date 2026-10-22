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
/// node has seen everything the chain has published. The head moves while the
/// indexer closes the gap, so the event is emitted only once a fresh head
/// reading, taken after a round of indexing, is within the chain's catchup gap
/// tolerance of the last indexed height. That tolerance is zero on chains whose
/// block interval dwarfs a round; Solana's slots advance about as fast as a
/// round takes, so it allows a few.
#[async_trait::async_trait]
pub trait ChainIndexer: Send + Sync + 'static {
    const CHAIN: Chain;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()>;
}
