use mpc_primitives::{Chain, ChainEvent};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Interface for a chain indexer that owns its full catchup + live loop.
///
/// Implementations emit the ordered event sequence (catchup events →
/// [`ChainEvent::CatchupCompleted`] → live events) on `events_tx`, resuming from
/// the chain's persisted progress and its own current tip. `cancel` is honoured
/// for supervisor-driven kill+restart on regression/watchdog.
#[async_trait::async_trait]
pub trait ChainIndexer: Send + Sync + 'static {
    const CHAIN: Chain;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()>;
}
