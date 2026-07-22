use std::time::Duration;

use futures_util::Stream;
use mpc_primitives::{Chain, ChainEvent};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// TODO: Consider removing default implementations from the trait and force to implement (also removes dependency for `tokio` and `tracing` in this crate)
/// Interface for a chain indexer that can catch up and livestream events from a specific chain.
#[async_trait::async_trait]
pub trait ChainIndexer: Send + Sync + 'static {
    const CHAIN: Chain;
    type Block: Send;
    type Iter: Stream<Item = Self::Block> + Send + Unpin + 'static;

    const RETRY_DELAY: Duration = Duration::from_millis(500);

    async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
        Ok(None)
    }

    async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    // TODO: this is only used in the legacy ChainStream pipeline, remove it once possible
    async fn catchup_range(&self, anchor_height: u64) -> Self::Iter {
        let _ = anchor_height;
        unimplemented!("catchup_range is only driven by the legacy ChainStream pipeline")
    }

    async fn process_catchup(&mut self, item: &Self::Block) -> anyhow::Result<()> {
        let _ = item;
        Ok(())
    }

    async fn next(&mut self) -> Option<Self::Block> {
        None
    }

    async fn process(&mut self, block: &Self::Block) -> anyhow::Result<()> {
        let _ = block;
        Ok(())
    }

    // TODO: remove default method implementation once all indexers implement it
    /// Owns the full catchup + live loop: emits catchup events, then
    /// [`ChainEvent::CatchupCompleted`], then live events on `events_tx`, resuming
    /// from the chain's persisted progress and its own current tip.
    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let _ = (events_tx, cancel);
        Err(anyhow::anyhow!(
            "run() not implemented for {}",
            Self::CHAIN.as_str()
        ))
    }

    /// Process the next block, return true for success, false for shutdown.
    async fn process_next_block(&mut self) -> bool {
        let Some(block) = self.next().await else {
            return false;
        };

        while let Err(err) = self.process(&block).await {
            tracing::warn!(?err, "live block processing failed; retrying");
            tokio::time::sleep(Self::RETRY_DELAY).await;
        }
        true
    }
}

/// Interface for a chain stream that can be started and can provide the next chain event.
#[async_trait::async_trait]
pub trait ChainStream: Send + 'static {
    type Indexer: ChainIndexer + Send;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer>;
    async fn next_event(&mut self) -> Option<ChainEvent>;
}
