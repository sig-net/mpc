use std::time::Duration;

use futures_util::Stream;
use mpc_primitives::{Chain, ChainEvent};

// TODO: Consider removing default implementations from the trait and force to implement (also removes dependency for `tokio` and `tracing` in this crate)
/// Interface for a chain indexer that can catch up and livestream events from a specific chain.
#[async_trait::async_trait]
pub trait ChainIndexer: Send + 'static {
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

    async fn catchup_range(&self, anchor_height: u64) -> Self::Iter;

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
