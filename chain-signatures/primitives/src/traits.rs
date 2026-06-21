use std::collections::HashMap;

use crate::{BidirectionalTx, BidirectionalTxId, Chain, SignId};

// TODO: Move these traits to a separate crate (mpc-indexer-core) later

/// Interface for the Indexer to query and update state.
/// Currently implemented by the Backlog
#[async_trait::async_trait]
pub trait StateManager: Send + Sync + Clone + 'static {
    /// Get the processed block height for a specific chain
    async fn get_processed_block(&self, chain: Chain) -> Option<u64>;

    /// Get the set of bidirectional transactions currently awaiting execution on the
    /// specified destination chain.
    async fn get_execution_watchers(
        &self,
        chain: Chain,
    ) -> HashMap<BidirectionalTxId, (SignId, BidirectionalTx)>;
}

/// Interface for the Indexer to report telemetry data.
pub trait ChainTelemetry: Send + Sync + Clone + 'static {
    /// Records that a block was parsed at the live tip
    fn indexed(&self, block: u64);

    /// Records that a block has reached finality/consensus
    fn finalized(&self, block: u64);
}

/// No-op implementation for tests
#[derive(Clone, Default)]
pub struct NoopChainTelemetry;

impl ChainTelemetry for NoopChainTelemetry {
    fn indexed(&self, _block: u64) {}
    fn finalized(&self, _block: u64) {}
}
