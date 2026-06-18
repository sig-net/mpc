use std::collections::HashMap;

use crate::{BidirectionalTx, BidirectionalTxId, Chain, SignId};

/// Interface for the Indexer to query and update state.
/// Currently implemented by the Backlog
#[async_trait::async_trait]
pub trait StateManager: Send + Sync + Clone + 'static {
    /// Get the last processed block height for a given chain.
    async fn get_processed_block(&self, chain: Chain) -> Option<u64>;

    /// Get the active execution watchers for a given chain.
    async fn get_execution_watchers(
        &self,
        chain: Chain,
    ) -> HashMap<BidirectionalTxId, (SignId, BidirectionalTx)>;
}
