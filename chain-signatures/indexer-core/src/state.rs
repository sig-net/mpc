use std::collections::HashMap;

use mpc_primitives::{BidirectionalTx, BidirectionalTxId, Chain, SignId};

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
