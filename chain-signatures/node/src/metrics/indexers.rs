use std::sync::LazyLock;

use prometheus::IntGaugeVec;

use super::try_create_int_gauge_vec_with_node_account_id;

/// Possible status options:
///     - "indexed" - latest block number seen by the indexer
///     - "finalized" - latest block number seen as finalized by the indexer
///     - "processed" - latest block number that where all requests got a response
pub(crate) static LATEST_BLOCK_NUMBER: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_latest_block_number",
        "Latest block number seen by the node",
        &["chain", "status"],
    )
    .unwrap()
});
