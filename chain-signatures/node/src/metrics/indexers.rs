use prometheus::IntGaugeVec;
use std::sync::LazyLock;

use super::try_create_int_gauge_vec_with_node_account_id;

/// Possible status options:
///     - "indexed" - latest block number seen by the indexer
///     - "finalized" - latest block number seen as finalized by the indexer
///     - "checkpoint" - latest block number for which a checkpoint was created
pub static LATEST_BLOCK_NUMBER: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_latest_block_number",
        "Latest block number seen by the node",
        &["chain", "status"],
    )
    .unwrap()
});
