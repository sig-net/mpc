use std::sync::LazyLock;

use prometheus::IntGaugeVec;

use super::try_create_int_gauge_vec_with_node_account_id;

pub(crate) static LATEST_BLOCK_NUMBER: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_latest_block_number",
        "Latest block number seen by the node",
        &["chain"],
    )
    .unwrap()
});
