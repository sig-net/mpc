use std::sync::LazyLock;

use prometheus::{exponential_buckets, Histogram, HistogramVec, IntGaugeVec};

use super::{
    try_create_histogram_vec_with_node_account_id, try_create_int_gauge_vec_with_node_account_id,
};

pub(crate) static LATEST_BLOCK_NUMBER: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_latest_block_number",
        "Latest block number seen by the node",
        &["chain"],
    )
    .unwrap()
});

pub(crate) static INDEXER_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_indexer_delay_secs",
        "Delay between block time of the request and the time a request gets indexed",
        &["chain"],
        Some(exponential_buckets(0.01, 1.5, 30).unwrap()),
    )
    .unwrap()
});

pub(crate) static ETH_BLOCK_RECEIPT_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_eth_block_receipt_latency_ms",
        "Latency of eth indexer getting block recepipts",
        &[],
        Some(exponential_buckets(5.0, 1.5, 20).unwrap()),
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});
