use std::sync::LazyLock;

use prometheus::{exponential_buckets, HistogramVec, IntGaugeVec};

use super::{try_create_histogram_vec, try_create_int_gauge_vec};

pub(crate) static LATEST_BLOCK_NUMBER: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_latest_block_number",
        "Latest block number seen by the node",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static INDEXER_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_indexer_delay_secs",
        "Delay between block time of the request and the time a request gets indexed",
        &["chain", "node_account_id"],
        Some(exponential_buckets(0.01, 1.5, 30).unwrap()),
    )
    .unwrap()
});

pub(crate) static ETH_BLOCK_RECEIPT_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_eth_block_receipt_latency_ms",
        "Latency of eth indexer getting block recepipts",
        &["node_account_id"],
        Some(exponential_buckets(5.0, 1.5, 20).unwrap()),
    )
    .unwrap()
});
