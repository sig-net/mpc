use std::sync::LazyLock;

use prometheus::{exponential_buckets, HistogramVec, IntGauge};

use super::{
    try_create_histogram_vec_with_node_account_id, try_create_int_gauge_vec_with_node_account_id,
};

pub(crate) static REDIS_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_redis_operation_latency_ms",
        "Latency of Redis operations in storage layers",
        &["protocol", "operation"],
        Some(exponential_buckets(1.0, 2.0, 15).unwrap()),
    )
    .unwrap()
});

pub(crate) static NUM_TRIPLES_MINE: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_num_triples_mine",
        "number of triples of the node's own",
        &[],
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static NUM_TRIPLES_TOTAL: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_num_triples_total",
        "number of total triples",
        &[],
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static NUM_PRESIGNATURES_MINE: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_num_presignatures_mine",
        "number of presignatures of the node's own",
        &[],
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static NUM_PRESIGNATURES_TOTAL: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_num_presignatures_total",
        "number of total presignatures",
        &[],
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});
