use std::sync::LazyLock;

use prometheus::{exponential_buckets, Counter, CounterVec, HistogramVec, IntGauge};

use super::{
    try_create_counter_vec_with_node_account_id, try_create_counter_vec_with_node_and_version,
    try_create_histogram_vec_with_node_account_id, Histogram,
};

pub(crate) static NUM_SIGN_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_sign_requests_count",
        "number of multichain sign requests, marked by sign requests indexed",
        &["chain"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_REQUESTS_MINE: LazyLock<Counter> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_sign_requests_count_mine",
        "number of multichain sign requests, marked by sign requests indexed",
        &[],
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static NUM_UNIQUE_SIGN_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_sign_requests_count_unique",
        "number of multichain sign requests, marked by sign requests indexed and deduped",
        &["chain"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_REQUESTS_MINE_IN_TIME: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_and_version(
        "multichain_sign_requests_success",
        "number of mine sign requests with in time response",
        &["chain"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_REQUESTS_MINE_DELAYED: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_and_version(
        "multichain_sign_requests_delayed",
        "number of mine sign requests that are delayed",
        &["chain"],
    )
    .unwrap()
});

pub(crate) static SIGN_TOTAL_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_sign_latency_sec",
        "Latency of multichain signing, start from indexing sign request, end when publish() called.",
        &["chain"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static SIGN_RESPOND_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::new(
        "multichain_sign_respond_latency_sec",
        "Latency of multichain signing, from received publish request to publish complete.",
        &["chain"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
});

pub(crate) static SIGN_QUEUE_SIZE: LazyLock<IntGauge> = LazyLock::new(|| {
    super::try_create_int_gauge_vec_with_node_account_id(
        "multichain_sign_queue_size",
        "number of requests in sign queue",
        &[],
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static BACKLOG_SIZE: LazyLock<prometheus::IntGaugeVec> = LazyLock::new(|| {
    super::try_create_int_gauge_vec_with_node_account_id(
        "multichain_backlog_size",
        "number of pending backlog requests by chain",
        &["chain"],
    )
    .unwrap()
});
