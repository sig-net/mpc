use std::sync::LazyLock;

use prometheus::{exponential_buckets, CounterVec, HistogramVec};

use super::{try_create_counter_vec, try_create_histogram_vec, Histogram};

pub(crate) static NUM_SIGN_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_sign_requests_count",
        "number of multichain sign requests, marked by sign requests indexed",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_REQUESTS_MINE: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_sign_requests_count_mine",
        "number of multichain sign requests, marked by sign requests indexed",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_UNIQUE_SIGN_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_sign_requests_count_unique",
        "number of multichain sign requests, marked by sign requests indexed and deduped",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_SUCCESS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_sign_requests_success",
        "number of successful multichain sign requests, marked by publish()",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_SUCCESS_30S: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
            "multichain_sign_requests_success_30s",
            "number of successful multichain sign requests that finished within 30s, marked by publish()",
            &["chain", "node_account_id"],
        )
        .unwrap()
});

pub(crate) static SIGN_TOTAL_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_sign_latency_sec",
        "Latency of multichain signing, start from indexing sign request, end when publish() called.",
        &["chain", "node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static SIGN_RESPOND_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::new(
        "multichain_sign_respond_latency_sec",
        "Latency of multichain signing, from received publish request to publish complete.",
        &["chain", "node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
});

pub(crate) static SIGN_QUEUE_SIZE: LazyLock<prometheus::IntGaugeVec> = LazyLock::new(|| {
    super::try_create_int_gauge_vec(
        "multichain_sign_queue_size",
        "number of requests in sign queue",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGNATURE_PUBLISH_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_signature_publish_failures",
        "number of failed signature publish",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGNATURE_PUBLISH_RESPONSE_ERRORS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_signature_publish_response_errors",
        "number of respond calls with response that cannot be converted to json",
        &["node_account_id"],
    )
    .unwrap()
});
