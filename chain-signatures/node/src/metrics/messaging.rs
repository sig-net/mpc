use std::sync::LazyLock;

use prometheus::{exponential_buckets, CounterVec, HistogramVec};

use super::{try_create_counter_vec, try_create_histogram_vec};

pub(crate) static NUM_SEND_ENCRYPTED_FAILURE: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_send_encrypted_failure",
        "number of successful send encrypted",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SEND_ENCRYPTED_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_send_encrypted_total",
        "number total send encrypted",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_RECEIVED_ENCRYPTED_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_received_encrypted_total",
        "number total received encrypted",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SEND_ENCRYPTED_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_send_encrypted_ms",
        "Latency of send encrypted.",
        &["node_account_id"],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static FAILED_SEND_ENCRYPTED_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_failed_send_encrypted_ms",
        "Latency of failed send encrypted.",
        &["node_account_id"],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static MSG_CLIENT_SEND_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_msg_client_send_delay_ms",
        "Delay between message creation and sending to the client",
        &["node_account_id"],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static WEB_ENDPOINT_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_web_endpoint_duration_ms",
        "Web endpoint response time in milliseconds",
        &["endpoint", "node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 25).unwrap()),
    )
    .unwrap()
});
