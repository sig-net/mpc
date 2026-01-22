use std::sync::LazyLock;

use prometheus::{exponential_buckets, Counter, Histogram, HistogramVec};

use super::{
    try_create_counter_vec_with_node_account_id, try_create_histogram_vec_with_node_account_id,
};

pub(crate) static NUM_SEND_ENCRYPTED_FAILURE: LazyLock<Counter> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_send_encrypted_failure",
        "number of successful send encrypted",
        &[],
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static NUM_SEND_ENCRYPTED_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_send_encrypted_total",
        "number total send encrypted",
        &[],
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static NUM_RECEIVED_ENCRYPTED_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_received_encrypted_total",
        "number total received encrypted",
        &[],
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static SEND_ENCRYPTED_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_send_encrypted_ms",
        "Latency of send encrypted.",
        &[],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static FAILED_SEND_ENCRYPTED_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_failed_send_encrypted_ms",
        "Latency of failed send encrypted.",
        &[],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static MSG_CLIENT_SEND_DELAY: LazyLock<Histogram> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_msg_client_send_delay_ms",
        "Delay between message creation and sending to the client",
        &[],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
    .with_label_values(&[] as &[&str])
});

pub(crate) static WEB_ENDPOINT_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_web_endpoint_duration_ms",
        "Web endpoint response time in milliseconds",
        &["endpoint"],
        Some(exponential_buckets(1.0, 1.5, 25).unwrap()),
    )
    .unwrap()
});
