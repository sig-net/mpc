use std::sync::LazyLock;
use tokio::sync::mpsc;

use prometheus::{exponential_buckets, Counter, Histogram, HistogramVec, IntGaugeVec};

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

pub(crate) static CHANNEL_CAPACITY_SIZE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    super::try_create_int_gauge_vec_with_node_account_id(
        "multichain_channel_capacity_size",
        "Estimated remaining capacity per message channel",
        &["channel"],
    )
    .unwrap()
});

pub(crate) fn set_channel_capacity(channel: &str, capacity: usize) {
    CHANNEL_CAPACITY_SIZE
        .with_label_values(&[channel])
        .set(capacity as i64);
}

pub(crate) fn set_channel_capacity_tx<T>(name: &'static str, tx: &mpsc::Sender<T>) {
    set_channel_capacity(name, tx.capacity());
}

pub(crate) fn remove_channel_capacity(channel: &str) {
    let _ = CHANNEL_CAPACITY_SIZE.remove_label_values(&[channel]);
}

pub(crate) static TASK_QUEUE_CAPACITY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_task_queue_capacity",
        "Distribution of queue capacities across message channels",
        &["channel"],
        Some(vec![
            0.0, 1.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 1500.0, 2000.0, 2500.0, 3000.0, 3500.0,
            4000.0, 4096.0,
        ]),
    )
    .unwrap()
});

pub(crate) fn observe_queue_capacity(channel: &str, len: usize) {
    TASK_QUEUE_CAPACITY
        .with_label_values(&[channel])
        .observe(len as f64);
}

pub(crate) static TASK_QUEUE_INBOX_COUNT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    super::try_create_int_gauge_vec_with_node_account_id(
        "multichain_task_queue_inbox_count",
        "Number of active inboxes per channel",
        &["channel"],
    )
    .unwrap()
});

pub(crate) fn set_inbox_count(channel: &str, count: usize) {
    TASK_QUEUE_INBOX_COUNT
        .with_label_values(&[channel])
        .set(count as i64);
}
