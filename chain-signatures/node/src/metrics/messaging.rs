use crate::util::channel_len;

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

pub(crate) static CHANNEL_QUEUE_SIZE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    super::try_create_int_gauge_vec_with_node_account_id(
        "multichain_channel_queue_size",
        "Estimated number of buffered messages queued per message channel",
        &["channel"],
    )
    .unwrap()
});

pub(crate) fn set_queue_len(channel: &str, len: usize) {
    CHANNEL_QUEUE_SIZE
        .with_label_values(&[channel])
        .set(len as i64);
}

pub fn set_queue_len_tx<T>(name: &'static str, tx: &mpsc::Sender<T>) {
    set_queue_len(name, channel_len(tx));
}

pub(crate) fn remove_queue_len(channel: &str) {
    let _ = CHANNEL_QUEUE_SIZE.remove_label_values(&[channel]);
}

pub(crate) static TASK_QUEUE_LEN: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_account_id(
        "multichain_task_queue_size",
        "Distribution of queue sizes across message channels",
        &["channel"],
        Some(vec![
            1.0, 10.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 4000.0, 8000.0, 16000.0, 32000.0,
        ]),
    )
    .unwrap()
});

pub(crate) fn observe_queue_len(channel: &str, len: usize) {
    TASK_QUEUE_LEN
        .with_label_values(&[channel])
        .observe(len as f64);
}
