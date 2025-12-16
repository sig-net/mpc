use std::sync::LazyLock;

use prometheus::{exponential_buckets, HistogramVec, IntGaugeVec};

use super::{try_create_histogram_vec, try_create_int_gauge_vec};

pub(crate) static NODE_RUNNING: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_node_is_up",
        "whether the multichain signer node is up and running",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NODE_VERSION: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_node_version",
        "node semantic version",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static CONFIGURATION_DIGEST: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_configuration_digest",
        "Configuration digest",
        &["node_account_id"],
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
