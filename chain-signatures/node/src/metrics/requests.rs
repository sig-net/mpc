use std::sync::LazyLock;

use prometheus::{exponential_buckets, CounterVec, HistogramVec, IntGauge};

use crate::metrics::{
    try_create_counter_vec_with_node_and_version, try_create_histogram_vec_with_node_and_version,
    LatencyStart,
};
use crate::protocol::Chain;

/// Steps and statuses of the sign request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignRequestStep {
    /// Time from block timestamp to first seen by indexer (Status: ok)
    /// Measures: network propagation delay + indexer polling latency
    Indexing,
    /// Time from indexing to signature generation start (Status: ok)
    AwaitingGeneration,
    /// Time to generate the signature (Status: ok, error)
    Generating,
    /// Time to respond to the sign request (Status: ok)
    Responding,
    /// Total time from indexing to responding
    /// Status:
    ///     - in_time: request was delivered in time (expected finality delay + margin)
    ///     - expired: request was delivered after expiration (expected finality delay + margin)
    Total,
}

impl SignRequestStep {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Indexing => "indexing",
            Self::AwaitingGeneration => "awaiting_generation",
            Self::Generating => "generating",
            Self::Responding => "responding",
            Self::Total => "total",
        }
    }
}

static SIGN_REQUEST_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_and_version(
        "multichain_sign_request_latency_sec",
        "Latency of multichain sign request processing with step and status specification.",
        &["chain", "step", "status"],
        // Start: 30ms, Factor: 1.4, Count: 42
        // Range: 0.03s -> ~29,300s (8.1 hours)
        Some(exponential_buckets(0.03, 1.4, 42).unwrap()),
    )
    .unwrap()
});

pub fn record_request_latency(
    chain: Chain,
    step: SignRequestStep,
    status: &str,
    start: impl LatencyStart,
) {
    let duration = start.elapsed_seconds();

    SIGN_REQUEST_LATENCY
        .with_label_values(&[chain.as_str(), step.as_str(), status])
        .observe(duration);
}
/// Some chains do not provide information about the block time.
/// For that reason we record indexing step reached with 0.0 latency.
pub fn record_indexing_step_reached(chain: Chain) {
    SIGN_REQUEST_LATENCY
        .with_label_values(&[chain.as_str(), SignRequestStep::Indexing.as_str(), "ok"])
        .observe(0.0);
}

pub(crate) static SIGN_REQUEST_DELAYED: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_and_version(
        "multichain_sign_request_delayed",
        "Number of delayed requests by chain",
        &["chain"],
    )
    .unwrap()
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
