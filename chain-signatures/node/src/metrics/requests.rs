use std::sync::LazyLock;
use std::time::Duration;

use prometheus::{exponential_buckets, CounterVec, HistogramVec, IntGauge};

use crate::metrics::{
    try_create_counter_vec_with_node_and_version, try_create_histogram_vec_with_node_and_version,
    LatencyStart,
};
use crate::protocol::Chain;
use mpc_primitives::RequestKind;

/// Steps and statuses of the sign request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignRequestStep {
    /// Time from block timestamp to first seen by indexer (Status: ok)
    /// Measures: network propagation delay + indexer polling latency
    Indexing,
    /// Time from indexing to signature generation start (Status: ok)
    AwaitingGeneration,
    /// Cumulative time in the organizing phase across all attempts (Status: ok).
    /// See `PhaseDurations` for the additivity caveat around governance pauses.
    Organizing,
    /// Cumulative time in the posit phase across all attempts (Status: ok).
    Posit,
    /// Cumulative time in the generating phase across all attempts (Status: ok).
    Generating,
    /// Time to respond to the sign request (Status: ok)
    Responding,
    /// Bidirectional only: time from publishing the initial response to the
    /// source chain until the target-chain execution is confirmed and the final
    /// response request is built (Status: ok).
    ///
    /// Recorded under `kind="respond_bidirectional"`, the kind the request has
    /// once the transition completes, so the whole second leg shares one kind.
    AwaitingExecution,
    /// Bidirectional only: time from indexing the initial request to the final
    /// response landing on the source chain, spanning both legs (Status: ok).
    ///
    /// The origin timestamp is node-local state that checkpoint recovery
    /// resets, so requests that cross a restart are not observed here.
    EndToEnd,
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
            Self::Organizing => "organizing",
            Self::Posit => "posit",
            Self::Generating => "generating",
            Self::Responding => "responding",
            Self::AwaitingExecution => "awaiting_execution",
            Self::EndToEnd => "end_to_end",
            Self::Total => "total",
        }
    }
}

static SIGN_REQUEST_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec_with_node_and_version(
        "multichain_sign_request_latency_sec",
        "Latency of multichain sign request processing with step, status and request kind specification.",
        &["chain", "step", "status", "kind"],
        // Start: 30ms, Factor: 1.4, Count: 42
        // Range: 0.03s -> ~29,300s (8.1 hours)
        Some(exponential_buckets(0.03, 1.4, 42).unwrap()),
    )
    .unwrap()
});

/// Observe a request latency given the elapsed duration directly. Use this
/// when the caller already has a `Duration` — e.g. an accumulator that
/// summed time across multiple attempts.
pub fn record_request_latency(
    chain: Chain,
    step: SignRequestStep,
    status: &str,
    kind: RequestKind,
    latency: Duration,
) {
    SIGN_REQUEST_LATENCY
        .with_label_values(&[chain.as_str(), step.as_str(), status, kind.as_str()])
        .observe(latency.as_secs_f64());
}

/// Observe a request latency by computing the elapsed time from a start
/// point (Instant, unix timestamp, SystemTime). Sugar around
/// `record_request_latency` for callers that have a start instead of a
/// pre-computed duration.
pub fn record_request_latency_since(
    chain: Chain,
    step: SignRequestStep,
    status: &str,
    kind: RequestKind,
    start: impl LatencyStart,
) {
    SIGN_REQUEST_LATENCY
        .with_label_values(&[chain.as_str(), step.as_str(), status, kind.as_str()])
        .observe(start.elapsed_seconds());
}
/// Some chains do not provide information about the block time.
/// For that reason we record indexing step reached with 0.0 latency.
pub fn record_indexing_step_reached(chain: Chain, kind: RequestKind) {
    SIGN_REQUEST_LATENCY
        .with_label_values(&[
            chain.as_str(),
            SignRequestStep::Indexing.as_str(),
            "ok",
            kind.as_str(),
        ])
        .observe(0.0);
}

pub(crate) static SIGN_REQUEST_DELAYED: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_and_version(
        "multichain_sign_request_delayed",
        "Number of delayed requests by chain, reported by the current proposer node.",
        &["chain"],
    )
    .unwrap()
});

/// Counts back-edges to organizing in the sign request state machine.
/// `from_phase` identifies the source: organizing (self-loop), posit
/// (consensus failed/timeout), or generating (construction or MPC failed).
pub(crate) static SIGN_REQUEST_LOOPS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_and_version(
        "multichain_sign_request_loops_total",
        "Number of back-edges to organizing in the sign request state machine, by chain and source phase.",
        &["chain", "from_phase"],
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

pub(crate) static PENDING_CHECKPOINTS: LazyLock<prometheus::IntGaugeVec> = LazyLock::new(|| {
    super::try_create_int_gauge_vec_with_node_account_id(
        "multichain_pending_checkpoints",
        "number of locally accumulated pending checkpoints by chain",
        &["chain"],
    )
    .unwrap()
});
