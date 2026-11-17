use std::sync::LazyLock;

use prometheus::CounterVec;

use crate::metrics::try_create_counter_vec_with_node_account_id;

/// Settlement stalls observed in shadow mode, by chain. No rebase is triggered
/// by these detections yet; the counter lets the signal be validated first.
pub(crate) static STALL_DETECTIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_stall_detections",
        "number of settlement stalls detected from checkpoint vote tallies, by chain",
        &["chain"],
    )
    .unwrap()
});

pub(crate) fn record_stall_detection(chain: crate::protocol::Chain) {
    STALL_DETECTIONS.with_label_values(&[chain.as_str()]).inc();
}

/// Successful stall-triggered re-indexes, by chain. A detection suppressed by
/// the backoff is counted only by `STALL_DETECTIONS`, never here.
pub(crate) static STALL_REBASES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_stall_rebases",
        "number of settlement-stall-triggered backlog re-indexes, by chain",
        &["chain"],
    )
    .unwrap()
});

pub(crate) fn record_stall_rebase(chain: crate::protocol::Chain) {
    STALL_REBASES.with_label_values(&[chain.as_str()]).inc();
}

#[cfg(test)]
pub(crate) fn stall_detection_count(chain: crate::protocol::Chain) -> u64 {
    STALL_DETECTIONS.with_label_values(&[chain.as_str()]).get() as u64
}

#[cfg(test)]
pub(crate) fn stall_rebase_count(chain: crate::protocol::Chain) -> u64 {
    STALL_REBASES.with_label_values(&[chain.as_str()]).get() as u64
}
