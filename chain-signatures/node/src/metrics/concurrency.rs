use std::sync::LazyLock;

use prometheus::{CounterVec, IntGauge};

use super::{
    try_create_counter_vec_with_node_account_id, try_create_int_gauge_vec_with_node_account_id,
};

pub(crate) static DESIRED_SLOTS: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_concurrency_desired_slots",
        "Current adaptive concurrency slot target",
        &["scope"],
    )
    .unwrap()
    .with_label_values(&["global"])
});

pub(crate) static PRESIG_ACTIVE: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_concurrency_presig_active",
        "Current number of active presignature protocols admitted by adaptive concurrency",
        &["scope"],
    )
    .unwrap()
    .with_label_values(&["global"])
});

pub(crate) static TRIPLE_ACTIVE: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_concurrency_triple_active",
        "Current number of active triple protocols admitted by adaptive concurrency",
        &["scope"],
    )
    .unwrap()
    .with_label_values(&["global"])
});

pub(crate) static WAITING_PRESIGS: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_concurrency_waiting_presigs",
        "Current number of presignature protocols waiting for adaptive concurrency admission",
        &["scope"],
    )
    .unwrap()
    .with_label_values(&["global"])
});

pub(crate) static WAITING_TRIPLES: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_concurrency_waiting_triples",
        "Current number of triple protocols waiting for adaptive concurrency admission",
        &["scope"],
    )
    .unwrap()
    .with_label_values(&["global"])
});

pub(crate) static CPU_UTILIZATION_PERCENT: LazyLock<IntGauge> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_concurrency_cpu_utilization_percent",
        "Last adaptive concurrency CPU sample in whole percent",
        &["scope"],
    )
    .unwrap()
    .with_label_values(&["global"])
});

pub(crate) static ADJUSTMENTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_concurrency_adjustments_total",
        "Total adaptive concurrency adjustment decisions",
        &["direction"],
    )
    .unwrap()
});
