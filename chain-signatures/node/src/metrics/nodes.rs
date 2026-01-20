use std::sync::LazyLock;

use prometheus::IntGaugeVec;

use super::try_create_int_gauge_vec_with_node_account_id;

pub(crate) static NODE_RUNNING: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_node_is_up",
        "whether the multichain signer node is up and running",
        &[],
    )
    .unwrap()
});

pub(crate) static PROCESS_START_TIME: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_process_start_time_seconds",
        "Unix timestamp of when the process started",
        &[],
    )
    .unwrap()
});

pub(crate) static NODE_VERSION: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_node_version",
        "node semantic version",
        &[],
    )
    .unwrap()
});

pub(crate) static CONFIGURATION_DIGEST: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_configuration_digest",
        "Configuration digest",
        &[],
    )
    .unwrap()
});
