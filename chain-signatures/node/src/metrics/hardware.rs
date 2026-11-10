use std::sync::LazyLock;

use prometheus::IntGaugeVec;

use super::try_create_int_gauge_vec_with_node_account_id;

pub(crate) static CPU_USAGE_PERCENTAGE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_cpu_usage_percentage",
        "CPU Usage Percentage",
        &["global"],
    )
    .unwrap()
});

pub(crate) static AVAILABLE_MEMORY_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_available_memory_bytes",
        "Available Memory in Bytes",
        &["available_mem"],
    )
    .unwrap()
});

pub(crate) static USED_MEMORY_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_used_memory_bytes",
        "Used Memory in Bytes",
        &["used"],
    )
    .unwrap()
});

pub(crate) static AVAILABLE_DISK_SPACE_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_available_disk_space_bytes",
        "Available Disk Space in Bytes",
        &["available_disk"],
    )
    .unwrap()
});

pub(crate) static TOTAL_DISK_SPACE_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_total_disk_space_bytes",
        "Total Disk Space in Bytes",
        &["total_disk"],
    )
    .unwrap()
});
