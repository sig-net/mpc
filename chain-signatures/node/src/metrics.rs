use std::sync::LazyLock;
use std::sync::Mutex;

use prometheus::{
    self, exponential_buckets, linear_buckets, CounterVec, HistogramOpts, HistogramVec,
    IntGaugeVec, Opts, Result,
};

pub(crate) static NODE_RUNNING: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_node_is_up",
        "whether the multichain signer node is up and running",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_sign_requests_count",
        "number of multichain sign requests, marked by sign requests indexed",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_REQUESTS_MINE: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_sign_requests_count_mine",
        "number of multichain sign requests, marked by sign requests indexed",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SIGN_SUCCESS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_sign_requests_success",
        "number of successful multichain sign requests, marked by publish()",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGN_TOTAL_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_sign_latency_sec",
        "Latency of multichain signing, start from indexing sign request, end when publish() called.",
        &["chain", "node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static SIGN_GENERATION_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::new(
        "multichain_sign_gen_latency_sec",
        "Latency of multichain signing, from start signature generation to completion.",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
});

pub(crate) static SIGN_RESPOND_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::new(
        "multichain_sign_respond_latency_sec",
        "Latency of multichain signing, from received publish request to publish complete.",
        &["chain", "node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
});

pub(crate) static TRIPLE_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_triple_latency_sec",
        "Latency of multichain triple generation, start from starting generation, end when triple generation complete.",
        &["node_account_id"],
        Some(exponential_buckets(5.0, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static PRESIGNATURE_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::new(
        "multichain_presignature_latency_sec",
        "Latency of multichain presignature generation, start from starting generation, end when presignature generation complete.",
        &["node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 20).unwrap()),
    )
});

pub(crate) static SIGN_QUEUE_SIZE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_sign_queue_size",
        "number of requests in sign queue",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGN_QUEUE_MINE_SIZE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_sign_queue_mine_size",
        "number of my requests in sign queue",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TRIPLE_GENERATORS_INTRODUCED: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_triple_generators_introduced",
        "number of triple generators",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TRIPLE_GENERATORS_TOTAL: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_triple_generators_total",
        "number of total ongoing triple generators",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TRIPLES_MINE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_triples_mine",
        "number of triples of the node's own",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_TRIPLES_TOTAL: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_triples_total",
        "number of total triples",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_PRESIGNATURES_MINE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_presignatures_mine",
        "number of presignatures of the node's own",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_PRESIGNATURES_TOTAL: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_presignatures_total",
        "number of total presignatures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_PRESIGNATURE_GENERATORS_TOTAL: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_presignature_generators_total",
        "number of total ongoing presignature generators",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static MESSAGE_QUEUE_SIZE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_message_queue_size",
        "size of message queue of the node",
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

pub(crate) static NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS: LazyLock<CounterVec> =
    LazyLock::new(|| {
        try_create_counter_vec(
            "multichain_num_total_historical_triple_generators",
            "number of all triple generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS: LazyLock<CounterVec> =
    LazyLock::new(|| {
        try_create_counter_vec(
            "multichain_num_total_historical_triple_generators_success",
            "number of all successful triple generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_MINE_SUCCESS: LazyLock<CounterVec> =
    LazyLock::new(|| {
        try_create_counter_vec(
            "multichain_num_total_historical_triple_generations_mine_success",
            "number of successful triple generators that was mine historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS: LazyLock<CounterVec> =
    LazyLock::new(|| {
        try_create_counter_vec(
            "multichain_num_total_historical_presignature_generators",
            "number of all presignature generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_SUCCESS: LazyLock<CounterVec> =
    LazyLock::new(|| {
        try_create_counter_vec(
            "multichain_num_total_historical_presignature_generators_success",
            "number of all successful presignature generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE: LazyLock<CounterVec> =
    LazyLock::new(|| {
        try_create_counter_vec(
            "multichain_num_total_historical_presignature_generators_mine",
            "number of mine presignature generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE_SUCCESS: LazyLock<CounterVec> =
    LazyLock::new(|| {
        try_create_counter_vec(
            "multichain_num_total_historical_presignature_generators_mine_success",
            "number of mine presignature generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static NUM_SIGN_SUCCESS_30S: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
            "multichain_sign_requests_success_30s",
            "number of successful multichain sign requests that finished within 30s, marked by publish()",
            &["chain", "node_account_id"],
        )
        .unwrap()
});

pub(crate) static PROTOCOL_LATENCY_ITER_TOTAL: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_protocol_iter_total",
        "Latency of multichain protocol iter, start of protocol till end of iteration",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 3.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static PROTOCOL_LATENCY_ITER_CRYPTO: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_protocol_iter_crypto",
        "Latency of multichain protocol iter, start of crypto iter till end",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static PROTOCOL_LATENCY_ITER_CONSENSUS: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_protocol_iter_consensus",
        "Latency of multichain protocol iter, start of consensus iter till end",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static PROTOCOL_LATENCY_ITER_MESSAGE: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_protocol_iter_message",
        "Latency of multichain protocol iter, start of message iter till end",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static NUM_SEND_ENCRYPTED_FAILURE: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_send_encrypted_failure",
        "number of successful send encrypted",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static NUM_SEND_ENCRYPTED_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_send_encrypted_total",
        "number total send encrypted",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SEND_ENCRYPTED_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_send_encrypted_ms",
        "Latency of send encrypted.",
        &["node_account_id"],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static FAILED_SEND_ENCRYPTED_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_failed_send_encrypted_ms",
        "Latency of failed send encrypted.",
        &["node_account_id"],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static NUM_TOTAL_HISTORICAL_SIGNATURE_GENERATORS: LazyLock<CounterVec> =
    LazyLock::new(|| {
        try_create_counter_vec(
            "multichain_num_total_historical_signature_generators",
            "number of all signature generators historically on the node",
            &["node_account_id"],
        )
        .unwrap()
    });

pub(crate) static TRIPLE_GENERATOR_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_triple_generator_failures",
        "total triple generator failures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGNATURE_GENERATOR_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_signature_generator_failures",
        "total signature generator failures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static PRESIGNATURE_GENERATOR_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_presignature_generator_failures",
        "total presignature generator failures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGNATURE_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_signature_failures",
        "total signature failures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGNATURE_PUBLISH_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_signature_publish_failures",
        "number of failed signature publish",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

// CPU Usage Percentage Metric
pub(crate) static CPU_USAGE_PERCENTAGE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_cpu_usage_percentage",
        "CPU Usage Percentage",
        &["global", "node_account_id"],
    )
    .unwrap()
});

// Available Memory Metric
pub(crate) static AVAILABLE_MEMORY_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_available_memory_bytes",
        "Available Memory in Bytes",
        &["available_mem", "node_account_id"],
    )
    .unwrap()
});

// Used Memory Metric
pub(crate) static USED_MEMORY_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_used_memory_bytes",
        "Used Memory in Bytes",
        &["used", "node_account_id"],
    )
    .unwrap()
});

// Disk Space Metric
pub(crate) static AVAILABLE_DISK_SPACE_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_available_disk_space_bytes",
        "Available Disk Space in Bytes",
        &["available_disk", "node_account_id"],
    )
    .unwrap()
});

// Total Disk Space Metric
pub(crate) static TOTAL_DISK_SPACE_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_total_disk_space_bytes",
        "Total Disk Space in Bytes",
        &["total_disk", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGNATURE_PUBLISH_RESPONSE_ERRORS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_signature_publish_response_errors",
        "number of respond calls with response that cannot be converted to json",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static PROTOCOL_ITER_CNT: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_protocol_iter_count",
        "Count of multichain protocol iter",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static CONFIGURATION_DIGEST_MPC: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_configuration_digest_mpc",
        "Configuration digest MPC",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static CONFIGURATION_DIGEST_ETH: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_configuration_digest_eth",
        "Configuration digest ETH",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static CONFIGURATION_DIGEST_SOL: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_configuration_digest_sol",
        "Configuration digest SOL",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static CONFIGURATION_DIGEST_OTHER: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_configuration_digest_other",
        "Configuration digest of other parameters",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static LATEST_BLOCK_NUMBER: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_latest_block_number",
        "Latest block number seen by the node",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static PRESIGNATURE_BEFORE_POKE_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_presignature_before_poke_delay_ms",
        "per presignature protocol, delay between generator creation and first poke that returns SendMany/SendPrivate",
        &["node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 25).unwrap()),
    )
    .unwrap()
});

pub(crate) static NUM_UNIQUE_SIGN_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_sign_requests_count_unique",
        "number of multichain sign requests, marked by sign requests indexed and deduped",
        &["chain", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static PRESIGNATURE_ACCRUED_WAIT_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_presignature_accrued_wait_delay_ms",
        "per presignature protocol, total accrued wait time between each poke that returned SendMany/SendPrivate/Return",
        &["node_account_id"],
        Some(exponential_buckets(10.0, 1.5, 35).unwrap()),
    )
    .unwrap()
});

pub(crate) static PRESIGNATURE_POKE_CPU_TIME: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_presignature_poke_cpu_ms",
        "per presignature protocol, per poke cpu time returned SendMany/SendPrivate/Return",
        &["node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 5).unwrap()),
    )
    .unwrap()
});

pub(crate) static TRIPLE_BEFORE_POKE_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_triple_before_poke_delay_ms",
        "per triple protocol, delay between generator creation and first poke that returns SendMany/SendPrivate",
        &["node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 30).unwrap()),
    )
    .unwrap()
});

pub(crate) static TRIPLE_ACCRUED_WAIT_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_triple_accrued_wait_delay_ms",
        "per triple protocol, total accrued wait time between each poke that returned SendMany/SendPrivate/Return",
        &["node_account_id"],
        Some(exponential_buckets(10.0, 1.5, 35).unwrap()),
    )
    .unwrap()
});

pub(crate) static TRIPLE_POKE_CPU_TIME: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_triple_poke_cpu_ms",
        "per signature protocol, per poke cpu time",
        &["node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 5).unwrap()),
    )
    .unwrap()
});

pub(crate) static SIGNATURE_BEFORE_POKE_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_signature_before_poke_delay_ms",
        "per signature protocol, delay between generator creation and first poke that returns SendMany/SendPrivate",
        &["node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 25).unwrap()),
    )
    .unwrap()
});

pub(crate) static SIGNATURE_ACCRUED_WAIT_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_signature_accrued_wait_delay_ms",
        "per signature protocol, total accrued wait time between each poke that returned SendMany/SendPrivate/Return",
        &["node_account_id"],
        Some(exponential_buckets(10.0, 1.5, 35).unwrap()),
    )
    .unwrap()
});

pub(crate) static SIGNATURE_POKE_CPU_TIME: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_signature_poke_cpu_ms",
        "per signature protocol, per poke cpu time returned SendMany/SendPrivate/Return",
        &["node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 5).unwrap()),
    )
    .unwrap()
});

pub(crate) static TRIPLE_LATENCY_TOTAL: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_triple_latency_total_sec",
        "Latency of multichain triple generation, start from generator creation, end when triple generation complete.",
        &["node_account_id"],
        Some(exponential_buckets(5.0, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static TRIPLE_POKES_CNT: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_triple_pokes_cnt",
        "total pokes per triple protocol",
        &["node_account_id"],
        Some(linear_buckets(0.0, 1.0, 500).unwrap()),
    )
    .unwrap()
});

pub(crate) static PRESIGNATURE_POKES_CNT: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_presignature_pokes_cnt",
        "total pokes per presignature protocol",
        &["node_account_id"],
        Some(linear_buckets(0.0, 1.0, 30).unwrap()),
    )
    .unwrap()
});

pub(crate) static SIGNATURE_POKES_CNT: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_signature_pokes_cnt",
        "total pokes per signature protocol",
        &["node_account_id"],
        Some(linear_buckets(0.0, 1.0, 30).unwrap()),
    )
    .unwrap()
});

pub(crate) static MSG_CLIENT_SEND_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_msg_client_send_delay_ms",
        "Delay between message creation and sending to the client",
        &["node_account_id"],
        Some(exponential_buckets(0.5, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub(crate) static INDEXER_DELAY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_indexer_delay_secs",
        "Delay between block time of the request and the time a request gets indexed",
        &["chain", "node_account_id"],
        Some(exponential_buckets(0.01, 1.5, 30).unwrap()),
    )
    .unwrap()
});

pub(crate) static ETH_BLOCK_RECEIPT_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_eth_block_receipt_latency_ms",
        "Latency of eth indexer getting block recepipts",
        &["node_account_id"],
        Some(exponential_buckets(5.0, 1.5, 20).unwrap()),
    )
    .unwrap()
});

pub fn try_create_int_gauge_vec(name: &str, help: &str, labels: &[&str]) -> Result<IntGaugeVec> {
    check_metric_multichain_prefix(name)?;
    let opts = Opts::new(name, help);
    let gauge = IntGaugeVec::new(opts, labels)?;
    prometheus::register(Box::new(gauge.clone()))?;
    Ok(gauge)
}

pub fn try_create_counter_vec(name: &str, help: &str, labels: &[&str]) -> Result<CounterVec> {
    check_metric_multichain_prefix(name)?;
    let opts = Opts::new(name, help);
    let counter = CounterVec::new(opts, labels)?;
    prometheus::register(Box::new(counter.clone()))?;
    Ok(counter)
}

/// Attempts to create a `HistogramVector`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_histogram_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Option<Vec<f64>>,
) -> Result<HistogramVec> {
    check_metric_multichain_prefix(name)?;
    let mut opts = HistogramOpts::new(name, help);
    if let Some(buckets) = buckets {
        opts = opts.buckets(buckets);
    }
    let histogram = HistogramVec::new(opts, labels)?;
    prometheus::register(Box::new(histogram.clone()))?;
    Ok(histogram)
}

fn check_metric_multichain_prefix(name: &str) -> Result<()> {
    if name.starts_with("multichain_") {
        Ok(())
    } else {
        Err(prometheus::Error::Msg(format!(
            "Metrics are expected to start with 'multichain_', got {name}"
        )))
    }
}

pub struct Histogram {
    pub histogram: HistogramVec,
    pub label_values: Mutex<Vec<String>>,
    pub exact: Mutex<Vec<f64>>,
}

impl Histogram {
    pub fn new(name: &str, help: &str, labels: &[&str], buckets: Option<Vec<f64>>) -> Self {
        let histogram = try_create_histogram_vec(name, help, labels, buckets).unwrap();
        Self {
            histogram,
            label_values: Mutex::new(Vec::new()),
            exact: Mutex::new(Vec::new()),
        }
    }

    #[cfg(feature = "bench")]
    pub fn with_label_values(&self, values: &[&str]) -> &Self {
        let mut label_values = self.label_values.lock().unwrap();
        *label_values = values.iter().map(|s| s.to_string()).collect();
        self
    }

    #[cfg(not(feature = "bench"))]
    pub fn with_label_values(&self, values: &[&str]) -> prometheus::Histogram {
        self.histogram.with_label_values(values)
    }

    pub fn observe(&self, value: f64) {
        let mut exact = self.exact.lock().unwrap();
        exact.push(value);

        let label_values = self.label_values.lock().unwrap();
        let label_values = label_values.iter().map(String::as_str).collect::<Vec<_>>();
        self.histogram
            .with_label_values(&label_values)
            .observe(value);
    }

    pub fn exact(&self) -> Vec<f64> {
        self.exact.lock().unwrap().clone()
    }
}
