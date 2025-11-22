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

// Redis operation metrics
pub(crate) static REDIS_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_redis_operation_latency_ms",
        "Latency of Redis operations in storage layers",
        &["protocol", "operation", "node_account_id"],
        Some(exponential_buckets(1.0, 2.0, 15).unwrap()),
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

pub(crate) static WEB_ENDPOINT_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_web_endpoint_duration_ms",
        "Web endpoint response time in milliseconds",
        &["endpoint", "node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 25).unwrap()),
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

pub(crate) static CONFIGURATION_DIGEST: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_configuration_digest",
        "Configuration digest",
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
    #[cfg(feature = "bench")]
    pub label_values: Mutex<Vec<String>>,
    #[cfg(feature = "bench")]
    pub exact: Mutex<Vec<f64>>,
}

impl Histogram {
    pub fn new(name: &str, help: &str, labels: &[&str], buckets: Option<Vec<f64>>) -> Self {
        let histogram = try_create_histogram_vec(name, help, labels, buckets).unwrap();
        Self {
            histogram,
            #[cfg(feature = "bench")]
            label_values: Mutex::new(Vec::new()),
            #[cfg(feature = "bench")]
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
        // Only keep exact samples / label_value bookkeeping when bench feature is enabled.
        #[cfg(feature = "bench")]
        {
            let mut exact = self.exact.lock().unwrap();
            exact.push(value);

            let label_values = self.label_values.lock().unwrap();
            let label_values = label_values.iter().map(String::as_str).collect::<Vec<_>>();
            self.histogram
                .with_label_values(&label_values)
                .observe(value);
        }

        #[cfg(not(feature = "bench"))]
        {
            // In production builds avoid additional locking and write straight to the histogram.
            // Use default/empty label set when bench-time label bookkeeping is not active.
            // (metric label handling is handled externally via the HistogramVec usage in the codebase)
            let empty: &[&str] = &[];
            self.histogram.with_label_values(empty).observe(value);
        }
    }

    pub fn exact(&self) -> Vec<f64> {
        #[cfg(feature = "bench")]
        {
            self.exact.lock().unwrap().clone()
        }

        #[cfg(not(feature = "bench"))]
        {
            Vec::new()
        }
    }
}

// SLO violation counters: incremented when certain metric thresholds are breached.
pub(crate) static REDIS_SLO_VIOLATIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_redis_slo_violations",
        "Count of Redis operation latencies exceeding configured SLO thresholds",
        &["protocol", "operation", "node_account_id"],
    )
    .unwrap()
});

pub(crate) static PROTOCOL_SLO_VIOLATIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_protocol_slo_violations",
        "Count of multichain protocol loop latencies exceeding configured SLO thresholds",
        &["node_account_id", "protocol"],
    )
    .unwrap()
});

pub(crate) static QUEUE_SLO_VIOLATIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_queue_slo_violations",
        "Count of queue/backlog sizes exceeding configured SLO thresholds",
        &["queue", "node_account_id"],
    )
    .unwrap()
});

/// Check a Redis latency against SLO and increment violation counter when above threshold.
pub fn check_redis_slo(protocol: &str, operation: &str, node: &str, latency_ms: f64) {
    // default threshold (ms) overridden by MPC_REDIS_SLO_MS env var
    let threshold = std::env::var("MPC_REDIS_SLO_MS")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(200.0);

    if latency_ms > threshold {
        REDIS_SLO_VIOLATIONS
            .with_label_values(&[protocol, operation, node])
            .inc();
        tracing::warn!(
            latency_ms,
            threshold,
            protocol,
            operation,
            node,
            "redis slo violated"
        );
    }
}

/// Check a protocol iteration latency (seconds) against SLO and increment violation counter.
pub fn check_protocol_slo(node: &str, protocol: &str, latency_s: f64) {
    // default threshold (sec) overridden by MPC_PROTOCOL_SLO_SEC env var
    let threshold = std::env::var("MPC_PROTOCOL_SLO_SEC")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(1.0);

    if latency_s > threshold {
        PROTOCOL_SLO_VIOLATIONS
            .with_label_values(&[node, protocol])
            .inc();
        tracing::warn!(
            latency_s,
            threshold,
            node,
            protocol,
            "protocol slo violated"
        );
    }
}

/// Check a queue/backlog size against SLO and increment violation counter when above threshold.
pub fn check_queue_slo(queue: &str, node: &str, size: i64) {
    // default threshold overridden by MPC_QUEUE_SLO_SIZE env var
    let threshold = std::env::var("MPC_QUEUE_SLO_SIZE")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100);

    if size > threshold {
        QUEUE_SLO_VIOLATIONS.with_label_values(&[queue, node]).inc();
        tracing::warn!(size, threshold, queue, node, "queue slo violated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_redis_slo_increments() {
        std::env::set_var("MPC_REDIS_SLO_MS", "10");
        let labels = ["proto", "op", "node_test"];
        let before = REDIS_SLO_VIOLATIONS.with_label_values(&labels).get();
        check_redis_slo(labels[0], labels[1], labels[2], 50.0);
        let after = REDIS_SLO_VIOLATIONS.with_label_values(&labels).get();
        assert!(after > before, "redis slo counter should increase");
    }

    #[test]
    fn test_check_protocol_and_queue_slo_increments() {
        std::env::set_var("MPC_PROTOCOL_SLO_SEC", "0");
        std::env::set_var("MPC_QUEUE_SLO_SIZE", "0");

        let proto_labels = ["node_test", "crypto"];
        let q_labels = ["sign_queue", "node_test"];

        let before_proto = PROTOCOL_SLO_VIOLATIONS
            .with_label_values(&proto_labels)
            .get();
        check_protocol_slo(proto_labels[0], proto_labels[1], 1.0);
        let after_proto = PROTOCOL_SLO_VIOLATIONS
            .with_label_values(&proto_labels)
            .get();
        assert!(
            after_proto > before_proto,
            "protocol slo counter should increase"
        );

        let before_q = QUEUE_SLO_VIOLATIONS.with_label_values(&q_labels).get();
        check_queue_slo(q_labels[0], q_labels[1], 10);
        let after_q = QUEUE_SLO_VIOLATIONS.with_label_values(&q_labels).get();
        assert!(after_q > before_q, "queue slo counter should increase");
    }
}
