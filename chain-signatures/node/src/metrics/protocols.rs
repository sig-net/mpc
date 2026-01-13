use std::sync::LazyLock;

use prometheus::{exponential_buckets, linear_buckets, CounterVec, HistogramVec, IntGaugeVec};

use super::{
    try_create_counter_vec, try_create_histogram_vec, try_create_int_gauge_vec, Histogram,
};

// Triple metrics
pub(crate) static TRIPLE_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_triple_latency_sec",
        "Latency of multichain triple generation, start from starting generation, end when triple generation complete.",
        &["node_account_id"],
        Some(exponential_buckets(5.0, 1.5, 20).unwrap()),
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

pub(crate) static TRIPLE_GENERATOR_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_triple_generator_failures",
        "total triple generator failures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static TRIPLE_GENERATOR_MINE_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_triple_generator_mine_failures",
        "mine triple generator failures",
        &["node_account_id"],
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

pub(crate) static TRIPLE_POKES_CNT: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_triple_pokes_cnt",
        "total pokes per triple protocol",
        &["node_account_id"],
        Some(linear_buckets(0.0, 1.0, 500).unwrap()),
    )
    .unwrap()
});

// Presignature metrics
pub(crate) static PRESIGNATURE_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::new(
        "multichain_presignature_latency_sec",
        "Latency of multichain presignature generation, start from starting generation, end when presignature generation complete.",
        &["node_account_id"],
        Some(exponential_buckets(1.0, 1.5, 20).unwrap()),
    )
});

pub(crate) static NUM_PRESIGNATURE_GENERATORS_TOTAL: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "multichain_num_presignature_generators_total",
        "number of total ongoing presignature generators",
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

pub(crate) static PRESIGNATURE_GENERATOR_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_presignature_generator_failures",
        "total presignature generator failures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static PRESIGNATURE_GENERATOR_MINE_FAILURES: LazyLock<CounterVec> =
    LazyLock::new(|| {
        try_create_counter_vec(
            "multichain_presignature_generator_mine_failures",
            "mine presignature generator failures",
            &["node_account_id"],
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

pub(crate) static PRESIGNATURE_POKES_CNT: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_presignature_pokes_cnt",
        "total pokes per presignature protocol",
        &["node_account_id"],
        Some(linear_buckets(0.0, 1.0, 30).unwrap()),
    )
    .unwrap()
});

// Signature metrics
pub(crate) static SIGN_GENERATION_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::new(
        "multichain_sign_gen_latency_sec",
        "Latency of multichain signing, from start signature generation to completion.",
        &["node_account_id"],
        Some(exponential_buckets(0.001, 2.0, 20).unwrap()),
    )
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

pub(crate) static SIGNATURE_GENERATOR_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_signature_generator_failures",
        "total signature generator failures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGNATURE_GENERATOR_MINE_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_signature_generator_mine_failures",
        "mine signature generator failures",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGNATURE_GENERATOR_SUCCESS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_num_total_historical_signature_generators_success",
        "total signature generator success",
        &["node_account_id"],
    )
    .unwrap()
});

pub(crate) static SIGNATURE_GENERATOR_MINE_SUCCESS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_signature_generator_mine_success",
        "mine signature generator success",
        &["node_account_id"],
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

pub(crate) static SIGNATURE_POKES_CNT: LazyLock<HistogramVec> = LazyLock::new(|| {
    try_create_histogram_vec(
        "multichain_signature_pokes_cnt",
        "total pokes per signature protocol",
        &["node_account_id"],
        Some(linear_buckets(0.0, 1.0, 30).unwrap()),
    )
    .unwrap()
});

// General protocol metrics
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

pub(crate) static PROTOCOL_ITER_CNT: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec(
        "multichain_protocol_iter_count",
        "Count of multichain protocol iter",
        &["node_account_id"],
    )
    .unwrap()
});
