use std::sync::{Mutex, OnceLock};

use near_account_id::AccountId;
use prometheus::{HistogramOpts, HistogramVec, Opts, Result};

pub mod hardware;
pub mod indexers;
pub mod messaging;
pub mod nodes;
pub mod protocols;
pub mod requests;
pub mod storage;

static NODE_ACCOUNT_ID: OnceLock<String> = OnceLock::new();
static VERSION: OnceLock<String> = OnceLock::new();

pub fn init_metrics(account_id: &AccountId, version: &str) {
    if let Err(existing) = NODE_ACCOUNT_ID.set(account_id.to_string()) {
        // If set twice with a different value it is a programmer error; keep simple and panic.
        if existing.as_str() != account_id.as_str() {
            panic!("node account id already set to a different value");
        }
    }
    if let Err(existing) = VERSION.set(version.to_string()) {
        if existing.as_str() != version {
            panic!("version already set to a different value");
        }
    }
}

pub fn node_account_id() -> &'static str {
    NODE_ACCOUNT_ID
        .get()
        .map(String::as_str)
        .unwrap_or("default-account.near")
}

pub fn version() -> &'static str {
    VERSION
        .get()
        .map(String::as_str)
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}

pub fn try_create_int_gauge_vec_with_node_account_id(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<prometheus::IntGaugeVec> {
    check_metric_multichain_prefix(name)?;
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("node_account_id".to_string(), node_account_id().to_string());
    let gauge = prometheus::IntGaugeVec::new(opts, labels)?;
    prometheus::register(Box::new(gauge.clone()))?;
    Ok(gauge)
}

pub fn try_create_counter_vec_with_node_and_version(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<prometheus::CounterVec> {
    check_metric_multichain_prefix(name)?;
    let mut opts = Opts::new(name, help);
    opts = opts
        .const_label("node_account_id".to_string(), node_account_id().to_string())
        .const_label("version".to_string(), version().to_string());
    let counter = prometheus::CounterVec::new(opts, labels)?;
    prometheus::register(Box::new(counter.clone()))?;
    Ok(counter)
}

pub fn try_create_counter_vec_with_node_account_id(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<prometheus::CounterVec> {
    check_metric_multichain_prefix(name)?;
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("node_account_id".to_string(), node_account_id().to_string());
    let counter = prometheus::CounterVec::new(opts, labels)?;
    prometheus::register(Box::new(counter.clone()))?;
    Ok(counter)
}

pub fn try_create_histogram_vec_with_node_account_id(
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
    opts = opts.const_label("node_account_id".to_string(), node_account_id().to_string());
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
        let histogram =
            try_create_histogram_vec_with_node_account_id(name, help, labels, buckets).unwrap();
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
