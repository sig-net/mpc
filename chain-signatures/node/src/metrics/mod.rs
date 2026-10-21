use std::{
    sync::{Mutex, OnceLock},
    time::{Instant, SystemTime},
};

use near_account_id::AccountId;
use prometheus::{HistogramOpts, HistogramVec, Opts, Result};

pub mod hardware;
pub mod indexers;
pub mod messaging;
pub mod nodes;
pub mod protocols;
pub mod publishers;
pub mod requests;
pub mod storage;
pub mod telemetry;

static NODE_ACCOUNT_ID: OnceLock<String> = OnceLock::new();
static VERSION: OnceLock<String> = OnceLock::new();
static GIT_COMMIT_HASH: OnceLock<String> = OnceLock::new();
static BUILD_TIMESTAMP: OnceLock<String> = OnceLock::new();

pub fn init_metrics(
    account_id: &AccountId,
    version: &str,
    git_commit_hash: Option<&str>,
    build_timestamp: Option<&str>,
) {
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
    if let Some(git_commit_hash) = git_commit_hash {
        if let Err(existing) = GIT_COMMIT_HASH.set(git_commit_hash.to_string()) {
            if existing.as_str() != git_commit_hash {
                panic!("git commit hash already set to a different value");
            }
        }
    }
    if let Some(build_timestamp) = build_timestamp {
        if let Err(existing) = BUILD_TIMESTAMP.set(build_timestamp.to_string()) {
            if existing.as_str() != build_timestamp {
                panic!("build timestamp already set to a different value");
            }
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

pub fn git_commit_hash() -> &'static str {
    GIT_COMMIT_HASH
        .get()
        .map(String::as_str)
        .unwrap_or("unknown")
}

pub fn build_timestamp() -> &'static str {
    BUILD_TIMESTAMP
        .get()
        .map(String::as_str)
        .unwrap_or("unknown")
}

pub fn try_create_int_gauge_vec_with_node_account_id(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<prometheus::IntGaugeVec> {
    register(prometheus::IntGaugeVec::new(
        node_opts(name, help)?,
        labels,
    )?)
}

pub fn try_create_gauge_vec_with_node_account_id(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<prometheus::GaugeVec> {
    register(prometheus::GaugeVec::new(node_opts(name, help)?, labels)?)
}

pub fn try_create_counter_vec_with_node_and_version(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<prometheus::CounterVec> {
    register(prometheus::CounterVec::new(
        node_build_opts(name, help)?,
        labels,
    )?)
}

pub fn try_create_counter_vec_with_node_account_id(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<prometheus::CounterVec> {
    register(prometheus::CounterVec::new(node_opts(name, help)?, labels)?)
}

pub fn try_create_histogram_vec_with_node_account_id(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Option<Vec<f64>>,
) -> Result<HistogramVec> {
    register(HistogramVec::new(
        histogram_opts(node_opts(name, help)?, buckets),
        labels,
    )?)
}

pub fn try_create_histogram_vec_with_node_and_version(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Option<Vec<f64>>,
) -> Result<HistogramVec> {
    register(HistogramVec::new(
        histogram_opts(node_build_opts(name, help)?, buckets),
        labels,
    )?)
}

/// `name`'s options with the node's account id as a const label.
fn node_opts(name: &str, help: &str) -> Result<Opts> {
    check_metric_multichain_prefix(name)?;
    Ok(Opts::new(name, help)
        .const_label("node_account_id".to_string(), node_account_id().to_string()))
}

/// [`node_opts`] plus the node's build as const labels.
fn node_build_opts(name: &str, help: &str) -> Result<Opts> {
    Ok(node_opts(name, help)?
        .const_label("version".to_string(), version().to_string())
        .const_label("git_commit_hash".to_string(), git_commit_hash().to_string())
        .const_label("build_timestamp".to_string(), build_timestamp().to_string()))
}

fn histogram_opts(opts: Opts, buckets: Option<Vec<f64>>) -> HistogramOpts {
    let opts = HistogramOpts::from(opts);
    match buckets {
        Some(buckets) => opts.buckets(buckets),
        None => opts,
    }
}

fn register<M: prometheus::core::Collector + Clone + 'static>(metric: M) -> Result<M> {
    prometheus::register(Box::new(metric.clone()))?;
    Ok(metric)
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

pub trait LatencyStart {
    fn elapsed_seconds(&self) -> f64;
}

impl LatencyStart for Instant {
    fn elapsed_seconds(&self) -> f64 {
        self.elapsed().as_secs_f64()
    }
}

impl LatencyStart for u64 {
    fn elapsed_seconds(&self) -> f64 {
        mpc_utils::time::unix_elapsed(*self).as_secs_f64()
    }
}

impl LatencyStart for SystemTime {
    fn elapsed_seconds(&self) -> f64 {
        self.elapsed().unwrap_or_default().as_secs_f64()
    }
}
