use criterion::measurement::ValueFormatter;
use criterion::Criterion;
use criterion::{measurement::Measurement, Throughput};
use integration_tests::cluster::{self, Cluster};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

pub const SIGNATURE_AMOUNT: usize = 30;

struct NodeTimeMeasurement {
    name: &'static str,
    data: Vec<f64>,
    at: Mutex<usize>,
}

impl Measurement for NodeTimeMeasurement {
    type Intermediate = f64;
    type Value = Duration;

    fn start(&self) -> Self::Intermediate {
        let mut at = self.at.lock().unwrap();
        let value = self.data[*at];
        *at += 1;
        if *at >= self.data.len() {
            *at = 0;
        }
        value
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        // Here, instead of using `elapsed`, you can fetch external runtime data points.
        // For example, you could read from a Prometheus metric, log file, or database.
        Duration::from_secs_f64(i)
    }

    fn add(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
        *a + *b
    }

    fn zero(&self) -> Self::Value {
        Duration::new(0, 0)
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        value.as_nanos() as f64
    }

    fn formatter(&self) -> &dyn criterion::measurement::ValueFormatter {
        &DurationFormatter
    }
}

fn bench_on_metrics(measurement: NodeTimeMeasurement) {
    let name = measurement.name.to_string();
    let mut c = Criterion::default()
        .sample_size(measurement.data.len())
        .warm_up_time(Duration::from_nanos(1))
        .measurement_time(Duration::from_millis(1))
        .with_measurement(measurement);

    let mut group = c.benchmark_group("bench_on_metrics");
    group.bench_function(name, |b| {
        b.iter(|| {
            std::thread::sleep(Duration::from_millis(1)); // Simulating work
        })
    });
    group.finish();
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let started = Instant::now();
    let (nodes, accounts) = rt.block_on(async {
        let nodes = cluster::spawn()
            .with_config(|cfg| {
                cfg.protocol.triple.min_triples = SIGNATURE_AMOUNT as u32 * 4;
                cfg.protocol.triple.max_triples = SIGNATURE_AMOUNT as u32 * 16;
                cfg.protocol.presignature.min_presignatures = SIGNATURE_AMOUNT as u32;
                cfg.protocol.presignature.max_presignatures = SIGNATURE_AMOUNT as u32 * 4;
            })
            .await
            .unwrap();

        let worker = nodes.worker();
        let mut accounts = Vec::with_capacity(SIGNATURE_AMOUNT * 2);
        for _ in 0..SIGNATURE_AMOUNT * 2 {
            accounts.push(worker.dev_create_account().await.unwrap());
        }

        (Arc::new(nodes), accounts)
    });

    let mut accounts = accounts.into_iter();
    let mut c = Criterion::default()
        .sample_size(SIGNATURE_AMOUNT)
        .warm_up_time(Duration::from_nanos(1))
        .measurement_time(Duration::from_millis(1));
    c.bench_function("sig(e2e) latency", |b| {
        let sign =
            |nodes: Arc<Cluster>, account| async move { nodes.sign().account(account).await };
        b.iter(|| rt.block_on(sign(nodes.clone(), accounts.next().unwrap())))
    });

    // cleanup and drop everything within the runtime so that async-drops work:
    let metrics = rt.block_on(async move { nodes.fetch_bench_metrics(0).await.unwrap() });

    bench_on_metrics(NodeTimeMeasurement {
        name: "sig(metrics) generation latency",
        data: metrics.sig_gen,
        at: Mutex::new(0),
    });
    bench_on_metrics(NodeTimeMeasurement {
        name: "sig(metrics) respond latency",
        data: metrics.sig_respond,
        at: Mutex::new(0),
    });
    bench_on_metrics(NodeTimeMeasurement {
        name: "presig(metrics) generation latency",
        data: metrics.presig_gen,
        at: Mutex::new(0),
    });
    println!("bench total time: {:?}", started.elapsed());
}

pub(crate) struct DurationFormatter;
impl DurationFormatter {
    fn bytes_per_second(&self, bytes: f64, typical: f64, values: &mut [f64]) -> &'static str {
        let bytes_per_second = bytes * (1e9 / typical);
        let (denominator, unit) = if bytes_per_second < 1024.0 {
            (1.0, "  B/s")
        } else if bytes_per_second < 1024.0 * 1024.0 {
            (1024.0, "KiB/s")
        } else if bytes_per_second < 1024.0 * 1024.0 * 1024.0 {
            (1024.0 * 1024.0, "MiB/s")
        } else {
            (1024.0 * 1024.0 * 1024.0, "GiB/s")
        };

        for val in values {
            let bytes_per_second = bytes * (1e9 / *val);
            *val = bytes_per_second / denominator;
        }

        unit
    }

    fn bytes_per_second_decimal(
        &self,
        bytes: f64,
        typical: f64,
        values: &mut [f64],
    ) -> &'static str {
        let bytes_per_second = bytes * (1e9 / typical);
        let (denominator, unit) = if bytes_per_second < 1000.0 {
            (1.0, "  B/s")
        } else if bytes_per_second < 1000.0 * 1000.0 {
            (1000.0, "KB/s")
        } else if bytes_per_second < 1000.0 * 1000.0 * 1000.0 {
            (1000.0 * 1000.0, "MB/s")
        } else {
            (1000.0 * 1000.0 * 1000.0, "GB/s")
        };

        for val in values {
            let bytes_per_second = bytes * (1e9 / *val);
            *val = bytes_per_second / denominator;
        }

        unit
    }

    fn elements_per_second(&self, elems: f64, typical: f64, values: &mut [f64]) -> &'static str {
        let elems_per_second = elems * (1e9 / typical);
        let (denominator, unit) = if elems_per_second < 1000.0 {
            (1.0, " elem/s")
        } else if elems_per_second < 1000.0 * 1000.0 {
            (1000.0, "Kelem/s")
        } else if elems_per_second < 1000.0 * 1000.0 * 1000.0 {
            (1000.0 * 1000.0, "Melem/s")
        } else {
            (1000.0 * 1000.0 * 1000.0, "Gelem/s")
        };

        for val in values {
            let elems_per_second = elems * (1e9 / *val);
            *val = elems_per_second / denominator;
        }

        unit
    }
}

impl ValueFormatter for DurationFormatter {
    fn scale_throughputs(
        &self,
        typical: f64,
        throughput: &Throughput,
        values: &mut [f64],
    ) -> &'static str {
        match *throughput {
            Throughput::Bytes(bytes) => self.bytes_per_second(bytes as f64, typical, values),
            Throughput::BytesDecimal(bytes) => {
                self.bytes_per_second_decimal(bytes as f64, typical, values)
            }
            Throughput::Elements(elems) => self.elements_per_second(elems as f64, typical, values),
        }
    }

    fn scale_values(&self, ns: f64, values: &mut [f64]) -> &'static str {
        let (factor, unit) = if ns < 10f64.powi(0) {
            (10f64.powi(3), "ps")
        } else if ns < 10f64.powi(3) {
            (10f64.powi(0), "ns")
        } else if ns < 10f64.powi(6) {
            (10f64.powi(-3), "µs")
        } else if ns < 10f64.powi(9) {
            (10f64.powi(-6), "ms")
        } else {
            (10f64.powi(-9), "s")
        };

        for val in values {
            *val *= factor;
        }

        unit
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        // no scaling is needed
        "ns"
    }
}
