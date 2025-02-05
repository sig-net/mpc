use criterion::measurement::ValueFormatter;
use criterion::{criterion_group, criterion_main, Criterion};
use integration_tests::cluster::{self, Cluster};
use near_workspaces::Account;
use std::sync::Arc;
use std::{future::Future, sync::Mutex};

pub const SIGNATURE_AMOUNT: usize = 10;

// fn bench_single_sign_latency(c: &mut Criterion) {
//     bench(c, "sign latency", |nodes, account| async move {
//         nodes.sign().account(account).await
//     });
// }

// fn bench<O, R: Future<Output = O>>(
//     c: &mut Criterion,
//     name: &str,
//     f: fn(Arc<Cluster>, Account) -> R,
// ) {
//     let rt = tokio::runtime::Builder::new_multi_thread()
//         .enable_all()
//         .build()
//         .unwrap();
//     let (nodes, accounts) = rt.block_on(async {
//         let nodes = cluster::spawn()
//             .with_config(|cfg| {
//                 cfg.protocol.triple.min_triples = SIGNATURE_AMOUNT as u32 * 4;
//                 cfg.protocol.triple.max_triples = SIGNATURE_AMOUNT as u32 * 16;
//                 cfg.protocol.presignature.min_presignatures = SIGNATURE_AMOUNT as u32;
//                 cfg.protocol.presignature.max_presignatures = SIGNATURE_AMOUNT as u32 * 4;
//             })
//             .await
//             .unwrap();

//         let worker = nodes.worker();
//         let mut accounts = Vec::with_capacity(SIGNATURE_AMOUNT * 2);
//         for _ in 0..SIGNATURE_AMOUNT * 2 {
//             accounts.push(worker.dev_create_account().await.unwrap());
//         }

//         (Arc::new(nodes), accounts)
//     });

//     println!("starting benchmark: {}", name);
//     let mut accounts = accounts.into_iter();
//     c.bench_function(name, |b| {
//         // b.to_async(&rt)
//         //     .iter(|| f(nodes.clone(), accounts.next().unwrap()))
//         b.iter(|| rt.block_on(f(nodes.clone(), accounts.next().unwrap())))
//     });
//     println!("stopping benchmark: {}", name);

//     // cleanup and drop everything within the runtime so that async-drops work:
//     rt.block_on(async move {
//         drop(nodes);
//     });
// }

// criterion_group!(
//     name = sign;
//     config = Criterion::default().sample_size(SIGNATURE_AMOUNT);
//     targets = bench_single_sign_latency
// );
// criterion_main!(sign);

use criterion::{measurement::Measurement, BenchmarkId, Throughput};
use std::time::Duration;

struct NodeTimeMeasurement {
    name: String,
    datapoints: Vec<f64>,
    at: Mutex<usize>,
}

impl Measurement for NodeTimeMeasurement {
    type Intermediate = f64;
    type Value = Duration;

    fn start(&self) -> Self::Intermediate {
        let mut at = self.at.lock().unwrap();
        let value = self.datapoints[*at];
        *at += 1;
        if *at >= self.datapoints.len() {
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

fn my_function() {
    std::thread::sleep(Duration::from_millis(1)); // Simulating work
}

fn benchmark(c: &mut Criterion<NodeTimeMeasurement>) {
    let mut group = c.benchmark_group("external_benchmark");
    // group.throughput(Throughput::Elements(1));
    group.bench_with_input(BenchmarkId::new("my_function", 1), &1, |b, _| {
        b.iter(|| {
            my_function();
        })
    });
    group.finish();
}

fn main() {
    // let datapoints = vec![
    //     0.1, 0.2, 0.3, 0.4, 0.5, 0.3, 0.2, 0.43, 0.15, 0.25, 0.111, 0.222,
    // ];
    // let datapoints: Vec<f64> = vec![
    //     0.12, 0.85, 0.73, 0.91, 0.44, 0.56, 0.77, 0.32, 0.68, 0.27, 0.93, 0.88, 0.15, 0.41, 0.79,
    //     0.36, 0.52, 0.69, 0.81, 0.25, 0.64, 0.48, 0.96, 0.19, 0.72, 0.53, 0.67, 0.39, 0.84, 0.21,
    //     0.74, 0.47, 0.59, 0.29, 0.92, 0.33, 0.55, 0.61, 0.87, 0.14, 0.49, 0.76, 0.26, 0.97, 0.43,
    //     0.62, 0.34, 0.89, 0.57, 0.31, 0.66, 0.22, 0.95, 0.45, 0.71, 0.38, 0.54, 0.82, 0.24, 0.78,
    //     0.63, 0.17, 0.99, 0.42, 0.51, 0.86, 0.28, 0.75, 0.58, 0.37, 0.46, 0.16, 0.83, 0.65, 0.23,
    //     0.91, 0.35, 0.44, 0.98, 0.12, 0.68, 0.19, 0.53, 0.72, 0.31, 0.79, 0.56, 0.48, 0.94, 0.21,
    //     0.61, 0.87, 0.33, 0.47, 0.55, 0.41, 0.92, 0.29, 0.73, 0.14, 0.39, 0.84, 0.26, 0.58, 0.97,
    //     0.42, 0.36, 0.64, 0.81, 0.49, 0.76, 0.53, 0.22, 0.95, 0.62, 0.37, 0.57, 0.45, 0.88, 0.28,
    //     0.69, 0.25, 0.74, 0.43, 0.32, 0.96, 0.59, 0.51, 0.86, 0.38, 0.67, 0.19, 0.93, 0.24, 0.71,
    //     0.48, 0.34, 0.89, 0.54, 0.27, 0.82, 0.16, 0.98, 0.63, 0.39, 0.55, 0.47, 0.91, 0.35, 0.44,
    //     0.79, 0.26, 0.68, 0.31, 0.53, 0.72, 0.41, 0.88, 0.21, 0.66, 0.95, 0.29, 0.76, 0.51, 0.36,
    //     0.83, 0.42, 0.58, 0.97, 0.22, 0.69, 0.24, 0.74, 0.46, 0.32, 0.94, 0.59, 0.45, 0.85, 0.37,
    //     0.67, 0.19, 0.92, 0.27, 0.71, 0.48, 0.33, 0.89, 0.54, 0.28,
    // ];

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let datapoints = rt.block_on(async {
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

        for account in accounts.into_iter() {
            if let Err(err) = nodes.sign().account(account).await {
                println!("failed to sign: {:?}", err);
            }
        }

        nodes.fetch_bench_sig(0).await.unwrap()
    });

    let amount = datapoints.len();
    let measurement = NodeTimeMeasurement {
        name: "node_time".to_string(),
        datapoints,
        at: Mutex::new(0),
    };
    let mut criterion = Criterion::default()
        .sample_size(amount)
        .warm_up_time(Duration::from_nanos(1))
        .measurement_time(Duration::from_millis(1))
        .with_measurement(measurement);
    benchmark(&mut criterion);
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
