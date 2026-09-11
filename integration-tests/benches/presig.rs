use criterion::measurement::{Measurement, ValueFormatter};
use criterion::{Criterion, Throughput};
use integration_tests::cluster;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PRESIG_PER_NODE: u32 = 16;

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

    fn formatter(&self) -> &dyn ValueFormatter {
        &DurationFormatter
    }
}

fn bench_on_metrics(measurement: NodeTimeMeasurement) {
    let name = measurement.name.to_string();
    let mut c = Criterion::default()
        .sample_size(measurement.data.len().max(10))
        .warm_up_time(Duration::from_nanos(1))
        .measurement_time(Duration::from_millis(1))
        .with_measurement(measurement);

    let mut group = c.benchmark_group("presig_gen");
    group.bench_function(name, |b| {
        b.iter(|| std::thread::sleep(Duration::from_millis(1)));
    });
    group.finish();
}

async fn collect_presig_samples(nodes: usize, threshold: usize) -> Vec<f64> {
    let cluster = cluster::spawn()
        .nodes(nodes)
        .threshold(threshold)
        .disable_prestockpile()
        .with_config(|cfg| {
            cfg.protocol.max_concurrent_introduction = 16;
            cfg.protocol.max_concurrent_generation = 512;
            cfg.protocol.triple.min_triples = PRESIG_PER_NODE * 2;
            cfg.protocol.triple.max_triples = PRESIG_PER_NODE * nodes as u32 * 8;
            cfg.protocol.presignature.min_presignatures = PRESIG_PER_NODE;
            cfg.protocol.presignature.max_presignatures = PRESIG_PER_NODE * nodes as u32 * 4;
        })
        .await
        .unwrap();

    let participants = cluster.participants().await.unwrap();
    cluster
        .nodes
        .ctx()
        .redis
        .stockpile_triples(&cluster.cfg, &participants, 4)
        .await;

    cluster
        .wait()
        .min_mine_presignatures(PRESIG_PER_NODE as usize)
        .await
        .unwrap();

    let mut samples = Vec::new();
    for id in 0..cluster.len() {
        samples.extend(cluster.fetch_bench_metrics(id).await.unwrap().presig_gen);
    }
    drop(cluster);
    samples
}

fn report(name: &str, samples: &[f64]) {
    if samples.is_empty() {
        println!("{name}: no samples");
        return;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();
    let mean = sorted.iter().sum::<f64>() / n as f64;
    let p50 = sorted[n / 2];
    let p99 = sorted[((n as f64 * 0.99) as usize).min(n - 1)];
    println!("{name}: n={n} mean={mean:.3}s p50={p50:.3}s p99={p99:.3}s");
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let started = Instant::now();

    let samples_3 = rt.block_on(collect_presig_samples(3, 2));
    report("presig(3n/t2)", &samples_3);
    if !samples_3.is_empty() {
        bench_on_metrics(NodeTimeMeasurement {
            name: "presig(3-node) generation latency",
            data: samples_3,
            at: Mutex::new(0),
        });
    }

    let samples_8 = rt.block_on(collect_presig_samples(8, 5));
    report("presig(8n/t5)", &samples_8);
    if !samples_8.is_empty() {
        bench_on_metrics(NodeTimeMeasurement {
            name: "presig(8-node) generation latency",
            data: samples_8,
            at: Mutex::new(0),
        });
    }

    println!("bench total time: {:?}", started.elapsed());
}

struct DurationFormatter;

impl DurationFormatter {
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
            *val = (elems * (1e9 / *val)) / denominator;
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
            Throughput::Elements(elems) => self.elements_per_second(elems as f64, typical, values),
            _ => "s",
        }
    }

    fn scale_values(&self, ns: f64, values: &mut [f64]) -> &'static str {
        let (factor, unit) = if ns < 10f64.powi(3) {
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
        "ns"
    }
}
