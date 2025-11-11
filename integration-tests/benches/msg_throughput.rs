use criterion::measurement::ValueFormatter;
use criterion::Criterion;
use criterion::{measurement::Measurement, Throughput};
use integration_tests::bench::MessageMetrics;
use integration_tests::cluster;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

/// Number of signature requests to process during the benchmark
pub const SIGNATURE_AMOUNT: usize = 30;

/// Custom measurement that reports message throughput metrics
struct MessageThroughputMeasurement {
    name: &'static str,
    metrics: Arc<Mutex<Vec<MessageMetrics>>>,
    at: Mutex<usize>,
}

impl Measurement for MessageThroughputMeasurement {
    type Intermediate = ();
    type Value = MessageMetrics;

    fn start(&self) -> Self::Intermediate {
        // Nothing to track at start - metrics are collected externally
    }

    fn end(&self, _: Self::Intermediate) -> Self::Value {
        let mut at = self.at.lock().unwrap();
        let metrics = self.metrics.lock().unwrap();
        let value = metrics[*at].clone();
        *at += 1;
        if *at >= metrics.len() {
            *at = 0;
        }
        value
    }

    fn add(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
        MessageMetrics {
            batches_sent: a.batches_sent + b.batches_sent,
            messages_sent: a.messages_sent + b.messages_sent,
            bytes_sent: a.bytes_sent + b.bytes_sent,
            latencies: {
                let mut combined = a.latencies.clone();
                combined.extend(b.latencies.clone());
                combined
            },
            start_time: a.start_time.or(b.start_time),
            end_time: b.end_time.or(a.end_time),
            per_node: {
                let mut combined = a.per_node.clone();
                for (k, v) in &b.per_node {
                    *combined.entry(k.clone()).or_insert(0) += v;
                }
                combined
            },
        }
    }

    fn zero(&self) -> Self::Value {
        MessageMetrics::default()
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        value.messages_per_second()
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        &ThroughputFormatter
    }
}

struct ThroughputFormatter;

impl ValueFormatter for ThroughputFormatter {
    fn scale_throughputs(
        &self,
        _typical: f64,
        throughput: &Throughput,
        values: &mut [f64],
    ) -> &'static str {
        match throughput {
            Throughput::Bytes(n) => {
                let bytes_per_second = *n as f64;
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
                    *val /= denominator;
                }
                unit
            }
            Throughput::Elements(n) => {
                let elems_per_second = *n as f64;
                let (denominator, unit) = if elems_per_second < 1000.0 {
                    (1.0, " msg/s")
                } else if elems_per_second < 1000.0 * 1000.0 {
                    (1000.0, "Kmsg/s")
                } else {
                    (1000.0 * 1000.0, "Mmsg/s")
                };

                for val in values {
                    *val /= denominator;
                }
                unit
            }
            _ => "units/s",
        }
    }

    fn scale_values(&self, _typical: f64, values: &mut [f64]) -> &'static str {
        // Values are already in msg/s
        values.iter_mut().for_each(|v| *v = *v);
        "msg/s"
    }

    fn scale_for_machines(&self, values: &mut [f64]) -> &'static str {
        self.scale_values(0.0, values)
    }
}

fn bench_on_metrics(measurement: MessageThroughputMeasurement) {
    let name = measurement.name.to_string();
    let metrics = measurement.metrics.lock().unwrap();
    let sample_size = metrics.len();
    drop(metrics);

    let mut c = Criterion::default()
        .sample_size(sample_size)
        .warm_up_time(Duration::from_nanos(1))
        .measurement_time(Duration::from_millis(1))
        .with_measurement(measurement);

    let mut group = c.benchmark_group("message_throughput");
    group.bench_function(name, |b| {
        b.iter(|| {
            std::thread::sleep(Duration::from_micros(100));
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

    // Spawn cluster with message proxy enabled
    let (_cluster, collected_metrics) = rt.block_on(async {
        let cluster = cluster::spawn()
            .disable_prestockpile()
            .with_message_proxy()
            .with_config(|cfg| {
                cfg.protocol.triple.min_triples = SIGNATURE_AMOUNT as u32 * 4;
                cfg.protocol.triple.max_triples = SIGNATURE_AMOUNT as u32 * 16;
                cfg.protocol.presignature.min_presignatures = SIGNATURE_AMOUNT as u32;
                cfg.protocol.presignature.max_presignatures = SIGNATURE_AMOUNT as u32 * 4;
            })
            .await
            .unwrap();

        let proxy = cluster
            .message_proxy
            .as_ref()
            .expect("Message proxy should be enabled");

        let mut collected_metrics = Vec::new();

        // Benchmark scenario: signature generation
        for i in 0..SIGNATURE_AMOUNT {
            // Reset metrics before each signature
            proxy.start_collection().await;

            // Create account and request signature
            let account = cluster.worker().dev_create_account().await.unwrap();

            // Execute signature request
            cluster.sign().account(account).await.unwrap();

            // Collect metrics
            let metrics = proxy.collect_metrics().await;

            tracing::info!(
                iteration = i,
                messages = metrics.messages_sent,
                bytes = metrics.bytes_sent,
                msg_per_sec = %format!("{:.2}", metrics.messages_per_second()),
                bytes_per_sec = %format!("{:.2}", metrics.bytes_per_second()),
                avg_latency_ms = %format!("{:.2}", metrics.avg_latency_ms()),
                "Signature request completed"
            );

            collected_metrics.push(metrics);
        }

        (Arc::new(cluster), collected_metrics)
    });

    // Report overall statistics
    let total_messages: usize = collected_metrics.iter().map(|m| m.messages_sent).sum();
    let total_bytes: usize = collected_metrics.iter().map(|m| m.bytes_sent).sum();
    let total_duration = started.elapsed();

    println!("\n=== Message Throughput Benchmark Results ===");
    println!("Total signatures: {}", SIGNATURE_AMOUNT);
    println!("Total messages: {}", total_messages);
    println!("Total bytes: {}", total_bytes);
    println!("Total time: {:?}", total_duration);
    println!(
        "Average messages/signature: {:.2}",
        total_messages as f64 / SIGNATURE_AMOUNT as f64
    );
    println!(
        "Average bytes/signature: {:.2}",
        total_bytes as f64 / SIGNATURE_AMOUNT as f64
    );
    println!(
        "Overall throughput: {:.2} msg/s",
        total_messages as f64 / total_duration.as_secs_f64()
    );
    println!(
        "Overall bandwidth: {:.2} KB/s",
        (total_bytes as f64 / 1024.0) / total_duration.as_secs_f64()
    );

    // Run Criterion benchmarks with collected metrics
    bench_on_metrics(MessageThroughputMeasurement {
        name: "msg_throughput(per_signature)",
        metrics: Arc::new(Mutex::new(collected_metrics)),
        at: Mutex::new(0),
    });

    println!("\nBenchmark total time: {:?}", started.elapsed());
}
