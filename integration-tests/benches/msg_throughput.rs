use criterion::Criterion;
use criterion::Throughput;
use integration_tests::cluster;
use std::time::Duration;
use std::time::Instant;

/// Number of signature requests to process during the benchmark
pub const SIGNATURE_AMOUNT: usize = 30;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let started = Instant::now();

    // Spawn cluster with message proxy enabled and collect metrics for each signature
    let collected_metrics = rt.block_on(async {
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

        // Wait for presignatures to be ready
        cluster.wait().min_mine_presignatures(SIGNATURE_AMOUNT).await.unwrap();

        let mut collected_metrics = Vec::new();

        // Collect metrics for each signature individually
        for i in 0..SIGNATURE_AMOUNT {
            proxy.start_collection().await;
            cluster.sign().await.unwrap();
            let metrics = proxy.collect_metrics().await;

            println!(
                "Signature {}: {} messages, {} bytes, {:.2} msg/s",
                i + 1,
                metrics.messages_sent,
                metrics.bytes_sent,
                metrics.messages_per_second()
            );

            collected_metrics.push(metrics);
        }

        drop(cluster);
        collected_metrics
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

    // Run Criterion benchmark with iter_custom
    let mut c = Criterion::default();
    let mut group = c.benchmark_group("message_throughput");

    // Set throughput to measure messages and bytes
    group.throughput(Throughput::Elements(
        collected_metrics.iter().map(|m| m.messages_sent as u64).sum()
    ));

    group.bench_function("signatures_with_message_metrics", |b| {
        let mut idx = 0;
        b.iter_custom(|iters| {
            let mut total_duration = Duration::ZERO;
            for _ in 0..iters {
                if idx >= collected_metrics.len() {
                    idx = 0;
                }
                let metrics = &collected_metrics[idx];
                idx += 1;

                // Use the actual duration from metrics if available
                if let (Some(start), Some(end)) = (metrics.start_time, metrics.end_time) {
                    total_duration += end.duration_since(start);
                }
            }
            total_duration
        });
    });

    group.finish();

    println!("\nBenchmark total time: {:?}", started.elapsed());
}
