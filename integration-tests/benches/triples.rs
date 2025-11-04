use criterion::{criterion_group, criterion_main, Criterion};
use integration_tests::mpc_fixture::MpcFixtureBuilder;
use std::time::{Duration, Instant};

fn bench_triple_generation(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Create the network once outside the benchmark
    let network = rt.block_on(async {
        MpcFixtureBuilder::default()
            .only_generate_triples()
            .with_min_triples_stockpile(5)
            .with_max_triples_stockpile(30)
            .build()
            .await
    });

    c.bench_function("triple generation (3 nodes, threshold 2)", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let mut total = Duration::new(0, 0);
                for _ in 0..iters {
                    let start = Instant::now();
                    network.wait_for_triples(5).await;
                    total += start.elapsed();

                    for node in &network.nodes {
                        node.triple_storage.clear().await;
                    }
                }
                total
            })
        })
    });
}

criterion_group!(benches, bench_triple_generation);
criterion_main!(benches);