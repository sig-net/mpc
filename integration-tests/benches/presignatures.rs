use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use integration_tests::mpc_fixture::MpcFixtureBuilder;

const PRESIGNATURES_PER_NODE: usize = 6;
const SAMPLE_SIZE: usize = 10;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .thread_name("presignature-bench")
        .build()
        .expect("failed to build tokio runtime")
}

fn bench_presignature_generation(c: &mut Criterion) {
    let rt = runtime();

    let fixture = rt.block_on(async {
        let fixture = MpcFixtureBuilder::default()
            .only_generate_presignatures()
            .with_min_presignatures_stockpile(PRESIGNATURES_PER_NODE as u32)
            .with_max_presignatures_stockpile((PRESIGNATURES_PER_NODE * 4) as u32)
            .build()
            .await;

        fixture.wait_for_presignatures(PRESIGNATURES_PER_NODE).await;
        fixture
    });

    let mut group = c.benchmark_group("presignature_generation");
    group.sample_size(SAMPLE_SIZE);

    group.bench_function(BenchmarkId::new("restock", PRESIGNATURES_PER_NODE), |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let elapsed = rt.block_on(async {
                    for node in &fixture.nodes {
                        assert!(
                            node.presignature_storage.clear().await,
                            "failed to clear presignature storage"
                        );
                    }

                    let start = Instant::now();
                    fixture.wait_for_presignatures(PRESIGNATURES_PER_NODE).await;
                    start.elapsed()
                });
                total += elapsed;
            }
            total
        });
    });

    group.finish();

    // ensure fixture is dropped inside runtime so async tasks can wind down cleanly
    rt.block_on(async move {
        drop(fixture);
        tokio::time::sleep(Duration::from_millis(1500)).await;
    });
}

criterion_group!(presignature_benches, bench_presignature_generation);
criterion_main!(presignature_benches);
