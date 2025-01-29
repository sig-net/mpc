use criterion::{criterion_group, criterion_main, Criterion};
use integration_tests::cluster::{self, Cluster};
use std::future::Future;
use std::sync::Arc;

fn bench_single_sign_latency(c: &mut Criterion) {
    bench(c, "sign latency", |nodes| async move { nodes.sign().await });
}

fn bench<O, R: Future<Output = O>>(c: &mut Criterion, name: &str, f: fn(Arc<Cluster>) -> R) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let cluster = rt.block_on(async {
        let nodes = cluster::spawn().wait_for_running().await.unwrap();
        nodes.wait().signable();
        nodes
    });
    let cluster = Arc::new(cluster);
    c.bench_function(name, |b| b.to_async(&rt).iter(|| f(cluster.clone())));
}

criterion_group!(sign, bench_single_sign_latency);
criterion_main!(sign);
