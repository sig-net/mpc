use criterion::{criterion_group, criterion_main, Criterion};
use integration_tests::cluster::{self, Cluster};
use near_workspaces::Account;
use std::future::Future;
use std::sync::Arc;

pub const SIGNATURE_AMOUNT: usize = 100;

fn bench_single_sign_latency(c: &mut Criterion) {
    bench(c, "sign latency", |nodes, account| async move {
        nodes.sign().account(account).await
    });
}

fn bench<O, R: Future<Output = O>>(
    c: &mut Criterion,
    name: &str,
    f: fn(Arc<Cluster>, Account) -> R,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
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

    println!("starting benchmark: {}", name);
    let mut accounts = accounts.into_iter();
    c.bench_function(name, |b| {
        // b.to_async(&rt)
        //     .iter(|| f(nodes.clone(), accounts.next().unwrap()))
        b.iter(|| rt.block_on(f(nodes.clone(), accounts.next().unwrap())))
    });
    println!("stopping benchmark: {}", name);

    // cleanup and drop everything within the runtime so that async-drops work:
    rt.block_on(async move {
        drop(nodes);
    });
}

criterion_group!(
    name = sign;
    config = Criterion::default().sample_size(SIGNATURE_AMOUNT);
    targets = bench_single_sign_latency
);
criterion_main!(sign);
