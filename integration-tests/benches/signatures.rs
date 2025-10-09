use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use integration_tests::mpc_fixture::MpcFixtureBuilder;
use k256::Scalar;
use mpc_node::protocol::{Chain, IndexedSignRequest, SignRequestType};
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};

const PRESIGNATURES_PER_NODE: usize = 6;
const SAMPLE_SIZE: usize = 10;
const SIGNATURE_TIMEOUT: Duration = Duration::from_secs(15);

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .thread_name("signature-bench")
        .build()
        .expect("failed to build tokio runtime")
}

fn bench_signature_generation(c: &mut Criterion) {
    let rt = runtime();

    let fixture = rt.block_on(async {
        let fixture = MpcFixtureBuilder::default()
            .only_generate_signatures()
            .with_min_presignatures_stockpile(PRESIGNATURES_PER_NODE as u32)
            .with_max_presignatures_stockpile((PRESIGNATURES_PER_NODE * 4) as u32)
            .build()
            .await;

        fixture.wait_for_presignatures(PRESIGNATURES_PER_NODE).await;
        fixture
    });

    let mut group = c.benchmark_group("signature_generation");
    group.sample_size(SAMPLE_SIZE);

    group.bench_function(BenchmarkId::new("publish", PRESIGNATURES_PER_NODE), |b| {
        let mut counter = 0u64;
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                counter = counter.wrapping_add(1);
                let request_id = counter;
                let elapsed = rt.block_on(async {
                    fixture.wait_for_presignatures(PRESIGNATURES_PER_NODE).await;

                    {
                        let mut actions = fixture.output.rpc_actions.lock().await;
                        actions.clear();
                    }

                    let request = sign_request(request_id);
                    for node in &fixture.nodes {
                        node.sign_tx
                            .send(request.clone())
                            .await
                            .expect("failed to enqueue sign request");
                    }

                    let start = Instant::now();
                    tokio::time::timeout(SIGNATURE_TIMEOUT, fixture.wait_for_actions(1))
                        .await
                        .expect("sign request timed out");
                    start.elapsed()
                });
                total += elapsed;
            }
            total
        })
    });

    group.finish();

    // ensure fixture is dropped inside runtime so async tasks can wind down cleanly
    rt.block_on(async move {
        drop(fixture);
        tokio::time::sleep(Duration::from_millis(1500)).await;
    });
}

fn sign_request(counter: u64) -> IndexedSignRequest {
    let mut entropy = [0u8; 32];
    entropy[..8].copy_from_slice(&counter.to_le_bytes());

    let mut request_id = [0u8; 32];
    request_id[..8].copy_from_slice(&counter.to_le_bytes());

    IndexedSignRequest {
        id: SignId::new(request_id),
        args: SignArgs {
            entropy,
            epsilon: Scalar::default(),
            payload: Scalar::default(),
            path: format!("bench/{counter}"),
            key_version: LATEST_MPC_KEY_VERSION,
        },
        chain: Chain::NEAR,
        unix_timestamp_indexed: counter,
        timestamp_sign_queue: None,
        total_timeout: SIGNATURE_TIMEOUT,
        sign_request_type: SignRequestType::Sign,
        participants: None,
    }
}

criterion_group!(signature_benches, bench_signature_generation);
criterion_main!(signature_benches);
