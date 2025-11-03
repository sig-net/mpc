use cait_sith::protocol::Participant;
use criterion::{criterion_group, criterion_main, Criterion};
use integration_tests::{cluster::spawner::ClusterSpawner, containers::Redis};
use mpc_node::storage::{PresignatureStorage, TripleStorage};
use near_account_id::AccountId;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn dummy_triple(id: u64) -> mpc_node::protocol::triple::Triple {
    use cait_sith::triples::{TriplePub, TripleShare};
    use elliptic_curve::CurveArithmetic;
    use k256::Secp256k1;

    mpc_node::protocol::triple::Triple {
        id,
        share: TripleShare {
            a: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            b: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            c: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
        },
        public: TriplePub {
            big_a: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_b: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_c: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            participants: vec![Participant::from(1), Participant::from(2)],
            threshold: 5,
        },
    }
}

fn dummy_presignature(id: u64) -> mpc_node::protocol::presignature::Presignature {
    use cait_sith::PresignOutput;
    use elliptic_curve::CurveArithmetic;
    use k256::Secp256k1;

    mpc_node::protocol::presignature::Presignature {
        id,
        output: PresignOutput {
            big_r: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            k: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            sigma: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
        },
        participants: vec![Participant::from(1), Participant::from(2)],
    }
}

async fn setup_redis_env(num_triples: usize) -> (Redis, TripleStorage, Participant) {
    let spawner = ClusterSpawner::default()
        .network("bench-redis-triples")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let node_id: AccountId = "test0.near".parse().unwrap();
    let me = Participant::from(0);
    let triples = redis.triple_storage(&node_id);

    // Pre-populate with triples
    for i in 0..num_triples {
        let t = dummy_triple(i as u64);
        if let Some(mut slot) = triples.reserve(t.id).await {
            slot.insert(t, me).await;
        }
    }

    (redis, triples, me)
}

async fn setup_redis_env_presignatures(num_presignatures: usize) -> (Redis, PresignatureStorage, Participant) {
    let spawner = ClusterSpawner::default()
        .network("bench-redis-presignatures")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let node_id: AccountId = "test0.near".parse().unwrap();
    let me = Participant::from(0);
    let presignatures = redis.presignature_storage(&node_id);

    // Pre-populate with presignatures
    for i in 0..num_presignatures {
        let p = dummy_presignature(i as u64);
        if let Some(mut slot) = presignatures.reserve(p.id).await {
            slot.insert(p, me).await;
        }
    }

    (redis, presignatures, me)
}

fn bench_redis_triple_operations_100(c: &mut Criterion) {
    let rt = runtime();
    let (_redis, triples, me) = rt.block_on(setup_redis_env(100));

    c.bench_function("reserve_insert_100_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let t = dummy_triple(99999); // Use a high ID to avoid conflicts
                if let Some(mut slot) = triples.reserve(t.id).await {
                    slot.insert(t, me).await;
                }
            });
        });
    });

    let test_ids = (0..100).map(|i| i as u64).collect::<Vec<_>>();
    let take_two_ids = test_ids.chunks(2).next().unwrap();

    c.bench_function("take_two_100_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = triples
                    .take_two(take_two_ids[0], take_two_ids[1], me, me)
                    .await;
            });
        });
    });

    c.bench_function("take_two_mine_100_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = triples.take_two_mine(me).await;
            });
        });
    });

    c.bench_function("fetch_owned_100_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = triples.fetch_owned(me).await;
            });
        });
    });

    // async drop:
    rt.block_on(async {
        drop(_redis);
    });
}

fn bench_redis_triple_operations_1000(c: &mut Criterion) {
    let rt = runtime();
    let (_redis, triples, me) = rt.block_on(setup_redis_env(1000));

    c.bench_function("reserve_insert_1000_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let t = dummy_triple(99999); // Use a high ID to avoid conflicts
                if let Some(mut slot) = triples.reserve(t.id).await {
                    slot.insert(t, me).await;
                }
            });
        });
    });

    let test_ids = (0..1000).map(|i| i as u64).collect::<Vec<_>>();
    let take_two_ids = test_ids.chunks(2).next().unwrap();

    c.bench_function("take_two_1000_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = triples
                    .take_two(take_two_ids[0], take_two_ids[1], me, me)
                    .await;
            });
        });
    });

    c.bench_function("take_two_mine_1000_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = triples.take_two_mine(me).await;
            });
        });
    });

    c.bench_function("fetch_owned_1000_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = triples.fetch_owned(me).await;
            });
        });
    });

    // async drop:
    rt.block_on(async {
        drop(_redis);
    });
}

fn bench_redis_triple_operations_10000(c: &mut Criterion) {
    let rt = runtime();
    let (_redis, triples, me) = rt.block_on(setup_redis_env(10000));

    c.bench_function("reserve_insert_10000_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let t = dummy_triple(99999); // Use a high ID to avoid conflicts
                if let Some(mut slot) = triples.reserve(t.id).await {
                    slot.insert(t, me).await;
                }
            });
        });
    });

    let test_ids = (0..10000).map(|i| i as u64).collect::<Vec<_>>();
    let take_two_ids = test_ids.chunks(2).next().unwrap();

    c.bench_function("take_two_10000_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = triples
                    .take_two(take_two_ids[0], take_two_ids[1], me, me)
                    .await;
            });
        });
    });

    c.bench_function("take_two_mine_10000_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = triples.take_two_mine(me).await;
            });
        });
    });

    c.bench_function("fetch_owned_10000_triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = triples.fetch_owned(me).await;
            });
        });
    });

    // async drop:
    rt.block_on(async {
        drop(_redis);
    });
}

fn bench_redis_presignature_operations_100(c: &mut Criterion) {
    let rt = runtime();
    let (_redis, presignatures, me) = rt.block_on(setup_redis_env_presignatures(100));

    c.bench_function("reserve_insert_100_presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                let p = dummy_presignature(99999); // Use a high ID to avoid conflicts
                if let Some(mut slot) = presignatures.reserve(p.id).await {
                    slot.insert(p, me).await;
                }
            });
        });
    });

    c.bench_function("take_mine_100_presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = presignatures.take_mine(me).await;
            });
        });
    });

    c.bench_function("fetch_owned_100_presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = presignatures.fetch_owned(me).await;
            });
        });
    });

    // async drop:
    rt.block_on(async {
        drop(_redis);
    });
}

fn bench_redis_presignature_operations_1000(c: &mut Criterion) {
    let rt = runtime();
    let (_redis, presignatures, me) = rt.block_on(setup_redis_env_presignatures(1000));

    c.bench_function("reserve_insert_1000_presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                let p = dummy_presignature(99999); // Use a high ID to avoid conflicts
                if let Some(mut slot) = presignatures.reserve(p.id).await {
                    slot.insert(p, me).await;
                }
            });
        });
    });

    c.bench_function("take_mine_1000_presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = presignatures.take_mine(me).await;
            });
        });
    });

    c.bench_function("fetch_owned_1000_presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = presignatures.fetch_owned(me).await;
            });
        });
    });

    // async drop:
    rt.block_on(async {
        drop(_redis);
    });
}

fn bench_redis_presignature_operations_10000(c: &mut Criterion) {
    let rt = runtime();
    let (_redis, presignatures, me) = rt.block_on(setup_redis_env_presignatures(10000));

    c.bench_function("reserve_insert_10000_presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                let p = dummy_presignature(99999); // Use a high ID to avoid conflicts
                if let Some(mut slot) = presignatures.reserve(p.id).await {
                    slot.insert(p, me).await;
                }
            });
        });
    });

    c.bench_function("take_mine_10000_presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = presignatures.take_mine(me).await;
            });
        });
    });

    c.bench_function("fetch_owned_10000_presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = presignatures.fetch_owned(me).await;
            });
        });
    });

    // async drop:
    rt.block_on(async {
        drop(_redis);
    });
}

criterion_group!(
    benches,
    bench_redis_triple_operations_100,
    bench_redis_triple_operations_1000,
    bench_redis_triple_operations_10000,
    bench_redis_presignature_operations_100,
    bench_redis_presignature_operations_1000,
    bench_redis_presignature_operations_10000,
);
criterion_main!(benches);
