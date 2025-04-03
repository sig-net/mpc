use std::{sync::Arc, time::Instant};

use cait_sith::{
    protocol::Participant,
    triples::{TriplePub, TripleShare},
    PresignOutput,
};
use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::CurveArithmetic;
use integration_tests::{cluster::spawner::ClusterSpawner, containers::Redis};
use k256::Secp256k1;
use mpc_node::{
    mesh::MeshState,
    node_client::{self, NodeClient},
    protocol::{
        contract::{primitives::Participants, RunningContractState},
        presignature::Presignature,
        sync::{SyncChannel, SyncTask},
        triple::Triple,
        ParticipantInfo, ProtocolState,
    },
    rpc::NodeStateWatcher,
    storage::{PresignatureStorage, TripleStorage},
};
use near_account_id::AccountId;
use tokio::{runtime::Runtime, sync::RwLock};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn participants(len: usize) -> Participants {
    let (_cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let mut participants = Participants::default();
    for i in 0..len {
        let id = Participant::from(i as u32);
        participants.insert(
            &id,
            ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: id.into(),
                url: "http://localhost:3030".to_string(),
                account_id: format!("test{i}.near").parse().unwrap(),
            },
        );
    }
    participants
}

struct SyncEnv {
    threshold: usize,
    node_id: AccountId,
    me: Participant,
    participants: Participants,
    mesh_state: Arc<RwLock<MeshState>>,
    client: NodeClient,
    redis: Redis,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    sync_channel: SyncChannel,
}

fn env() -> (Runtime, SyncEnv) {
    let threshold = 1;
    let node_id = "test0.near".parse().unwrap();
    let me = Participant::from(0);
    let participants = participants(12);

    let rt = runtime();
    let env = rt.block_on(async move {
        let spawner = ClusterSpawner::default()
            .with_config(|cfg| {
                cfg.protocol.triple.min_triples = 3 * 1024;
                cfg.protocol.triple.max_triples = 1000000;
            })
            .network("bench-protocol-sync")
            .init_network()
            .await
            .unwrap();

        let redis = spawner.spawn_redis().await;
        let triples = redis.triple_storage(&node_id);
        let presignatures = redis.presignature_storage(&node_id);
        {
            let participants = into_contract_participants(&participants);
            redis
                .stockpile_triples(&spawner.cfg, &participants, 1)
                .await;
        }
        let client = NodeClient::new(&node_client::Options::default());
        let mesh_state = Arc::new(RwLock::new(MeshState {
            stable: participants.keys_vec(),
            active: participants.clone(),
        }));

        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk = sk.public_key();
        let watcher = NodeStateWatcher::mock(
            &node_id,
            ProtocolState::Running(RunningContractState {
                epoch: 0,
                public_key: *pk.as_affine(),
                participants: participants.clone(),
                candidates: Default::default(),
                join_votes: Default::default(),
                leave_votes: Default::default(),
                threshold,
            }),
        );
        let (sync_channel, sync) = SyncTask::new(
            &client,
            triples.clone(),
            presignatures.clone(),
            mesh_state.clone(),
            watcher.clone(),
        );

        // let sync_handle = tokio::spawn(sync.run());

        SyncEnv {
            threshold,
            node_id,
            me,
            participants,
            mesh_state,
            client,
            redis,
            triples,
            presignatures,
            sync_channel,
        }
    });

    (rt, env)
}

fn bench_load_keys(c: &mut Criterion) {
    let env_start = Instant::now();
    let (rt, env) = env();
    tracing::info!(elapsed = ?env_start.elapsed(), "init store env");

    c.bench_function("add 1000 triples", |b| {
        b.iter(|| {
            rt.block_on(async {
                for i in 0..1000 {
                    let t = dummy_triple(i);
                    env.triples
                        .reserve(t.id, env.me)
                        .await
                        .unwrap()
                        .insert(t, env.me)
                        .await;
                }
            });
        })
    });

    c.bench_function("add 1000 presignatures", |b| {
        b.iter(|| {
            rt.block_on(async {
                for i in 0..1000 {
                    let p = dummy_presignature(i);
                    env.presignatures
                        .reserve(p.id, env.me)
                        .await
                        .unwrap()
                        .insert(p, env.me)
                        .await;
                }
            });
        })
    });

    c.bench_function("load 1024 mine triple keys", |b| {
        b.iter(|| {
            let task = || async {
                env.triples.fetch_owned(env.me).await;
            };

            rt.block_on(task());
        })
    });

    // async drop:
    rt.block_on(async {
        drop(env);
    });
}

criterion_group!(bench_sync, bench_load_keys,);
criterion_main!(bench_sync);

// TODO: cleanup and move this to a common test utils module
fn dummy_presignature(id: u64) -> Presignature {
    Presignature {
        id,
        output: PresignOutput {
            big_r: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            k: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            sigma: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
        },
        participants: vec![Participant::from(1), Participant::from(2)],
    }
}

// TODO: cleanup and move this to a common test utils module
fn dummy_triple(id: u64) -> Triple {
    Triple {
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

fn into_contract_participants(
    participants: &Participants,
) -> mpc_contract::primitives::Participants {
    mpc_contract::primitives::Participants {
        next_id: participants.len() as u32,
        participants: participants
            .participants
            .values()
            .map(|info| {
                (
                    info.account_id.clone(),
                    mpc_contract::primitives::ParticipantInfo {
                        account_id: info.account_id.clone(),
                        url: info.url.clone(),
                        cipher_pk: info.cipher_pk.to_bytes(),
                        sign_pk: near_sdk::PublicKey::from_parts(
                            match info.sign_pk.key_type() {
                                near_crypto::KeyType::ED25519 => near_sdk::CurveType::ED25519,
                                near_crypto::KeyType::SECP256K1 => near_sdk::CurveType::SECP256K1,
                            },
                            info.sign_pk.key_data().to_vec(),
                        )
                        .unwrap(),
                    },
                )
            })
            .collect(),
        account_to_participant_id: participants
            .participants
            .iter()
            .map(|(participant, info)| (info.account_id.clone(), (*participant).into()))
            .collect(),
    }
}
