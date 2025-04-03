use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers;
use k256::Secp256k1;
use mpc_node::mesh::MeshState;
use mpc_node::node_client::{self, NodeClient};
use mpc_node::protocol::contract::primitives::Participants;
use mpc_node::protocol::contract::RunningContractState;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::sync::SyncTask;
use mpc_node::protocol::triple::Triple;
use mpc_node::protocol::{ParticipantInfo, ProtocolState};
use mpc_node::rpc::NodeStateWatcher;
use tokio::sync::RwLock;

#[test_log::test(tokio::test)]
async fn test_protocol_sync_take() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("test-protocol-sync")
        .init_network()
        .await?;

    let node_id = "test.near".parse().unwrap();
    let redis = containers::Redis::run(&spawner).await;
    let triples = redis.triple_storage(&node_id);
    let presignatures = redis.presignature_storage(&node_id);
    let client = NodeClient::new(&node_client::Options::default());
    // No participants yet, but sync should still be able to see that the threshold is 1
    let threshold = 1;
    let me = Participant::from(0);
    let participants = {
        let (_cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
        let mut participants = Participants::default();
        participants.insert(
            &me,
            ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: me.into(),
                url: "http://localhost:3030".to_string(),
                account_id: "test.near".parse().unwrap(),
            },
        );
        participants
    };
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
            participants,
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold,
        }),
    );
    let (_sync_channel, sync) = SyncTask::new(
        &client,
        triples.clone(),
        presignatures.clone(),
        mesh_state,
        watcher,
    );
    let sync_handle = tokio::spawn(sync.run());

    let mut triple_set = HashSet::new();
    let mut presignature_set = HashSet::new();

    for i in 0..10 {
        let t = dummy_triple(i);
        triple_set.insert(t.id);
        assert!(triples.reserve(i).await.unwrap().insert(t, me).await);
    }
    for i in 0..10 {
        let p = dummy_presignature(i);
        presignature_set.insert(p.id);
        assert!(presignatures.reserve(i).await.unwrap().insert(p, me).await);
    }

    // Give it some time for sync to process the inserts
    tokio::time::sleep(Duration::from_secs(3)).await;

    sync_handle.abort();
    Ok(())
}

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
