use std::time::Duration;

use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
use integration_tests::cluster;
use k256::Secp256k1;

use integration_tests::cluster::spawner::ClusterSpawner;
use mpc_node::mesh::Mesh;
use mpc_node::node_client::{self, NodeClient};
use mpc_node::protocol::contract::primitives::Participants;
use mpc_node::protocol::contract::RunningContractState;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::sync::{SyncTask, SyncUpdate};
use mpc_node::protocol::triple::Triple;
use mpc_node::protocol::{ParticipantInfo, ProtocolState};
use mpc_node::rpc::NodeStateWatcher;
use mpc_node::storage::{PresignatureStorage, TripleStorage};

#[test_log::test(tokio::test)]
async fn test_state_sync_update() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("protocol-sync")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let num_nodes = 1;
    let threshold = 2;
    let node0_account_id = "p0_test.near".parse().unwrap();
    let node1 = Participant::from(1);

    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();
    let ping_interval = Duration::from_millis(300);
    let client = NodeClient::new(&node_client::Options::default());
    let participants = participants(num_nodes);
    let node0_triples = redis.triple_storage(&node0_account_id);
    let node0_presignatures = redis.presignature_storage(&node0_account_id);

    let watcher = NodeStateWatcher::mock(
        &node0_account_id,
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

    let mesh = Mesh::new(
        &client,
        mpc_node::mesh::Options {
            ping_interval: ping_interval.as_millis() as u64,
        },
    );
    let (sync_channel, sync) = SyncTask::new(
        &client,
        node0_triples.clone(),
        node0_presignatures.clone(),
        mesh.state().clone(),
        watcher,
    );
    tokio::spawn(sync.run());

    // insert shares of triples/presignatures to node0, that belong to node1
    insert_triples(&node0_triples, node1, 0..=5).await;
    insert_presignatures(&node0_presignatures, node1, 0..=5).await;

    // Create an update where node1 is trying to sync with node0, where node1 only has
    // triples/presignatures 0 to 3, so 4 and 5 should be deleted from node0.
    let valid = vec![0, 1, 2, 3];
    let invalid = vec![4, 5];

    let update = SyncUpdate {
        from: node1,
        triples: valid.iter().copied().collect(),
        presignatures: valid.iter().copied().collect(),
    };
    sync_channel.request_update(update).await;
    // Give it some time for sync to process the update
    tokio::time::sleep(Duration::from_secs(3)).await;

    validate_triples(&node0_triples, node1, &valid, &invalid).await;
    validate_presignatures(&node0_presignatures, node1, &valid, &invalid).await;

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_state_sync_e2e() {
    // start the cluster of nodes immediately without waiting for them to be running.
    let nodes = cluster::spawn()
        .disable_wait_running()
        .disable_prestockpile()
        .await
        .unwrap();

    // immediately add to triples/presignatures storage the triples/presignatures we want to invalidate.

    // NOTE: cannot reliably get the first participant until running state is reached, so
    // this assumes that 0 is the first participant.
    let node0 = 0;
    let node0_triples = nodes.triples(node0);
    let node0_presignatures = nodes.presignatures(node0);

    let node1 = Participant::from(1);
    let node1_triples = nodes.triples(u32::from(node1) as usize);
    let node1_presignatures = nodes.presignatures(u32::from(node1) as usize);

    // insert triples that will be invalidated after a sync, since nobody else has them.
    // node0 is saying that they have 0 to 5, but node1 will sync and say they have 4 and 5 only.
    insert_triples(&node0_triples, node1, 0..=5).await;
    insert_triples(&node1_triples, node1, 4..=5).await;
    insert_presignatures(&node0_presignatures, node1, 0..=5).await;
    insert_presignatures(&node1_presignatures, node1, 4..=5).await;

    // Wait for the nodes to be running and then check the nodes has the right triples/presignatures
    nodes.wait().running().await.unwrap();
    // Give some time for the first sync broadcast to finish.
    tokio::time::sleep(Duration::from_secs(3)).await;

    validate_triples(&node0_triples, node1, &[4, 5], &[0, 1, 2, 3]).await;
    validate_triples(&node1_triples, node1, &[4, 5], &[0, 1, 2, 3]).await;
    validate_presignatures(&node0_presignatures, node1, &[4, 5], &[0, 1, 2, 3]).await;
    validate_presignatures(&node0_presignatures, node1, &[4, 5], &[0, 1, 2, 3]).await;

    // Check that signing works as normal.
    nodes.wait().signable().await.unwrap();
    nodes.sign().await.unwrap();
}

async fn insert_triples(
    triples: &TripleStorage,
    node: Participant,
    range: impl IntoIterator<Item = u64>,
) {
    for id in range {
        triples
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_triple(id), node)
            .await;
    }
}

async fn validate_triples(
    triples: &TripleStorage,
    owner: Participant,
    valid: &[u64],
    invalid: &[u64],
) {
    for id in valid {
        assert!(
            triples.contains_by_owner(*id, owner).await,
            "triple={id} should be valid"
        );
    }

    for id in invalid {
        assert!(
            !triples.contains_by_owner(*id, owner).await,
            "triple={id} should be invalid"
        );
    }
}

async fn insert_presignatures(
    presignatures: &PresignatureStorage,
    node: Participant,
    range: impl IntoIterator<Item = u64>,
) {
    for id in range {
        presignatures
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_presignature(id), node)
            .await;
    }
}

async fn validate_presignatures(
    presignatures: &PresignatureStorage,
    owner: Participant,
    valid: &[u64],
    invalid: &[u64],
) {
    for id in valid {
        assert!(
            presignatures.contains_by_owner(*id, owner).await,
            "presignature={id} should be valid"
        );
    }

    for id in invalid {
        assert!(
            !presignatures.contains_by_owner(*id, owner).await,
            "presignature={id} should be invalid"
        );
    }
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

// TODO: cleanup and move this to a common test utils module
fn participants(num_nodes: usize) -> Participants {
    let (_cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let mut participants = Participants::default();
    for i in 0..num_nodes {
        let id = Participant::from(i as u32);
        participants.insert(
            &id,
            ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: id.into(),
                url: "http://localhost:3030".to_string(),
                account_id: format!("p{i}_test.near").parse().unwrap(),
            },
        );
    }
    participants
}
