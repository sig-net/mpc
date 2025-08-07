use std::collections::HashMap;

use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers;
use k256::Secp256k1;
use mpc_crypto::PublicKey;
use mpc_node::protocol::presignature::{Presignature, PresignatureId, PresignatureSpawner};
use mpc_node::protocol::triple::{Triple, TripleId, TripleSpawner};
use mpc_node::protocol::MessageChannel;
use mpc_node::types::SecretKeyShare;
use test_log::test;

#[test(tokio::test)]
async fn test_triple_persistence() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("test-triple-persistence")
        .init_network()
        .await?;

    let node0 = Participant::from(0);
    let node1 = Participant::from(1);
    let (_, _, msg) = MessageChannel::new();
    let node0_id = "party0.near".parse().unwrap();
    let redis = containers::Redis::run(&spawner).await;
    let triple_storage = redis.triple_storage(&node0_id);
    let triple_spawner = TripleSpawner::new(node0, 5, 123, &node0_id, &triple_storage, msg);

    let triple_id1: u64 = 1;
    let triple_id2: u64 = 2;

    // Check that the storage is empty at the start
    assert!(!triple_storage.contains(triple_id1).await);
    assert!(!triple_spawner.contains_mine(triple_id1).await);
    assert_eq!(triple_storage.len_generated().await, 0);
    assert_eq!(triple_storage.len_by_owner(node0).await, 0);
    assert!(triple_storage.is_empty().await);
    assert_eq!(triple_spawner.len_potential().await, 0);

    triple_storage
        .reserve(triple_id1)
        .await
        .unwrap()
        .insert(dummy_triple(triple_id1), node1)
        .await;
    triple_storage
        .reserve(triple_id2)
        .await
        .unwrap()
        .insert(dummy_triple(triple_id2), node1)
        .await;

    assert_eq!(
        triple_storage.fetch_participants(triple_id1).await,
        dummy_participants(1..=2),
    );

    // Try kicking the participants if to check they don't have the shares:
    let mut kick = HashMap::new();
    kick.insert(triple_id1, vec![Participant::from(1)]);
    kick.insert(triple_id2, vec![Participant::from(1), Participant::from(2)]);
    triple_storage.kick_participants(kick).await;
    assert_eq!(
        triple_storage.fetch_participants(triple_id1).await,
        vec![Participant::from(2)],
    );
    assert_eq!(triple_storage.fetch_participants(triple_id2).await, vec![]);

    // Check that the storage contains the foreign triple
    assert!(triple_spawner.contains(triple_id1).await);
    assert!(triple_spawner.contains(triple_id2).await);
    assert!(!triple_spawner.contains_mine(triple_id1).await);
    assert!(!triple_spawner.contains_mine(triple_id2).await);
    assert_eq!(triple_storage.len_generated().await, 2);
    assert_eq!(triple_storage.len_by_owner(node0).await, 0);
    assert_eq!(triple_spawner.len_potential().await, 2);

    // Take triple and check that it is removed from the storage and added to used set
    triple_storage
        .take_two(triple_id1, triple_id2, node1, node0)
        .await
        .unwrap();
    assert!(!triple_spawner.contains(triple_id1).await);
    assert!(!triple_spawner.contains(triple_id2).await);
    assert!(!triple_spawner.contains_mine(triple_id1).await);
    assert!(!triple_spawner.contains_mine(triple_id2).await);
    assert_eq!(triple_storage.len_generated().await, 0);
    assert_eq!(triple_spawner.len_mine().await, 0);
    assert_eq!(triple_spawner.len_potential().await, 0);
    assert!(triple_storage.contains_used(triple_id1).await);
    assert!(triple_storage.contains_used(triple_id2).await);

    // Attempt to re-reserve used triples and check that it cannot be reserved since it is used.
    assert!(triple_storage.reserve(triple_id1).await.is_none());
    assert!(triple_storage.reserve(triple_id2).await.is_none());
    assert!(!triple_spawner.contains(triple_id1).await);
    assert!(!triple_spawner.contains(triple_id2).await);

    let id3 = 3;
    let id4: u64 = 4;

    // check that reserve and unreserve works:
    let slot = triple_storage.reserve(id3).await.unwrap();
    slot.unreserve().await;

    // Add mine triple and check that it is in the storage
    triple_storage
        .reserve(id3)
        .await
        .unwrap()
        .insert(dummy_triple(id3), node0)
        .await;
    triple_storage
        .reserve(id4)
        .await
        .unwrap()
        .insert(dummy_triple(id4), node0)
        .await;
    assert!(triple_spawner.contains(id3).await);
    assert!(triple_spawner.contains(id4).await);
    assert!(triple_spawner.contains_mine(id3).await);
    assert!(triple_spawner.contains_mine(id4).await);
    assert_eq!(triple_storage.len_generated().await, 2);
    assert_eq!(triple_spawner.len_mine().await, 2);
    assert_eq!(triple_spawner.len_potential().await, 2);

    // Take mine triple and check that it is removed from the storage and added to used set
    triple_storage.take_two_mine(node0).await.unwrap();
    assert!(!triple_spawner.contains(id3).await);
    assert!(!triple_spawner.contains(id4).await);
    assert!(!triple_spawner.contains_mine(id3).await);
    assert!(!triple_spawner.contains_mine(id4).await);
    assert_eq!(triple_storage.len_generated().await, 0);
    assert_eq!(triple_spawner.len_mine().await, 0);
    assert!(triple_storage.is_empty().await);
    assert_eq!(triple_spawner.len_potential().await, 0);
    assert!(triple_storage.contains_used(id3).await);
    assert!(triple_storage.contains_used(id4).await);

    // Attempt to re-insert used mine triples and check that it fails
    assert!(triple_storage.reserve(id3).await.is_none());
    assert!(triple_storage.reserve(id4).await.is_none());
    assert!(!triple_spawner.contains(id3).await);
    assert!(!triple_spawner.contains(id4).await);

    assert!(triple_storage.clear().await);
    // Have our node0 observe shares for triples 10 to 15 where node1 is owner.
    for id in 10..=15 {
        triple_storage
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_triple(id), node1)
            .await;
    }

    // Have our node0 own 16 to 20
    for id in 16..=20 {
        triple_storage
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_triple(id), node0)
            .await;
    }

    // Let's say Node1 somehow used up triple 10, 11, 12 so we only have 13,14,15
    let mut outdated: Vec<TripleId> = triple_storage.remove_outdated(node1, &[13, 14, 15]).await;
    outdated.sort();
    assert_eq!(outdated, vec![10, 11, 12]);

    assert_eq!(triple_storage.len_generated().await, 8);
    assert_eq!(triple_spawner.len_mine().await, 5);
    assert_eq!(triple_spawner.len_potential().await, 8);

    Ok(())
}

#[test(tokio::test)]
async fn test_presignature_persistence() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("test-presignature-persistence")
        .init_network()
        .await?;

    let node0 = Participant::from(0);
    let node1 = Participant::from(1);
    let (_, _, msg) = MessageChannel::new();
    let node0_id = "party0.near".parse().unwrap();
    let redis = containers::Redis::run(&spawner).await;
    let triple_storage = redis.triple_storage(&node0_id);
    let presignature_storage = redis.presignature_storage(&node0_id);
    let presignature_spawner = PresignatureSpawner::new(
        Participant::from(0),
        5,
        123,
        &SecretKeyShare::default(),
        &PublicKey::default(),
        &node0_id,
        &triple_storage,
        &presignature_storage,
        msg,
    );

    let id = 1;
    let presignature = dummy_presignature(id);

    // Check that the storage is empty at the start
    assert!(!presignature_storage.contains(id).await);
    assert!(!presignature_spawner.contains_mine(id).await);
    assert_eq!(presignature_storage.len_generated().await, 0);
    assert_eq!(presignature_spawner.len_mine().await, 0);
    assert!(presignature_storage.is_empty().await);
    assert_eq!(presignature_spawner.len_potential().await, 0);

    // check that reserve then dropping unreserves the slot:
    let slot = presignature_storage.reserve(presignature.id).await.unwrap();
    if let Some(task) = slot.unreserve() {
        task.await.unwrap();
    }

    // Insert presignature owned by node1, with our node0 view being that it is a foreign presignature
    assert!(
        presignature_storage
            .reserve(presignature.id)
            .await
            .unwrap()
            .insert(presignature, node1)
            .await
    );

    // Check that the storage contains the foreign presignature
    assert!(presignature_storage.contains(id).await);
    assert!(!presignature_spawner.contains_mine(id).await);
    assert_eq!(presignature_storage.len_generated().await, 1);
    assert_eq!(presignature_spawner.len_mine().await, 0);
    assert_eq!(presignature_spawner.len_potential().await, 1);

    // Take presignature and check that it is removed from the storage and added to used set
    presignature_storage.take(id, node1, node0).await.unwrap();
    assert!(!presignature_storage.contains(id).await);
    assert!(!presignature_spawner.contains_mine(id).await);
    assert_eq!(presignature_storage.len_generated().await, 0);
    assert_eq!(presignature_spawner.len_mine().await, 0);
    assert_eq!(presignature_spawner.len_potential().await, 0);
    assert!(presignature_storage.contains_used(id).await);

    // Attempt to re-insert used presignature and check that it fails
    assert!(presignature_storage.reserve(id).await.is_none());
    assert!(!presignature_spawner.contains(id).await);

    let id2 = 2;
    let mine_presignature = dummy_presignature(id2);

    // Add a presignature to our own node0
    assert!(
        presignature_storage
            .reserve(id2)
            .await
            .unwrap()
            .insert(mine_presignature, node0)
            .await
    );

    assert!(presignature_storage.contains(id2).await);
    assert!(presignature_spawner.contains_mine(id2).await);
    assert_eq!(presignature_storage.len_generated().await, 1);
    assert_eq!(presignature_spawner.len_mine().await, 1);
    assert_eq!(presignature_spawner.len_potential().await, 1);

    // Take mine presignature and check that it is removed from the storage and added to used set
    presignature_storage.take_mine(node0).await.unwrap();
    assert!(!presignature_storage.contains(id2).await);
    assert!(!presignature_spawner.contains_mine(id2).await);
    assert_eq!(presignature_storage.len_generated().await, 0);
    assert_eq!(presignature_spawner.len_mine().await, 0);
    assert!(presignature_storage.is_empty().await);
    assert_eq!(presignature_spawner.len_potential().await, 0);
    assert!(presignature_storage.contains_used(id2).await);

    // Attempt to re-insert used mine presignature and check that it fails
    assert!(presignature_storage.reserve(id2).await.is_none());
    assert!(!presignature_spawner.contains(id2).await);

    presignature_storage
        .reserve(10)
        .await
        .unwrap()
        .insert(dummy_presignature(10), node1)
        .await;
    presignature_storage
        .reserve(11)
        .await
        .unwrap()
        .insert(dummy_presignature(11), node1)
        .await;

    // Try kicking the participants if to check they don't have the shares:
    let mut kick = HashMap::new();
    kick.insert(10, vec![Participant::from(1)]);
    kick.insert(11, vec![Participant::from(1), Participant::from(2)]);
    presignature_storage.kick_participants(kick).await;
    assert_eq!(
        presignature_storage.fetch_participants(10).await,
        vec![Participant::from(2)],
    );
    assert_eq!(presignature_storage.fetch_participants(11).await, vec![]);

    assert!(presignature_storage.clear().await);
    // Have our node0 observe shares for triples 10 to 15 where node1 is owner.
    for id in 10..=15 {
        presignature_storage
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_presignature(id), node1)
            .await;
    }

    // Have our node0 own 16 to 20
    for id in 16..=20 {
        presignature_storage
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_presignature(id), node0)
            .await;
    }

    // Let's say Node1 somehow used up triple 10, 11, 12 so we only have 13,14,15
    let mut outdated: Vec<PresignatureId> = presignature_storage
        .remove_outdated(node1, &[13, 14, 15])
        .await;
    outdated.sort();
    assert_eq!(outdated, vec![10, 11, 12]);

    assert_eq!(presignature_storage.len_generated().await, 8);
    assert_eq!(presignature_spawner.len_mine().await, 5);
    assert_eq!(presignature_spawner.len_potential().await, 8);

    Ok(())
}

fn dummy_presignature(id: u64) -> Presignature {
    Presignature {
        id,
        output: PresignOutput {
            big_r: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            k: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            sigma: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
        },
        participants: dummy_participants(1..=2),
    }
}

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
            participants: dummy_participants(1..=2),
            threshold: 5,
        },
    }
}

fn dummy_participants(participants: impl IntoIterator<Item = u32>) -> Vec<Participant> {
    participants.into_iter().map(Participant::from).collect()
}
