use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers;
use k256::Secp256k1;
use mpc_node::protocol::presignature::{Presignature, PresignatureManager};
use mpc_node::protocol::triple::{Triple, TripleManager};
use mpc_node::protocol::MessageChannel;
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
    let triple_manager = TripleManager::new(node0, 5, 123, &node0_id, &triple_storage, msg);

    let triple_id1: u64 = 1;
    let triple_id2: u64 = 2;

    // Check that the storage is empty at the start
    assert!(!triple_manager.contains(triple_id1).await);
    assert!(!triple_manager.contains_mine(triple_id1).await);
    assert_eq!(triple_manager.len_generated().await, 0);
    assert_eq!(triple_manager.len_mine().await, 0);
    assert!(triple_manager.is_empty().await);
    assert_eq!(triple_manager.len_potential().await, 0);

    triple_manager
        .reserve(triple_id1)
        .await
        .unwrap()
        .insert(dummy_triple(triple_id1), node1)
        .await;
    triple_manager
        .reserve(triple_id2)
        .await
        .unwrap()
        .insert(dummy_triple(triple_id2), node1)
        .await;

    // Check that the storage contains the foreign triple
    assert!(triple_manager.contains(triple_id1).await);
    assert!(triple_manager.contains(triple_id2).await);
    assert!(!triple_manager.contains_mine(triple_id1).await);
    assert!(!triple_manager.contains_mine(triple_id2).await);
    assert_eq!(triple_manager.len_generated().await, 2);
    assert_eq!(triple_manager.len_mine().await, 0);
    assert_eq!(triple_manager.len_potential().await, 2);

    // Take triple and check that it is removed from the storage and added to used set
    triple_manager
        .take_two(triple_id1, triple_id2, node1)
        .await
        .unwrap();
    assert!(!triple_manager.contains(triple_id1).await);
    assert!(!triple_manager.contains(triple_id2).await);
    assert!(!triple_manager.contains_mine(triple_id1).await);
    assert!(!triple_manager.contains_mine(triple_id2).await);
    assert_eq!(triple_manager.len_generated().await, 0);
    assert_eq!(triple_manager.len_mine().await, 0);
    assert_eq!(triple_manager.len_potential().await, 0);
    assert!(triple_storage.contains_used(triple_id1).await.unwrap());
    assert!(triple_storage.contains_used(triple_id2).await.unwrap());

    // Attempt to re-reserve used triples and check that it cannot be reserved since it is used.
    assert!(triple_manager.reserve(triple_id1).await.is_none());
    assert!(triple_manager.reserve(triple_id2).await.is_none());
    assert!(!triple_manager.contains(triple_id1).await);
    assert!(!triple_manager.contains(triple_id2).await);

    let mine_id1: u64 = 3;
    let mine_id2: u64 = 4;

    // Add mine triple and check that it is in the storage
    triple_manager
        .reserve(mine_id1)
        .await
        .unwrap()
        .insert(dummy_triple(mine_id1), node0)
        .await;
    triple_manager
        .reserve(mine_id2)
        .await
        .unwrap()
        .insert(dummy_triple(mine_id2), node0)
        .await;
    assert!(triple_manager.contains(mine_id1).await);
    assert!(triple_manager.contains(mine_id2).await);
    assert!(triple_manager.contains_mine(mine_id1).await);
    assert!(triple_manager.contains_mine(mine_id2).await);
    assert_eq!(triple_manager.len_generated().await, 2);
    assert_eq!(triple_manager.len_mine().await, 2);
    assert_eq!(triple_manager.len_potential().await, 2);

    // Take mine triple and check that it is removed from the storage and added to used set
    triple_manager.take_two_mine().await.unwrap();
    assert!(!triple_manager.contains(mine_id1).await);
    assert!(!triple_manager.contains(mine_id2).await);
    assert!(!triple_manager.contains_mine(mine_id1).await);
    assert!(!triple_manager.contains_mine(mine_id2).await);
    assert_eq!(triple_manager.len_generated().await, 0);
    assert_eq!(triple_manager.len_mine().await, 0);
    assert!(triple_manager.is_empty().await);
    assert_eq!(triple_manager.len_potential().await, 0);
    assert!(triple_storage.contains_used(mine_id1).await.unwrap());
    assert!(triple_storage.contains_used(mine_id2).await.unwrap());

    // Attempt to re-insert used mine triples and check that it fails
    assert!(triple_manager.reserve(mine_id1).await.is_none());
    assert!(triple_manager.reserve(mine_id2).await.is_none());
    assert!(!triple_manager.contains(mine_id1).await);
    assert!(!triple_manager.contains(mine_id2).await);

    triple_storage.clear().await.unwrap();
    // Have our node0 observe shares for triples 10 to 15 where node1 is owner.
    for id in 10..=15 {
        triple_manager
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_triple(id), node1)
            .await;
    }

    // Let's say Node1 somehow used up triple 10, 11, 12 so we only have 13,14,15
    let mut outdated = triple_storage.remove_outdated(node1, &[13, 14, 15]).await;
    outdated.sort();
    assert_eq!(outdated, vec![10, 11, 12]);

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
    let mut presignature_manager = PresignatureManager::new(
        Participant::from(0),
        5,
        123,
        &node0_id,
        &triple_storage,
        &presignature_storage,
        msg,
    );

    let id = 1;
    let presignature = dummy_presignature(id);

    // Check that the storage is empty at the start
    assert!(!presignature_manager.contains(id).await);
    assert!(!presignature_manager.contains_mine(id).await);
    assert_eq!(presignature_manager.len_generated().await, 0);
    assert_eq!(presignature_manager.len_mine().await, 0);
    assert!(presignature_manager.is_empty().await);
    assert_eq!(presignature_manager.len_potential().await, 0);

    // Insert presignature owned by node1, with our node0 view being that it is a foreign presignature
    assert!(
        presignature_manager
            .reserve(presignature.id)
            .await
            .unwrap()
            .insert(presignature, node1)
            .await
    );

    // Check that the storage contains the foreign presignature
    assert!(presignature_manager.contains(id).await);
    assert!(!presignature_manager.contains_mine(id).await);
    assert_eq!(presignature_manager.len_generated().await, 1);
    assert_eq!(presignature_manager.len_mine().await, 0);
    assert_eq!(presignature_manager.len_potential().await, 1);

    // Take presignature and check that it is removed from the storage and added to used set
    presignature_manager.take(id, node1).await.unwrap();
    assert!(!presignature_manager.contains(id).await);
    assert!(!presignature_manager.contains_mine(id).await);
    assert_eq!(presignature_manager.len_generated().await, 0);
    assert_eq!(presignature_manager.len_mine().await, 0);
    assert_eq!(presignature_manager.len_potential().await, 0);
    assert!(presignature_storage.contains_used(id).await.unwrap());

    // Attempt to re-insert used presignature and check that it fails
    assert!(presignature_manager.reserve(id).await.is_none());
    assert!(!presignature_manager.contains(id).await);

    let id2 = 2;
    let mine_presignature = dummy_presignature(id2);

    // Add a presignature to our own node0
    assert!(
        presignature_manager
            .reserve(id2)
            .await
            .unwrap()
            .insert(mine_presignature, node0)
            .await
    );

    assert!(presignature_manager.contains(id2).await);
    assert!(presignature_manager.contains_mine(id2).await);
    assert_eq!(presignature_manager.len_generated().await, 1);
    assert_eq!(presignature_manager.len_mine().await, 1);
    assert_eq!(presignature_manager.len_potential().await, 1);

    // Take mine presignature and check that it is removed from the storage and added to used set
    presignature_manager.take_mine().await.unwrap();
    assert!(!presignature_manager.contains(id2).await);
    assert!(!presignature_manager.contains_mine(id2).await);
    assert_eq!(presignature_manager.len_generated().await, 0);
    assert_eq!(presignature_manager.len_mine().await, 0);
    assert!(presignature_manager.is_empty().await);
    assert_eq!(presignature_manager.len_potential().await, 0);
    assert!(presignature_storage.contains_used(id2).await.unwrap());

    // Attempt to re-insert used mine presignature and check that it fails
    assert!(presignature_manager.reserve(id2).await.is_none());
    assert!(!presignature_manager.contains(id2).await);

    presignature_storage.clear().await.unwrap();
    // Have our node0 observe shares for triples 10 to 15 where node1 is owner.
    for id in 10..=15 {
        presignature_manager
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_presignature(id), node1)
            .await;
    }

    // Let's say Node1 somehow used up triple 10, 11, 12 so we only have 13,14,15
    let mut outdated = presignature_storage
        .remove_outdated(node1, &[13, 14, 15])
        .await;
    outdated.sort();
    assert_eq!(outdated, vec![10, 11, 12]);

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
        participants: vec![Participant::from(1), Participant::from(2)],
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
            participants: vec![Participant::from(1), Participant::from(2)],
            threshold: 5,
        },
    }
}
