use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers;
use k256::Secp256k1;
use mpc_node::protocol::presignature::{Presignature, PresignatureId, PresignatureManager};
use mpc_node::protocol::sync::SyncChannel;
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
    let node_id = "test.near".parse().unwrap();
    let redis = containers::Redis::run(&spawner).await;
    let triple_storage = redis.triple_storage(&node_id);
    let triple_manager = TripleManager::new(node0, 5, 123, &node_id, &triple_storage, msg);

    let triple_id_1: u64 = 1;
    let triple_1 = dummy_triple(triple_id_1);
    let triple_id_2: u64 = 2;
    let triple_2 = dummy_triple(triple_id_2);

    // Check that the storage is empty at the start
    assert!(!triple_manager.contains(triple_id_1).await);
    assert!(!triple_manager.contains_mine(triple_id_1).await);
    assert_eq!(triple_manager.len_generated().await, 0);
    assert_eq!(triple_manager.len_mine().await, 0);
    assert!(triple_manager.is_empty().await);
    assert_eq!(triple_manager.len_potential().await, 0);

    triple_manager.insert(triple_1.clone(), node1).await;
    triple_manager.insert(triple_2.clone(), node1).await;

    // Check that the storage contains the foreign triple
    assert!(triple_manager.contains(triple_id_1).await);
    assert!(triple_manager.contains(triple_id_2).await);
    assert!(!triple_manager.contains_mine(triple_id_1).await);
    assert!(!triple_manager.contains_mine(triple_id_2).await);
    assert_eq!(triple_manager.len_generated().await, 2);
    assert_eq!(triple_manager.len_mine().await, 0);
    assert_eq!(triple_manager.len_potential().await, 2);

    // Take triple and check that it is removed from the storage and added to used set
    triple_manager
        .take_two(triple_id_1, triple_id_2)
        .await
        .unwrap();
    assert!(!triple_manager.contains(triple_id_1).await);
    assert!(!triple_manager.contains(triple_id_2).await);
    assert!(!triple_manager.contains_mine(triple_id_1).await);
    assert!(!triple_manager.contains_mine(triple_id_2).await);
    assert_eq!(triple_manager.len_generated().await, 0);
    assert_eq!(triple_manager.len_mine().await, 0);
    assert_eq!(triple_manager.len_potential().await, 0);
    assert!(triple_storage.contains_used(triple_id_1).await.unwrap());
    assert!(triple_storage.contains_used(triple_id_2).await.unwrap());

    // Attempt to re-insert used triples and check that it fails
    triple_manager.insert(triple_1, node1).await;
    assert!(!triple_manager.contains(triple_id_1).await);
    triple_manager.insert(triple_2, node1).await;
    assert!(!triple_manager.contains(triple_id_2).await);

    let mine_id_1: u64 = 3;
    let mine_triple_1 = dummy_triple(mine_id_1);
    let mine_id_2: u64 = 4;
    let mine_triple_2 = dummy_triple(mine_id_2);

    // Add mine triple and check that it is in the storage
    triple_manager.insert(mine_triple_1.clone(), node0).await;
    triple_manager.insert(mine_triple_2.clone(), node0).await;
    assert!(triple_manager.contains(mine_id_1).await);
    assert!(triple_manager.contains(mine_id_2).await);
    assert!(triple_manager.contains_mine(mine_id_1).await);
    assert!(triple_manager.contains_mine(mine_id_2).await);
    assert_eq!(triple_manager.len_generated().await, 2);
    assert_eq!(triple_manager.len_mine().await, 2);
    assert_eq!(triple_manager.len_potential().await, 2);

    // Take mine triple and check that it is removed from the storage and added to used set
    triple_manager.take_two_mine().await.unwrap();
    assert!(!triple_manager.contains(mine_id_1).await);
    assert!(!triple_manager.contains(mine_id_2).await);
    assert!(!triple_manager.contains_mine(mine_id_1).await);
    assert!(!triple_manager.contains_mine(mine_id_2).await);
    assert_eq!(triple_manager.len_generated().await, 0);
    assert_eq!(triple_manager.len_mine().await, 0);
    assert!(triple_manager.is_empty().await);
    assert_eq!(triple_manager.len_potential().await, 0);
    assert!(triple_storage.contains_used(mine_id_1).await.unwrap());
    assert!(triple_storage.contains_used(mine_id_2).await.unwrap());

    // Attempt to re-insert used mine triples and check that it fails
    triple_manager.insert(mine_triple_1, node0).await;
    assert!(!triple_manager.contains(mine_id_1).await);
    triple_manager.insert(mine_triple_2, node0).await;
    assert!(!triple_manager.contains(mine_id_2).await);

    Ok(())
}

#[test(tokio::test)]
async fn test_presignature_persistence() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("test-presignature-persistence")
        .init_network()
        .await?;

    let node_id = "test.near".parse().unwrap();
    let redis = containers::Redis::run(&spawner).await;
    let presignature_storage = redis.presignature_storage(&node_id);
    let (_, _, msg) = MessageChannel::new();
    let (_, sync) = SyncChannel::new();
    let mut presignature_manager = PresignatureManager::new(
        Participant::from(0),
        5,
        123,
        &node_id,
        &presignature_storage,
        msg,
        sync,
    );

    let presignature = dummy_presignature(1);
    let presignature_id: PresignatureId = presignature.id;

    // Check that the storage is empty at the start
    assert!(!presignature_manager.contains(&presignature_id).await);
    assert!(!presignature_manager.contains_mine(&presignature_id).await);
    assert_eq!(presignature_manager.len_generated().await, 0);
    assert_eq!(presignature_manager.len_mine().await, 0);
    assert!(presignature_manager.is_empty().await);
    assert_eq!(presignature_manager.len_potential().await, 0);

    presignature_manager
        .insert(presignature, false, false)
        .await;

    // Check that the storage contains the foreign presignature
    assert!(presignature_manager.contains(&presignature_id).await);
    assert!(!presignature_manager.contains_mine(&presignature_id).await);
    assert_eq!(presignature_manager.len_generated().await, 1);
    assert_eq!(presignature_manager.len_mine().await, 0);
    assert_eq!(presignature_manager.len_potential().await, 1);

    // Take presignature and check that it is removed from the storage and added to used set
    presignature_manager.take(presignature_id).await.unwrap();
    assert!(!presignature_manager.contains(&presignature_id).await);
    assert!(!presignature_manager.contains_mine(&presignature_id).await);
    assert_eq!(presignature_manager.len_generated().await, 0);
    assert_eq!(presignature_manager.len_mine().await, 0);
    assert_eq!(presignature_manager.len_potential().await, 0);
    assert!(presignature_storage
        .contains_used(&presignature_id)
        .await
        .unwrap());

    // Attempt to re-insert used presignature and check that it fails
    let presignature = dummy_presignature(presignature_id);
    presignature_manager
        .insert(presignature, false, false)
        .await;
    assert!(!presignature_manager.contains(&presignature_id).await);

    let mine_presignature = dummy_presignature(2);
    let mine_presig_id: PresignatureId = mine_presignature.id;

    // Add mine presignature and check that it is in the storage
    presignature_manager
        .insert(mine_presignature, true, false)
        .await;
    assert!(presignature_manager.contains(&mine_presig_id).await);
    assert!(presignature_manager.contains_mine(&mine_presig_id).await);
    assert_eq!(presignature_manager.len_generated().await, 1);
    assert_eq!(presignature_manager.len_mine().await, 1);
    assert_eq!(presignature_manager.len_potential().await, 1);

    // Take mine presignature and check that it is removed from the storage and added to used set
    presignature_manager.take_mine().await.unwrap();
    assert!(!presignature_manager.contains(&mine_presig_id).await);
    assert!(!presignature_manager.contains_mine(&mine_presig_id).await);
    assert_eq!(presignature_manager.len_generated().await, 0);
    assert_eq!(presignature_manager.len_mine().await, 0);
    assert!(presignature_manager.is_empty().await);
    assert_eq!(presignature_manager.len_potential().await, 0);
    assert!(presignature_storage
        .contains_used(&mine_presig_id)
        .await
        .unwrap());

    // Attempt to re-insert used mine presignature and check that it fails
    let mine_presignature = dummy_presignature(mine_presig_id);
    presignature_manager
        .insert(mine_presignature, true, false)
        .await;
    assert!(!presignature_manager.contains(&mine_presig_id).await);

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
