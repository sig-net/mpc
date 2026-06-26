use cait_sith::protocol::Participant;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers;
use mpc_crypto::PublicKey;
use mpc_node::protocol::presignature::PresignatureSpawner;
use mpc_node::protocol::triple::TripleSpawner;
use mpc_node::protocol::MessageChannel;
use mpc_node::types::SecretKeyShare;
use test_log::test;

use super::helpers::{dummy_pair, dummy_presignature};

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
    let triple_storage = redis.triple_storage(&node0_id, node0);
    let triple_spawner =
        TripleSpawner::new(node0, 5, 123, &triple_storage, msg, node0_id.to_string());

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
        .create_slot(triple_id1, node1)
        .await
        .unwrap()
        .insert(dummy_pair(triple_id1), node1)
        .await;
    triple_storage
        .create_slot(triple_id2, node1)
        .await
        .unwrap()
        .insert(dummy_pair(triple_id2), node1)
        .await;

    // Check that the storage contains the foreign triple
    assert!(triple_spawner.contains(triple_id1).await);
    assert!(triple_spawner.contains(triple_id2).await);
    assert!(!triple_spawner.contains_mine(triple_id1).await);
    assert!(!triple_spawner.contains_mine(triple_id2).await);
    assert_eq!(triple_storage.len_generated().await, 2);
    assert_eq!(triple_storage.len_by_owner(node0).await, 0);
    assert_eq!(triple_spawner.len_potential().await, 2);

    // Take triple pairs and check that they are removed from the storage and marked as using
    let _taken1 = triple_storage.take(triple_id1, node1).await.unwrap();
    let _taken2 = triple_storage.take(triple_id2, node1).await.unwrap();
    assert!(!triple_spawner.contains(triple_id1).await);
    assert!(!triple_spawner.contains(triple_id2).await);
    assert!(!triple_spawner.contains_mine(triple_id1).await);
    assert!(!triple_spawner.contains_mine(triple_id2).await);
    assert_eq!(triple_storage.len_generated().await, 0);
    assert_eq!(triple_spawner.len_mine().await, 0);
    assert_eq!(triple_spawner.len_potential().await, 0);
    assert!(triple_storage.contains_using(triple_id1).await);
    assert!(triple_storage.contains_using(triple_id2).await);

    // Attempt to re-create slot for in-use triples and check that it fails
    assert!(triple_storage
        .create_slot(triple_id1, node1)
        .await
        .is_none());
    assert!(triple_storage
        .create_slot(triple_id2, node1)
        .await
        .is_none());

    let id3 = 3;
    let id4: u64 = 4;

    // Add mine triple and check that it is in the storage
    triple_storage
        .create_slot(id3, node0)
        .await
        .unwrap()
        .insert(dummy_pair(id3), node0)
        .await;
    triple_storage
        .create_slot(id4, node0)
        .await
        .unwrap()
        .insert(dummy_pair(id4), node0)
        .await;
    assert!(triple_spawner.contains(id3).await);
    assert!(triple_spawner.contains(id4).await);
    assert!(triple_spawner.contains_mine(id3).await);
    assert!(triple_spawner.contains_mine(id4).await);
    assert_eq!(triple_storage.len_generated().await, 2);
    assert_eq!(triple_spawner.len_mine().await, 2);
    assert_eq!(triple_spawner.len_potential().await, 2);

    // Take mine triple pairs and check that they are removed from the storage and marked as using
    let _taken3 = triple_storage.take_mine().await.unwrap();
    let _taken4 = triple_storage.take_mine().await.unwrap();
    assert!(!triple_spawner.contains(id3).await);
    assert!(!triple_spawner.contains(id4).await);
    assert!(!triple_spawner.contains_mine(id3).await);
    assert!(!triple_spawner.contains_mine(id4).await);
    assert_eq!(triple_storage.len_generated().await, 0);
    assert_eq!(triple_spawner.len_mine().await, 0);
    assert!(triple_storage.is_empty().await);
    assert_eq!(triple_spawner.len_potential().await, 0);
    assert!(triple_storage.contains_using(id3).await);
    assert!(triple_storage.contains_using(id4).await);

    // Attempt to re-create slot for in-use mine triples and check that it fails
    assert!(triple_storage.create_slot(id3, node0).await.is_none());
    assert!(triple_storage.create_slot(id4, node0).await.is_none());

    assert!(triple_storage.clear().await);
    // Have our node0 observe shares for triples 10 to 15 where node1 is owner.
    for id in 10..=15 {
        triple_storage
            .create_slot(id, node1)
            .await
            .unwrap()
            .insert(dummy_pair(id), node1)
            .await;
    }

    // Have our node0 own 16 to 20
    for id in 16..=20 {
        triple_storage
            .create_slot(id, node0)
            .await
            .unwrap()
            .insert(dummy_pair(id), node0)
            .await;
    }

    // Let's say Node1 somehow used up triple 10, 11, 12 so we only have 13,14,15.
    // We also include ID 99 which doesn't exist to test the not_found tracking.
    let result = triple_storage
        .remove_outdated(node1, &[13, 14, 15, 99])
        .await
        .unwrap();
    let mut outdated = result.removed;
    outdated.sort();
    assert_eq!(outdated, vec![10, 11, 12]);
    assert_eq!(result.not_found, vec![99]);

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
    let triple_storage = redis.triple_storage(&node0_id, node0);
    let presignature_storage = redis.presignature_storage(&node0_id, node0);
    let presignature_spawner = PresignatureSpawner::new(
        Participant::from(0),
        5,
        123,
        &SecretKeyShare::default(),
        &PublicKey::default(),
        &triple_storage,
        &presignature_storage,
        msg,
        node0_id.to_string(),
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

    // Insert presignature owned by node1, with our node0 view being that it is a foreign presignature
    assert!(
        presignature_storage
            .create_slot(presignature.id, node1)
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

    // Take presignature and check that it is removed from the storage and marked as using
    let _taken_ps1 = presignature_storage.take(id, node1).await.unwrap();
    assert!(!presignature_storage.contains(id).await);
    assert!(!presignature_spawner.contains_mine(id).await);
    assert_eq!(presignature_storage.len_generated().await, 0);
    assert_eq!(presignature_spawner.len_mine().await, 0);
    assert_eq!(presignature_spawner.len_potential().await, 0);
    assert!(presignature_storage.contains_using(id).await);

    // Attempt to re-create slot for in-use presignature and check that it fails
    assert!(presignature_storage.create_slot(id, node1).await.is_none());

    let id2 = 2;
    let mine_presignature = dummy_presignature(id2);

    // Add a presignature to our own node0
    assert!(
        presignature_storage
            .create_slot(id2, node0)
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

    // Take mine presignature and check that it is removed from the storage and marked as using
    let _taken_ps2 = presignature_storage.take_mine().await.unwrap();
    assert!(!presignature_storage.contains(id2).await);
    assert!(!presignature_spawner.contains_mine(id2).await);
    assert_eq!(presignature_storage.len_generated().await, 0);
    assert_eq!(presignature_spawner.len_mine().await, 0);
    assert!(presignature_storage.is_empty().await);
    assert_eq!(presignature_spawner.len_potential().await, 0);
    assert!(presignature_storage.contains_using(id2).await);

    // Attempt to re-create slot for in-use mine presignature and check that it fails
    assert!(presignature_storage.create_slot(id2, node0).await.is_none());

    presignature_storage.clear().await;
    // Have our node0 observe shares for triples 10 to 15 where node1 is owner.
    for id in 10..=15 {
        presignature_storage
            .create_slot(id, node1)
            .await
            .unwrap()
            .insert(dummy_presignature(id), node1)
            .await;
    }

    // Have our node0 own 16 to 20
    for id in 16..=20 {
        presignature_storage
            .create_slot(id, node0)
            .await
            .unwrap()
            .insert(dummy_presignature(id), node0)
            .await;
    }

    // Let's say Node1 somehow used up triple 10, 11, 12 so we only have 13,14,15.
    // We also include ID 99 which doesn't exist to test the not_found tracking.
    let result = presignature_storage
        .remove_outdated(node1, &[13, 14, 15, 99])
        .await
        .unwrap();
    let mut outdated = result.removed;
    outdated.sort();
    assert_eq!(outdated, vec![10, 11, 12]);
    assert_eq!(result.not_found, vec![99]);

    assert_eq!(presignature_storage.len_generated().await, 8);
    assert_eq!(presignature_spawner.len_mine().await, 5);
    assert_eq!(presignature_spawner.len_potential().await, 8);

    Ok(())
}

#[test(tokio::test)]
async fn test_checkpoint_persistence() -> anyhow::Result<()> {
    use mpc_node::storage::checkpoint_storage::CheckpointStorage;
    use mpc_primitives::{Chain, Checkpoint};
    use near_account_id::AccountId;

    let spawner = ClusterSpawner::default()
        .network("test-checkpoint-persistence")
        .init_network()
        .await?;

    let redis = containers::Redis::run(&spawner).await;
    let pool = redis.pool();
    let account_id: AccountId = "party0.near".parse().unwrap();
    let storage = CheckpointStorage::Redis(pool.clone(), account_id);

    // 1. Clean storage returns None
    assert!(storage.load_latest(Chain::Solana).await?.is_none());

    // 2. Persist first checkpoint (simulates consensus confirmation)
    let tx1 = mpc_primitives::PendingTx {
        sign_id: mpc_primitives::SignId::new([1u8; 32]),
        transaction: vec![1, 2, 3],
    };
    let cp1 = Checkpoint {
        chain: Chain::Solana,
        block_height: 10,
        pending_requests: vec![tx1],
    };
    storage.persist(&cp1).await?;

    // 3. Verify latest
    let latest = storage.load_latest(Chain::Solana).await?.unwrap();
    assert_eq!(latest.block_height, 10);
    assert_eq!(latest.pending_requests.len(), 1);
    assert_eq!(latest.pending_requests[0].transaction, vec![1, 2, 3]);

    // 4. Persist second checkpoint at higher height (newer consensus checkpoint)
    let tx2 = mpc_primitives::PendingTx {
        sign_id: mpc_primitives::SignId::new([2u8; 32]),
        transaction: vec![4, 5, 6],
    };
    let cp2 = Checkpoint {
        chain: Chain::Solana,
        block_height: 20,
        pending_requests: vec![tx2],
    };
    storage.persist(&cp2).await?;

    // 5. Verify latest is updated
    let latest = storage.load_latest(Chain::Solana).await?.unwrap();
    assert_eq!(latest.block_height, 20);
    assert_eq!(latest.pending_requests.len(), 1);
    assert_eq!(latest.pending_requests[0].transaction, vec![4, 5, 6]);

    Ok(())
}
