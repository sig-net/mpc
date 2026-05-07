use std::time::Duration;

use cait_sith::protocol::Participant;
use integration_tests::cluster;

use super::helpers::{
    assert_presig_owned_state, assert_triples_owned_state, insert_presignatures_for_owner,
    insert_triples_for_owner,
};

#[test_log::test(tokio::test)]
async fn test_state_sync_e2e_large_outdated_stockpile() {
    // start the cluster of nodes immediately without waiting for them to be running.
    let mut spawner = cluster::spawn();
    {
        let worker = spawner.prespawn_sandbox().await.unwrap().clone();
        spawner.create_accounts(&worker).await;
    }
    // NOTE: cannot reliably get the first participant until running state is reached, so
    // this assumes that 0 and 1 is the first and second participants.
    let node0 = Participant::from(0);
    let node0_account_id = spawner.account_id(Into::<u32>::into(node0) as usize);
    let node1 = Participant::from(1);
    let node1_account_id = spawner.account_id(Into::<u32>::into(node1) as usize);
    let holders = vec![node0, node1];
    let redis = spawner.prespawn_redis().await;

    // immediately add to triples/presignatures storage the triples/presignatures we want to invalidate.
    let node0_triples = redis.triple_storage(&node0_account_id, node0);
    let node0_presignatures = redis.presignature_storage(&node0_account_id, node0);
    let node1_triples = redis.triple_storage(&node1_account_id, node1);
    let node1_presignatures = redis.presignature_storage(&node1_account_id, node1);

    // insert triples that will be invalidated after a sync, since nobody else has them.
    // node0 is saying that they have 0 to 5, but node1 will sync and say they have 4 and 5 only.
    insert_triples_for_owner(&node0_triples, node1, &holders, 0..=10000).await;
    insert_triples_for_owner(&node1_triples, node1, &holders, 0..=5).await;
    insert_presignatures_for_owner(&node0_presignatures, node1, &holders, 0..=10000).await;
    insert_presignatures_for_owner(&node1_presignatures, node1, &holders, 0..=5).await;

    let _nodes = spawner
        .disable_prestockpile()
        .with_config(|cfg| {
            // Need these to be set otherwise we will be constantly taking our mock triples:
            cfg.protocol.triple.min_triples = 1;
            cfg.protocol.triple.max_triples = 1;
            cfg.protocol.presignature.min_presignatures = 1;
            cfg.protocol.presignature.max_presignatures = 1;
        })
        .await
        .unwrap();

    // Give some time for the first sync broadcast to finish.
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert_triples_owned_state(
        &node0_triples,
        node1,
        &[0, 1, 2, 3, 4, 5],
        &[6, 100, 500, 2030, 1337, 10000],
    )
    .await;
    assert_triples_owned_state(
        &node1_triples,
        node1,
        &[0, 1, 2, 3, 4, 5],
        &[6, 100, 500, 2030, 1337, 10000],
    )
    .await;
    assert_presig_owned_state(
        &node1_presignatures,
        node1,
        &[0, 1, 2, 3, 4, 5],
        &[6, 100, 500, 2030, 1337, 10000],
    )
    .await;
    assert_presig_owned_state(
        &node0_presignatures,
        node1,
        &[0, 1, 2, 3, 4, 5],
        &[6, 100, 500, 2030, 1337, 10000],
    )
    .await;

    // TODO: add back being able to sign after sync. Need to be able to update the config from integration tests.
    // // Check that signing works as normal.
    // nodes.wait().signable().await.unwrap();
    // nodes.sign().await.unwrap();
}

#[test_log::test(tokio::test)]
async fn test_state_sync_e2e() {
    // Setup 3 nodes with T=2 (default cluster setup).
    let mut spawner = cluster::spawn();
    {
        let worker = spawner.prespawn_sandbox().await.unwrap().clone();
        spawner.create_accounts(&worker).await;
    }

    let node0 = Participant::from(0);
    let node1 = Participant::from(1);
    let node2 = Participant::from(2);
    let node0_account_id = spawner.account_id(Into::<u32>::into(node0) as usize);
    let node1_account_id = spawner.account_id(Into::<u32>::into(node1) as usize);
    let node2_account_id = spawner.account_id(Into::<u32>::into(node2) as usize);
    let holders = vec![node0, node1, node2];
    let redis = spawner.prespawn_redis().await;

    // Wait for Redis to be fully accepting connections on the host port.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Get triple/presignature storage for each node.
    let node0_triples = redis.triple_storage(&node0_account_id, node0);
    let node0_presignatures = redis.presignature_storage(&node0_account_id, node0);
    let node1_triples = redis.triple_storage(&node1_account_id, node1);
    let node1_presignatures = redis.presignature_storage(&node1_account_id, node1);
    let node2_triples = redis.triple_storage(&node2_account_id, node2);
    let node2_presignatures = redis.presignature_storage(&node2_account_id, node2);

    // Populate 3 triples and 3 presignatures: each node owns 1, all nodes hold shares.
    for storage in [&node0_triples, &node1_triples, &node2_triples] {
        insert_triples_for_owner(storage, node0, &holders, 0..=0).await;
        insert_triples_for_owner(storage, node1, &holders, 1..=1).await;
        insert_triples_for_owner(storage, node2, &holders, 2..=2).await;
    }
    for storage in [
        &node0_presignatures,
        &node1_presignatures,
        &node2_presignatures,
    ] {
        insert_presignatures_for_owner(storage, node0, &holders, 0..=0).await;
        insert_presignatures_for_owner(storage, node1, &holders, 1..=1).await;
        insert_presignatures_for_owner(storage, node2, &holders, 2..=2).await;
    }

    // Add 1 extra T and P owned by node0, only on node0's storage.
    // After sync, node0 will learn that node1 and node2 don't have id=99,
    // dropping it below threshold (T=2), so it should be pruned.
    insert_triples_for_owner(&node0_triples, node0, &holders, 99..=99).await;
    insert_presignatures_for_owner(&node0_presignatures, node0, &holders, 99..=99).await;

    // Add 1 extra T and P owned by node1, on node0 and node1 only (not node2).
    // After sync, node1 learns node2 doesn't have id=88, removing node2 from participants.
    // But node0 still has it, so 2 holders remain (= threshold), and it should survive.
    for storage in [&node0_triples, &node1_triples] {
        insert_triples_for_owner(storage, node1, &holders, 88..=88).await;
    }
    for storage in [&node0_presignatures, &node1_presignatures] {
        insert_presignatures_for_owner(storage, node1, &holders, 88..=88).await;
    }

    // Add 1 extra T and P owned by node0, but only on node1 and node2 (not on node0 itself).
    // When node0 broadcasts its owned IDs, id=77 won't be included (node0 doesn't have it),
    // so node1 and node2 will remove it via remove_outdated.
    for storage in [&node1_triples, &node2_triples] {
        insert_triples_for_owner(storage, node0, &holders, 77..=77).await;
    }
    for storage in [&node1_presignatures, &node2_presignatures] {
        insert_presignatures_for_owner(storage, node0, &holders, 77..=77).await;
    }

    let _cluster = spawner
        .disable_prestockpile()
        .with_config(|cfg| {
            cfg.protocol.triple.min_triples = 1;
            cfg.protocol.triple.max_triples = 1;
            cfg.protocol.presignature.min_presignatures = 1;
            cfg.protocol.presignature.max_presignatures = 1;
        })
        .await
        .unwrap();

    // Give some time for the first sync broadcast to finish.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // After sync, all 3 consistent triples/presignatures should be present on every node.
    // id=99 (only on node0) should have been pruned (below threshold).
    // id=88 (on node0 and node1) should survive (exactly at threshold=2).
    // id=77 (owned by node0, only on node1/node2) should be removed via remove_outdated.
    for triples in [&node0_triples, &node1_triples] {
        assert_triples_owned_state(triples, node0, &[0], &[1, 2, 77, 99]).await;
        assert_triples_owned_state(triples, node1, &[1, 88], &[0, 2]).await;
        assert_triples_owned_state(triples, node2, &[2], &[0, 1]).await;
    }
    assert_triples_owned_state(&node2_triples, node0, &[0], &[1, 2, 77, 99]).await;
    assert_triples_owned_state(&node2_triples, node1, &[1], &[0, 2, 88]).await;
    assert_triples_owned_state(&node2_triples, node2, &[2], &[0, 1]).await;

    for presignatures in [&node0_presignatures, &node1_presignatures] {
        assert_presig_owned_state(presignatures, node0, &[0], &[1, 2, 77, 99]).await;
        assert_presig_owned_state(presignatures, node1, &[1, 88], &[0, 2]).await;
        assert_presig_owned_state(presignatures, node2, &[2], &[0, 1]).await;
    }
    assert_presig_owned_state(&node2_presignatures, node0, &[0], &[1, 2, 77, 99]).await;
    assert_presig_owned_state(&node2_presignatures, node1, &[1], &[0, 2, 88]).await;
    assert_presig_owned_state(&node2_presignatures, node2, &[2], &[0, 1]).await;
}
