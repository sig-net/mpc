use std::time::Duration;

use cait_sith::protocol::Participant;
use integration_tests::cluster;

use super::helpers::{
    assert_presignatures_owned_state, assert_triples_owned_state, insert_presignatures_for_owner,
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
    let node0_triples = redis.triple_storage(&node0_account_id);
    let node0_presignatures = redis.presignature_storage(&node0_account_id);
    let node1_triples = redis.triple_storage(&node1_account_id);
    let node1_presignatures = redis.presignature_storage(&node1_account_id);

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
    assert_presignatures_owned_state(
        &node1_presignatures,
        node1,
        &[0, 1, 2, 3, 4, 5],
        &[6, 100, 500, 2030, 1337, 10000],
    )
    .await;
    assert_presignatures_owned_state(
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
