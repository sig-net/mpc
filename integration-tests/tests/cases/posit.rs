use cait_sith::protocol::Participant;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers;
use mpc_crypto::PublicKey;
use mpc_node::protocol::message::MessageOutbox;
use mpc_node::protocol::posit::{PositAction, PositRejectReason};
use mpc_node::protocol::presignature::{FullPresignatureId, PresignatureSpawner};
use mpc_node::protocol::triple::TripleSpawner;
use mpc_node::protocol::{AcceptLimits, Message, MessageChannel};
use mpc_node::types::SecretKeyShare;
use std::time::Duration;
use test_log::test;

use super::helpers::{dummy_pair, dummy_presignature};

/// Collects the posit replies the spawner queued for sending.
fn drain_posit_replies(outbox: &mut MessageOutbox) -> Vec<PositAction> {
    let outgoing = outbox.intercept_outgoing_messages();
    let mut actions = Vec::new();
    while let Ok(sent) = outgoing.try_recv() {
        if let Message::Posit(posit) = sent.message {
            actions.push(posit.action);
        }
    }
    actions
}

/// Node 0 acts as deliberator for posits proposed by node 1, for a triple and
/// then a presignature. Only a PROPOSE runs the storage checks and draws a
/// REJECT for a stored artifact. ACCEPT, REJECT and START are never answered
/// with one, and a START cannot restart generation of a stored artifact.
#[test(tokio::test)]
async fn test_generation_posits_check_storage_only_on_propose() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("test-generation-posits-check-storage-only-on-propose")
        .init_network()
        .await?;

    let node0 = Participant::from(0);
    let node1 = Participant::from(1);
    let (_, mut outbox, msg) = MessageChannel::new();
    let node0_id = "party0.near".parse().unwrap();
    let redis = containers::Redis::run(&spawner).await;
    let triple_storage = redis.triple_storage(&node0_id, node0);
    let presignature_storage = redis.presignature_storage(&node0_id, node0);
    let mut triple_spawner = TripleSpawner::new(
        node0,
        5,
        123,
        &triple_storage,
        msg.clone(),
        node0_id.to_string(),
    );
    let mut presignature_spawner = PresignatureSpawner::new(
        node0,
        5,
        123,
        &SecretKeyShare::default(),
        &PublicKey::default(),
        &triple_storage,
        &presignature_storage,
        msg,
        node0_id.to_string(),
    );
    let timeout = Duration::from_secs(10);
    let limits = AcceptLimits::new(10, 16, 3);
    let already_stored = vec![PositAction::RejectWithReason(
        PositRejectReason::AlreadyGenerating,
    )];
    let no_entry = vec![PositAction::RejectWithReason(
        PositRejectReason::InvalidRequest,
    )];
    let start = || PositAction::Start(vec![node0, node1]);
    // ACCEPT and REJECT repeat after the START, as late replies.
    let non_propose_actions = || {
        vec![
            PositAction::Accept,
            PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating),
            start(),
            PositAction::Accept,
            PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating),
        ]
    };

    // Triple: a PROPOSE for an unknown id is accepted and opens an entry.
    let triple_id = 1;
    triple_spawner
        .process_posit_for_test(triple_id, node1, PositAction::Propose, timeout, limits)
        .await;
    assert_eq!(drain_posit_replies(&mut outbox), vec![PositAction::Accept]);
    // Once the triple is stored, a repeated PROPOSE fails the storage check.
    triple_storage
        .create_slot(triple_id, node1)
        .await
        .unwrap()
        .insert(dummy_pair(triple_id), node1)
        .await;
    triple_spawner
        .process_posit_for_test(triple_id, node1, PositAction::Propose, timeout, limits)
        .await;
    assert_eq!(drain_posit_replies(&mut outbox), already_stored);
    // The other actions draw no reply. The START consumes the entry, but
    // generation start refuses the stored id.
    for action in non_propose_actions() {
        triple_spawner
            .process_posit_for_test(triple_id, node1, action, timeout, limits)
            .await;
    }
    assert_eq!(drain_posit_replies(&mut outbox), vec![]);
    assert_eq!(triple_spawner.len_ongoing(), 0);
    // A START without an entry is refused.
    triple_spawner
        .process_posit_for_test(triple_id, node1, start(), timeout, limits)
        .await;
    assert_eq!(drain_posit_replies(&mut outbox), no_entry);

    // Presignature: same steps. The PROPOSE also needs the triple pair held.
    let pair_id = 7;
    let presignature_id = FullPresignatureId::from_pair(pair_id);
    triple_storage
        .create_slot(pair_id, node1)
        .await
        .unwrap()
        .insert(dummy_pair(pair_id), node1)
        .await;
    presignature_spawner
        .process_posit_for_test(
            presignature_id,
            node1,
            PositAction::Propose,
            timeout,
            limits,
        )
        .await;
    assert_eq!(drain_posit_replies(&mut outbox), vec![PositAction::Accept]);
    assert!(
        presignature_storage
            .create_slot(presignature_id.id, node1)
            .await
            .unwrap()
            .insert(dummy_presignature(presignature_id.id), node1)
            .await
    );
    presignature_spawner
        .process_posit_for_test(
            presignature_id,
            node1,
            PositAction::Propose,
            timeout,
            limits,
        )
        .await;
    assert_eq!(drain_posit_replies(&mut outbox), already_stored);
    for action in non_propose_actions() {
        presignature_spawner
            .process_posit_for_test(presignature_id, node1, action, timeout, limits)
            .await;
    }
    assert_eq!(drain_posit_replies(&mut outbox), vec![]);
    assert_eq!(presignature_spawner.len_ongoing(), 0);
    presignature_spawner
        .process_posit_for_test(presignature_id, node1, start(), timeout, limits)
        .await;
    assert_eq!(drain_posit_replies(&mut outbox), no_entry);

    Ok(())
}

/// A deliberator refuses a PROPOSE from cached counts alone: too many
/// generations running, or too many artifacts in the pool.
#[test(tokio::test)]
async fn test_generation_posits_reject_on_load() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("test-generation-posits-reject-on-load")
        .init_network()
        .await?;

    let node0 = Participant::from(0);
    let node1 = Participant::from(1);
    let (_, mut outbox, msg) = MessageChannel::new();
    let node0_id = "party0.near".parse().unwrap();
    let redis = containers::Redis::run(&spawner).await;
    let triple_storage = redis.triple_storage(&node0_id, node0);
    let presignature_storage = redis.presignature_storage(&node0_id, node0);
    let mut triple_spawner = TripleSpawner::new(
        node0,
        5,
        123,
        &triple_storage,
        msg.clone(),
        node0_id.to_string(),
    );
    let mut presignature_spawner = PresignatureSpawner::new(
        node0,
        5,
        123,
        &SecretKeyShare::default(),
        &PublicKey::default(),
        &triple_storage,
        &presignature_storage,
        msg,
        node0_id.to_string(),
    );
    let timeout = Duration::from_secs(10);
    let reject = |reason| vec![PositAction::RejectWithReason(reason)];
    // The presignature PROPOSE also needs its pair held.
    let pair_id = 1;
    triple_storage
        .create_slot(pair_id, node1)
        .await
        .unwrap()
        .insert(dummy_pair(pair_id), node1)
        .await;
    let presignature_id = FullPresignatureId::from_pair(pair_id);

    // A generation cap of zero saturates the deliberator.
    let saturated = AcceptLimits::new(1, 0, 3);
    triple_spawner
        .process_posit_for_test(2, node1, PositAction::Propose, timeout, saturated)
        .await;
    assert_eq!(
        drain_posit_replies(&mut outbox),
        reject(PositRejectReason::Saturated)
    );
    presignature_spawner
        .process_posit_for_test(
            presignature_id,
            node1,
            PositAction::Propose,
            timeout,
            saturated,
        )
        .await;
    assert_eq!(
        drain_posit_replies(&mut outbox),
        reject(PositRejectReason::Saturated)
    );

    // A floor of zero makes even an empty pool overstocked.
    let overstocked = AcceptLimits::new(0, 16, 3);
    triple_spawner
        .process_posit_for_test(2, node1, PositAction::Propose, timeout, overstocked)
        .await;
    assert_eq!(
        drain_posit_replies(&mut outbox),
        reject(PositRejectReason::Overstocked)
    );
    presignature_spawner
        .process_posit_for_test(
            presignature_id,
            node1,
            PositAction::Propose,
            timeout,
            overstocked,
        )
        .await;
    assert_eq!(
        drain_posit_replies(&mut outbox),
        reject(PositRejectReason::Overstocked)
    );

    // Within both limits the same proposals are accepted.
    let limits = AcceptLimits::new(1, 16, 3);
    triple_spawner
        .process_posit_for_test(2, node1, PositAction::Propose, timeout, limits)
        .await;
    assert_eq!(drain_posit_replies(&mut outbox), vec![PositAction::Accept]);
    presignature_spawner
        .process_posit_for_test(
            presignature_id,
            node1,
            PositAction::Propose,
            timeout,
            limits,
        )
        .await;
    assert_eq!(drain_posit_replies(&mut outbox), vec![PositAction::Accept]);

    Ok(())
}
