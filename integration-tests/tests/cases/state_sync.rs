use cait_sith::protocol::Participant;
use deadpool_redis::redis::AsyncCommands;
use integration_tests::mpc_fixture::{MpcFixtureBuilder, MpcFixtureNode};
use mpc_node::protocol::message::SignedMessage;
use mpc_node::protocol::sync::SyncUpdate;
use test_log::test;

use std::time::Duration;

use super::helpers::{
    assert_presig_owned_state, assert_triples_owned_state, insert_presignatures_for_owner,
    insert_triples_for_owner,
};

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_noop_when_fully_synced() {
    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let node0 = &fixture.nodes[0];
    let node1 = &fixture.nodes[1];

    // Snapshot node1's owned artifacts before sync.
    let node1_triples_before = node1.owned_triples().await;
    let node1_presigs_before = node1.owned_presignatures().await;
    assert!(
        !node1_triples_before.is_empty(),
        "node1 should own triples from fixture"
    );
    assert!(
        !node1_presigs_before.is_empty(),
        "node1 should own presignatures from fixture"
    );

    let node0_triples = node0.owned_triples().await;
    let node0_presigs = node0.owned_presignatures().await;

    // Responder side: node1 receives node0's sync update and reports what it's missing.
    let response = node1
        .sync(node0, node0_triples.clone(), node0_presigs.clone())
        .await;
    assert!(
        response.triples.is_empty(),
        "node1 should have all of node0's triples"
    );
    assert!(
        response.presignatures.is_empty(),
        "node1 should have all of node0's presignatures"
    );

    // Caller side: node0 processes the response (nothing to remove since response is empty).
    node0.process_sync_response(node1.me, 2, &response).await;

    // Verify node1's artifact state is exactly unchanged after sync.
    let node1_triples_after = node1.owned_triples().await;
    let node1_presigs_after = node1.owned_presignatures().await;
    assert_eq!(
        node1_triples_after, node1_triples_before,
        "node1 triples should be unchanged after sync"
    );
    assert_eq!(
        node1_presigs_after, node1_presigs_before,
        "node1 presignatures should be unchanged after sync"
    );

    // Verify node0's artifact state is also unchanged.
    let node0_triples_after = node0.owned_triples().await;
    let node0_presigs_after = node0.owned_presignatures().await;
    assert_eq!(
        node0_triples_after, node0_triples,
        "node0 triples should be unchanged after sync"
    );
    assert_eq!(
        node0_presigs_after, node0_presigs,
        "node0 presignatures should be unchanged after sync"
    );

    // Verify holders are full (all 3 nodes) for every artifact on both nodes.
    let all_participants = fixture.sorted_participants();
    for node in [node0, node1] {
        for id in &node.owned_triples().await {
            let holders = node.triple_storage.fetch_holders(*id).await;
            assert_eq!(
                holders, all_participants,
                "triple {id} on {:?} should have all participants as holders",
                node.me
            );
        }
        for id in &node.owned_presignatures().await {
            let holders = node.presignature_storage.fetch_holders(*id).await;
            assert_eq!(
                holders, all_participants,
                "presignature {id} on {:?} should have all participants as holders",
                node.me
            );
        }
    }
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_prune_below_threshold() {
    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let node0 = &fixture.nodes[0];
    let node1 = &fixture.nodes[1];
    let node2 = &fixture.nodes[2];
    let all_participants = fixture.sorted_participants();

    // Snapshot fixture artifacts before any mutations.
    let node0_triples_before = node0.owned_triples().await;
    let node0_presigs_before = node0.owned_presignatures().await;

    // Insert artifact id=99 only on node0's storage (claimed by all 3 holders).
    insert_triples_for_owner(&node0.triple_storage, node0.me, &all_participants, 99..=99).await;
    insert_presignatures_for_owner(
        &node0.presignature_storage,
        node0.me,
        &all_participants,
        99..=99,
    )
    .await;

    // node0 tells node1 "I own id=99", node1 responds "I don't have it".
    let response = node1.sync(node0, vec![99], vec![99]).await;
    assert_eq!(response.triples, vec![99]);
    assert_eq!(response.presignatures, vec![99]);

    // node2 also doesn't have it.
    let response2 = node2.sync(node0, vec![99], vec![99]).await;
    assert_eq!(response2.triples, vec![99]);
    assert_eq!(response2.presignatures, vec![99]);

    // Process node1's response first (removes node1, 2 holders remain = threshold, survives).
    node0.process_sync_response(node1.me, 2, &response).await;
    assert_triples_owned_state(&node0.triple_storage, node0.me, &[99], &[]).await;
    assert_presig_owned_state(&node0.presignature_storage, node0.me, &[99], &[]).await;

    // Verify holders of 99: node1 removed, only node0 + node2 remain.
    let mut expected_holders = vec![node0.me, node2.me];
    expected_holders.sort();
    let holders_99 = node0.triple_storage.fetch_holders(99).await;
    assert_eq!(
        holders_99, expected_holders,
        "triple 99 should have node0+node2 as holders after first sync"
    );
    let holders_99 = node0.presignature_storage.fetch_holders(99).await;
    assert_eq!(
        holders_99, expected_holders,
        "presig 99 should have node0+node2 as holders after first sync"
    );

    // Process node2's response (removes node2, 1 holder < threshold → pruned).
    node0.process_sync_response(node2.me, 2, &response2).await;
    assert_triples_owned_state(&node0.triple_storage, node0.me, &[], &[99]).await;
    assert_presig_owned_state(&node0.presignature_storage, node0.me, &[], &[99]).await;

    // Verify fixture artifacts on node0 are unchanged (only id=99 was pruned).
    let node0_triples_after = node0.owned_triples().await;
    let node0_presigs_after = node0.owned_presignatures().await;
    assert_eq!(
        node0_triples_after, node0_triples_before,
        "node0 fixture triples should be unchanged"
    );
    assert_eq!(
        node0_presigs_after, node0_presigs_before,
        "node0 fixture presignatures should be unchanged"
    );

    // Verify holders of fixture artifacts are still full on node0.
    for id in &node0_triples_after {
        let holders = node0.triple_storage.fetch_holders(*id).await;
        assert_eq!(
            holders, all_participants,
            "fixture triple {id} should still have all holders"
        );
    }
    for id in &node0_presigs_after {
        let holders = node0.presignature_storage.fetch_holders(*id).await;
        assert_eq!(
            holders, all_participants,
            "fixture presig {id} should still have all holders"
        );
    }
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_prunes_artifacts_with_missing_holders_metadata() {
    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let node0 = &fixture.nodes[0];
    let node1 = &fixture.nodes[1];
    let node2 = &fixture.nodes[2];
    let all_participants = fixture.sorted_participants();

    insert_triples_for_owner(&node0.triple_storage, node0.me, &all_participants, 99..=99).await;
    insert_presignatures_for_owner(
        &node0.presignature_storage,
        node0.me,
        &all_participants,
        99..=99,
    )
    .await;

    let pool = fixture.redis_container.pool();
    let mut conn = pool.get().await.unwrap();
    let triple_holders_key = format!("{}:holders:{}", node0.triple_storage.artifact_key(), 99);
    let presig_holders_key = format!(
        "{}:holders:{}",
        node0.presignature_storage.artifact_key(),
        99
    );
    let _: usize = conn.del(&triple_holders_key).await.unwrap();
    let _: usize = conn.del(&presig_holders_key).await.unwrap();

    let response1 = node1.sync(node0, vec![99], vec![99]).await;
    let response2 = node2.sync(node0, vec![99], vec![99]).await;
    assert_eq!(response1.triples, vec![99]);
    assert_eq!(response1.presignatures, vec![99]);
    assert_eq!(response2.triples, vec![99]);
    assert_eq!(response2.presignatures, vec![99]);

    node0.process_sync_response(node1.me, 2, &response1).await;
    node0.process_sync_response(node2.me, 2, &response2).await;

    assert_triples_owned_state(&node0.triple_storage, node0.me, &[], &[99]).await;
    assert_presig_owned_state(&node0.presignature_storage, node0.me, &[], &[99]).await;
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_reports_missing_when_holders_metadata_is_missing_on_responder() {
    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let node0 = &fixture.nodes[0];
    let node1 = &fixture.nodes[1];
    let all_participants = fixture.sorted_participants();

    insert_triples_for_owner(
        &node1.triple_storage,
        node0.me,
        &all_participants,
        303..=303,
    )
    .await;
    insert_presignatures_for_owner(
        &node1.presignature_storage,
        node0.me,
        &all_participants,
        303..=303,
    )
    .await;

    let pool = fixture.redis_container.pool();
    let mut conn = pool.get().await.unwrap();
    let triple_holders_key = format!("{}:holders:{}", node1.triple_storage.artifact_key(), 303);
    let presig_holders_key = format!(
        "{}:holders:{}",
        node1.presignature_storage.artifact_key(),
        303
    );
    let _: usize = conn.del(&triple_holders_key).await.unwrap();
    let _: usize = conn.del(&presig_holders_key).await.unwrap();

    let response = node1.sync(node0, vec![303], vec![303]).await;
    assert_eq!(
        response.triples,
        vec![303],
        "responder should report triple as missing when holders metadata is gone"
    );
    assert_eq!(
        response.presignatures,
        vec![303],
        "responder should report presignature as missing when holders metadata is gone"
    );

    assert_triples_owned_state(&node1.triple_storage, node0.me, &[], &[303]).await;
    assert_presig_owned_state(&node1.presignature_storage, node0.me, &[], &[303]).await;
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_reports_missing_when_owner_mapping_is_missing_on_responder() {
    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let node0 = &fixture.nodes[0];
    let node1 = &fixture.nodes[1];
    let all_participants = fixture.sorted_participants();

    insert_triples_for_owner(
        &node1.triple_storage,
        node0.me,
        &all_participants,
        404..=404,
    )
    .await;
    insert_presignatures_for_owner(
        &node1.presignature_storage,
        node0.me,
        &all_participants,
        404..=404,
    )
    .await;

    let pool = fixture.redis_container.pool();
    let mut conn = pool.get().await.unwrap();
    let triple_owner_key = format!(
        "{}:p{}",
        node1.triple_storage.owner_keys(),
        u32::from(node0.me)
    );
    let presig_owner_key = format!(
        "{}:p{}",
        node1.presignature_storage.owner_keys(),
        u32::from(node0.me)
    );
    let _: usize = conn.srem(&triple_owner_key, 404).await.unwrap();
    let _: usize = conn.srem(&presig_owner_key, 404).await.unwrap();

    let response = node1.sync(node0, vec![404], vec![404]).await;
    assert_eq!(
        response.triples,
        vec![404],
        "responder should report triple as missing when owner mapping is gone"
    );
    assert_eq!(
        response.presignatures,
        vec![404],
        "responder should report presignature as missing when owner mapping is gone"
    );
    assert_triples_owned_state(&node1.triple_storage, node0.me, &[], &[404]).await;
    assert_presig_owned_state(&node1.presignature_storage, node0.me, &[], &[404]).await;
}

/// Orphaned artifact: owner doesn't have id=77 but other nodes do.
/// When owner broadcasts its sync update (without id=77), responders remove it
/// via remove_outdated.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_remove_outdated_orphan() {
    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let node0 = &fixture.nodes[0];
    let node1 = &fixture.nodes[1];
    let all_participants = fixture.sorted_participants();

    // Snapshot fixture artifacts on node1 before mutations.
    let node1_triples_before = node1.owned_triples().await;
    let node1_presigs_before = node1.owned_presignatures().await;

    // Insert id=77 owned by node0, but only on node1 (NOT on node0).
    insert_triples_for_owner(&node1.triple_storage, node0.me, &all_participants, 77..=77).await;
    insert_presignatures_for_owner(
        &node1.presignature_storage,
        node0.me,
        &all_participants,
        77..=77,
    )
    .await;

    // Verify node1 has id=77 before sync.
    assert_triples_owned_state(&node1.triple_storage, node0.me, &[77], &[]).await;
    assert_presig_owned_state(&node1.presignature_storage, node0.me, &[77], &[]).await;

    // Verify holders of id=77 are all participants.
    let holders = node1.triple_storage.fetch_holders(77).await;
    assert_eq!(
        holders, all_participants,
        "triple 77 should have all participants as holders before sync"
    );
    let holders = node1.presignature_storage.fetch_holders(77).await;
    assert_eq!(
        holders, all_participants,
        "presig 77 should have all participants as holders before sync"
    );

    // node0 broadcasts its sync update (which does NOT include id=77 since node0 doesn't have it).
    // Responder runs remove_outdated, which removes id=77.
    let node0_triples = node0.owned_triples().await;
    let node0_presigs = node0.owned_presignatures().await;
    assert!(!node0_triples.contains(&77), "node0 should not own id=77");

    let response = node1
        .sync(node0, node0_triples.clone(), node0_presigs.clone())
        .await;
    assert!(
        response.triples.is_empty(),
        "node1 should not report any missing triples (remove_outdated handles orphans)"
    );
    assert!(
        response.presignatures.is_empty(),
        "node1 should not report any missing presignatures"
    );

    // After sync, id=77 should be removed from node1 (via remove_outdated).
    assert_triples_owned_state(&node1.triple_storage, node0.me, &[], &[77]).await;
    assert_presig_owned_state(&node1.presignature_storage, node0.me, &[], &[77]).await;

    // Verify fixture artifacts on node1 are unchanged (only id=77 was removed).
    let node1_triples_after = node1.owned_triples().await;
    let node1_presigs_after = node1.owned_presignatures().await;
    assert_eq!(
        node1_triples_after, node1_triples_before,
        "node1 fixture triples should be unchanged"
    );
    assert_eq!(
        node1_presigs_after, node1_presigs_before,
        "node1 fixture presignatures should be unchanged"
    );

    // Verify holders of fixture artifacts are still full on node1.
    for id in &node1_triples_after {
        let holders = node1.triple_storage.fetch_holders(*id).await;
        assert_eq!(
            holders, all_participants,
            "fixture triple {id} should still have all holders"
        );
    }
    for id in &node1_presigs_after {
        let holders = node1.presignature_storage.fetch_holders(*id).await;
        assert_eq!(
            holders, all_participants,
            "fixture presig {id} should still have all holders"
        );
    }
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_matrix() {
    #[derive(Debug, Clone, Copy)]
    enum ArtifactState {
        Generating,
        Stored,
        Using,
        None,
    }

    struct ExpectedCallerState {
        /// Should the artifact appear in the caller's sync update?
        in_update: bool,
        /// Should the caller still have it in Redis after process_sync_response?
        stored_after: bool,
    }

    struct ExpectedResponderState {
        /// Should the responder report the artifact as not_found (missing)?
        missing: bool,
        /// Should the responder still have it in Redis after sync?
        stored_after: bool,
    }

    struct Case {
        caller: ArtifactState,
        responder: ArtifactState,
        expected_caller: ExpectedCallerState,
        expected_responder: ExpectedResponderState,
    }

    // Caller is always the owner (mine=true), responder is the peer (mine=false).
    #[rustfmt::skip] // cargo fmt makes the matrix unreadable
    let test_matrix = [
        // Caller: Stored (in update) ──────────────────────────────
        Case { caller: ArtifactState::Stored,     responder: ArtifactState::Stored,     expected_caller: ExpectedCallerState { in_update: true,  stored_after: true  }, expected_responder: ExpectedResponderState { missing: false, stored_after: true  } },
        Case { caller: ArtifactState::Stored,     responder: ArtifactState::Generating, expected_caller: ExpectedCallerState { in_update: true,  stored_after: true  }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
        Case { caller: ArtifactState::Stored,     responder: ArtifactState::Using,      expected_caller: ExpectedCallerState { in_update: true,  stored_after: true  }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
        Case { caller: ArtifactState::Stored,     responder: ArtifactState::None,       expected_caller: ExpectedCallerState { in_update: true,  stored_after: true  }, expected_responder: ExpectedResponderState { missing: true,  stored_after: false } },
        // Caller: Generating (in update) ──────────────────────────
        Case { caller: ArtifactState::Generating, responder: ArtifactState::Stored,     expected_caller: ExpectedCallerState { in_update: true,  stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: true  } },
        Case { caller: ArtifactState::Generating, responder: ArtifactState::Generating, expected_caller: ExpectedCallerState { in_update: true,  stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
        Case { caller: ArtifactState::Generating, responder: ArtifactState::Using,      expected_caller: ExpectedCallerState { in_update: true,  stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
        Case { caller: ArtifactState::Generating, responder: ArtifactState::None,       expected_caller: ExpectedCallerState { in_update: true,  stored_after: false }, expected_responder: ExpectedResponderState { missing: true,  stored_after: false } },
        // Caller: Using (in update) ──────────────────────────────
        Case { caller: ArtifactState::Using,      responder: ArtifactState::Stored,     expected_caller: ExpectedCallerState { in_update: true,  stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: true  } },
        Case { caller: ArtifactState::Using,      responder: ArtifactState::Generating, expected_caller: ExpectedCallerState { in_update: true,  stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
        Case { caller: ArtifactState::Using,      responder: ArtifactState::Using,      expected_caller: ExpectedCallerState { in_update: true,  stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
        Case { caller: ArtifactState::Using,      responder: ArtifactState::None,       expected_caller: ExpectedCallerState { in_update: true,  stored_after: false }, expected_responder: ExpectedResponderState { missing: true,  stored_after: false } },
        // Caller: None (NOT in update) ────────────────────────────
        Case { caller: ArtifactState::None,       responder: ArtifactState::Stored,     expected_caller: ExpectedCallerState { in_update: false, stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
        Case { caller: ArtifactState::None,       responder: ArtifactState::Generating, expected_caller: ExpectedCallerState { in_update: false, stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
        Case { caller: ArtifactState::None,       responder: ArtifactState::Using,      expected_caller: ExpectedCallerState { in_update: false, stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
        Case { caller: ArtifactState::None,       responder: ArtifactState::None,       expected_caller: ExpectedCallerState { in_update: false, stored_after: false }, expected_responder: ExpectedResponderState { missing: false, stored_after: false } },
    ];

    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let caller = &fixture.nodes[0];
    let responder = &fixture.nodes[1];
    let all_participants = fixture.sorted_participants();

    for (i, case) in test_matrix.iter().enumerate() {
        let id: u64 = 800 + i as u64;
        tracing::info!(id, ?case.caller, ?case.responder, "=== case {i} ===");

        // Hold slots/taken artifacts alive until assertions are done.
        let mut caller_slot = None;
        let mut caller_taken = None;
        let mut responder_slot = None;
        let mut responder_taken = None;

        // --- Set up caller (owner) state ---
        match case.caller {
            ArtifactState::Stored => {
                insert_triples_for_owner(
                    &caller.triple_storage,
                    caller.me,
                    &all_participants,
                    id..=id,
                )
                .await;
            }
            ArtifactState::Generating => {
                caller_slot = Some(
                    caller
                        .triple_storage
                        .create_slot(id, caller.me)
                        .await
                        .unwrap(),
                );
            }
            ArtifactState::Using => {
                insert_triples_for_owner(
                    &caller.triple_storage,
                    caller.me,
                    &all_participants,
                    id..=id,
                )
                .await;
                caller_taken = Some(caller.triple_storage.take(id, caller.me).await.unwrap());
            }
            ArtifactState::None => {}
        }

        // --- Set up responder (peer) state ---
        match case.responder {
            ArtifactState::Stored => {
                insert_triples_for_owner(
                    &responder.triple_storage,
                    caller.me,
                    &all_participants,
                    id..=id,
                )
                .await;
            }
            ArtifactState::Generating => {
                responder_slot = Some(
                    responder
                        .triple_storage
                        .create_slot(id, caller.me)
                        .await
                        .unwrap(),
                );
            }
            ArtifactState::Using => {
                insert_triples_for_owner(
                    &responder.triple_storage,
                    caller.me,
                    &all_participants,
                    id..=id,
                )
                .await;
                responder_taken = Some(responder.triple_storage.take(id, caller.me).await.unwrap());
            }
            ArtifactState::None => {}
        }

        // --- Build caller's sync update ---
        let caller_update = caller.owned_triples_with_reserved().await;
        assert_eq!(
            caller_update.contains(&id),
            case.expected_caller.in_update,
            "case {i}: caller={:?} → expected in_update={}",
            case.caller,
            case.expected_caller.in_update,
        );

        // --- Responder processes the sync update ---
        let response = responder
            .sync(
                caller,
                caller_update,
                vec![], // this matrix only tests triples
            )
            .await;

        // Verify the full SyncUpdate response from the responder.
        assert_eq!(
            response.from, responder.me,
            "case {i}: response.from should be the responder",
        );
        assert_eq!(
            response.triples.contains(&id),
            case.expected_responder.missing,
            "case {i}: caller={:?}, responder={:?} → expected missing={}",
            case.caller,
            case.responder,
            case.expected_responder.missing,
        );

        // --- Verify responder's Redis state after sync ---
        assert_eq!(
            responder
                .triple_storage
                .contains_by_owner(id, caller.me)
                .await,
            case.expected_responder.stored_after,
            "case {i}: caller={:?}, responder={:?} → expected responder stored_after={}",
            case.caller,
            case.responder,
            case.expected_responder.stored_after,
        );

        // --- Caller processes the sync response (remove holder / prune) ---
        caller
            .process_sync_response(responder.me, 2, &response)
            .await;
        assert_eq!(
            caller.triple_storage.contains_by_owner(id, caller.me).await,
            case.expected_caller.stored_after,
            "case {i}: caller={:?}, responder={:?} → expected caller stored_after={}",
            case.caller,
            case.responder,
            case.expected_caller.stored_after,
        );

        // Clean up held slots/taken before next iteration.
        drop(caller_slot);
        drop(caller_taken);
        drop(responder_slot);
        drop(responder_taken);
        // Wait for async Drop cleanup.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// How many triple and presignature shares a node holds for each owner.
async fn shares_by_owner(
    node: &MpcFixtureNode,
    owners: &[Participant],
) -> Vec<(Participant, usize, usize)> {
    let mut shares = Vec::new();
    for &owner in owners {
        shares.push((
            owner,
            node.triple_storage.len_by_owner(owner).await,
            node.presignature_storage.len_by_owner(owner).await,
        ));
    }
    shares
}

fn empty_update(from: Participant) -> SyncUpdate {
    SyncUpdate {
        from,
        triples: vec![],
        presignatures: vec![],
    }
}

/// A caller with a key the contract doesn't know can't make a node drop shares,
/// whether it claims to be the receiver (the owner of its own artifacts) or
/// another owner.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_rejects_outside_caller() {
    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let node0 = &fixture.nodes[0];
    let node1 = &fixture.nodes[1];
    let owners = fixture.sorted_participants();
    let before = shares_by_owner(node1, &owners).await;
    assert!(
        before.iter().all(|&(_, t, p)| t > 0 && p > 0),
        "node1 should hold shares of every owner's artifacts: {before:?}"
    );

    let outsider_sk = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
    for claimed in [node1.me, node0.me] {
        let result = node1
            .try_sync(claimed, &outsider_sk, &empty_update(claimed))
            .await;
        assert!(
            result.is_err(),
            "outsider claiming {claimed:?} should be rejected"
        );
    }

    assert_eq!(shares_by_owner(node1, &owners).await, before);
}

/// A participant can't pass as another node: claiming another sender fails the
/// signature check, and a `from` inside the payload is ignored for the signer.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_rejects_impersonation() {
    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let node0 = &fixture.nodes[0];
    let node1 = &fixture.nodes[1];
    let node2 = &fixture.nodes[2];
    let owners = fixture.sorted_participants();
    let before = shares_by_owner(node1, &owners).await;
    assert!(
        before.iter().all(|&(_, t, p)| t > 0 && p > 0),
        "node1 should hold shares of every owner's artifacts: {before:?}"
    );

    let node2_network = node2.config.borrow().local.network.clone();
    let node2_sk = node2_network.sign_sk.clone();

    // node2's key, but the signed envelope claims another sender.
    for victim in [node0.me, node1.me] {
        let result = node1
            .try_sync(victim, &node2_sk, &empty_update(victim))
            .await;
        assert!(
            result.is_err(),
            "node2 signing as {victim:?} should be rejected"
        );
    }

    // Signed honestly as node2, with node0 named inside the payload. If that
    // `from` were trusted, node1 would drop its shares of node0's artifacts,
    // since none of them are in node2's list.
    let update = SyncUpdate {
        from: node0.me,
        triples: node2.owned_triples().await,
        presignatures: node2.owned_presignatures().await,
    };
    let reply = node1
        .try_sync(node2.me, &node2_sk, &update)
        .await
        .expect("node2 signing as itself should be accepted");
    // The reply goes to the signer, so only node2 can open it.
    let response = node1
        .open_reply(&reply, &node2_network.cipher_sk)
        .expect("node2 should open the reply");
    assert_eq!(response.from, node1.me);
    assert!(response.triples.is_empty() && response.presignatures.is_empty());

    assert_eq!(shares_by_owner(node1, &owners).await, before);
}

/// A caller only accepts a reply signed by the node it asked. Otherwise a
/// forged reply listing the caller's artifacts as missing would make it drop
/// that node as a holder and prune them.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sync_reply_rejects_forged_responder() {
    let fixture = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    let node0 = &fixture.nodes[0];
    let node1 = &fixture.nodes[1];
    let node2 = &fixture.nodes[2];
    let node0_network = node0.config.borrow().local.network.clone();
    let node0_triples = node0.owned_triples().await;
    let node0_presigs = node0.owned_presignatures().await;
    let update = SyncUpdate {
        from: node0.me,
        triples: node0_triples.clone(),
        presignatures: node0_presigs.clone(),
    };

    // Control: node1's genuine reply opens as node1's.
    let reply = node1
        .try_sync(node0.me, &node0_network.sign_sk, &update)
        .await
        .expect("node0's update should be accepted");
    let response = node1
        .open_reply(&reply, &node0_network.cipher_sk)
        .expect("genuine reply should open");
    assert_eq!(response.from, node1.me);

    // A reply from a node other than the one asked: node0 asked node2 but
    // got node1's reply.
    assert!(
        node2.open_reply(&reply, &node0_network.cipher_sk).is_err(),
        "reply signed by node1 should not pass as node2's"
    );

    // A reply forged with a key the contract doesn't know, claiming to be
    // node1 and listing all of node0's artifacts as missing.
    let outsider_sk = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
    let forged = SyncUpdate {
        from: node1.me,
        triples: node0_triples,
        presignatures: node0_presigs,
    };
    let forged = SignedMessage::encrypt(
        &forged,
        node1.me,
        &outsider_sk,
        &node0_network.cipher_sk.public_key(),
    )
    .expect("encrypt forged reply");
    assert!(
        node1.open_reply(&forged, &node0_network.cipher_sk).is_err(),
        "forged reply should be rejected"
    );
}
