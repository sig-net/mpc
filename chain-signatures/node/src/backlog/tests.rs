use super::{
    AnyProgress, Backlog, BacklogEntry, BacklogError, Bidirectional, Checkpoint, Checkpoints,
    Executing, Final, Generating, Initial, PendingRequests, Publishing, Sign,
};
use crate::backlog::mock::{
    bidi_initial_status, mock_bidi_request, mock_bidi_response, mock_bidirectional_tx,
    mock_execution_entry, mock_execution_entry_with_timestamp, mock_participants, mock_publishing,
    mock_publishing_with_proposer, mock_sign_request, mock_signature_output, mock_tx,
    pending_execution_status, single_entry_checkpoint, BacklogTestExt,
};
use crate::sign_bidirectional::{BidirectionalProgress, SignProgress, SignStatus};
use mpc_chain_integration_core::StateManager;
use mpc_primitives::{Chain, ChainConfig as _, ExecutionOutcome, SignId, SignKind};
use std::sync::Arc;

fn digest_hex(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str)
        .unwrap()
        .try_into()
        .expect("digest hex must be 32 bytes")
}

// =========================================================================
// 1. Backlog Operations & Isolation
// =========================================================================

#[tokio::test]
async fn test_backlog_chain_isolation() {
    let backlog = Backlog::new();

    let sign_id_eth = SignId::from_u8(1);
    let sign_id_sol = SignId::from_u8(2);
    let sign_id_near = SignId::from_u8(3);

    backlog
        .insert_mock_bidirectional(sign_id_eth, Chain::Ethereum)
        .await;
    backlog
        .insert_mock_bidirectional(sign_id_sol, Chain::Solana)
        .await;
    backlog
        .insert_mock_bidirectional(sign_id_near, Chain::NEAR)
        .await;

    // Verify correct transactions in each chain
    assert!(backlog.get(Chain::Ethereum, &sign_id_eth).await.is_some());
    assert!(backlog.get(Chain::Ethereum, &sign_id_sol).await.is_none());
    assert!(backlog.get(Chain::Solana, &sign_id_sol).await.is_some());
    assert!(backlog.get(Chain::Solana, &sign_id_eth).await.is_none());
    assert!(backlog.get(Chain::NEAR, &sign_id_near).await.is_some());
    assert!(backlog.get(Chain::NEAR, &sign_id_eth).await.is_none());
}

#[tokio::test]
async fn test_backlog_filter_by_status() {
    let backlog = Backlog::new();

    // Add transactions with different statuses to Solana
    let sign_id0 = SignId::from_u8(0);
    let sign_id1 = SignId::from_u8(1);
    let tx2 = mock_bidirectional_tx(SignId::from_u8(2), Chain::Solana);
    let tx3 = mock_bidirectional_tx(SignId::from_u8(3), Chain::Solana);

    backlog
        .insert_mock_bidirectional(sign_id1, Chain::Solana)
        .await;
    backlog.insert_mock_final(&tx2).await;
    backlog.insert_mock_executing(&tx3).await;

    // Add transaction to Canton
    let tx4 = mock_bidirectional_tx(SignId::from_u8(4), Chain::Canton);
    backlog.insert_mock_executing(&tx4).await;

    // Filter Solana by Pending execution
    let sol_pending = backlog
        .get_by::<Bidirectional<Executing>>(Chain::Solana, &tx3.sign_id())
        .await;
    assert!(sol_pending.is_some());

    // Filter Solana by Initial Generating
    let sol_awaiting = backlog
        .get_by::<Bidirectional<Initial<Generating>>>(Chain::Solana, &sign_id1)
        .await;
    assert!(sol_awaiting.is_some());

    // Filter Solana by bidirectional completion awaiting final respond
    let sol_completion = backlog
        .get_by::<Bidirectional<Final<Generating>>>(Chain::Solana, &tx2.sign_id())
        .await;
    assert!(sol_completion.is_some());

    // Filter Canton by Pending execution
    let canton_pending = backlog
        .get_by::<Bidirectional<Executing>>(Chain::Canton, &tx4.sign_id())
        .await;
    assert!(canton_pending.is_some());

    // Filter non-existent chain returns empty
    let near_pending = backlog
        .get_by::<Bidirectional<Executing>>(Chain::NEAR, &sign_id0)
        .await;
    assert!(near_pending.is_none());
}

#[tokio::test]
async fn test_backlog_concurrent_access() {
    let backlog = Backlog::new();
    let mut handles = vec![];

    // Spawn multiple tasks that insert concurrently to different chains
    for i in 0..5 {
        let backlog = backlog.clone();
        let handle = tokio::spawn(async move {
            backlog
                .insert_mock_bidirectional(SignId::from_u8(i), Chain::Ethereum)
                .await;
        });
        handles.push(handle);
    }

    for i in 5..10 {
        let backlog = backlog.clone();
        let handle = tokio::spawn(async move {
            backlog
                .insert_mock_bidirectional(SignId::from_u8(i), Chain::Solana)
                .await;
        });
        handles.push(handle);
    }

    // Wait for all insertions and verify all were inserted
    for handle in handles {
        handle.await.unwrap();
    }
    assert_eq!(backlog.len_by_chain(Chain::Ethereum).await, 5);
    assert_eq!(backlog.len_by_chain(Chain::Solana).await, 5);

    // Spawn multiple tasks that remove concurrently
    let mut handles = vec![];
    for i in 0..5 {
        let backlog = backlog.clone();
        let handle = tokio::spawn(async move {
            let id = SignId::from_u8(i);
            backlog.remove(Chain::Ethereum, &id).await
        });
        handles.push(handle);
    }

    // Wait for all removals
    for handle in handles {
        let removed = handle.await.unwrap();
        assert!(removed);
    }

    // Verify Ethereum chain is now empty, but Solana still has data
    assert_eq!(backlog.len_by_chain(Chain::Ethereum).await, 0);
    assert_eq!(backlog.len_by_chain(Chain::Solana).await, 5);
}

#[tokio::test]
async fn test_total_pending_accounting() {
    let backlog = Backlog::new();
    assert_eq!(backlog.len(), 0);
    assert!(backlog.is_empty());

    let sign_id1 = SignId::from_u8(1);
    let sign_id2 = SignId::from_u8(2);
    let sign_id_missing = SignId::from_u8(99);

    // Increments on insert
    backlog.insert_mock_sign(sign_id1, Chain::Ethereum).await;
    assert_eq!(backlog.len(), 1);
    assert!(!backlog.is_empty());

    // Duplicate insert does not increment
    backlog.insert_mock_sign(sign_id1, Chain::Ethereum).await;
    assert_eq!(backlog.len(), 1);

    // Counts across chains
    backlog.insert_mock_sign(sign_id2, Chain::Solana).await;
    assert_eq!(backlog.len(), 2);

    // Removing non-existent ID does not decrement
    assert!(!backlog.remove(Chain::Ethereum, &sign_id_missing).await);
    assert_eq!(backlog.len(), 2);

    // Decrements on valid remove
    assert!(backlog.remove(Chain::Ethereum, &sign_id1).await);
    assert_eq!(backlog.len(), 1);

    assert!(backlog.remove(Chain::Solana, &sign_id2).await);
    assert_eq!(backlog.len(), 0);
    assert!(backlog.is_empty());
}

// =========================================================================
// 2. Periodic & Boundary Checkpoints
// =========================================================================

#[tokio::test]
async fn test_automatic_checkpoint_on_interval() {
    for chain in [Chain::Ethereum, Chain::Solana] {
        let backlog = Backlog::new();
        let interval = chain.checkpoint_interval().unwrap();

        backlog
            .insert_mock_bidirectional(SignId::from_u8(1), chain)
            .await;

        // Heights before interval should not create checkpoints
        for i in 1..interval {
            let cp = backlog.set_processed_block(chain, i).await;
            assert!(
                cp.is_none(),
                "Block {i} should not make checkpoint for {chain}"
            );
        }

        // At interval boundary, creates checkpoint
        let cp = backlog
            .set_processed_block(chain, interval)
            .await
            .expect("should checkpoint at interval");
        assert_eq!(cp.block_height, interval);
        assert_eq!(cp.chain, chain);
        assert_eq!(cp.pending_requests.len(), 1);

        // Next block does not trigger
        assert!(backlog
            .set_processed_block(chain, interval + 1)
            .await
            .is_none());

        // At 2 * interval, creates next checkpoint
        let cp2 = backlog
            .set_processed_block(chain, 2 * interval)
            .await
            .expect("should checkpoint at 2*interval");
        assert_eq!(cp2.block_height, 2 * interval);
    }
}

#[tokio::test]
async fn test_boundary_crossing_rules() {
    let backlog = Backlog::new();
    backlog
        .insert_mock_bidirectional(SignId::from_u8(1), Chain::Solana)
        .await;

    // 1. Within first bucket (50 / 120 == 0 == prev default 0): no checkpoint
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 50, 120)
        .await;
    assert!(cp.is_none());

    // 2. Exact boundary multiple (120 crosses to bucket 1): triggers checkpoint
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 120, 120)
        .await;
    assert_eq!(cp.expect("exact multiple checkpoints").block_height, 120);

    // 3. Same bucket (130 / 120 == 1): no new boundary crossed
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 130, 120)
        .await;
    assert!(cp.is_none());

    // 4. Sparse jump across multiple buckets (500 is in bucket 4): triggers checkpoint
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 500, 120)
        .await
        .expect("jump to bucket 4 checkpoints");
    assert_eq!(cp.block_height, 500);
    assert_eq!(cp.pending_requests.len(), 1);

    // 5. Another query in same bucket 4 (480 / 120 == 4): no checkpoint
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 480, 120)
        .await;
    assert!(cp.is_none());

    // 6. Crosses from bucket 4 to bucket 5 (600 / 120 == 5): triggers checkpoint
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 600, 120)
        .await
        .expect("jump to bucket 5 checkpoints");
    assert_eq!(cp.block_height, 600);
}

// =========================================================================
// 3. Checkpoint Structure & Invariants
// =========================================================================

#[tokio::test]
async fn test_checkpoint_creation() {
    let backlog = Backlog::new();

    let tx1 = mock_bidirectional_tx(SignId::from_u8(1), Chain::Solana);
    let tx2 = mock_bidirectional_tx(SignId::from_u8(2), Chain::Solana);

    backlog.insert_mock_executing(&tx1).await;
    backlog.insert_mock_final(&tx2).await;
    backlog.set_processed_block(Chain::Solana, 100).await;

    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

    assert_eq!(checkpoint.block_height, 100);
    assert_eq!(checkpoint.pending_requests.len(), 2);
    // Guard the checkpoint digest wire format; update only for intentional changes.
    assert_eq!(
        checkpoint.digest(),
        digest_hex("449d3cbc30e57ae4964916e0366dc88c8b6d9678d4011f9a20da43ba07396836")
    );
}

#[test]
fn test_checkpoint_digest_invariants() {
    let tx1 = mock_tx(1);
    let tx2 = mock_tx(2);

    let mut pending1 = PendingRequests::new();
    pending1.insert(
        tx1.sign_id(),
        mock_execution_entry(&tx1, Chain::Ethereum, bidi_initial_status()),
    );
    pending1.insert(
        tx2.sign_id(),
        mock_execution_entry(&tx2, Chain::Ethereum, bidi_initial_status()),
    );
    pending1.set_processed_block(100);

    let pending2 = pending1.clone();

    let cp1 = Checkpoints::snapshot(&pending1, Chain::Ethereum);
    let cp2 = Checkpoints::snapshot(&pending2, Chain::Ethereum);

    // Invariant 1: Identical data yields identical checkpoint and digest
    assert_eq!(cp1, cp2);
    assert_eq!(cp1.digest(), cp2.digest());

    // Invariant 2: Different block height changes equality and digest
    let mut cp3 = Checkpoints::snapshot(&pending2, Chain::Ethereum);
    cp3.block_height = 101;
    assert_ne!(cp1, cp3);

    // Invariant 3: Request timestamp does not affect the digest
    let entry_ts0 =
        mock_execution_entry_with_timestamp(&tx1, Chain::Ethereum, bidi_initial_status(), 0);
    let entry_ts99 =
        mock_execution_entry_with_timestamp(&tx1, Chain::Ethereum, bidi_initial_status(), 9999);
    assert_eq!(
        single_entry_checkpoint(entry_ts0).digest(),
        single_entry_checkpoint(entry_ts99).digest()
    );

    // Invariant 4: Different requests produce distinct digests
    let tx10 = mock_tx(10);
    let tx11 = mock_tx(11);
    let cp_diff1 = single_entry_checkpoint(mock_execution_entry(
        &tx10,
        Chain::Ethereum,
        bidi_initial_status(),
    ));
    let cp_diff2 = single_entry_checkpoint(mock_execution_entry(
        &tx11,
        Chain::Ethereum,
        bidi_initial_status(),
    ));
    assert_ne!(cp_diff1.digest(), cp_diff2.digest());
    assert_eq!(
        cp_diff1.digest(),
        digest_hex("a31e0d66f5b4fb860cc62e809cc29918b9138550b5cd62e1c752fc40ce6c2779")
    );
}

#[test]
fn test_checkpoint_consensus_projection() {
    let tx = mock_bidirectional_tx(SignId::from_u8(60), Chain::Ethereum);
    let sign_id = tx.sign_id();

    // Initial source-chain phase: generation, and publishing by any proposer,
    // all collapse to a single digest.
    let generation = single_entry_checkpoint(mock_execution_entry(
        &tx,
        Chain::Ethereum,
        bidi_initial_status(),
    ));
    let publish = single_entry_checkpoint(mock_execution_entry(
        &tx,
        Chain::Ethereum,
        SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Publishing(
            mock_publishing(),
        ))),
    ));
    let publish_other = single_entry_checkpoint(mock_execution_entry(
        &tx,
        Chain::Ethereum,
        SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Publishing(
            mock_publishing_with_proposer(false),
        ))),
    ));
    assert_eq!(generation.digest(), publish.digest());
    assert_eq!(generation.digest(), publish_other.digest());

    // Plain `Sign` requests follow the same initial-phase projection.
    let plain = mock_sign_request(sign_id, Chain::Ethereum);
    let plain_generation = single_entry_checkpoint(BacklogEntry::new(Arc::clone(&plain)));
    let plain_publish = single_entry_checkpoint(BacklogEntry::with_status(
        plain,
        SignStatus::Sign(SignProgress::Publishing(mock_publishing())),
    ));
    assert_eq!(plain_generation.digest(), plain_publish.digest());

    // Post-initial phase: awaiting target-chain execution and the final
    // response generation/publish states share the same checkpoint digest.
    let execution = single_entry_checkpoint(mock_execution_entry(
        &tx,
        Chain::Ethereum,
        pending_execution_status(&tx),
    ));
    let response_request = mock_bidi_response(&tx);
    let origin_request = mock_bidi_request(sign_id, Chain::Ethereum);
    let gen_bidirectional = single_entry_checkpoint(BacklogEntry::with_status(
        Arc::clone(&origin_request),
        SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: Arc::clone(&response_request),
            progress: SignProgress::Generating,
        }),
    ));
    let pub_bidirectional = single_entry_checkpoint(BacklogEntry::with_status(
        origin_request,
        SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: response_request,
            progress: SignProgress::Publishing(mock_publishing()),
        }),
    ));
    assert_eq!(execution.digest(), gen_bidirectional.digest());
    assert_eq!(execution.digest(), pub_bidirectional.digest());

    // Initial and post-initial phases must remain distinct.
    assert_ne!(generation.digest(), execution.digest());
}

#[test]
fn test_checkpoint_serialization() {
    let tx1 = mock_tx(1);
    let checkpoint = single_entry_checkpoint(mock_execution_entry(
        &tx1,
        Chain::Ethereum,
        pending_execution_status(&tx1),
    ));

    let json = serde_json::to_string(&checkpoint).unwrap();
    let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();

    assert_eq!(checkpoint, deserialized);
    assert_eq!(
        checkpoint.digest(),
        digest_hex("12f5bc5c4f0fea1debafceb8879644ea545309775b3e2cc266335cd3247d5394")
    );
    assert_eq!(checkpoint.digest(), deserialized.digest());

    let restored_entry = &deserialized.pending_requests[0];
    assert_eq!(restored_entry.sign_id(), tx1.sign_id());
    let SignKind::SignBidirectional(ref event) = restored_entry.request.kind else {
        panic!("Expected SignBidirectional kind");
    };
    assert_eq!(event.dest, "test_dest");
    assert_eq!(restored_entry.status, pending_execution_status(&tx1));
}

// =========================================================================
// 4. Entry Lifecycle & Watchers
// =========================================================================

#[tokio::test]
async fn test_plain_sign_typestate_lifecycle() {
    let backlog = Backlog::new();
    let sign_id = SignId::from_u8(1);
    let req = mock_sign_request(sign_id, Chain::Ethereum);

    // 1. Initial entry via Backlog::insert_sign
    let entry = backlog.insert_sign(Arc::clone(&req)).await;
    assert_eq!(entry.sign_id(), sign_id);
    assert_eq!(entry.state(), &Sign(Generating));

    // Verify querying with wrong state returns None
    assert!(backlog
        .get_by::<Sign<Publishing>>(Chain::Ethereum, &sign_id)
        .await
        .is_none());

    // 2. Advance to publishing
    let (pk, output) = mock_signature_output(&req.args);
    let pub_entry = entry
        .advance(pk, &output, mock_participants(), true)
        .await
        .expect("advance call should succeed");

    assert_eq!(pub_entry.sign_id(), sign_id);
    assert_eq!(pub_entry.request().id, sign_id);

    // 3. Verify signature
    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let valid_sig = mpc_crypto::generate_signature(&root_sk, &req.args);
    pub_entry
        .verify_signature(root_sk.public_key().into(), &valid_sig)
        .expect("signature should verify");

    // 4. Wildcard AnyProgress retrieval and complete removing from backlog
    let any_entry = backlog
        .get_by::<Sign<AnyProgress>>(Chain::Ethereum, &sign_id)
        .await
        .expect("should match AnyProgress");
    let removed = any_entry.complete().await;
    assert!(removed);
    assert!(backlog.get(Chain::Ethereum, &sign_id).await.is_none());

    // 5. Chained advance from insert to complete
    let sign_id2 = SignId::from_u8(11);
    let req2 = mock_sign_request(sign_id2, Chain::Ethereum);
    let (pk2, output2) = mock_signature_output(&req2.args);
    let completed = backlog
        .insert_sign(req2)
        .await
        .advance(pk2, &output2, mock_participants(), true)
        .await
        .expect("chained advance should succeed")
        .complete()
        .await;
    assert!(completed);
    assert!(backlog.get(Chain::Ethereum, &sign_id2).await.is_none());

    // 6. Invalid signature rejection
    let sign_id3 = SignId::from_u8(99);
    let entry3 = backlog.insert_mock_sign(sign_id3, Chain::Ethereum).await;
    let wrong_root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let wrong_pk = wrong_root_sk.public_key().into();
    let dummy_output = cait_sith::FullSignature {
        big_r: k256::AffinePoint::GENERATOR,
        s: k256::Scalar::ONE,
    };
    let result = entry3
        .advance(wrong_pk, &dummy_output, mock_participants(), true)
        .await;
    assert_eq!(result.unwrap_err(), BacklogError::InvalidSignature);
}

#[tokio::test]
async fn test_bidirectional_typestate_lifecycle() {
    let backlog = Backlog::new();
    let sign_id = SignId::from_u8(2);
    let req = mock_bidi_request(sign_id, Chain::Solana);

    // 1. Initial Generating via insert_bidirectional
    let bidi_entry = backlog.insert_bidirectional(Arc::clone(&req)).await;
    assert_eq!(bidi_entry.sign_id(), sign_id);
    assert_eq!(bidi_entry.state(), &Bidirectional(Initial(Generating)));

    // 2. Advance to Publishing & verify phase 1 signature
    let (pk1, output1) = mock_signature_output(&req.args);
    let pub_entry = bidi_entry
        .advance(pk1, &output1, mock_participants(), true)
        .await
        .expect("advance call should succeed");

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let sig1 = mpc_crypto::generate_signature(&root_sk, &req.args);
    pub_entry
        .verify_signature(root_sk.public_key().into(), &sig1)
        .expect("sig1 should verify");

    // 3. Advance to Executing
    let tx = Arc::new(mock_bidirectional_tx(sign_id, Chain::Solana));
    let exec_entry = pub_entry
        .advance(Arc::clone(&tx))
        .await
        .expect("should advance to executing");
    assert_eq!(exec_entry.execution_tx().id, tx.id);

    // Verify get_by can retrieve Executing state directly from backlog
    assert!(backlog
        .get_by::<Bidirectional<Executing>>(Chain::Solana, &sign_id)
        .await
        .is_some());
    assert!(backlog
        .get_by::<Bidirectional<Initial<Generating>>>(Chain::Solana, &sign_id)
        .await
        .is_none());

    // 4. Advance to Final Generating
    let final_entry = exec_entry
        .advance(ExecutionOutcome::Success { output: vec![] })
        .await
        .expect("should advance to final");
    assert_eq!(final_entry.request().id, sign_id);

    // Verify get_by can retrieve Final<Generating> state directly from backlog
    assert!(backlog
        .get_by::<Bidirectional<Final<Generating>>>(Chain::Solana, &sign_id)
        .await
        .is_some());

    // 5. Advance to Final Publishing & verify phase 2 signature
    let (pk2, output2) = mock_signature_output(&final_entry.request().args);
    let final_pub_entry = final_entry
        .advance(pk2, &output2, mock_participants(), true)
        .await
        .expect("advance call should succeed");
    assert_eq!(final_pub_entry.respond_request().id, sign_id);

    let sig2 = mpc_crypto::generate_signature(&root_sk, &final_pub_entry.respond_request().args);
    final_pub_entry
        .verify_signature(root_sk.public_key().into(), &sig2)
        .expect("sig2 should verify");

    // 6. Complete removing from backlog
    let completed = final_pub_entry.complete().await;
    assert!(completed);
    assert!(backlog.get(Chain::Solana, &sign_id).await.is_none());

    // 7. Full method-chained bidirectional advancement
    let sign_id2 = SignId::from_u8(22);
    let req2 = mock_bidi_request(sign_id2, Chain::Solana);
    let tx2 = Arc::new(mock_bidirectional_tx(sign_id2, Chain::Solana));
    let (cpk1, cout1) = mock_signature_output(&req2.args);

    let bidi_final_gen = backlog
        .insert_bidirectional(req2)
        .await
        .advance(cpk1, &cout1, mock_participants(), true)
        .await
        .expect("chained advance to publishing")
        .advance(tx2)
        .await
        .expect("chained advance to executing")
        .advance(ExecutionOutcome::Success { output: vec![] })
        .await
        .expect("chained advance to final generating");

    let (cpk2, cout2) = mock_signature_output(&bidi_final_gen.request().args);
    let chained_done = bidi_final_gen
        .advance(cpk2, &cout2, mock_participants(), true)
        .await
        .expect("chained advance to final publishing")
        .complete()
        .await;

    assert!(chained_done);
    assert!(backlog.get(Chain::Solana, &sign_id2).await.is_none());
}

#[tokio::test]
async fn test_bidirectional_executing_advance_outcomes() {
    let backlog = Backlog::new();
    let tx = mock_tx(20);
    let sign_id = tx.sign_id();

    let entry = backlog.insert_mock_executing(&tx).await;

    // Test Success outcome
    let success_entry = entry
        .advance(ExecutionOutcome::Success {
            output: vec![0x01, 0x02],
        })
        .await
        .expect("advance success");

    // Verified: sign_id and chain match invariant by construction
    assert_eq!(success_entry.sign_id(), sign_id);
    assert_eq!(success_entry.chain, tx.source_chain);
    let SignKind::RespondBidirectional(respond) = &success_entry.request().kind else {
        panic!("expected RespondBidirectional kind");
    };
    assert_eq!(respond.tx_id, tx.id);
    assert_eq!(respond.output, vec![0x01, 0x02]);

    // Test Failed outcome
    let tx2 = mock_tx(21);
    let sign_id2 = tx2.sign_id();
    let entry2 = backlog.insert_mock_executing(&tx2).await;
    let failed_entry = entry2
        .advance(ExecutionOutcome::Failed)
        .await
        .expect("advance failed");

    assert_eq!(failed_entry.sign_id(), sign_id2);
    assert_eq!(failed_entry.chain, tx2.source_chain);
    let SignKind::RespondBidirectional(respond2) = &failed_entry.request().kind else {
        panic!("expected RespondBidirectional kind");
    };
    assert_eq!(respond2.tx_id, tx2.id);
    assert!(respond2.output.starts_with(&[0xde, 0xad, 0xbe, 0xef]));
}

#[tokio::test]
async fn test_watch_unwatch_and_respond() {
    let backlog = Backlog::new();
    let tx = mock_tx(7);
    let sign_id = tx.sign_id();

    let entry = backlog.insert_mock_executing(&tx).await;

    // Unwatch returns the watcher (automatically registered on advance to executing)
    let (watched_id, watched_tx) = backlog
        .unwatch_execution(tx.target_chain, &tx.id)
        .await
        .expect("watcher present");
    assert_eq!(watched_id, sign_id);
    assert_eq!(watched_tx.id, tx.id);

    // Watch execution on target chain using typed SignEntry
    backlog.watch_execution(&entry).await;

    // Also verify entry.watch_execution() method
    entry.watch_execution().await;

    let (watched_id2, watched_tx2) = backlog
        .unwatch_execution(tx.target_chain, &tx.id)
        .await
        .expect("watcher present");
    assert_eq!(watched_id2, sign_id);
    assert_eq!(watched_tx2.id, tx.id);

    // Advance executing entry to final response signing
    let entry = backlog
        .get_by::<Bidirectional<Executing>>(tx.source_chain, &sign_id)
        .await
        .expect("executing entry exists");
    entry
        .advance(ExecutionOutcome::Success { output: vec![] })
        .await
        .expect("respond should transition to final generating");
    assert!(backlog
        .get_by::<Bidirectional<Final<Generating>>>(tx.source_chain, &sign_id)
        .await
        .is_some());
}

// =========================================================================
// 5. Recovery & Requeuing
// =========================================================================

#[tokio::test]
async fn test_recovery_restores_state_and_watchers() {
    let backlog = Backlog::new();
    let tx = mock_tx(6);
    let sign_id = tx.sign_id();

    backlog.insert_mock_executing(&tx).await;
    backlog.set_processed_block(Chain::Solana, 10).await;
    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

    let recovered = Backlog::new();
    recovered
        .checkpoints()
        .storage()
        .persist(&checkpoint)
        .await
        .unwrap();
    recovered.recover_by_checkpoint(&checkpoint).await;

    // Restores execution entry
    let entry = recovered
        .get_by::<Bidirectional<Executing>>(Chain::Solana, &sign_id)
        .await
        .expect("executing entry restored");
    assert_eq!(entry.sign_id(), sign_id);

    // Restores watchers on target chain
    let watchers = recovered.get_execution_watchers(Chain::Ethereum).await;
    assert_eq!(watchers.len(), 1);
    assert!(watchers.contains_key(&tx.id));

    // Visible as latest checkpoint
    assert_eq!(
        recovered.checkpoints().latest(Chain::Solana).await.unwrap(),
        Some(checkpoint)
    );

    // Preserves SignKind
    let recovered_entry = recovered
        .get(Chain::Solana, &sign_id)
        .await
        .expect("missing recovered entry");
    assert_matches!(
        recovered_entry.request().kind,
        SignKind::SignBidirectional(_)
    );
}

#[tokio::test]
async fn test_recovery_requeues_completed_bidirectional_requests() {
    let backlog = Backlog::new();
    let tx = mock_tx(42);

    backlog.insert_mock_final(&tx).await;
    backlog.set_processed_block(Chain::Solana, 10).await;
    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

    let recovered = Backlog::new();
    recovered.recover_by_checkpoint(&checkpoint).await;

    let requeued = recovered.requeueable_requests(Chain::Solana).await;
    assert_eq!(requeued.len(), 1);
    assert_matches!(
        requeued[0].request().kind,
        SignKind::RespondBidirectional(_)
    );
}

#[tokio::test]
async fn test_recovery_preserves_pending_checkpoints() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;
    let interval = chain.checkpoint_interval().unwrap();

    backlog.set_processed_block(chain, interval).await.unwrap();
    backlog
        .set_processed_block(chain, 2 * interval)
        .await
        .unwrap();
    assert_eq!(backlog.checkpoints().count(chain), 2);

    // Recovery does not discard pending checkpoints needed for consensus matching
    let recovery_cp = Checkpoint::reset(chain, interval / 2);
    backlog.recover_by_checkpoint(&recovery_cp).await;
    assert_eq!(backlog.checkpoints().count(chain), 2);
}

#[tokio::test]
async fn test_total_pending_on_recovery() {
    let backlog = Backlog::new();
    for i in 1..=3 {
        backlog
            .insert_mock_sign(SignId::from_u8(i), Chain::Ethereum)
            .await;
    }
    backlog.set_processed_block(Chain::Ethereum, 10).await;
    let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();

    // Clean recovery updates count from 0 to 3
    let clean = Backlog::new();
    assert_eq!(clean.len(), 0);
    clean.recover_by_checkpoint(&checkpoint).await;
    assert_eq!(clean.len(), 3);

    // Dirty recovery overwrites pre-existing state to match checkpoint size exactly
    let dirty = Backlog::new();
    dirty
        .insert_mock_sign(SignId::from_u8(99), Chain::Ethereum)
        .await;
    assert_eq!(dirty.len(), 1);
    dirty.recover_by_checkpoint(&checkpoint).await;
    assert_eq!(dirty.len(), 3);
}

// =========================================================================
// 6. Typestate Querying, Casting & Advancement
// =========================================================================

#[tokio::test]
async fn test_publishable_requests() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;

    // 1. Plain sign request advanced to publishing
    let req1 = mock_sign_request(SignId::from_u8(1), chain);
    let (pk1, out1) = mock_signature_output(&req1.args);
    backlog
        .insert_sign(req1)
        .await
        .advance(pk1, &out1, mock_participants(), true)
        .await
        .unwrap();

    // 2. Plain sign request still generating (not publishable)
    backlog.insert_mock_sign(SignId::from_u8(2), chain).await;

    // 3. Bidirectional request advanced to Phase 1 publishing
    let req3 = mock_bidi_request(SignId::from_u8(3), chain);
    let (pk3, out3) = mock_signature_output(&req3.args);
    backlog
        .insert_bidirectional(req3)
        .await
        .advance(pk3, &out3, mock_participants(), false)
        .await
        .unwrap();

    // 4. Query publishable requests: only req1 and req3 should appear
    let publishable = backlog.publishable_requests(chain).await;
    assert_eq!(publishable.len(), 2);
    assert_eq!(publishable[0].sign_id(), SignId::from_u8(1));
    assert!(publishable[0].is_proposer());
    assert_eq!(publishable[1].sign_id(), SignId::from_u8(3));
    assert!(!publishable[1].is_proposer());
}

#[tokio::test]
async fn test_insert_and_accessors() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;
    let sign_id = SignId::from_u8(10);
    let req = mock_sign_request(sign_id, chain);

    let (entry, is_new) = backlog.insert(Arc::clone(&req)).await;
    assert!(is_new);
    assert_eq!(entry.chain(), chain);
    assert_eq!(entry.sign_id(), sign_id);
    assert_eq!(entry.request_id(), sign_id.request_id);
    assert_eq!(entry.request().id, sign_id);
    assert_eq!(entry.into_request().id, sign_id);

    // Duplicate insert should report is_new == false
    let (_, is_new2) = backlog.insert(req).await;
    assert!(!is_new2);
}

#[tokio::test]
async fn test_dynamic_entry_cast_and_is() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;
    let sign_id = SignId::from_u8(5);
    let req = mock_sign_request(sign_id, chain);

    let (pk, out) = mock_signature_output(&req.args);
    backlog
        .insert_sign(req)
        .await
        .advance(pk, &out, mock_participants(), true)
        .await
        .unwrap();

    // Dynamic entry via backlog.get
    let dyn_entry = backlog.get(chain, &sign_id).await.expect("entry exists");
    assert!(dyn_entry.is::<Sign<Publishing>>());
    assert!(!dyn_entry.is::<Sign<Generating>>());
    assert!(!dyn_entry.is::<Bidirectional<Executing>>());

    // Borrowed downcast via cast
    let cast_entry = dyn_entry.cast::<Sign<Publishing>>();
    assert!(cast_entry.is_some());
    assert_eq!(cast_entry.unwrap().sign_id(), sign_id);
    assert!(dyn_entry.cast::<Sign<Generating>>().is_none());

    // Owned conversion via try_into
    let typed = dyn_entry.try_into::<Sign<Publishing>>().expect("matches");
    assert_eq!(typed.sign_id(), sign_id);
    assert!(typed.is_proposer());
}

#[tokio::test]
async fn test_initial_any_progress_advance() {
    let backlog = Backlog::new();
    let sign_id = SignId::from_u8(7);
    let tx = Arc::new(mock_bidirectional_tx(sign_id, Chain::Solana));

    backlog
        .insert_mock_bidirectional(sign_id, Chain::Solana)
        .await;

    // Retrieve via wildcard AnyProgress
    let entry = backlog
        .get_by::<Bidirectional<Initial<AnyProgress>>>(Chain::Solana, &sign_id)
        .await
        .expect("wildcard initial entry exists");

    // Advance directly to Executing
    let exec_entry = entry
        .advance(Arc::clone(&tx))
        .await
        .expect("advances to executing");
    assert_eq!(exec_entry.execution_tx().id, tx.id);
    assert!(backlog
        .get_by::<Bidirectional<Executing>>(Chain::Solana, &sign_id)
        .await
        .is_some());
}

#[tokio::test]
async fn test_pending_executions_typestate() {
    let backlog = Backlog::new();
    let mut tx1 = mock_tx(11);
    tx1.source_chain = Chain::Ethereum;
    tx1.target_chain = Chain::Solana;
    let mut tx2_sol = mock_tx(12);
    tx2_sol.source_chain = Chain::Solana;
    tx2_sol.target_chain = Chain::Ethereum;

    backlog.insert_mock_executing(&tx1).await;
    backlog.insert_mock_executing(&tx2_sol).await;

    // Plain sign on Ethereum (should not appear in pending executions)
    backlog
        .insert_mock_sign(SignId::from_u8(99), Chain::Ethereum)
        .await;

    let eth_execs = backlog.pending_executions(Chain::Ethereum).await;
    assert_eq!(eth_execs.len(), 1);
    assert_eq!(eth_execs[0].sign_id(), tx1.sign_id());
    assert_eq!(eth_execs[0].execution_tx().id, tx1.id);

    let sol_execs = backlog.pending_executions(Chain::Solana).await;
    assert_eq!(sol_execs.len(), 1);
    assert_eq!(sol_execs[0].sign_id(), tx2_sol.sign_id());
    assert_eq!(sol_execs[0].execution_tx().id, tx2_sol.id);
}
