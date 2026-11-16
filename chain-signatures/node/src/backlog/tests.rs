use super::checkpoint_interval;
use super::{
    AnyProgress, Backlog, BacklogEntry, BacklogError, Bidirectional, Checkpoint, Checkpoints,
    Executing, ExecutionWatch, Final, Generating, Initial, PendingRequests, Publishing, Sign,
};
use crate::backlog::mock::{
    bidi_initial_status, mock_bidi_request, mock_bidi_response, mock_bidirectional_tx,
    mock_execution_entry, mock_execution_entry_with_timestamp, mock_participants, mock_publishing,
    mock_publishing_with_proposer, mock_root_pk, mock_sign_request, mock_signature_output, mock_tx,
    pending_execution_status, single_entry_checkpoint, BacklogTestExt,
};
use crate::sign_bidirectional::{BidirectionalProgress, SignProgress, SignStatus};
use crate::storage::checkpoint_storage::CheckpointStorage;
use mpc_chain_integration_core::StateManager;
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ExecutionOutcome, IndexedSignRequest, SignId,
    SignKind,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

trait ObservedSince {
    fn observed_since(self, at: Instant) -> Self;
}

impl ObservedSince for super::SignEntry<Bidirectional<Executing>> {
    fn observed_since(self, at: Instant) -> Self {
        let tx = Arc::clone(self.execution_tx());
        self.with_execution_watch(ExecutionWatch::new(tx, Some(at)))
    }
}

fn routed_tx(id: u8, source: Chain, target: Chain) -> BidirectionalTx {
    let mut tx = mock_tx(id);
    tx.source_chain = source;
    tx.target_chain = target;
    tx
}

/// The sign ids watching under `tx`'s flat id.
async fn watch_members(
    backlog: &Backlog,
    tx: &BidirectionalTx,
) -> std::collections::HashSet<SignId> {
    backlog
        .get_execution_watchers(tx.target_chain)
        .await
        .get(&tx.id)
        .map(|members| members.iter().map(|member| member.sign_id).collect())
        .unwrap_or_default()
}

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
        let interval = checkpoint_interval(chain).unwrap();

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
        digest_hex("05a0fe7b2a3546a652a21f2f0003fe49b6bf6c8ece39f27dd073c0ec5537144b")
    );
}

/// A body as earlier versions stored it: no source facts of its own, and a digest field.
#[derive(serde::Serialize)]
struct OldEntry {
    request: Arc<IndexedSignRequest>,
    status: SignStatus,
}

#[derive(serde::Serialize)]
struct OldCheckpoint {
    chain: Chain,
    block_height: u64,
    pending_requests: Vec<OldEntry>,
    #[serde(with = "serde_bytes")]
    cumulative_digest: [u8; 32],
}

/// The two entries, at this height, whose digest earlier versions pinned as
/// [`OLD_FORMAT_DIGEST`].
async fn old_format_body() -> Checkpoint {
    let backlog = Backlog::new();
    backlog
        .insert_mock_executing(&mock_bidirectional_tx(SignId::from_u8(1), Chain::Solana))
        .await;
    backlog
        .insert_mock_final(&mock_bidirectional_tx(SignId::from_u8(2), Chain::Solana))
        .await;
    backlog.set_processed_block(Chain::Solana, 100).await;
    let current = backlog.checkpoint(Chain::Solana).await.unwrap();
    let old = OldCheckpoint {
        chain: current.chain,
        block_height: current.block_height,
        pending_requests: current
            .pending_requests
            .into_iter()
            .map(|entry| OldEntry {
                request: entry.request,
                status: entry.status,
            })
            .collect(),
        cumulative_digest: [7; 32],
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&old, &mut bytes).unwrap();
    ciborium::from_reader(bytes.as_slice()).unwrap()
}

const OLD_FORMAT_DIGEST: &str = "449d3cbc30e57ae4964916e0366dc88c8b6d9678d4011f9a20da43ba07396836";

/// A stored body from an earlier version must confirm the digest already settled, or the chain
/// does not start after an upgrade.
#[tokio::test]
async fn an_old_format_body_keeps_its_digest() {
    let body = old_format_body().await;
    assert_eq!(body.digest(), digest_hex(OLD_FORMAT_DIGEST));
    assert!(body
        .pending_requests
        .iter()
        .all(|entry| entry.tx_ids.len() == 1));

    let mut bytes = Vec::new();
    ciborium::into_writer(&body, &mut bytes).unwrap();
    let reread: Checkpoint = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(reread.digest(), digest_hex(OLD_FORMAT_DIGEST));
}

/// What a node stores on adoption is what it holds in memory, as long as the digest allows.
#[tokio::test]
async fn adopting_an_old_format_body_stores_it_rebuilt() {
    let body = old_format_body().await;
    let backlog = Backlog::new();
    backlog.regress(&body, mock_root_pk()).await.unwrap();

    let stored = backlog
        .checkpoints()
        .latest(Chain::Solana)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.digest(), digest_hex(OLD_FORMAT_DIGEST));
    assert!(stored.pending_requests.iter().all(|entry| matches!(
        entry.status,
        SignStatus::Bidirectional(BidirectionalProgress::Executing(_))
    )));
}

/// A rebuild that changes an entry's phase would change an old-format digest, so that body is
/// stored as sent and still confirms the digest it was adopted under.
#[tokio::test]
async fn an_old_format_body_that_cannot_be_rebuilt_is_stored_as_sent() {
    let mut body = old_format_body().await;
    let entry = &mut body.pending_requests[0];
    let mut request = (*entry.request).clone();
    if let SignKind::SignBidirectional(event) = &mut request.kind {
        event.caip2_id = "unknown:1".to_string();
    }
    entry.request = Arc::new(request);

    let backlog = Backlog::new();
    backlog.regress(&body, mock_root_pk()).await.unwrap();

    let stored = backlog
        .checkpoints()
        .latest(Chain::Solana)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.digest(), digest_hex(OLD_FORMAT_DIGEST));
    assert_eq!(stored, body);
}

/// An old-format body is rebuilt on loading too, as it may be one stored as sent. Nothing it
/// says of a response survives a restart, and a first leg with a published signature is not
/// signed again.
#[tokio::test]
async fn loading_an_old_format_body_rebuilds_its_progress() {
    let mut body = old_format_body().await;
    let answered = body
        .pending_requests
        .iter_mut()
        .find(|entry| {
            matches!(
                entry.status,
                SignStatus::Bidirectional(BidirectionalProgress::Final { .. })
            )
        })
        .unwrap();
    let sign_id = answered.sign_id();
    let mut request = (*answered.request).clone();
    if let SignKind::SignBidirectional(event) = &mut request.kind {
        event.caip2_id = "unknown:1".to_string();
    }
    answered.request = Arc::new(request);

    let backlog = Backlog::new();
    backlog.regress(&body, mock_root_pk()).await.unwrap();
    assert_eq!(
        backlog
            .checkpoints()
            .latest(Chain::Solana)
            .await
            .unwrap()
            .unwrap(),
        body,
        "stored as sent, since a rebuild would change its digest"
    );

    let restarted = backlog.clone();
    restarted
        .recover_local(Chain::Solana, mock_root_pk())
        .await
        .unwrap();

    let pending = restarted.pending(&Chain::Solana).read().await;
    let entry = pending.get(&sign_id).unwrap();
    assert!(!entry.tx_ids.is_empty());
    assert!(matches!(
        entry.status,
        SignStatus::Bidirectional(BidirectionalProgress::Initial(_))
    ));
    drop(pending);
    assert!(restarted
        .requeueable_requests(Chain::Solana)
        .await
        .iter()
        .all(|queued| queued.sign_id() != sign_id));
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
        digest_hex("40dbe3f5aba0ab212cc9e7a3cdd992e278f3cb9796b88c6b859ed17199bbab8c")
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
        digest_hex("4d35080e6b80ebe6501767b61e8320068f6870920106fc8f09f4f2be6ea79e12")
    );
    assert_eq!(checkpoint.digest(), deserialized.digest());

    let restored_entry = &deserialized.pending_requests[0];
    assert_eq!(restored_entry.sign_id(), tx1.sign_id());
    let SignKind::SignBidirectional(ref event) = restored_entry.request.kind else {
        panic!("Expected SignBidirectional kind");
    };
    assert_eq!(event.dest, "");
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
        .advance(ExecutionOutcome::Success { output: vec![] }, 456)
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
        .advance(ExecutionOutcome::Success { output: vec![] }, 456)
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
        .advance(
            ExecutionOutcome::Success {
                output: vec![0x01, 0x02],
            },
            456,
        )
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
        .advance(ExecutionOutcome::Failed, 456)
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
async fn extraction_failure_cannot_advance_into_response_signing() {
    for chain in [
        Chain::Midnight,
        Chain::Solana,
        Chain::Canton,
        Chain::Hydration,
    ] {
        let backlog = Backlog::new();
        let tx = mock_bidirectional_tx(SignId::from_u8(22), chain);
        let entry = backlog.insert_mock_executing(&tx).await;
        let before = backlog.checkpoint(chain).await.unwrap();
        assert!(entry
            .advance(ExecutionOutcome::ExtractionFailed, 456)
            .await
            .is_err());
        assert_eq!(
            before.digest(),
            backlog.checkpoint(chain).await.unwrap().digest()
        );
        assert!(backlog
            .get(chain, &tx.sign_id())
            .await
            .unwrap()
            .state()
            .is_pending_execution());
        assert_eq!(
            backlog.get_execution_watchers(tx.target_chain).await.len(),
            1
        );
    }
}

#[tokio::test]
async fn test_watch_unwatch_and_respond() {
    let backlog = Backlog::new();
    let tx = mock_tx(7);
    let sign_id = tx.sign_id();

    backlog.insert_mock_executing(&tx).await;

    // Unwatch returns the executing SignEntry (automatically registered on advance to executing)
    let executing_entry = backlog
        .unwatch_execution(tx.target_chain, &tx.id, tx.source_chain, &tx.sign_id())
        .await
        .expect("watcher present");
    assert_eq!(executing_entry.sign_id(), sign_id);
    assert_eq!(executing_entry.execution_tx().id, tx.id);

    // Watch execution on target chain using typed SignEntry
    backlog.watch_execution(&executing_entry).await;

    // Also verify entry.watch_execution() method
    executing_entry.watch_execution().await;

    let executing_entry = backlog
        .unwatch_execution(tx.target_chain, &tx.id, tx.source_chain, &tx.sign_id())
        .await
        .expect("watcher present");
    assert_eq!(executing_entry.sign_id(), sign_id);
    assert_eq!(executing_entry.execution_tx().id, tx.id);

    // Advance executing entry to final response signing
    executing_entry
        .advance(ExecutionOutcome::Success { output: vec![] }, 456)
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
async fn test_recovery_reports_restored_backlog_size() {
    // A chain no other test uses: the gauge is shared by every test.
    let chain = Chain::Bitcoin;
    let mut pending = PendingRequests::new();
    for id in 1..=3 {
        let request = mock_sign_request(SignId::from_u8(id), chain);
        pending.insert(request.id, BacklogEntry::new(request));
    }
    pending.set_processed_block(100);
    let checkpoint = Checkpoints::snapshot(&pending, chain);

    Backlog::new().recover_by_checkpoint(&checkpoint).await;

    let size = crate::metrics::requests::BACKLOG_SIZE
        .with_label_values(&[chain.as_str()])
        .get();
    assert_eq!(size, 3);
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
    let interval = checkpoint_interval(chain).unwrap();

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
async fn pending_executions_targeting_spans_sources() {
    let backlog = Backlog::new();
    let tx1 = routed_tx(31, Chain::Ethereum, Chain::Tron);
    let tx2 = routed_tx(32, Chain::Solana, Chain::Tron);
    let tx3 = routed_tx(33, Chain::Ethereum, Chain::Solana);

    backlog.insert_mock_executing(&tx1).await;
    backlog.insert_mock_executing(&tx2).await;
    backlog.insert_mock_executing(&tx3).await;
    backlog
        .insert_mock_sign(SignId::from_u8(99), Chain::Ethereum)
        .await;

    let mut tron = backlog.get_pending_executions(Chain::Tron).await;
    tron.sort_by_key(|member| member.sign_id.request_id);
    assert_eq!(tron.len(), 2);
    assert_eq!(tron[0].sign_id, tx1.sign_id());
    assert_eq!(tron[1].sign_id, tx2.sign_id());
    assert!(backlog
        .get_pending_executions(Chain::Hydration)
        .await
        .is_empty());
}

#[tokio::test]
async fn test_advance_rejects_invalid_publish_transition() {
    let backlog = Backlog::new();
    let sign_id = SignId::from_u8(77);
    let req = mock_bidi_request(sign_id, Chain::Solana);
    let tx = Arc::new(mock_bidirectional_tx(sign_id, Chain::Solana));
    let (pk, output) = mock_signature_output(&req.args);

    // Insert as Bidirectional(Initial(Generating))
    let entry = backlog.insert_bidirectional(Arc::clone(&req)).await;

    // Simulate an external event (e.g. peer respond event) moving the storage entry to Executing
    {
        let mut pending = backlog.pending(&Chain::Solana).write().await;
        let storage_entry = pending.requests.get_mut(&sign_id).unwrap();
        storage_entry.status =
            SignStatus::Bidirectional(BidirectionalProgress::Executing(Arc::clone(&tx)));
    }

    // Now the stale handle tries to advance to Publishing
    let err = entry
        .advance(pk, &output, mock_participants(), true)
        .await
        .unwrap_err();
    assert_eq!(err, BacklogError::InvalidPublishTransition);

    // Also test when storage entry has already advanced to Publishing
    let sign_id2 = SignId::from_u8(78);
    let req2 = mock_sign_request(sign_id2, Chain::Ethereum);
    let (pk2, output2) = mock_signature_output(&req2.args);
    let entry2 = backlog.insert_sign(Arc::clone(&req2)).await;

    // Advance storage directly
    let _ = backlog
        .get_by::<Sign<Generating>>(Chain::Ethereum, &sign_id2)
        .await
        .unwrap()
        .advance(pk2, &output2, mock_participants(), true)
        .await
        .unwrap();

    // Stale handle tries to advance again
    let err2 = entry2
        .advance(pk2, &output2, mock_participants(), true)
        .await
        .unwrap_err();
    assert_eq!(err2, BacklogError::InvalidPublishTransition);
}

/// A first-leg round that finishes after its request was answered must not fill the response's
/// progress, or the node publishes the first-leg signature as the response.
#[tokio::test]
async fn a_first_leg_round_cannot_publish_into_the_response() {
    let backlog = Backlog::new();
    let tx = mock_tx(79);
    let req = mock_bidi_request(tx.sign_id(), Chain::Solana);
    let (pk, output) = mock_signature_output(&req.args);
    let first_leg = backlog.insert_bidirectional(Arc::clone(&req)).await;
    let answered = SignStatus::Bidirectional(BidirectionalProgress::Final {
        respond_request: mock_bidi_response(&tx),
        progress: SignProgress::Generating,
    });
    backlog
        .pending(&Chain::Solana)
        .write()
        .await
        .requests
        .get_mut(&tx.sign_id())
        .unwrap()
        .status = answered.clone();

    let err = first_leg
        .advance(pk, &output, mock_participants(), true)
        .await
        .unwrap_err();

    assert_eq!(err, BacklogError::InvalidPublishTransition);
    let entry = backlog.entry(Chain::Solana, &tx.sign_id()).await.unwrap();
    assert_eq!(entry.status, answered);
}

/// A marked entry is answered Unviable at catchup, so it spends no presignature on a first leg.
#[tokio::test]
async fn catchup_does_not_requeue_a_marked_entry() {
    let backlog = Backlog::new();
    let sign_id = SignId::from_u8(80);
    backlog
        .insert_bidirectional(mock_bidi_request(sign_id, Chain::Solana))
        .await;
    assert_eq!(backlog.requeueable_requests(Chain::Solana).await.len(), 1);

    backlog
        .pending(&Chain::Solana)
        .write()
        .await
        .requests
        .get_mut(&sign_id)
        .unwrap()
        .unviable_at = Some(5);

    assert!(backlog.requeueable_requests(Chain::Solana).await.is_empty());
}

/// A restart before an answered entry's response is signed must still sign it: no other path
/// sends it, and the mark stays on the entry.
#[tokio::test]
async fn catchup_requeues_a_marked_entry_already_answered() {
    let backlog = Backlog::new();
    let tx = mock_tx(81);
    backlog
        .insert_bidirectional(mock_bidi_request(tx.sign_id(), Chain::Solana))
        .await;
    {
        let mut pending = backlog.pending(&Chain::Solana).write().await;
        let entry = pending.requests.get_mut(&tx.sign_id()).unwrap();
        entry.unviable_at = Some(5);
        entry.status = SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: mock_bidi_response(&tx),
            progress: SignProgress::Generating,
        });
    }

    let requeued = backlog.requeueable_requests(Chain::Solana).await;
    assert_eq!(requeued.len(), 1);
    assert_matches!(
        requeued[0].request().kind,
        SignKind::RespondBidirectional(_)
    );
}

#[tokio::test]
async fn respond_observed_at_survives_the_unwatch_lookup() {
    let backlog = Backlog::new();
    let tx = mock_bidirectional_tx(SignId::new([71; 32]), Chain::Solana);
    backlog.insert_mock_executing(&tx).await;

    let entry = backlog
        .unwatch_execution(tx.target_chain, &tx.id, tx.source_chain, &tx.sign_id())
        .await
        .expect("watch must resolve to the executing entry");

    let measured = entry
        .awaiting_execution()
        .expect("wait start must survive the lookup the handler goes through");
    assert!(
        measured < Duration::from_secs(60),
        "a freshly published entry has barely been waiting, got {measured:?}"
    );
}

/// The tron expiry walk's inclusion arm re-registers an existing
/// watch: the resident wait start must survive.
#[tokio::test]
async fn watch_execution_re_register_keeps_the_wait_start() {
    let backlog = Backlog::new();
    let tx = mock_bidirectional_tx(SignId::new([73; 32]), Chain::Solana);
    backlog.insert_mock_executing(&tx).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    StateManager::watch_execution(&backlog, tx.target_chain, Arc::new(tx.clone())).await;

    let entry = backlog
        .unwatch_execution(tx.target_chain, &tx.id, tx.source_chain, &tx.sign_id())
        .await
        .expect("the re-registered watch must resolve");
    let measured = entry
        .awaiting_execution()
        .expect("the wait start must survive the re-register");
    assert!(
        measured >= Duration::from_millis(90),
        "a restarted measurement would read near zero, got {measured:?}"
    );
}

/// Re-registering with no resident watch (lost) stays unmeasured,
/// honest `EXECUTION_WAIT_UNMEASURED` case.
#[tokio::test]
async fn watch_execution_without_a_resident_watch_starts_unmeasured() {
    let backlog = Backlog::new();
    let tx = mock_bidirectional_tx(SignId::new([79; 32]), Chain::Solana);
    backlog.insert_mock_executing(&tx).await;
    backlog
        .unwatch_execution(tx.target_chain, &tx.id, tx.source_chain, &tx.sign_id())
        .await
        .expect("the initial watch must resolve");

    StateManager::watch_execution(&backlog, tx.target_chain, Arc::new(tx.clone())).await;

    let entry = backlog
        .unwatch_execution(tx.target_chain, &tx.id, tx.source_chain, &tx.sign_id())
        .await
        .expect("the re-registered watch must resolve");
    assert_eq!(entry.awaiting_execution(), None);
}

#[tokio::test]
async fn re_signed_replacement_keeps_both_flat_id_watches() {
    let backlog = Backlog::new();
    let tx = mock_bidirectional_tx(SignId::new([85; 32]), Chain::Solana);
    backlog.insert_mock_executing(&tx).await;
    let mut replacement = tx.clone();
    replacement.id = BidirectionalTxId([0xee; 32]);
    StateManager::watch_execution(&backlog, tx.target_chain, Arc::new(tx.clone())).await;
    StateManager::watch_execution(&backlog, tx.target_chain, Arc::new(replacement)).await;

    let watchers = backlog.get_execution_watchers(tx.target_chain).await;
    assert_eq!(watchers.len(), 2, "one sign id, two flat ids: both watched");
}

#[tokio::test]
async fn executing_entry_for_falls_back_to_the_backlog_entry_without_a_watch() {
    let backlog = Backlog::new();
    let tx = mock_bidirectional_tx(SignId::new([77; 32]), Chain::Solana);
    backlog.insert_mock_executing(&tx).await;
    backlog
        .unwatch_execution(tx.target_chain, &tx.id, tx.source_chain, &tx.sign_id())
        .await;

    let entry = backlog
        .executing_entry_for(tx.target_chain, &tx.id, tx.source_chain, &tx.sign_id())
        .await
        .expect("a watch-less entry must fall back to the backlog");
    assert_eq!(
        entry.awaiting_execution(),
        None,
        "no watch survived to measure the wait from"
    );

    assert!(
        backlog
            .executing_entry_for(
                tx.target_chain,
                &tx.id,
                tx.source_chain,
                &SignId::new([1; 32]),
            )
            .await
            .is_none(),
        "the fallback is keyed by sign id, not the flat tx id"
    );
}

#[tokio::test]
async fn executing_entry_for_resolves_only_the_entrys_own_watch_for_duplicate_ids() {
    let backlog = Backlog::new();
    let first = mock_bidirectional_tx(SignId::new([81; 32]), Chain::Solana);
    let mut second = first.clone();
    second.request_id = [0x7f; 32];
    let first_entry = backlog.insert_mock_executing(&first).await;
    let second_entry = backlog.insert_mock_executing(&second).await;
    backlog.watch_execution(&first_entry).await;
    // Same flat id: both entries keep their own watches.
    backlog.watch_execution(&second_entry).await;

    assert_eq!(
        watch_members(&backlog, &first).await,
        [first.sign_id(), second.sign_id()].into(),
        "both entries hold their own watch"
    );

    // By second's keys its own watch answers and is consumed.
    let resolved = backlog
        .executing_entry_for(
            second.target_chain,
            &second.id,
            second.source_chain,
            &second.sign_id(),
        )
        .await
        .expect("second resolves through its watch");
    assert_eq!(resolved.sign_id(), second.sign_id());
    assert!(
        resolved.awaiting_execution().is_some(),
        "the watch arm restores the wait measurement"
    );
    assert_eq!(
        watch_members(&backlog, &first).await,
        [first.sign_id()].into(),
        "second's resolution consumes only its own watch"
    );

    // Re-register second, then first resolves through its own watch.
    backlog.watch_execution(&second_entry).await;
    let resolved = backlog
        .executing_entry_for(
            first.target_chain,
            &first.id,
            first.source_chain,
            &first.sign_id(),
        )
        .await
        .expect("first resolves through its own watch");
    assert_eq!(resolved.sign_id(), first.sign_id());
    assert!(
        resolved.awaiting_execution().is_some(),
        "first's own watch restores the wait measurement"
    );
    assert_eq!(
        watch_members(&backlog, &first).await,
        [second.sign_id()].into(),
        "first's resolution consumes only its own watch"
    );
}

#[tokio::test]
async fn plain_lookup_cannot_measure_the_execution_wait() {
    let backlog = Backlog::new();
    let tx = mock_bidirectional_tx(SignId::new([75; 32]), Chain::Solana);
    backlog.insert_mock_executing(&tx).await;

    let entry = backlog
        .get_by::<Bidirectional<Executing>>(Chain::Solana, &tx.sign_id())
        .await
        .expect("entry must still be executing");
    assert_eq!(entry.awaiting_execution(), None);
}

#[tokio::test]
async fn live_regress_preserves_only_matching_execution_wait_starts() {
    let backlog = Backlog::new();
    let retained = mock_bidirectional_tx(SignId::from_u8(80), Chain::Solana);
    let restored = mock_bidirectional_tx(SignId::from_u8(81), Chain::Solana);
    let stale = mock_bidirectional_tx(SignId::from_u8(82), Chain::Solana);
    let unrelated = mock_bidirectional_tx(SignId::from_u8(83), Chain::Canton);

    // Backdate the wait so it is distinguishable from one restarted at recovery.
    let observed_at = Instant::now()
        .checked_sub(Duration::from_secs(120))
        .expect("clock must support backdating");
    let entry = backlog
        .insert_mock_executing(&retained)
        .await
        .with_execution_watch(ExecutionWatch::new(
            Arc::new(retained.clone()),
            Some(observed_at),
        ));
    backlog.watch_execution(&entry).await;
    backlog.insert_mock_executing(&restored).await;
    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();
    backlog
        .unwatch_execution(
            restored.target_chain,
            &restored.id,
            restored.source_chain,
            &restored.sign_id(),
        )
        .await
        .unwrap();
    backlog.insert_mock_executing(&stale).await;
    let unrelated_observed_at = backlog
        .insert_mock_executing(&unrelated)
        .await
        .respond_observed_at();

    backlog.regress(&checkpoint, mock_root_pk()).await.unwrap();

    let entry = backlog
        .unwatch_execution(
            retained.target_chain,
            &retained.id,
            retained.source_chain,
            &retained.sign_id(),
        )
        .await
        .expect("matching execution must remain watched");
    assert_eq!(entry.respond_observed_at(), Some(observed_at));
    assert!(entry.awaiting_execution().unwrap() >= Duration::from_secs(120));
    let entry = backlog
        .unwatch_execution(
            restored.target_chain,
            &restored.id,
            restored.source_chain,
            &restored.sign_id(),
        )
        .await
        .expect("checkpoint execution must be re-watched");
    assert_eq!(entry.respond_observed_at(), None);
    assert!(backlog
        .unwatch_execution(
            stale.target_chain,
            &stale.id,
            stale.source_chain,
            &stale.sign_id()
        )
        .await
        .is_none());
    let entry = backlog
        .unwatch_execution(
            unrelated.target_chain,
            &unrelated.id,
            unrelated.source_chain,
            &unrelated.sign_id(),
        )
        .await
        .expect("other source chain must remain watched");
    assert_eq!(entry.respond_observed_at(), unrelated_observed_at);
}

/// Twins under one flat id keep their own wait starts across recovery
/// and re-registration.
#[tokio::test]
async fn twin_wait_starts_survive_recovery_and_re_registration() {
    let backlog = Backlog::new();
    let first_tx = mock_bidirectional_tx(SignId::from_u8(90), Chain::Solana);
    let mut twin_tx = first_tx.clone();
    twin_tx.request_id = [0x7f; 32];
    let now = Instant::now();
    let first_observed = now
        .checked_sub(Duration::from_secs(120))
        .expect("clock must support backdating");
    let twin_observed = now
        .checked_sub(Duration::from_secs(60))
        .expect("clock must support backdating");
    let first_entry = backlog
        .insert_mock_executing(&first_tx)
        .await
        .observed_since(first_observed);
    backlog.watch_execution(&first_entry).await;
    let twin_entry = backlog
        .insert_mock_executing(&twin_tx)
        .await
        .observed_since(twin_observed);
    backlog.watch_execution(&twin_entry).await;

    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();
    backlog.regress(&checkpoint, mock_root_pk()).await.unwrap();

    let first = backlog
        .unwatch_execution(
            first_tx.target_chain,
            &first_tx.id,
            first_tx.source_chain,
            &first_tx.sign_id(),
        )
        .await
        .expect("first twin must remain watched");
    assert_eq!(first.respond_observed_at(), Some(first_observed));
    let twin = backlog
        .unwatch_execution(
            twin_tx.target_chain,
            &twin_tx.id,
            twin_tx.source_chain,
            &twin_tx.sign_id(),
        )
        .await
        .expect("twin must remain watched");
    assert_eq!(twin.respond_observed_at(), Some(twin_observed));

    // Re-register one twin while both are resident.
    backlog
        .watch_execution(&first.observed_since(first_observed))
        .await;
    backlog
        .watch_execution(&twin.observed_since(twin_observed))
        .await;
    StateManager::watch_execution(&backlog, twin_tx.target_chain, Arc::new(twin_tx.clone())).await;
    let re_registered = backlog
        .unwatch_execution(
            twin_tx.target_chain,
            &twin_tx.id,
            twin_tx.source_chain,
            &twin_tx.sign_id(),
        )
        .await
        .expect("re-registered twin must resolve");
    assert_eq!(re_registered.respond_observed_at(), Some(twin_observed));
    let sibling = backlog
        .unwatch_execution(
            first_tx.target_chain,
            &first_tx.id,
            first_tx.source_chain,
            &first_tx.sign_id(),
        )
        .await
        .expect("sibling watch must survive the re-register");
    assert_eq!(sibling.respond_observed_at(), Some(first_observed));
}

#[tokio::test]
async fn recovered_executing_entry_has_no_wait_start() {
    let backlog = Backlog::new();
    let tx = mock_bidirectional_tx(SignId::new([73; 32]), Chain::Solana);
    backlog.insert_mock_executing(&tx).await;

    let checkpoint = backlog
        .checkpoint(Chain::Solana)
        .await
        .expect("checkpoint must snapshot");
    let recovered = Backlog::new();
    recovered.recover_by_checkpoint(&checkpoint).await;

    let entry = recovered
        .unwatch_execution(tx.target_chain, &tx.id, tx.source_chain, &tx.sign_id())
        .await
        .expect("recovery must re-register the watch");
    assert_eq!(
        entry.awaiting_execution(),
        None,
        "a wait that began before the restart has no measurable start"
    );
}

/// The final-response request stamps its own queue timestamp with "now", so the
/// round trip's origin has to be carried across the transition explicitly.
#[tokio::test]
async fn advance_carries_the_origin_into_the_final_response() {
    let backlog = Backlog::new();
    let tx = mock_bidirectional_tx(SignId::new([74; 32]), Chain::Solana);
    let executing = backlog.insert_mock_executing(&tx).await;
    let origin = executing.request().unix_timestamp_indexed;

    let entry = executing
        .advance(ExecutionOutcome::Success { output: vec![] }, 456)
        .await
        .expect("advance to final generating");

    let SignKind::RespondBidirectional(response) = &entry.request().kind else {
        panic!("expected RespondBidirectional");
    };
    assert_eq!(response.origin_indexed_at, Some(origin));
}

/// The mock cadence must checkpoint exactly the chains production does: a
/// chain checkpointed only in tests, or only in production, would hide bugs.
#[test]
fn mock_cadence_covers_the_same_chains_as_production() {
    for chain in Chain::iter() {
        assert_eq!(
            super::mock_checkpoint_interval(chain).is_some(),
            mpc_primitives::ChainConfig::checkpoint_interval(&chain).is_some(),
            "{chain:?}"
        );
    }
}

/// A request that leaves the backlog loses its record.
#[tokio::test]
async fn a_removed_request_loses_its_record() {
    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let request = mock_sign_request(SignId::new([1; 32]), Chain::Solana);
    let (pk, output) = mock_signature_output(&request.args);
    let (entry, _) = backlog.insert(Arc::clone(&request)).await;
    entry
        .advance(pk, &output, mock_participants(), true)
        .await
        .unwrap();
    assert_eq!(storage.load_local(Chain::Solana).await.unwrap().len(), 1);

    backlog.remove(Chain::Solana, &request.id).await;

    let deleted = async {
        while !storage.load_local(Chain::Solana).await.unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), deleted)
        .await
        .expect("the record is deleted");
}

/// A first-leg signature stored after the attestation does not replace it.
#[tokio::test]
async fn the_legs_of_a_request_have_separate_records() {
    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let tx = mock_tx(42);
    let chain = tx.source_chain;
    let first_leg = mock_bidi_request(tx.sign_id(), chain);
    let entry: crate::backlog::SignEntry<Generating> = backlog
        .insert_bidirectional(Arc::clone(&first_leg))
        .await
        .into();
    let attestation = SignStatus::Bidirectional(BidirectionalProgress::Final {
        respond_request: mock_bidi_response(&tx),
        progress: SignProgress::Publishing(crate::backlog::mock::mock_publishing()),
    });
    storage
        .put_local(chain, first_leg.id, &attestation)
        .await
        .unwrap();

    let (pk, output) = mock_signature_output(&first_leg.args);
    entry
        .advance(pk, &output, mock_participants(), true)
        .await
        .unwrap();

    let records = storage.load_local(chain).await.unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.contains(&(first_leg.id, attestation)));
}

/// A round that finishes after its request left the backlog leaves no record.
#[tokio::test]
async fn a_round_after_removal_leaves_no_record() {
    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let request = mock_sign_request(SignId::new([1; 32]), Chain::Solana);
    let (pk, output) = mock_signature_output(&request.args);
    let (entry, _) = backlog.insert(Arc::clone(&request)).await;
    backlog.remove(Chain::Solana, &request.id).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    let result = entry.advance(pk, &output, mock_participants(), true).await;

    assert_matches!(result, Err(BacklogError::NotFound { .. }));
    assert!(storage.load_local(Chain::Solana).await.unwrap().is_empty());
}

/// A signature that cannot be stored is published anyway, as before there were records.
#[tokio::test]
async fn a_signature_that_cannot_be_stored_is_still_published() {
    let backlog = Backlog::persisted(CheckpointStorage::failing());
    let request = mock_sign_request(SignId::new([1; 32]), Chain::Solana);
    let (pk, output) = mock_signature_output(&request.args);
    let (entry, _) = backlog.insert(request).await;

    let result = entry.advance(pk, &output, mock_participants(), true).await;

    assert!(result.is_ok());
    assert_eq!(backlog.publishable_requests(Chain::Solana).await.len(), 1);
}
/// An attestation stored after the checkpoint outranks the watch the checkpoint holds.
#[tokio::test]
async fn a_stored_attestation_is_published_after_a_restart() {
    let storage = CheckpointStorage::in_memory();
    let tx = mock_tx(42);
    let chain = Chain::Ethereum; // `single_entry_checkpoint`'s
    let executing = mock_execution_entry(&tx, chain, pending_execution_status(&tx));
    let checkpoint = single_entry_checkpoint(executing.clone());
    storage.persist(&checkpoint).await.unwrap();
    let record = SignStatus::Bidirectional(BidirectionalProgress::Final {
        respond_request: mock_bidi_response(&tx),
        progress: SignProgress::Publishing(mock_publishing()),
    });
    storage
        .put_local(chain, executing.sign_id(), &record)
        .await
        .unwrap();

    let records = storage.load_local(chain).await.unwrap();
    let restarted = Backlog::persisted(storage);
    restarted
        .recover_local(chain, mock_root_pk())
        .await
        .unwrap();
    restarted.claim_local(chain, records).await;

    assert_eq!(restarted.publishable_requests(chain).await.len(), 1);
    assert!(restarted.requeueable_requests(chain).await.is_empty());
}

/// A first leg's record stays once its entry moves on, and must not take the entry back.
#[tokio::test]
async fn a_first_leg_record_does_not_undo_later_progress() {
    let tx = mock_tx(42);
    let mut executing = mock_execution_entry(&tx, Chain::Solana, pending_execution_status(&tx));
    let status = executing.status.clone();
    let publish = SignProgress::Publishing(mock_publishing());

    executing.apply_record(SignStatus::Bidirectional(BidirectionalProgress::Initial(
        publish,
    )));
    assert_eq!(executing.status, status);
}

/// A rebase rebuilds progress from the source chain alone, so it depends on the record.
#[tokio::test]
async fn a_rebased_node_publishes_what_it_stored() {
    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let request = mock_bidi_request(SignId::new([1; 32]), Chain::Solana);
    let (pk, output) = mock_signature_output(&request.args);
    let peer = Backlog::new();
    peer.insert_bidirectional(Arc::clone(&request)).await;
    let consensus = peer.checkpoint(Chain::Solana).await.unwrap();
    backlog
        .insert_bidirectional(Arc::clone(&request))
        .await
        .advance(pk, &output, mock_participants(), true)
        .await
        .unwrap();

    backlog.regress(&consensus, mock_root_pk()).await.unwrap();
    let records = storage.load_local(Chain::Solana).await.unwrap();
    backlog.claim_local(Chain::Solana, records).await;

    assert_eq!(backlog.publishable_requests(Chain::Solana).await.len(), 1);
    assert!(backlog.requeueable_requests(Chain::Solana).await.is_empty());
}

/// With both legs stored, the attestation is claimed whichever record comes first.
#[tokio::test]
async fn both_records_claim_the_attestation_in_any_order() {
    for attestation_first in [false, true] {
        let backlog = Backlog::new();
        let tx = mock_tx(42);
        let chain = tx.source_chain;
        let request = mock_bidi_request(tx.sign_id(), chain);
        backlog.insert_bidirectional(Arc::clone(&request)).await;
        let publishing = SignProgress::Publishing(crate::backlog::mock::mock_publishing());
        let first_leg =
            SignStatus::Bidirectional(BidirectionalProgress::Initial(publishing.clone()));
        let attestation = SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: mock_bidi_response(&tx),
            progress: publishing,
        });
        let mut records = vec![(request.id, first_leg), (request.id, attestation.clone())];
        if attestation_first {
            records.reverse();
        }

        backlog.claim_local(chain, records).await;

        let entry = backlog.get(chain, &request.id).await.unwrap();
        assert_eq!(entry.status(), &attestation);
    }
}

/// Each stored record against each entry status: the record applies only where marked.
#[test]
fn a_record_applies_only_to_an_entry_behind_it() {
    use BidirectionalProgress::{Executing, Final, Initial, Parked};
    let tx = mock_tx(42);
    let execution = Arc::new(tx.clone());
    let record = || SignProgress::Publishing(mock_publishing());
    let held = || SignProgress::Publishing(mock_publishing_with_proposer(false));
    let gen = || SignProgress::Generating;
    let fin = |progress| Final {
        respond_request: mock_bidi_response(&tx),
        progress,
    };
    let statuses = [
        SignStatus::Sign(gen()),
        SignStatus::Sign(held()),
        SignStatus::Bidirectional(Initial(gen())),
        SignStatus::Bidirectional(Initial(held())),
        SignStatus::Bidirectional(Executing(Arc::clone(&execution))),
        SignStatus::Bidirectional(fin(gen())),
        SignStatus::Bidirectional(fin(held())),
        SignStatus::Bidirectional(Parked(execution)),
    ];
    let records = [
        (SignStatus::Sign(record()), [1, 0, 0, 0, 0, 0, 0, 0]),
        (
            SignStatus::Bidirectional(Initial(record())),
            [0, 0, 1, 0, 0, 0, 0, 0],
        ),
        (
            SignStatus::Bidirectional(fin(record())),
            [0, 0, 1, 1, 1, 1, 0, 0],
        ),
    ];
    for (record, applies) in records {
        for (status, applies) in statuses.iter().zip(applies) {
            let mut entry = mock_execution_entry(&tx, Chain::Solana, status.clone());
            entry.apply_record(record.clone());
            let expected = if applies == 1 { &record } else { status };
            assert_eq!(&entry.status, expected, "{record:?} on {status:?}");
        }
    }
}
