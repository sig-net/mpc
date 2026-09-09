use super::*;
use crate::sign_bidirectional::{BidirectionalProgress, PublishState, SignProgress, SignStatus};
use alloy::primitives::{Address, B256};
use cait_sith::protocol::Participant;
use k256::{AffinePoint, Scalar};
use mpc_chain_solana::Pubkey;
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, RespondBidirectionalTx, SignArgs, SignBidirectionalEvent,
    SignId, SignKind,
};
use std::convert::TryInto;

fn digest_hex(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str)
        .unwrap()
        .try_into()
        .expect("digest hex must be 32 bytes")
}

fn test_signature() -> mpc_primitives::Signature {
    mpc_primitives::Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0)
}

fn test_publish_state(is_proposer: bool) -> Arc<PublishState> {
    Arc::new(PublishState::new(
        test_signature(),
        vec![Participant::from(0u32), Participant::from(1u32)],
        is_proposer,
    ))
}

fn pending_execution_status(tx: &BidirectionalTx) -> SignStatus {
    SignStatus::Bidirectional(BidirectionalProgress::Executing(Arc::new(tx.clone())))
}

fn bidi_initial_status() -> SignStatus {
    SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Generating))
}

fn bidi_final_status(tx: &BidirectionalTx, chain: Chain) -> SignStatus {
    let sign_id = SignId::new(tx.request_id);
    let completion_request = IndexedSignRequest::respond_bidirectional(
        sign_id,
        create_test_args(sign_id.request_id[0]),
        chain,
        0,
        RespondBidirectionalTx {
            tx_id: tx.id,
            output: vec![],
            chain_ctx: None,
        },
    );
    SignStatus::Bidirectional(BidirectionalProgress::Final {
        respond_request: Arc::new(completion_request),
        progress: SignProgress::Generating,
    })
}

fn create_test_tx(id: u8) -> BidirectionalTx {
    BidirectionalTx {
        id: BidirectionalTxId(B256::from([id; 32]).0),
        sender: [0u8; 32],
        serialized_transaction: vec![1, 2, 3],
        source_chain: Chain::Solana,
        target_chain: Chain::Ethereum,
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: 1,
        deposit: 1000,
        path: "test_path".to_string(),
        algo: "ECDSA".to_string(),
        dest: "0x1234567890123456789012345678901234567890".to_string(),
        params: "{}".to_string(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        request_id: [id; 32],
        from_address: **Address::ZERO,
        nonce: 0,
    }
}

fn create_test_event(dest: &str) -> SignBidirectionalEvent {
    let mut program_id = [0u8; 32];
    let prefix_len = dest.len().min(program_id.len());
    program_id[..prefix_len].copy_from_slice(&dest.as_bytes()[..prefix_len]);

    SignBidirectionalEvent {
        sender: Default::default(),
        serialized_transaction: vec![],
        dest: dest.to_string(),
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: 0,
        deposit: 0,
        path: "".to_string(),
        algo: "".to_string(),
        params: "".to_string(),
        chain: Chain::Solana,
        chain_ctx: Some(program_id.to_vec()),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
    }
}

fn create_test_args(id: u8) -> SignArgs {
    SignArgs {
        entropy: [id; 32],
        epsilon: k256::Scalar::from(1u64),
        payload: k256::Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    }
}

fn create_indexed_request(
    sign_id: SignId,
    chain: Chain,
    args: SignArgs,
    kind: SignKind,
    unix_timestamp_indexed: u64,
) -> Arc<IndexedSignRequest> {
    Arc::new(IndexedSignRequest::new(
        sign_id,
        args,
        chain,
        unix_timestamp_indexed,
        kind,
    ))
}

fn create_bidirectional_request(
    sign_id: SignId,
    chain: Chain,
    dest: &str,
    unix_timestamp_indexed: u64,
) -> Arc<IndexedSignRequest> {
    Arc::new(IndexedSignRequest::sign_bidirectional(
        sign_id,
        create_test_args(sign_id.request_id[0]),
        chain,
        unix_timestamp_indexed,
        create_test_event(dest),
    ))
}

fn create_execution_entry(
    tx: BidirectionalTx,
    chain: Chain,
    status: SignStatus,
    dest: &str,
) -> BacklogEntry {
    create_execution_entry_with_timestamp(tx, chain, status, dest, 0)
}

fn create_execution_entry_with_timestamp(
    tx: BidirectionalTx,
    chain: Chain,
    status: SignStatus,
    dest: &str,
    unix_timestamp_indexed: u64,
) -> BacklogEntry {
    let sign_id = SignId::new(tx.request_id);
    let request = Arc::new(IndexedSignRequest::new(
        sign_id,
        create_test_args(tx.request_id[0]),
        chain,
        unix_timestamp_indexed,
        SignKind::SignBidirectional(create_test_event(dest)),
    ));

    match &status {
        SignStatus::Bidirectional(BidirectionalProgress::Executing(tx)) => {
            BacklogEntry::pending_execution(request, Arc::clone(tx))
        }
        _ => BacklogEntry::with_status(request, status),
    }
}

/// Builds a checkpoint for a chain with exactly one backlog entry at height 100.
fn single_entry_checkpoint(entry: BacklogEntry) -> Checkpoint {
    let mut pending = PendingRequests::new();
    pending.insert(entry.sign_id(), entry);
    pending.set_processed_block(100);
    pending.checkpoint(Chain::Ethereum)
}

async fn insert_bidirectional_with_status(
    backlog: &Backlog,
    chain: Chain,
    tx: BidirectionalTx,
    status: SignStatus,
    dest: &str,
) {
    let sign_id = SignId::new(tx.request_id);
    backlog
        .insert(create_bidirectional_request(sign_id, chain, dest, 0))
        .await;
    backlog.set_status(chain, &sign_id, status).await;
}

#[tokio::test]
async fn test_backlog_chain_isolation() {
    let backlog = Backlog::new();

    let tx_eth = create_test_tx(1);
    let tx_sol = create_test_tx(2);
    let tx_near = create_test_tx(3);

    let sign_id_eth = SignId::new(tx_eth.request_id);
    let sign_id_sol = SignId::new(tx_sol.request_id);
    let sign_id_near = SignId::new(tx_near.request_id);

    // Insert into different chains
    insert_bidirectional_with_status(
        &backlog,
        Chain::Ethereum,
        tx_eth.clone(),
        bidi_initial_status(),
        "ethereum",
    )
    .await;
    insert_bidirectional_with_status(
        &backlog,
        Chain::Solana,
        tx_sol.clone(),
        bidi_initial_status(),
        "solana",
    )
    .await;
    insert_bidirectional_with_status(
        &backlog,
        Chain::NEAR,
        tx_near.clone(),
        bidi_initial_status(),
        "near",
    )
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

    // Add transactions with different statuses to Ethereum
    let tx0 = create_test_tx(0);
    let tx1 = create_test_tx(1);
    let tx2 = create_test_tx(2);
    let tx3 = create_test_tx(3);

    insert_bidirectional_with_status(
        &backlog,
        Chain::Ethereum,
        tx1,
        bidi_initial_status(),
        "ethereum",
    )
    .await;
    insert_bidirectional_with_status(
        &backlog,
        Chain::Ethereum,
        tx2.clone(),
        bidi_final_status(&tx2, Chain::Ethereum),
        "ethereum",
    )
    .await;
    insert_bidirectional_with_status(
        &backlog,
        Chain::Ethereum,
        tx3.clone(),
        pending_execution_status(&tx3),
        "ethereum",
    )
    .await;

    // Add transactions to Solana
    let tx4 = create_test_tx(4);
    insert_bidirectional_with_status(
        &backlog,
        Chain::Solana,
        tx4.clone(),
        pending_execution_status(&tx4),
        "solana",
    )
    .await;

    // Filter Ethereum by Pending
    let eth_pending = backlog
        .pending_execution(Chain::Ethereum, &SignId::new(tx3.request_id))
        .await;
    assert!(eth_pending.is_some());

    let eth_awaiting = backlog.pending_generations(Chain::Ethereum).await;
    assert_eq!(eth_awaiting.len(), 1);

    // Filter Ethereum by bidirectional completion awaiting final respond
    let eth_completion = backlog
        .pending_generation_bidirectionals(Chain::Ethereum)
        .await;
    assert_eq!(eth_completion.len(), 1);

    // Filter Solana by Pending
    let sol_pending = backlog
        .pending_execution(Chain::Solana, &SignId::new(tx4.request_id))
        .await;
    assert!(sol_pending.is_some());

    // Filter non-existent chain returns empty
    let near_pending = backlog
        .pending_execution(Chain::NEAR, &SignId::new(tx0.request_id))
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
            let tx = create_test_tx(i);
            insert_bidirectional_with_status(
                &backlog,
                Chain::Ethereum,
                tx,
                bidi_initial_status(),
                "ethereum",
            )
            .await;
        });
        handles.push(handle);
    }

    for i in 5..10 {
        let backlog = backlog.clone();
        let handle = tokio::spawn(async move {
            let tx = create_test_tx(i);
            insert_bidirectional_with_status(
                &backlog,
                Chain::Solana,
                tx,
                bidi_initial_status(),
                "solana",
            )
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
            let id = SignId::new([i; 32]);
            backlog.remove(Chain::Ethereum, &id).await
        });
        handles.push(handle);
    }

    // Wait for all removals
    for handle in handles {
        let removed = handle.await.unwrap();
        assert!(removed.is_some());
    }

    // Verify Ethereum chain is now empty, but Solana still has data
    assert_eq!(backlog.len_by_chain(Chain::Ethereum).await, 0);
    assert_eq!(backlog.len_by_chain(Chain::Solana).await, 5);
}

#[tokio::test]
async fn test_checkpoint_creation() {
    let backlog = Backlog::new();

    // Add some transactions
    let tx1 = create_test_tx(1);
    let tx2 = create_test_tx(2);

    insert_bidirectional_with_status(
        &backlog,
        Chain::Ethereum,
        tx1.clone(),
        pending_execution_status(&tx1),
        "ethereum",
    )
    .await;
    insert_bidirectional_with_status(
        &backlog,
        Chain::Ethereum,
        tx2.clone(),
        bidi_final_status(&tx2, Chain::Ethereum),
        "ethereum",
    )
    .await;

    backlog
        .set_processed_block(Chain::Ethereum, 100)
        .await
        .unwrap();

    let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();
    assert_eq!(checkpoint.block_height, 100);
    assert_eq!(checkpoint.chain, Chain::Ethereum);
    assert_eq!(checkpoint.pending_requests.len(), 2);
    // Guard the checkpoint digest wire format; update only for intentional changes.
    assert_eq!(
        checkpoint.digest(),
        digest_hex("884b11ef5550724b788b7e29e9a07e7a6fd46f94d604e6d38bae71a36816b65e")
    );
}

#[tokio::test]
async fn test_checkpoint_equality() {
    let tx1 = create_test_tx(1);
    let tx2 = create_test_tx(2);
    let mut pending1 = PendingRequests::new();
    pending1.insert(
        SignId::new(tx1.request_id),
        create_execution_entry(
            tx1.clone(),
            Chain::Ethereum,
            bidi_initial_status(),
            "ethereum",
        ),
    );
    pending1.insert(
        SignId::new(tx2.request_id),
        create_execution_entry(
            tx2.clone(),
            Chain::Ethereum,
            bidi_initial_status(),
            "ethereum",
        ),
    );
    pending1.set_processed_block(100);

    let mut pending2 = PendingRequests::new();
    pending2.insert(
        SignId::new(tx1.request_id),
        create_execution_entry(
            tx1.clone(),
            Chain::Ethereum,
            bidi_initial_status(),
            "ethereum",
        ),
    );
    pending2.insert(
        SignId::new(tx2.request_id),
        create_execution_entry(
            tx2.clone(),
            Chain::Ethereum,
            bidi_initial_status(),
            "ethereum",
        ),
    );
    pending2.set_processed_block(100);

    let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
    let checkpoint2 = pending2.checkpoint(Chain::Ethereum);
    // Same data should be equal
    assert_eq!(checkpoint1, checkpoint2);
    assert_eq!(checkpoint1.digest(), checkpoint2.digest());

    // Different block height should not be equal
    let mut checkpoint3 = pending2.checkpoint(Chain::Ethereum);
    checkpoint3.block_height = 101;
    assert_ne!(checkpoint1, checkpoint3);
}

#[test]
fn test_checkpoint_consensus_projection() {
    let tx = create_test_tx(60);
    let sign_id = SignId::new(tx.request_id);

    // The digest commits only to the consensus projection of each entry's
    // status (sorted by sign_id), not to the request or publish content.

    // Initial source-chain phase: generation, and publishing by any proposer,
    // all collapse to a single digest.
    let generation = single_entry_checkpoint(create_execution_entry(
        tx.clone(),
        Chain::Ethereum,
        bidi_initial_status(),
        "ethereum",
    ));
    let publish = single_entry_checkpoint(create_execution_entry(
        tx.clone(),
        Chain::Ethereum,
        SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Publishing(
            test_publish_state(true),
        ))),
        "ethereum",
    ));
    let publish_other = single_entry_checkpoint(create_execution_entry(
        tx.clone(),
        Chain::Ethereum,
        SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Publishing(
            test_publish_state(false),
        ))),
        "ethereum",
    ));
    assert_eq!(generation.digest(), publish.digest());
    assert_eq!(generation.digest(), publish_other.digest());

    // Plain `Sign` requests follow the same initial-phase projection.
    let plain = create_indexed_request(
        sign_id,
        Chain::Ethereum,
        create_test_args(60),
        SignKind::Sign,
        0,
    );
    let plain_generation = single_entry_checkpoint(BacklogEntry::new(Arc::clone(&plain)));
    let plain_publish = single_entry_checkpoint(BacklogEntry::with_status(
        plain,
        SignStatus::Sign(SignProgress::Publishing(test_publish_state(true))),
    ));
    assert_eq!(plain_generation.digest(), plain_publish.digest());

    // Post-initial phase: awaiting target-chain execution and the final
    // response generation/publish states are not observable at the
    // source-chain checkpoint height, so they share the checkpoint digest.
    let execution = single_entry_checkpoint(create_execution_entry(
        tx.clone(),
        Chain::Ethereum,
        pending_execution_status(&tx),
        "ethereum",
    ));
    let response_request = Arc::new(IndexedSignRequest::respond_bidirectional(
        sign_id,
        create_test_args(sign_id.request_id[0]),
        Chain::Ethereum,
        0,
        RespondBidirectionalTx {
            tx_id: tx.id,
            output: vec![],
            chain_ctx: None,
        },
    ));
    let origin_request = create_bidirectional_request(sign_id, Chain::Ethereum, "ethereum", 0);
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
            progress: SignProgress::Publishing(test_publish_state(true)),
        }),
    ));
    assert_eq!(
        execution.digest(),
        gen_bidirectional.digest(),
        "PendingExecution must yield the same checkpoint digest as the final response generation state"
    );
    assert_eq!(
        execution.digest(),
        pub_bidirectional.digest(),
        "PendingExecution must yield the same checkpoint digest as the final response publish state"
    );

    // The initial source-chain phase is observable at this height and must
    // still differ from the post-initial phase.
    assert_ne!(
        generation.digest(),
        execution.digest(),
        "the initial source-chain phase must remain distinct in the checkpoint"
    );
}

#[test]
fn test_respond_updates_entry_atomically() {
    let tx = create_test_tx(23);
    let sign_id = SignId::new(tx.request_id);
    let mut entry = create_execution_entry(
        tx.clone(),
        Chain::Ethereum,
        pending_execution_status(&tx),
        "ethereum",
    );
    let response_request = IndexedSignRequest::respond_bidirectional(
        sign_id,
        create_test_args(23),
        Chain::Ethereum,
        0,
        RespondBidirectionalTx {
            tx_id: tx.id,
            output: vec![],
            chain_ctx: None,
        },
    );

    entry.respond(Arc::new(response_request)).unwrap();

    assert_matches!(entry.request().kind, SignKind::RespondBidirectional(_));
    assert_matches!(
        entry.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Final {
            progress: SignProgress::Generating,
            ..
        })
    );
}

#[test]
fn test_respond_rejects_mismatched_request_id() {
    let tx = create_test_tx(24);
    let original_sign_id = SignId::new(tx.request_id);
    let mut entry = create_execution_entry(
        tx.clone(),
        Chain::Ethereum,
        pending_execution_status(&tx),
        "ethereum",
    );
    let response_request = IndexedSignRequest::respond_bidirectional(
        SignId::new([25; 32]),
        create_test_args(25),
        Chain::Ethereum,
        0,
        RespondBidirectionalTx {
            tx_id: tx.id,
            output: vec![],
            chain_ctx: None,
        },
    );

    let err = entry.respond(Arc::new(response_request)).unwrap_err();

    assert_matches!(err, BacklogError::InvalidBidirectionalResponseTransition);
    assert_eq!(entry.sign_id(), original_sign_id);
    assert_matches!(
        entry.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Executing(_))
    );
}

#[tokio::test]
async fn test_checkpoint_digest_ignores_timestamp() {
    let tx = create_test_tx(8);

    let entry1 = create_execution_entry_with_timestamp(
        tx.clone(),
        Chain::Ethereum,
        bidi_initial_status(),
        "ethereum",
        1000,
    );
    let entry2 = create_execution_entry_with_timestamp(
        tx.clone(),
        Chain::Ethereum,
        bidi_initial_status(),
        "ethereum",
        9999,
    );

    let mut pending1 = PendingRequests::new();
    pending1.insert(SignId::new(tx.request_id), entry1);
    pending1.set_processed_block(200);

    let mut pending2 = PendingRequests::new();
    pending2.insert(SignId::new(tx.request_id), entry2);
    pending2.set_processed_block(200);

    let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
    let checkpoint2 = pending2.checkpoint(Chain::Ethereum);

    assert_eq!(checkpoint1.digest(), checkpoint2.digest());
}

#[tokio::test]
async fn test_checkpoint_digest_differs_for_different_requests() {
    let tx1 = create_test_tx(10);
    let tx2 = create_test_tx(11);

    let mut pending1 = PendingRequests::new();
    pending1.insert(
        SignId::new(tx1.request_id),
        create_execution_entry(
            tx1.clone(),
            Chain::Ethereum,
            bidi_initial_status(),
            "ethereum",
        ),
    );
    pending1.set_processed_block(100);

    let mut pending2 = PendingRequests::new();
    pending2.insert(
        SignId::new(tx2.request_id),
        create_execution_entry(
            tx2.clone(),
            Chain::Ethereum,
            bidi_initial_status(),
            "ethereum",
        ),
    );
    pending2.set_processed_block(100);

    let checkpoint1 = pending1.checkpoint(Chain::Ethereum);
    let checkpoint2 = pending2.checkpoint(Chain::Ethereum);

    assert_ne!(checkpoint1.digest(), checkpoint2.digest());
    assert_eq!(
        checkpoint1.digest(),
        digest_hex("a31e0d66f5b4fb860cc62e809cc29918b9138550b5cd62e1c752fc40ce6c2779")
    );
}

#[tokio::test]
async fn test_checkpoint_serialization() {
    let tx1 = create_test_tx(1);

    let mut pending = PendingRequests::new();
    pending.insert(
        SignId::new(tx1.request_id),
        create_execution_entry(
            tx1.clone(),
            Chain::Ethereum,
            pending_execution_status(&tx1),
            "ethereum",
        ),
    );
    pending.set_processed_block(100);
    let checkpoint = pending.checkpoint(Chain::Ethereum);

    // Test JSON serialization
    let json = serde_json::to_string(&checkpoint).unwrap();
    let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();

    assert_eq!(checkpoint, deserialized);
    // Guard the checkpoint digest wire format; update only for intentional changes.
    assert_eq!(
        checkpoint.digest(),
        digest_hex("12f5bc5c4f0fea1debafceb8879644ea545309775b3e2cc266335cd3247d5394")
    );
    assert_eq!(checkpoint.digest(), deserialized.digest());

    let restored_entry = &deserialized.pending_requests[0];
    assert_eq!(restored_entry.sign_id(), SignId::new(tx1.request_id));
    let SignKind::SignBidirectional(ref event) = restored_entry.request.kind else {
        panic!("Expected SignBidirectional kind");
    };
    assert_eq!(event.dest, "ethereum");
    assert_eq!(restored_entry.status, pending_execution_status(&tx1));
}

#[tokio::test]
async fn test_recover_restores_execution_watchers() {
    let backlog = Backlog::new();
    let tx = create_test_tx(6);
    let sign_id = SignId::new(tx.request_id);

    insert_bidirectional_with_status(
        &backlog,
        Chain::Solana,
        tx.clone(),
        pending_execution_status(&tx),
        "ethereum",
    )
    .await;
    backlog.set_processed_block(Chain::Solana, 10).await;

    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

    let recovered = Backlog::new();
    recovered.recover_by_checkpoint(&checkpoint).await;

    let entry = recovered
        .get(Chain::Solana, &sign_id)
        .await
        .expect("entry should exist");
    assert_eq!(entry.sign_id(), sign_id);
    assert_eq!(entry.status(), pending_execution_status(&tx));

    let watchers = recovered.get_execution_watchers(Chain::Ethereum).await;
    assert_eq!(watchers.len(), 1);
    assert!(watchers.contains_key(&tx.id));
}

#[tokio::test]
async fn test_recovery_makes_checkpoint_visible_as_latest() {
    let backlog = Backlog::new();
    let tx = create_test_tx(16);

    insert_bidirectional_with_status(
        &backlog,
        Chain::Solana,
        tx.clone(),
        pending_execution_status(&tx),
        "ethereum",
    )
    .await;
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

    assert_eq!(
        recovered.checkpoints().latest(Chain::Solana).await.unwrap(),
        Some(checkpoint),
        "recovered checkpoint should be visible via latest for /checkpoint"
    );
}

#[tokio::test]
async fn test_recover_preserves_sign_kind() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([42u8; 32]);
    let args = SignArgs {
        entropy: [1u8; 32],
        epsilon: k256::Scalar::from(1u64),
        payload: k256::Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };

    let program_id = Pubkey::new_unique();
    let sign_kind = SignKind::SignBidirectional(SignBidirectionalEvent {
        sender: Default::default(),
        serialized_transaction: vec![1, 2, 3],
        dest: "ethereum".to_string(),
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: 1,
        deposit: 10,
        path: "m/0".to_string(),
        algo: "ECDSA".to_string(),
        params: "{}".to_string(),
        chain: Chain::Solana,
        chain_ctx: Some(program_id.to_bytes().to_vec()),
        output_deserialization_schema: vec![9],
        respond_serialization_schema: vec![8],
    });

    backlog
        .insert(create_indexed_request(
            sign_id,
            Chain::Solana,
            args,
            sign_kind,
            0,
        ))
        .await;
    backlog.set_processed_block(Chain::Solana, 10).await;

    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

    let recovered = Backlog::new();
    recovered.recover_by_checkpoint(&checkpoint).await;

    let recovered_entry = recovered
        .get(Chain::Solana, &sign_id)
        .await
        .expect("missing recovered entry");

    assert_matches!(recovered_entry.request.kind, SignKind::SignBidirectional(_));
}

#[tokio::test]
async fn test_recovered_completed_bidirectional_requests_are_requeued_for_final_respond() {
    for offset in 0..2 {
        let backlog = Backlog::new();
        let tx = create_test_tx(8 + offset as u8);
        let sign_id = SignId::new(tx.request_id);

        let completion_request = Arc::new(IndexedSignRequest::respond_bidirectional(
            sign_id,
            create_test_args(sign_id.request_id[0]),
            Chain::Solana,
            0,
            RespondBidirectionalTx {
                tx_id: tx.id,
                output: vec![],
                chain_ctx: None,
            },
        ));
        let status = SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: Arc::clone(&completion_request),
            progress: SignProgress::Generating,
        });

        insert_bidirectional_with_status(
            &backlog,
            Chain::Solana,
            tx.clone(),
            status.clone(),
            "ethereum",
        )
        .await;
        backlog.set_processed_block(Chain::Solana, 10).await;

        let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

        let recovered = Backlog::new();
        recovered.recover_by_checkpoint(&checkpoint).await;

        let requeued = recovered.take_requeueable_requests(Chain::Solana).await;
        assert_eq!(
            requeued.len(),
            1,
            "completed bidirectional request should be requeued for final respond"
        );
        assert_matches!(requeued[0].kind, SignKind::RespondBidirectional(_));
    }
}

#[tokio::test]
async fn test_awaiting_response_bidirectional_requeues() {
    let backlog = Backlog::new();
    let tx = create_test_tx(42);
    let sign_id = SignId::new(tx.request_id);

    let completion_request = Arc::new(IndexedSignRequest::respond_bidirectional(
        sign_id,
        create_test_args(sign_id.request_id[0]),
        Chain::Solana,
        0,
        RespondBidirectionalTx {
            tx_id: tx.id,
            output: vec![1, 2, 3],
            chain_ctx: None,
        },
    ));

    backlog
        .insert(create_bidirectional_request(
            sign_id,
            Chain::Solana,
            "ethereum",
            0,
        ))
        .await;
    backlog
        .set_status(
            Chain::Solana,
            &sign_id,
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request: completion_request,
                progress: SignProgress::Generating,
            }),
        )
        .await;

    let requeued = backlog.take_requeueable_requests(Chain::Solana).await;
    assert_eq!(requeued.len(), 1);
    assert_matches!(requeued[0].kind, SignKind::RespondBidirectional(_));
}

#[tokio::test]
async fn test_publish_accepts_bidirectional_pending_generation() {
    let backlog = Backlog::new();
    let tx = create_test_tx(43);
    let sign_id = SignId::new(tx.request_id);

    backlog
        .insert(create_bidirectional_request(
            sign_id,
            Chain::Solana,
            "ethereum",
            0,
        ))
        .await;

    backlog
        .publish(Chain::Solana, &sign_id, test_publish_state(true))
        .await
        .expect("pending generation should transition to publishing");

    let entry = backlog
        .get(Chain::Solana, &sign_id)
        .await
        .expect("entry should remain in backlog");
    assert_matches!(
        entry.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Publishing(_)))
    );
}

/// The flag keeps the per-block sweep to one publish per pending-publish
/// episode. Entering pending-publish again, as the second bidirectional leg
/// does, starts a new one.
#[tokio::test]
async fn test_mark_publish_dispatched_is_once_per_episode() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([45u8; 32]);

    assert!(
        !backlog
            .mark_publish_dispatched(Chain::Solana, &sign_id)
            .await,
        "an entry that is not in the backlog cannot be dispatched"
    );

    backlog
        .insert(create_bidirectional_request(
            sign_id,
            Chain::Solana,
            "ethereum",
            0,
        ))
        .await;
    backlog
        .publish(Chain::Solana, &sign_id, test_publish_state(false))
        .await
        .expect("pending generation should transition to pending publish");

    let dispatched = |backlog: Backlog| async move {
        let publishable = backlog.publishable_requests(Chain::Solana).await;
        assert_eq!(publishable.len(), 1, "the entry stays in the scan");
        publishable[0].2
    };

    assert!(!dispatched(backlog.clone()).await);
    assert!(
        backlog
            .mark_publish_dispatched(Chain::Solana, &sign_id)
            .await
    );
    assert!(
        !backlog
            .mark_publish_dispatched(Chain::Solana, &sign_id)
            .await,
        "the second dispatch is refused"
    );
    assert!(
        dispatched(backlog.clone()).await,
        "the scan reports it, so the sweep skips it and the resume still sees it"
    );

    backlog
        .set_status(
            Chain::Solana,
            &sign_id,
            SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Generating)),
        )
        .await;
    backlog
        .publish(Chain::Solana, &sign_id, test_publish_state(false))
        .await
        .expect("re-entering pending publish starts a new episode");
    assert!(
        !dispatched(backlog.clone()).await,
        "a new episode is scheduled afresh"
    );
}

#[tokio::test]
async fn test_publish_accepts_final_respond_generation() {
    let backlog = Backlog::new();
    let tx = create_test_tx(44);
    let sign_id = SignId::new(tx.request_id);

    let completion_request = Arc::new(IndexedSignRequest::respond_bidirectional(
        sign_id,
        create_test_args(sign_id.request_id[0]),
        Chain::Solana,
        0,
        RespondBidirectionalTx {
            tx_id: tx.id,
            output: vec![],
            chain_ctx: None,
        },
    ));

    backlog
        .insert(create_bidirectional_request(
            sign_id,
            Chain::Solana,
            "ethereum",
            0,
        ))
        .await;
    backlog
        .set_status(
            Chain::Solana,
            &sign_id,
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request: completion_request,
                progress: SignProgress::Generating,
            }),
        )
        .await;

    backlog
        .publish(Chain::Solana, &sign_id, test_publish_state(true))
        .await
        .expect("final respond generation should transition to publishing");

    let entry = backlog
        .get(Chain::Solana, &sign_id)
        .await
        .expect("entry should remain in backlog");
    assert_matches!(
        entry.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Final {
            progress: SignProgress::Publishing(_),
            ..
        })
    );
}

#[tokio::test]
async fn test_watch_unwatch_and_set_status() {
    use k256::Scalar;
    let backlog = Backlog::new();
    let tx = create_test_tx(7);
    let sign_id = SignId::new(tx.request_id);

    // Insert a pending Sign request on the source chain
    let args = SignArgs {
        entropy: [1u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };
    let unix_timestamp_indexed = 0;
    backlog
        .insert(create_indexed_request(
            sign_id,
            tx.source_chain,
            args.clone(),
            SignKind::Sign,
            unix_timestamp_indexed,
        ))
        .await;

    // Watch execution on the target chain
    backlog
        .watch_execution(tx.target_chain, sign_id, Arc::new(tx.clone()))
        .await;

    // Unwatch should return the watcher
    let maybe = backlog.unwatch_execution(tx.target_chain, &tx.id).await;
    assert!(maybe.is_some());
    let (s, watched_tx) = maybe.unwrap();
    assert_eq!(s, sign_id);
    assert_eq!(watched_tx.id, tx.id);

    // set_status should update the sign request status
    let completion_request = Arc::new(IndexedSignRequest::respond_bidirectional(
        sign_id,
        create_test_args(sign_id.request_id[0]),
        tx.source_chain,
        0,
        RespondBidirectionalTx {
            tx_id: tx.id,
            output: vec![],
            chain_ctx: None,
        },
    ));
    backlog
        .set_status(
            tx.source_chain,
            &sign_id,
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request: completion_request,
                progress: SignProgress::Generating,
            }),
        )
        .await;
    let successes = backlog
        .pending_generation_bidirectionals(tx.source_chain)
        .await;
    assert!(successes.contains_key(&sign_id));
}

#[tokio::test]
async fn test_automatic_checkpoint_on_interval() {
    let backlog = Backlog::new();

    // Add some transactions
    let tx1 = create_test_tx(1);
    insert_bidirectional_with_status(
        &backlog,
        Chain::Ethereum,
        tx1.clone(),
        pending_execution_status(&tx1),
        "ethereum",
    )
    .await;

    let interval = Chain::Ethereum.checkpoint_interval().unwrap();

    // First few blocks shouldn't create checkpoints
    for i in 1..interval {
        let checkpoint = backlog.set_processed_block(Chain::Ethereum, i).await;
        assert!(checkpoint.is_none(), "Block {i} should not make checkpoint");
    }

    // At block interval, should create checkpoint
    let checkpoint = backlog.set_processed_block(Chain::Ethereum, interval).await;
    assert!(checkpoint.is_some());
    let checkpoint = checkpoint.unwrap();
    assert_eq!(checkpoint.block_height, interval);
    assert_eq!(checkpoint.chain, Chain::Ethereum);
    assert_eq!(checkpoint.pending_requests.len(), 1);

    let checkpoint = backlog
        .set_processed_block(Chain::Ethereum, interval + 1)
        .await;
    assert!(checkpoint.is_none());

    let checkpoint = backlog
        .set_processed_block(Chain::Ethereum, 2 * interval)
        .await;
    assert!(checkpoint.is_some());
    let checkpoint = checkpoint.unwrap();
    assert_eq!(checkpoint.block_height, 2 * interval);
}

#[tokio::test]
async fn test_automatic_checkpoint_solana_interval() {
    let backlog = Backlog::new();
    let interval = Chain::Solana.checkpoint_interval().unwrap();

    // Add transaction
    let tx1 = create_test_tx(1);
    insert_bidirectional_with_status(
        &backlog,
        Chain::Solana,
        tx1.clone(),
        pending_execution_status(&tx1),
        "solana",
    )
    .await;

    // Solana interval is 10 blocks
    for i in 1..interval {
        let checkpoint = backlog.set_processed_block(Chain::Solana, i).await;
        assert!(checkpoint.is_none(), "Block {i} should not make checkpoint");
    }

    // At block interval, should create checkpoint
    let checkpoint = backlog.set_processed_block(Chain::Solana, interval).await;
    assert!(checkpoint.is_some());
    let checkpoint = checkpoint.unwrap();
    assert_eq!(checkpoint.block_height, interval);
    assert_eq!(checkpoint.chain, Chain::Solana);
}

async fn seed_pending_solana_request(backlog: &Backlog) {
    let tx = create_test_tx(1);
    insert_bidirectional_with_status(
        backlog,
        Chain::Solana,
        tx.clone(),
        pending_execution_status(&tx),
        "solana",
    )
    .await;
}

#[tokio::test]
async fn test_boundary_crossing_sparse_request_waits_until_next_bucket() {
    let backlog = Backlog::new();
    seed_pending_solana_request(&backlog).await;

    // This documents the main caveat of boundary-crossing checkpointing:
    // sparse requests still wait if the next observed slot remains in the
    // same interval bucket.
    //
    // 480 -> 500: same bucket (both / 120 == 4), no checkpoint.
    backlog
        .set_processed_block_interval(Chain::Solana, 480, 120)
        .await;
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 500, 120)
        .await;
    assert!(cp.is_none());

    // 500 -> 600: crosses from bucket 4 to bucket 5
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 600, 120)
        .await;
    assert!(cp.is_some());
    let cp = cp.unwrap();
    assert_eq!(cp.block_height, 600);
    assert_eq!(cp.pending_requests.len(), 1);
}

#[tokio::test]
async fn test_boundary_crossing_same_bucket_no_checkpoint() {
    let backlog = Backlog::new();
    seed_pending_solana_request(&backlog).await;

    // 121 crosses from bucket 0 to bucket 1
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 121, 120)
        .await;
    assert!(cp.is_some());

    // 130 stays in bucket 1; no new boundary crossed
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 130, 120)
        .await;
    assert!(cp.is_none());
}

#[tokio::test]
async fn test_boundary_crossing_within_first_bucket_no_checkpoint() {
    let backlog = Backlog::new();
    seed_pending_solana_request(&backlog).await;

    // First observed slot 50 is still in bucket 0 (50 / 120 == 0 == prev default 0)
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 50, 120)
        .await;
    assert!(cp.is_none());
}

#[tokio::test]
async fn test_boundary_crossing_exact_multiple_still_checkpoints() {
    let backlog = Backlog::new();
    seed_pending_solana_request(&backlog).await;

    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 119, 120)
        .await;
    assert!(cp.is_none());

    // Exact multiple still works; it crosses from bucket 0 to bucket 1
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 120, 120)
        .await;
    assert!(cp.is_some());
    assert_eq!(cp.unwrap().block_height, 120);
}

#[tokio::test]
async fn test_boundary_crossing_first_observed_height_above_interval() {
    let backlog = Backlog::new();
    seed_pending_solana_request(&backlog).await;

    // First ever processed block is 500 (prev defaults to 0)
    // 500 / 120 = 4 > 0, so a boundary was crossed.
    let cp = backlog
        .set_processed_block_interval(Chain::Solana, 500, 120)
        .await
        .unwrap();
    assert_eq!(cp.block_height, 500);
    assert_eq!(cp.pending_requests.len(), 1);
}

#[tokio::test]
async fn test_advance_rejects_plain_sign_entries() {
    let backlog = Backlog::new();
    let tx = create_test_tx(8);
    let sign_id = SignId::new(tx.request_id);

    let args = SignArgs {
        entropy: [1u8; 32],
        epsilon: k256::Scalar::from(1u64),
        payload: k256::Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };

    backlog
        .insert(create_indexed_request(
            sign_id,
            tx.source_chain,
            args,
            SignKind::Sign,
            0,
        ))
        .await;

    let err = backlog
        .advance(tx.source_chain, sign_id, Arc::new(tx))
        .await
        .expect_err("advance should fail for plain Sign requests");

    assert_matches!(err, BacklogError::InvalidAdvanceTransition);
}

#[tokio::test]
async fn test_advance_accepts_pending_generation_bidirectional() {
    let backlog = Backlog::new();
    let tx = create_test_tx(9);
    let sign_id = SignId::new(tx.request_id);

    backlog
        .insert(create_bidirectional_request(
            sign_id,
            tx.source_chain,
            "ethereum",
            0,
        ))
        .await;

    backlog
        .advance(tx.source_chain, sign_id, Arc::new(tx.clone()))
        .await
        .expect("advance should accept catchup advancement from PendingGeneration");

    let entry = backlog
        .get(tx.source_chain, &sign_id)
        .await
        .expect("entry should remain in backlog");
    assert_eq!(entry.status(), pending_execution_status(&tx));
}

#[tokio::test]
async fn test_advance_accepts_pending_publish_bidirectional() {
    let backlog = Backlog::new();
    let tx = create_test_tx(10);
    let sign_id = SignId::new(tx.request_id);

    backlog
        .insert(create_bidirectional_request(
            sign_id,
            tx.source_chain,
            "ethereum",
            0,
        ))
        .await;
    backlog
        .set_status(
            tx.source_chain,
            &sign_id,
            SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Publishing(
                test_publish_state(true),
            ))),
        )
        .await;

    backlog
        .advance(tx.source_chain, sign_id, Arc::new(tx.clone()))
        .await
        .expect("advance should succeed once respond() is confirmed from PendingPublish");

    let entry = backlog
        .get(tx.source_chain, &sign_id)
        .await
        .expect("entry should remain in backlog");
    assert_eq!(entry.status(), pending_execution_status(&tx));
    assert_eq!(
        entry.execution_tx().map(|execution| execution.id),
        Some(tx.id)
    );
}

#[tokio::test]
async fn test_total_pending_increments_on_insert() {
    let backlog = Backlog::new();
    let tx = create_test_tx(1);

    backlog
        .insert(create_indexed_request(
            SignId::new(tx.request_id),
            Chain::Ethereum,
            create_test_args(1),
            SignKind::Sign,
            0,
        ))
        .await;

    assert_eq!(backlog.len(), 1);
    assert!(!backlog.is_empty());
}

#[tokio::test]
async fn test_total_pending_ignores_duplicate_inserts() {
    let backlog = Backlog::new();
    let tx = create_test_tx(1);
    let request = create_indexed_request(
        SignId::new(tx.request_id),
        Chain::Ethereum,
        create_test_args(1),
        SignKind::Sign,
        0,
    );

    // Insert first time
    backlog.insert(Arc::clone(&request)).await;
    assert_eq!(backlog.len(), 1);

    // Insert exactly the same ID again (overwrites)
    backlog.insert(request).await;
    assert_eq!(
        backlog.len(),
        1,
        "Duplicate insert should not increment total"
    );
}

#[tokio::test]
async fn test_total_pending_counts_across_chains() {
    let backlog = Backlog::new();

    backlog
        .insert(create_indexed_request(
            SignId::new(create_test_tx(1).request_id),
            Chain::Ethereum,
            create_test_args(1),
            SignKind::Sign,
            0,
        ))
        .await;

    backlog
        .insert(create_indexed_request(
            SignId::new(create_test_tx(2).request_id),
            Chain::Solana,
            create_test_args(2),
            SignKind::Sign,
            0,
        ))
        .await;

    assert_eq!(backlog.len(), 2);
}

#[tokio::test]
async fn test_total_pending_decrements_on_remove() {
    let backlog = Backlog::new();
    let sign_id = SignId::new(create_test_tx(1).request_id);

    backlog
        .insert(create_indexed_request(
            sign_id,
            Chain::Ethereum,
            create_test_args(1),
            SignKind::Sign,
            0,
        ))
        .await;
    assert_eq!(backlog.len(), 1);

    backlog.remove(Chain::Ethereum, &sign_id).await;
    assert_eq!(backlog.len(), 0);
    assert!(backlog.is_empty());
}

#[tokio::test]
async fn test_total_pending_ignores_invalid_removes() {
    let backlog = Backlog::new();
    let sign_id1 = SignId::new(create_test_tx(1).request_id);
    let sign_id2 = SignId::new(create_test_tx(2).request_id); // Not inserted

    backlog
        .insert(create_indexed_request(
            sign_id1,
            Chain::Ethereum,
            create_test_args(1),
            SignKind::Sign,
            0,
        ))
        .await;

    backlog.remove(Chain::Ethereum, &sign_id2).await;
    assert_eq!(
        backlog.len(),
        1,
        "Removing non-existent ID should not decrement total"
    );
}

#[tokio::test]
async fn test_total_pending_updates_on_clean_recovery() {
    let backlog = Backlog::new();

    // Populate 3 requests and create a checkpoint
    for i in 1..=3 {
        backlog
            .insert(create_indexed_request(
                SignId::new(create_test_tx(i).request_id),
                Chain::Ethereum,
                create_test_args(i),
                SignKind::Sign,
                0,
            ))
            .await;
    }
    backlog.set_processed_block(Chain::Ethereum, 10).await;
    let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();

    // Clean backlog recovers the checkpoint
    let recovered = Backlog::new();
    assert_eq!(recovered.len(), 0);

    recovered.recover_by_checkpoint(&checkpoint).await;

    assert_eq!(recovered.len(), 3);
}

#[tokio::test]
async fn test_total_pending_updates_on_dirty_recovery() {
    let backlog = Backlog::new();

    // Populate 3 requests and create a checkpoint
    for i in 1..=3 {
        backlog
            .insert(create_indexed_request(
                SignId::new(create_test_tx(i).request_id),
                Chain::Ethereum,
                create_test_args(i),
                SignKind::Sign,
                0,
            ))
            .await;
    }
    backlog.set_processed_block(Chain::Ethereum, 10).await;
    let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();

    // Dirty backlog has 1 entirely different request before recovery
    let dirty_backlog = Backlog::new();
    dirty_backlog
        .insert(create_indexed_request(
            SignId::new([99u8; 32]),
            Chain::Ethereum,
            create_test_args(99),
            SignKind::Sign,
            0,
        ))
        .await;

    assert_eq!(dirty_backlog.len(), 1);

    // Recover from checkpoint (should overwrite the dirty state)
    dirty_backlog.recover_by_checkpoint(&checkpoint).await;

    assert_eq!(
        dirty_backlog.len(),
        3,
        "Total should reflect exactly the restored checkpoint size, ignoring the overwritten dirty state"
    );
}

#[tokio::test]
async fn test_recovery_keeps_pending_checkpoints() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;
    let interval = chain.checkpoint_interval().unwrap();

    backlog.set_processed_block(chain, interval).await.unwrap();
    backlog
        .set_processed_block(chain, 2 * interval)
        .await
        .unwrap();

    assert_eq!(
        backlog.checkpoints().count(chain),
        2,
        "two checkpoints should be pending"
    );

    // Recover the request backlog without discarding checkpoints that may
    // still be needed to match an on-chain consensus digest.
    let fresh = Backlog::new();
    let recovery_cp = fresh.set_processed_block(chain, interval / 2).await;
    // interval/2 is not a multiple of interval → no auto-checkpoint
    assert!(recovery_cp.is_none());
    // Force create a checkpoint at that height
    let fresh_cp = fresh.checkpoint(chain).await.unwrap();
    assert_eq!(fresh_cp.block_height, interval / 2);

    backlog.recover_by_checkpoint(&fresh_cp).await;
    assert_eq!(
        backlog.checkpoints().count(chain),
        2,
        "pending checkpoints should remain available for consensus matching"
    );
}

#[tokio::test]
async fn test_hydrate_initializes_pending_and_recovers_backlog() {
    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let chain = Chain::Ethereum;
    let interval = chain.checkpoint_interval().unwrap();

    // Create pending checkpoints
    backlog.set_processed_block(chain, interval).await.unwrap();
    backlog
        .set_processed_block(chain, 2 * interval)
        .await
        .unwrap();
    assert_eq!(backlog.checkpoints().count(chain), 2);

    // A new Backlog instance sharing storage starts with 0 count and None processed block
    let restarted = Backlog::persisted(storage);
    assert_eq!(restarted.checkpoints().count(chain), 0);
    assert_eq!(restarted.get_processed_block(chain).await, None);

    // Hydrate initializes the counter and recovers from the latest checkpoint
    let hydrated = restarted.hydrate(chain).await.unwrap();
    assert!(hydrated.is_some());
    assert_eq!(hydrated.unwrap().block_height, 2 * interval);
    assert_eq!(restarted.checkpoints().count(chain), 2);
    assert_eq!(
        restarted.get_processed_block(chain).await,
        Some(2 * interval)
    );
}
