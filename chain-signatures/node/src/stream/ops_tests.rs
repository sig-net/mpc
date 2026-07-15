use super::*;
use crate::backlog::Backlog;
use crate::mesh::connection::NodeStatus;
use crate::mesh::{wait_threshold_active, MeshState};
use crate::protocol::contract::primitives::ParticipantInfo;
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::SignStatus;
use crate::storage::checkpoint_storage::CheckpointStorage;
use crate::stream::ops::process_execution_confirmed;
use crate::stream::test_utils::{
    make_test_stream_context_with_generator_pk, respond_event, test_bidirectional_tx,
    test_canton_sign_bidirectional_request, test_indexed_request, test_sign_args,
};
use crate::util::current_unix_timestamp;

use alloy::primitives::B256;
use cait_sith::protocol::Participant;
use k256::{ProjectivePoint, Scalar};
use mpc_chain_canton::CantonChainCtx;
use mpc_chain_integration_core::{NoopChainTelemetry, StateManager};
use mpc_primitives::{RespondBidirectionalTx, SignArgs, SignBidirectionalEvent, SignKind};
use near_primitives::types::AccountId;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

#[test]
fn signature_respond_event_conversion() {
    let big_r = ProjectivePoint::GENERATOR.to_affine();
    let s_scalar = Scalar::from(5u64);
    let recovery_id: u8 = 1;

    let event = SignatureRespondedEvent {
        request_id: [0u8; 32],
        signature: Signature::new(big_r, s_scalar, recovery_id),
        chain: Chain::Ethereum,
    };

    // check fields
    let sig = event.signature;
    assert_eq!(sig.recovery_id, recovery_id);
    assert_eq!(sig.s, s_scalar);
    assert_eq!(sig.big_r, big_r);
    assert_eq!(event.chain, Chain::Ethereum);
}

#[tokio::test]
async fn recover_backlog_requeues_pending_signs() {
    // Prepare backlog with a single pending sign request on a chain that
    // should be marked for requeue during recovery.
    let backlog = Backlog::new();
    let sign_id = SignId::new([9u8; 32]);
    let args = SignArgs {
        entropy: [1u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };

    // Add a request and persist a checkpoint so recover() can load it
    let unix_timestamp_indexed = current_unix_timestamp();
    backlog
        .insert(test_indexed_request(
            sign_id,
            Chain::Solana,
            args.clone(),
            unix_timestamp_indexed,
            SignKind::Sign,
        ))
        .await;
    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

    let threshold = 1;
    let mut mesh_state = MeshState::default();
    let participant = Participant::from(0u32);
    mesh_state.update(participant, NodeStatus::Active, ParticipantInfo::new(0));
    let (_mesh_tx, mut mesh_rx) = watch::channel(mesh_state);
    wait_threshold_active(&mut mesh_rx, threshold).await;
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    backlog.recover_by_checkpoint(checkpoint).await.unwrap();

    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, false);
    requeue_pending_sign_requests(&ctx, Chain::Solana)
        .await
        .unwrap();

    // We should receive the recovered sign request
    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .expect("recv should not timeout");

    match msg.expect("sign_rx should contain a message") {
        SignCommand::Request(req) => {
            assert_eq!(req.id, sign_id);
            assert_eq!(req.args, args);
            assert_eq!(req.chain, Chain::Solana);
            assert_eq!(req.kind, SignKind::Sign);
            // Verify that the unix_timestamp_indexed is preserved from the original entry
            assert_eq!(req.unix_timestamp_indexed, unix_timestamp_indexed);
            assert!(req.unix_timestamp_indexed <= current_unix_timestamp());
        }
        other => panic!("unexpected message: {:?}", other),
    }
}

#[tokio::test]
async fn process_execution_confirmed_success_creates_respond_request() {
    let backlog = Backlog::new();
    let tx = test_bidirectional_tx(1, Chain::Solana, Chain::Ethereum);
    let sign_id = SignId::new(tx.request_id);

    // Insert a pending Sign request on the source chain
    let args = SignArgs {
        entropy: [1u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };
    let unix_timestamp_indexed = current_unix_timestamp();
    backlog
        .insert(test_indexed_request(
            sign_id,
            tx.source_chain,
            args.clone(),
            unix_timestamp_indexed,
            SignKind::Sign,
        ))
        .await;

    backlog
        .watch_execution(tx.target_chain, sign_id, tx.clone())
        .await;

    let (sign_tx, mut sign_rx) = mpsc::channel(4);

    // Call the handler with a Success and empty output
    let tx_id = tx.id;
    // ensure watcher exists before processing
    let before_watchers = backlog.get_execution_watchers(tx.target_chain).await;
    assert!(before_watchers.contains_key(&tx.id));
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
    process_execution_confirmed(
        tx_id,
        sign_id,
        tx.source_chain,
        123u64,
        ExecutionOutcome::Success { output: vec![] },
        &ctx,
        tx.target_chain,
    )
    .await
    .unwrap();

    // Watcher should be removed
    let watchers = ctx.backlog.get_execution_watchers(tx.target_chain).await;
    tracing::info!(?watchers, "watchers after execution confirmed");
    assert!(watchers.is_empty());

    // Source chain request should now wait for final bidirectional response.
    // inspect the transaction to provide more debugging info on failure
    let maybe_tx = ctx.backlog.get(tx.source_chain, &sign_id).await;
    assert!(maybe_tx.is_some(), "expected sign tx to still exist");
    let tx_after = maybe_tx.unwrap();
    assert_eq!(
        tx_after.status(),
        SignStatus::PendingGenerationBidirectional,
        "expected PendingGenerationBidirectional but found status: {:?}",
        tx_after.status()
    );
    assert!(matches!(
        tx_after.request.kind,
        SignKind::RespondBidirectional(_)
    ));

    // A sign request should have been sent to the sign queue
    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => {
            if let mpc_primitives::SignKind::RespondBidirectional(res) = req.kind {
                assert_eq!(res.tx_id, tx.id);
            } else {
                panic!("Expected RespondBidirectional request");
            }
        }
        _ => panic!("Expected SignCommand::Request"),
    }
}

#[tokio::test]
async fn process_execution_confirmed_is_idempotent_after_first_processing() {
    let backlog = Backlog::new();
    let tx = test_bidirectional_tx(7, Chain::Solana, Chain::Ethereum);
    let sign_id = SignId::new(tx.request_id);
    let args = SignArgs {
        entropy: [7u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };
    backlog
        .insert(test_indexed_request(
            sign_id,
            tx.source_chain,
            args,
            current_unix_timestamp(),
            SignKind::Sign,
        ))
        .await;
    backlog
        .watch_execution(tx.target_chain, sign_id, tx.clone())
        .await;

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    process_execution_confirmed(
        tx.id,
        sign_id,
        tx.source_chain,
        123u64,
        ExecutionOutcome::Success { output: vec![] },
        &ctx,
        tx.target_chain,
    )
    .await
    .unwrap();

    process_execution_confirmed(
        tx.id,
        sign_id,
        tx.source_chain,
        124u64,
        ExecutionOutcome::Success { output: vec![] },
        &ctx,
        tx.target_chain,
    )
    .await
    .unwrap();

    let first = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match first {
        SignCommand::Request(req) => {
            assert!(matches!(req.kind, SignKind::RespondBidirectional(_)))
        }
        other => panic!("expected one sign request, got {other:?}"),
    }

    let no_second = timeout(Duration::from_millis(100), sign_rx.recv()).await;
    assert!(matches!(no_second, Err(_) | Ok(None)));

    assert!(ctx
        .backlog
        .get_execution_watchers(tx.target_chain)
        .await
        .is_empty());
}

#[tokio::test]
async fn process_execution_confirmed_warns_but_still_uses_watcher_sign_id() {
    let backlog = Backlog::new();
    let tx = test_bidirectional_tx(8, Chain::Solana, Chain::Ethereum);
    let sign_id = SignId::new(tx.request_id);
    let mismatched_sign_id = SignId::new([88u8; 32]);
    let args = SignArgs {
        entropy: [8u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };
    backlog
        .insert(test_indexed_request(
            sign_id,
            tx.source_chain,
            args,
            current_unix_timestamp(),
            SignKind::Sign,
        ))
        .await;
    backlog
        .watch_execution(tx.target_chain, sign_id, tx.clone())
        .await;

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    process_execution_confirmed(
        tx.id,
        mismatched_sign_id,
        tx.source_chain,
        321u64,
        ExecutionOutcome::Failed,
        &ctx,
        tx.target_chain,
    )
    .await
    .unwrap();

    let tx_after = ctx.backlog.get(tx.source_chain, &sign_id).await.unwrap();
    assert_eq!(
        tx_after.status(),
        SignStatus::PendingGenerationBidirectional
    );
    assert!(matches!(
        tx_after.request.kind,
        SignKind::RespondBidirectional(_)
    ));
    assert!(ctx
        .backlog
        .get_execution_watchers(tx.target_chain)
        .await
        .is_empty());

    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => assert_eq!(req.id, sign_id),
        other => panic!("expected sign request, got {other:?}"),
    }
}

#[tokio::test]
async fn process_execution_confirmed_recovery_requeues_final_respond_after_send_failure() {
    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let tx = test_bidirectional_tx(9, Chain::Solana, Chain::Ethereum);
    let sign_id = SignId::new(tx.request_id);
    let args = SignArgs {
        entropy: [9u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };
    backlog
        .insert(test_indexed_request(
            sign_id,
            tx.source_chain,
            args.clone(),
            current_unix_timestamp(),
            SignKind::Sign,
        ))
        .await;
    backlog
        .watch_execution(tx.target_chain, sign_id, tx.clone())
        .await;

    let (sign_tx, sign_rx) = mpsc::channel(4);
    drop(sign_rx);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    process_execution_confirmed(
        tx.id,
        sign_id,
        tx.source_chain,
        444u64,
        ExecutionOutcome::Success { output: vec![] },
        &ctx,
        tx.target_chain,
    )
    .await
    .expect_err("send failure should surface as an error");

    ctx.backlog.set_processed_block(tx.source_chain, 10).await;
    let checkpoint = ctx.backlog.checkpoint(tx.source_chain).await.unwrap();

    // Simulate consensus confirmation so storage has the checkpoint
    ctx.backlog
        .on_consensus_confirmed(tx.source_chain, &checkpoint)
        .await;

    let threshold = 1;
    let mut mesh_state = MeshState::default();
    let participant = Participant::from(0u32);
    mesh_state.update(participant, NodeStatus::Active, ParticipantInfo::new(0));
    let (_mesh_tx, mut mesh_rx) = watch::channel(mesh_state);
    wait_threshold_active(&mut mesh_rx, threshold).await;
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let recovered = Backlog::persisted(storage.clone());

    let checkpoint = recovered
        .storage
        .load_latest(tx.source_chain)
        .await
        .unwrap()
        .unwrap();
    recovered.recover_by_checkpoint(checkpoint).await.unwrap();

    let recovered_ctx = make_test_stream_context_with_generator_pk(recovered, sign_tx, false);
    requeue_pending_sign_requests(&recovered_ctx, tx.source_chain)
        .await
        .unwrap();

    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => {
            assert_eq!(req.id, sign_id);
            assert!(matches!(req.kind, SignKind::RespondBidirectional(_)));
        }
        other => panic!("expected recovered final respond request, got {other:?}"),
    }
}

#[tokio::test]
async fn process_respond_event_rejects_invalid_bidirectional_target_chain() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([11u8; 32]);
    let args = SignArgs {
        entropy: [11u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };

    let mut rlp_s = rlp::RlpStream::new_list(9);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    rlp_s.append(&Vec::<u8>::new());
    rlp_s.append(&0u64);
    rlp_s.append(&Vec::<u8>::new());
    rlp_s.append(&1u64);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    let unsigned_rlp = rlp_s.out().to_vec();

    backlog
        .insert(IndexedSignRequest::sign_bidirectional(
            sign_id,
            args.clone(),
            Chain::Ethereum,
            current_unix_timestamp(),
            SignBidirectionalEvent {
                sender: Default::default(),
                serialized_transaction: unsigned_rlp,
                dest: "0x1234567890123456789012345678901234567890".to_string(),
                caip2_id: "not-a-chain".to_string(),
                key_version: 0,
                deposit: 0,
                path: "m/0".to_string(),
                algo: "ECDSA".to_string(),
                params: "{}".to_string(),
                chain: Chain::Solana,
                chain_ctx: Some(Pubkey::new_unique().to_bytes().to_vec()),
                output_deserialization_schema: vec![],
                respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            },
        ))
        .await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let event = SignatureRespondedEvent {
        request_id: sign_id.request_id,
        signature: mpc_crypto::generate_signature(&root_sk, &args),
        chain: Chain::Ethereum,
    };

    let account_id: AccountId = "test.near".parse().unwrap();
    let public_key = root_sk.public_key().into();
    let (_contract_watcher, _tx) =
        ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    let err = process_respond_event(event, &ctx, public_key)
        .await
        .expect_err("invalid chain should fail");
    // The underlying `UnknownCaip2Id` cause is carried in the error's source chain.
    let cause = err
        .chain()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(cause.contains("unknown CAIP-2 chain ID: not-a-chain"));
}

#[tokio::test]
async fn process_sign_request_rejects_respond_bidirectional_kind() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([12u8; 32]);
    let args = SignArgs {
        entropy: [12u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };

    let request = IndexedSignRequest::respond_bidirectional(
        sign_id,
        args,
        Chain::Solana,
        current_unix_timestamp(),
        RespondBidirectionalTx {
            tx_id: BidirectionalTxId(B256::from([12u8; 32]).0),
            output: vec![],
            chain_ctx: None,
        },
    );

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
    let err = process_sign_request(request, &ctx)
        .await
        .expect_err("RespondBidirectional should be rejected from the sign queue path");
    assert!(err.to_string().contains("Unexpected sign request kind"));
}

#[tokio::test]
async fn process_respond_event_rejects_invalid_signature() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([15u8; 32]);
    let args = test_sign_args(15);

    backlog
        .insert(test_indexed_request(
            sign_id,
            Chain::Ethereum,
            args.clone(),
            current_unix_timestamp(),
            SignKind::Sign,
        ))
        .await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let mut invalid_signature = mpc_crypto::generate_signature(&root_sk, &args);
    invalid_signature.s += Scalar::ONE;

    let event = SignatureRespondedEvent {
        request_id: sign_id.request_id,
        signature: invalid_signature,
        chain: Chain::Ethereum,
    };

    let account_id: AccountId = "test.near".parse().unwrap();
    let public_key = root_sk.public_key().into();
    let (_contract_watcher, _tx) =
        ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    let err = process_respond_event(event, &ctx, public_key)
        .await
        .expect_err("invalid signature should be rejected");
    assert!(err.to_string().contains("invalid signature"));
    assert!(ctx.backlog.get(Chain::Ethereum, &sign_id).await.is_some());
}

#[tokio::test]
async fn process_respond_bidirectional_event_duplicate_is_idempotent() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([13u8; 32]);
    let args = test_sign_args(13);

    backlog
        .insert(IndexedSignRequest::respond_bidirectional(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
            RespondBidirectionalTx {
                tx_id: BidirectionalTxId(B256::from([13u8; 32]).0),
                output: vec![1, 2, 3],
                chain_ctx: None,
            },
        ))
        .await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let signature = mpc_crypto::generate_signature(&root_sk, &args);

    let duplicate_event0 = respond_event(sign_id, signature);
    let duplicate_event1 = respond_event(sign_id, signature);

    let account_id: AccountId = "test.near".parse().unwrap();
    let public_key = root_sk.public_key().into();
    let (_contract_watcher, _tx) =
        ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    process_respond_bidirectional_event(duplicate_event0, &ctx, public_key)
        .await
        .expect("first completion should succeed");

    process_respond_bidirectional_event(duplicate_event1, &ctx, public_key)
        .await
        .expect("duplicate completion should be ignored");

    let first = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match first {
        SignCommand::Completion(id) => assert_eq!(id, sign_id),
        other => panic!("expected completion, got {other:?}"),
    }

    let no_second = timeout(Duration::from_millis(100), sign_rx.recv()).await;
    assert!(matches!(no_second, Err(_) | Ok(None)));
}

#[tokio::test]
async fn process_respond_bidirectional_event_rejects_invalid_signature() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([16u8; 32]);
    let args = test_sign_args(16);

    backlog
        .insert(IndexedSignRequest::respond_bidirectional(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
            RespondBidirectionalTx {
                tx_id: BidirectionalTxId(B256::from([16u8; 32]).0),
                output: vec![1, 2, 3],
                chain_ctx: None,
            },
        ))
        .await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let mut invalid_signature = mpc_crypto::generate_signature(&root_sk, &args);
    invalid_signature.s += Scalar::ONE;

    let event = respond_event(sign_id, invalid_signature);

    let account_id: AccountId = "test.near".parse().unwrap();
    let public_key = root_sk.public_key().into();
    let (_contract_watcher, _tx) =
        ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    let err = process_respond_bidirectional_event(event, &ctx, public_key)
        .await
        .expect_err("invalid signature should be rejected");
    assert!(err.to_string().contains("invalid signature"));
    assert!(ctx.backlog.get(Chain::Solana, &sign_id).await.is_some());
}

#[tokio::test]
async fn process_respond_event_duplicate_ethereum_is_idempotent() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([3u8; 32]);
    let args = test_sign_args(1);

    backlog
        .insert(test_indexed_request(
            sign_id,
            Chain::Ethereum,
            args.clone(),
            current_unix_timestamp(),
            SignKind::Sign,
        ))
        .await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let event = SignatureRespondedEvent {
        request_id: sign_id.request_id,
        signature: mpc_crypto::generate_signature(&root_sk, &args),
        chain: Chain::Ethereum,
    };

    let account_id: AccountId = "test.near".parse().unwrap();
    let public_key = root_sk.public_key().into();
    let (_contract_watcher, _tx) =
        ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    // First event should complete the request.
    process_respond_event(event.clone(), &ctx, public_key)
        .await
        .expect("first respond event should succeed");

    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Completion(id) => assert_eq!(id, sign_id),
        _ => panic!("expected completion"),
    }

    // Duplicate events should be ignored, not treated as an error.
    // This mirrors production behavior where the same respond log can be
    // emitted repeatedly by the Ethereum indexer pipeline.
    for _ in 0..16 {
        process_respond_event(event.clone(), &ctx, public_key)
            .await
            .expect("duplicate respond event should be idempotent");
    }

    let no_extra = timeout(Duration::from_millis(100), sign_rx.recv()).await;
    assert!(
        matches!(no_extra, Err(_) | Ok(None)),
        "expected no additional completion message, got: {no_extra:?}"
    );
}

#[tokio::test]
async fn process_respond_event_advances_bidirectional_from_pending_publish() {
    let backlog = Backlog::new();
    let tx = test_bidirectional_tx(14, Chain::Ethereum, Chain::Solana);
    let sign_id = SignId::new(tx.request_id);
    let args = test_sign_args(14);

    let mut rlp_s = rlp::RlpStream::new_list(9);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    rlp_s.append(&Vec::<u8>::new());
    rlp_s.append(&0u64);
    rlp_s.append(&Vec::<u8>::new());
    rlp_s.append(&1u64);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    let unsigned_rlp = rlp_s.out().to_vec();

    backlog
        .insert(IndexedSignRequest::sign_bidirectional(
            sign_id,
            args.clone(),
            Chain::Ethereum,
            current_unix_timestamp(),
            SignBidirectionalEvent {
                sender: Default::default(),
                serialized_transaction: unsigned_rlp,
                dest: tx.dest.clone(),
                caip2_id: tx.caip2_id.clone(),
                key_version: tx.key_version,
                deposit: tx.deposit,
                path: tx.path.clone(),
                algo: tx.algo.clone(),
                params: tx.params.clone(),
                chain: Chain::Solana,
                chain_ctx: Some(Pubkey::new_unique().to_bytes().to_vec()),
                output_deserialization_schema: tx.output_deserialization_schema.clone(),
                respond_serialization_schema: tx.respond_serialization_schema.clone(),
            },
        ))
        .await;

    backlog
        .set_status(
            Chain::Ethereum,
            &sign_id,
            crate::sign_bidirectional::SignStatus::PendingPublish {
                publish: crate::sign_bidirectional::PublishState {
                    signature: Signature::new(
                        ProjectivePoint::GENERATOR.to_affine(),
                        Scalar::ONE,
                        0,
                    ),
                    participants: vec![],
                    is_proposer: true,
                },
            },
        )
        .await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let event = SignatureRespondedEvent {
        request_id: sign_id.request_id,
        signature: mpc_crypto::generate_signature(&root_sk, &args),
        chain: Chain::Ethereum,
    };

    let account_id: AccountId = "test.near".parse().unwrap();
    let public_key = root_sk.public_key().into();
    let (_contract_watcher, _tx) =
        ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, false);

    process_respond_event(event, &ctx, public_key)
        .await
        .expect("respond event should advance pending publish bidirectional entries");

    let entry = ctx
        .backlog
        .get(Chain::Ethereum, &sign_id)
        .await
        .expect("entry should remain in backlog");
    assert!(matches!(
        entry.status(),
        SignStatus::PendingExecution { .. }
    ));
    let execution_tx_id = entry
        .execution_tx()
        .expect("pending execution entries should store the execution transaction")
        .id;

    let watchers = ctx.backlog.get_execution_watchers(Chain::Solana).await;
    assert_eq!(watchers.len(), 1);
    assert!(watchers.contains_key(&execution_tx_id));
}

#[tokio::test]
async fn process_execution_confirmed_failed_creates_error_respond_request() {
    let backlog = Backlog::new();

    let tx = test_bidirectional_tx(2, Chain::Solana, Chain::Ethereum);
    let sign_id = SignId::new(tx.request_id);

    // Insert pending Sign request on source chain
    let args = SignArgs {
        entropy: [2u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(3u64),
        path: "test".to_string(),
        key_version: 1,
    };
    let unix_timestamp_indexed = current_unix_timestamp();
    backlog
        .insert(test_indexed_request(
            sign_id,
            tx.source_chain,
            args.clone(),
            unix_timestamp_indexed,
            SignKind::Sign,
        ))
        .await;

    backlog
        .watch_execution(tx.target_chain, sign_id, tx.clone())
        .await;

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    process_execution_confirmed(
        tx.id,
        sign_id,
        tx.source_chain,
        456u64,
        ExecutionOutcome::Failed,
        &ctx,
        tx.target_chain,
    )
    .await
    .unwrap();

    // Watcher removed
    let watchers = ctx.backlog.get_execution_watchers(tx.target_chain).await;
    assert!(watchers.is_empty());

    // Source chain should now wait for final bidirectional response.
    let waiting = ctx
        .backlog
        .pending_generation_bidirectionals(tx.source_chain)
        .await;
    assert!(waiting.contains_key(&sign_id));

    let tx_after = ctx.backlog.get(tx.source_chain, &sign_id).await.unwrap();
    assert!(matches!(
        tx_after.request.kind,
        SignKind::RespondBidirectional(_)
    ));

    // A sign request should have been sent
    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => {
            if let mpc_primitives::SignKind::RespondBidirectional(res) = req.kind {
                assert_eq!(res.tx_id, tx.id);
                // Expect the serialized output to begin with MAGIC_ERROR_PREFIX
                assert!(res.output.starts_with(&[0xde, 0xad, 0xbe, 0xef]));
            } else {
                panic!("Expected RespondBidirectional request");
            }
        }
        _ => panic!("Expected SignCommand::Request"),
    }
}

#[tokio::test]
async fn process_execution_confirmed_cross_chain_emits_before_target_catchup() {
    let backlog = Backlog::new();

    use alloy::primitives::{Address, B256};
    let tx = BidirectionalTx {
        id: BidirectionalTxId(B256::from([4u8; 32]).0),
        sender: [0u8; 32],
        serialized_transaction: vec![1, 2, 3],
        source_chain: Chain::Solana,
        target_chain: Chain::Ethereum,
        caip2_id: "test_caip2_id".to_string(),
        key_version: 1,
        deposit: 1000,
        path: "test_path".to_string(),
        algo: "ECDSA".to_string(),
        dest: "0x1234567890123456789012345678901234567890".to_string(),
        params: "{}".to_string(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        request_id: [4u8; 32],
        from_address: **Address::ZERO,
        nonce: 0,
    };
    let sign_id = SignId::new(tx.request_id);

    let args = SignArgs {
        entropy: [4u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };

    backlog
        .insert(test_indexed_request(
            sign_id,
            tx.source_chain,
            args,
            current_unix_timestamp(),
            SignKind::Sign,
        ))
        .await;

    backlog
        .watch_execution(tx.target_chain, sign_id, tx.clone())
        .await;

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, false);
    process_execution_confirmed(
        tx.id,
        sign_id,
        tx.source_chain,
        789u64,
        ExecutionOutcome::Failed,
        &ctx,
        tx.target_chain,
    )
    .await
    .unwrap();

    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => {
            assert_eq!(req.chain, Chain::Solana);
            assert!(matches!(
                req.kind,
                mpc_primitives::SignKind::RespondBidirectional(_)
            ));
        }
        other => panic!("expected cross-chain follow-up request, got {other:?}"),
    }
}

#[tokio::test]
async fn process_execution_confirmed_carries_canton_chain_ctx_to_final_request() {
    let backlog = Backlog::new();
    let mut tx = test_bidirectional_tx(24, Chain::Canton, Chain::Ethereum);
    tx.sender = [7u8; 32];
    let sign_id = SignId::new(tx.request_id);
    let sign_event_contract_id = "#sign-event-cid";

    backlog
        .insert(test_canton_sign_bidirectional_request(
            sign_id,
            sign_event_contract_id,
        ))
        .await;

    backlog
        .watch_execution(tx.target_chain, sign_id, tx.clone())
        .await;

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    process_execution_confirmed(
        tx.id,
        sign_id,
        tx.source_chain,
        456u64,
        ExecutionOutcome::Success { output: vec![1] },
        &ctx,
        tx.target_chain,
    )
    .await
    .unwrap();

    let assert_canton_ctx = |ctx_bytes: Option<&[u8]>| {
        let bytes = ctx_bytes.expect("chain_ctx present");
        let decoded: CantonChainCtx = borsh::from_slice(bytes).expect("CantonChainCtx decodes");
        assert_eq!(decoded.sign_event_contract_id, sign_event_contract_id);
    };

    assert!(ctx
        .backlog
        .get_execution_watchers(tx.target_chain)
        .await
        .is_empty());
    let tx_after = ctx.backlog.get(tx.source_chain, &sign_id).await.unwrap();
    assert_eq!(
        tx_after.status(),
        SignStatus::PendingGenerationBidirectional
    );
    match &tx_after.request.kind {
        SignKind::RespondBidirectional(res) => {
            assert_eq!(res.tx_id, tx.id);
            assert_eq!(res.output, vec![1]);
            assert_canton_ctx(res.chain_ctx.as_deref());
        }
        other => panic!("Expected RespondBidirectional request, got {other:?}"),
    }

    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => {
            assert_eq!(req.id, sign_id);
            assert_eq!(req.chain, tx.source_chain);
            match req.kind {
                SignKind::RespondBidirectional(res) => {
                    assert_eq!(res.tx_id, tx.id);
                    assert_eq!(res.output, vec![1]);
                    assert_canton_ctx(res.chain_ctx.as_deref());
                }
                other => panic!("Expected RespondBidirectional request, got {other:?}"),
            }
        }
        other => panic!("Expected SignCommand::Request, got {other:?}"),
    }
}

#[tokio::test]
async fn requeue_pending_sign_requests_is_chain_scoped() {
    let backlog = Backlog::new();
    let solana_sign_id = SignId::new([7u8; 32]);
    let ethereum_sign_id = SignId::new([8u8; 32]);
    let args = SignArgs {
        entropy: [1u8; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    };

    backlog
        .insert(test_indexed_request(
            solana_sign_id,
            Chain::Solana,
            args.clone(),
            current_unix_timestamp(),
            SignKind::Sign,
        ))
        .await;
    backlog
        .insert(test_indexed_request(
            ethereum_sign_id,
            Chain::Ethereum,
            args,
            current_unix_timestamp(),
            SignKind::Sign,
        ))
        .await;

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, false);

    requeue_pending_sign_requests(&ctx, Chain::Solana)
        .await
        .unwrap();

    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => assert_eq!(req.id, solana_sign_id),
        other => panic!("unexpected message: {other:?}"),
    }

    let no_extra = timeout(Duration::from_millis(100), sign_rx.recv()).await;
    assert!(
        matches!(no_extra, Err(_) | Ok(None)),
        "expected no cross-chain requeue, got: {no_extra:?}"
    );
}

#[tokio::test]
async fn catchup_blocks_do_not_consume_checkpoint_slots() {
    // During catchup, process_block_event should NOT create checkpoints
    // (which consume slots). If it did, 33 checkpoint intervals worth of
    // blocks would fill the 32-slot cap and stall catchup forever.
    let chain = Chain::Ethereum;
    let backlog = Backlog::new();
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let telemetry = NoopChainTelemetry;
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, false);

    // Process 33 checkpoint intervals at caught_up=false
    let interval = chain.checkpoint_interval().unwrap(); // 100 for Ethereum
    for i in 1..=33 {
        process_block_event(chain, i * interval, &ctx, &telemetry)
            .await
            .unwrap();
    }

    // Slots should still be available — no pending checkpoints created
    assert!(
        ctx.backlog.has_checkpoint_slot(chain).await,
        "catchup should not consume checkpoint slots; 33 intervals without caught_up \
         would fill the 32-slot cap and cause a permanent stall"
    );
}
