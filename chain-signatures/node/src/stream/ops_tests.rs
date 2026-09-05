use super::*;
use crate::backlog::mock::{
    mock_bidi_request, mock_bidi_response_request, mock_participants, mock_sign_request,
    mock_signature_output, mock_tx, BacklogTestExt,
};
use crate::backlog::{Backlog, Bidirectional, Final, Generating};
use crate::mesh::connection::NodeStatus;
use crate::mesh::{wait_threshold_active, MeshState};
use crate::protocol::contract::primitives::ParticipantInfo;
use crate::rpc::{ContractStateWatcher, RpcAction};
use crate::sign_bidirectional::{BidirectionalProgress, SignProgress, SignStatus};
use crate::storage::checkpoint_storage::CheckpointStorage;
use crate::stream::ops::process_execution_confirmed;
use crate::stream::test_utils::{
    make_test_stream_context, make_test_stream_context_with_generator_pk,
    make_test_stream_context_with_rpc, respond_event, test_bidirectional_tx,
    test_canton_sign_bidirectional_request, test_sign_args,
};
use crate::types::SignCommand;
use alloy::primitives::B256;
use cait_sith::protocol::Participant;
use k256::{ProjectivePoint, Scalar};
use mpc_chain_canton::CantonChainCtx;
use mpc_chain_integration_core::{NoopChainTelemetry, StateManager};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, ChainConfig as _, IndexedSignRequest, SignArgs,
    SignBidirectionalEvent, SignKind, Signature,
};
use mpc_utils::time::current_unix_timestamp;
use near_primitives::types::AccountId;
use std::sync::Arc;
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
    let entry = backlog.insert_mock_sign(sign_id, Chain::Solana).await;
    let expected_args = entry.request().args.clone();
    let expected_timestamp = entry.request().unix_timestamp_indexed;
    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

    let threshold = 1;
    let mut mesh_state = MeshState::default();
    let participant = Participant::from(0u32);
    mesh_state.update(participant, NodeStatus::Active, ParticipantInfo::new(0));
    let (_mesh_tx, mut mesh_rx) = watch::channel(mesh_state);
    wait_threshold_active(&mut mesh_rx, threshold).await;
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    backlog.recover_by_checkpoint(&checkpoint).await;

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
            assert_eq!(req.sign_id(), sign_id);
            assert_eq!(req.request().args, expected_args);
            assert_eq!(req.chain(), Chain::Solana);
            assert_eq!(req.request().kind, SignKind::Sign);
            // Verify that the unix_timestamp_indexed is preserved from the original entry
            assert_eq!(req.request().unix_timestamp_indexed, expected_timestamp);
            assert!(req.request().unix_timestamp_indexed <= current_unix_timestamp());
        }
        other => panic!("unexpected message: {:?}", other),
    }
}

async fn seed_executing_entry(
    backlog: &Backlog,
    request: Arc<IndexedSignRequest>,
    tx: Arc<BidirectionalTx>,
) {
    let (pk, output) = mock_signature_output(&request.args);
    backlog
        .insert_bidirectional(request)
        .await
        .advance(pk, &output, vec![], true)
        .await
        .expect("advance to publishing")
        .advance(tx)
        .await
        .expect("advance to executing");
}

#[tokio::test]
async fn process_execution_confirmed_success_creates_respond_request() {
    let backlog = Backlog::new();
    let tx = test_bidirectional_tx(1, Chain::Solana, Chain::Ethereum);
    let sign_id = tx.sign_id();
    backlog.insert_mock_executing(&tx).await;

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
    assert_matches!(
        tx_after.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Final {
            progress: SignProgress::Generating,
            ..
        })
    );
    assert_matches!(tx_after.request().kind, SignKind::RespondBidirectional(_));

    // A sign request should have been sent to the sign queue
    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => {
            if let mpc_primitives::SignKind::RespondBidirectional(res) = &req.request().kind {
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
    let sign_id = tx.sign_id();
    backlog.insert_mock_executing(&tx).await;

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
            assert_matches!(req.request().kind, SignKind::RespondBidirectional(_));
        }
        other => panic!("expected one sign request, got {other:?}"),
    }

    let no_second = timeout(Duration::from_millis(100), sign_rx.recv()).await;
    assert_matches!(no_second, Err(_) | Ok(None));

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
    let sign_id = tx.sign_id();
    let mismatched_sign_id = SignId::new([88u8; 32]);
    backlog.insert_mock_executing(&tx).await;

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
    assert_matches!(
        tx_after.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Final {
            progress: SignProgress::Generating,
            ..
        })
    );
    assert_matches!(tx_after.request().kind, SignKind::RespondBidirectional(_));
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
        SignCommand::Request(req) => assert_eq!(req.sign_id(), sign_id),
        other => panic!("expected sign request, got {other:?}"),
    }
}

#[tokio::test]
async fn process_execution_confirmed_recovery_requeues_final_respond_after_send_failure() {
    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let tx = test_bidirectional_tx(9, Chain::Solana, Chain::Ethereum);
    let sign_id = tx.sign_id();
    backlog.insert_mock_executing(&tx).await;

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
    assert_matches!(
        ctx.backlog
            .checkpoints()
            .confirm(tx.source_chain, checkpoint.digest())
            .await,
        Ok(true)
    );

    let threshold = 1;
    let mut mesh_state = MeshState::default();
    let participant = Participant::from(0u32);
    mesh_state.update(participant, NodeStatus::Active, ParticipantInfo::new(0));
    let (_mesh_tx, mut mesh_rx) = watch::channel(mesh_state);
    wait_threshold_active(&mut mesh_rx, threshold).await;
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let recovered = Backlog::persisted(storage.clone());

    let checkpoint = recovered
        .checkpoints()
        .storage()
        .load_latest(tx.source_chain)
        .await
        .unwrap()
        .unwrap();
    recovered.recover_by_checkpoint(&checkpoint).await;

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
            assert_eq!(req.sign_id(), sign_id);
            assert_matches!(req.request().kind, SignKind::RespondBidirectional(_));
        }
        other => panic!("expected recovered final respond request, got {other:?}"),
    }
}

#[tokio::test]
async fn process_respond_event_quarantines_invalid_bidirectional_target_chain() {
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
        .insert(Arc::new(IndexedSignRequest::sign_bidirectional(
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
        )))
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

    // An unknown target chain fails the same deterministic derivation on every
    // node and every replay, so the entry is quarantined rather than errored:
    // leaving it would park it in pending-publish with every node republishing it.
    process_respond_event(event, &ctx, public_key)
        .await
        .expect("quarantining is not an error");
    assert!(
        ctx.backlog.get(Chain::Ethereum, &sign_id).await.is_none(),
        "an entry with an unknown target chain must leave the backlog"
    );
}

#[tokio::test]
async fn process_sign_request_rejects_respond_bidirectional_kind() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([12u8; 32]);
    let tx_id = BidirectionalTxId(B256::from([12u8; 32]).0);
    let request = mock_bidi_response_request(sign_id, tx_id, Chain::Solana);

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
    let err = process_sign_request(request, &ctx)
        .await
        .expect_err("RespondBidirectional should be rejected from the sign queue path");
    assert!(err.to_string().contains("Unexpected sign request kind"));
}

/// Admission cannot be the only gate: checkpoint recovery restores backlog entries
/// wholesale, so a poison entry can exist without ever passing admission. The
/// respond path must then quarantine it (deterministically, on every node), or it
/// parks in pending-publish forever with every node publishing it.
#[tokio::test]
async fn process_respond_event_quarantines_a_bidirectional_entry_that_cannot_advance() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([23u8; 32]);
    let req = mock_bidi_request(sign_id, Chain::Solana);

    // Inserted directly, as checkpoint recovery would: never passed admission.
    backlog.insert(req.clone()).await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let signature = mpc_crypto::generate_signature(&root_sk, &req.args);
    let event = SignatureRespondedEvent {
        request_id: sign_id.request_id,
        signature,
        chain: Chain::Solana,
    };

    let public_key = root_sk.public_key().into();
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let (ctx, _cp, _mesh, _rpc_rx) =
        make_test_stream_context(backlog, sign_tx, true, public_key, 1);

    process_respond_event(event, &ctx, public_key)
        .await
        .expect("quarantining is not an error");

    assert!(
        ctx.backlog.get(Chain::Solana, &sign_id).await.is_none(),
        "an entry that can never advance must leave the backlog"
    );
}

/// A Solana-sourced bidirectional event targeting Ethereum; `serialized_transaction`
/// is the part the admission tests vary.
fn bidirectional_event(serialized_transaction: Vec<u8>) -> SignBidirectionalEvent {
    SignBidirectionalEvent {
        sender: [0u8; 32],
        serialized_transaction,
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: 0,
        deposit: 0,
        path: String::new(),
        algo: String::new(),
        dest: Chain::Ethereum.to_string(),
        params: String::new(),
        chain: Chain::Solana,
        chain_ctx: None,
        output_deserialization_schema: vec![],
        respond_serialization_schema: vec![],
    }
}

/// A non-empty but undecodable transaction is the same poison pill as an empty one,
/// with a worse blast radius: admitted, it signs, publishes leg 1, then fails
/// deterministically in respond processing before the cancel, leaving the entry in
/// pending-publish forever while every node fires into a retry loop that
/// nothing ends. Admission runs the same derivations respond processing will need.
#[tokio::test]
async fn process_sign_request_rejects_undecodable_bidirectional_transaction() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([14u8; 32]);
    let request = mock_bidi_request(sign_id, Chain::Solana);

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);
    let err = process_sign_request(request, &ctx)
        .await
        .expect_err("undecodable serialized_transaction should be rejected at ingestion");
    assert!(format!("{err:#}").contains("undecodable serialized_transaction"));
    assert!(
        backlog.get(Chain::Solana, &sign_id).await.is_none(),
        "rejected request must not be stored in the backlog"
    );
}

#[tokio::test]
async fn process_sign_request_rejects_empty_bidirectional_serialized_transaction() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([13u8; 32]);

    // A bidirectional request with an empty `serialized_transaction`. If accepted
    // it would sit in the backlog and later panic in `sign_and_hash_transaction`
    // (empty RLP) when the respond event advances it to execution.
    let event = bidirectional_event(vec![]);
    let request = Arc::new(IndexedSignRequest::sign_bidirectional(
        sign_id,
        test_sign_args(13),
        Chain::Solana,
        current_unix_timestamp(),
        event,
    ));

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);
    let err = process_sign_request(request, &ctx)
        .await
        .expect_err("empty serialized_transaction should be rejected at ingestion");
    assert!(format!("{err:#}").contains("empty serialized_transaction"));

    // The poison-pill request must not have entered the backlog.
    assert!(
        backlog.get(Chain::Solana, &sign_id).await.is_none(),
        "rejected request must not be stored in the backlog"
    );
}

#[tokio::test]
async fn process_sign_request_duplicate_is_idempotent() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([9u8; 32]);
    let request = mock_sign_request(sign_id, Chain::Ethereum);

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, false);

    // First emission inserts a new entry.
    let was_new = process_sign_request(Arc::clone(&request), &ctx)
        .await
        .expect("first sign request should be accepted");
    assert!(was_new, "first insert must report a new entry");
    assert_eq!(backlog.len(), 1);

    // Replay: the indexer re-emitted the same SignId
    // backlog.insert is keyed on SignId, so the replay is absorbed, not duplicated.
    let is_new = process_sign_request(request, &ctx)
        .await
        .expect("replayed sign request should be accepted");
    assert!(!is_new, "replayed insert must report an existing entry");
    assert_eq!(
        backlog.len(),
        1,
        "replaying the same SignId must not grow the backlog"
    );

    // No sign command was enqueued during catchup
    assert!(
        timeout(Duration::from_millis(100), sign_rx.recv())
            .await
            .is_err(),
        "no sign command should be enqueued during catchup"
    );

    // After catchup, the backlog is re-queued to the sign queue.
    requeue_pending_sign_requests(&ctx, Chain::Ethereum)
        .await
        .expect("requeue should succeed");

    // The re-queued request should be sent to the sign queue.
    match timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .expect("requeue should enqueue the pending request")
        .expect("sign channel open")
    {
        SignCommand::Request(req) => assert_eq!(req.sign_id(), sign_id),
        other => panic!("expected a single requeued request, got {other:?}"),
    }
    assert!(
        timeout(Duration::from_millis(100), sign_rx.recv())
            .await
            .is_err(),
        "the replayed duplicate must not produce a second command"
    );
}

#[tokio::test]
async fn process_respond_event_rejects_invalid_signature() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([15u8; 32]);
    let entry = backlog.insert_mock_sign(sign_id, Chain::Ethereum).await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let mut invalid_signature = mpc_crypto::generate_signature(&root_sk, &entry.request().args);
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
    let tx = test_bidirectional_tx(13, Chain::Solana, Chain::Ethereum);
    let sign_id = tx.sign_id();
    let entry = backlog.insert_mock_final(&tx).await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let signature = mpc_crypto::generate_signature(&root_sk, &entry.request().args);

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
    assert_matches!(no_second, Err(_) | Ok(None));
}

#[tokio::test]
async fn process_respond_bidirectional_event_rejects_invalid_signature() {
    let backlog = Backlog::new();
    let tx = test_bidirectional_tx(16, Chain::Solana, Chain::Ethereum);
    let sign_id = tx.sign_id();
    let entry = backlog.insert_mock_final(&tx).await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let mut invalid_signature = mpc_crypto::generate_signature(&root_sk, &entry.request().args);
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
    let entry = backlog.insert_mock_sign(sign_id, Chain::Ethereum).await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let event = SignatureRespondedEvent {
        request_id: sign_id.request_id,
        signature: mpc_crypto::generate_signature(&root_sk, &entry.request().args),
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
    let sign_id = tx.sign_id();
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

    let req = Arc::new(IndexedSignRequest::sign_bidirectional(
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
    ));
    let (pk, output) = mock_signature_output(&req.args);
    backlog
        .insert_bidirectional(req)
        .await
        .advance(pk, &output, vec![], true)
        .await
        .unwrap();

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
    assert_matches!(
        entry.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Executing(_))
    );
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
    let sign_id = tx.sign_id();
    backlog.insert_mock_executing(&tx).await;

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
    assert!(ctx
        .backlog
        .get_by::<Bidirectional<Final<Generating>>>(tx.source_chain, &sign_id)
        .await
        .is_some());

    let tx_after = ctx.backlog.get(tx.source_chain, &sign_id).await.unwrap();
    assert_matches!(tx_after.request().kind, SignKind::RespondBidirectional(_));

    // A sign request should have been sent
    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => {
            if let mpc_primitives::SignKind::RespondBidirectional(res) = &req.request().kind {
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

    let tx = test_bidirectional_tx(4, Chain::Solana, Chain::Ethereum);
    let sign_id = tx.sign_id();
    backlog.insert_mock_executing(&tx).await;

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
            assert_eq!(req.chain(), Chain::Solana);
            assert_matches!(
                req.request().kind,
                mpc_primitives::SignKind::RespondBidirectional(_)
            );
        }
        other => panic!("expected cross-chain follow-up request, got {other:?}"),
    }
}

#[tokio::test]
async fn process_execution_confirmed_carries_canton_chain_ctx_to_final_request() {
    let backlog = Backlog::new();
    let mut tx = test_bidirectional_tx(24, Chain::Canton, Chain::Ethereum);
    tx.sender = [7u8; 32];
    let sign_id = tx.sign_id();
    let sign_event_contract_id = "#sign-event-cid";

    let request = test_canton_sign_bidirectional_request(sign_id, sign_event_contract_id);
    seed_executing_entry(&backlog, request, Arc::new(tx.clone())).await;

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
    assert_matches!(
        tx_after.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Final {
            progress: SignProgress::Generating,
            ..
        })
    );
    match &tx_after.request().kind {
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
            assert_eq!(req.sign_id(), sign_id);
            assert_eq!(req.chain(), tx.source_chain);
            match &req.request().kind {
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

    backlog
        .insert_mock_sign(solana_sign_id, Chain::Solana)
        .await;
    backlog
        .insert_mock_sign(ethereum_sign_id, Chain::Ethereum)
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
        SignCommand::Request(req) => assert_eq!(req.sign_id(), solana_sign_id),
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
        ctx.backlog.checkpoints().has_slot(chain),
        "catchup should not consume checkpoint slots; 33 intervals without caught_up \
         would fill the 32-slot cap and cause a permanent stall"
    );
}

#[tokio::test]
async fn live_block_votes_for_checkpoint() {
    let chain = Chain::Ethereum;
    let backlog = Backlog::new();
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let telemetry = NoopChainTelemetry;
    let (ctx, mut rpc_rx) = make_test_stream_context_with_rpc(
        backlog,
        sign_tx,
        true,
        ProjectivePoint::GENERATOR.to_affine(),
    );
    let interval = chain.checkpoint_interval().unwrap();

    process_block_event(chain, interval, &ctx, &telemetry)
        .await
        .unwrap();

    let action = timeout(Duration::from_secs(1), rpc_rx.recv())
        .await
        .expect("checkpoint vote should be queued")
        .expect("rpc channel should remain open");
    match action {
        crate::rpc::RpcAction::VoteCheckpoint { checkpoint, .. } => {
            assert_eq!(checkpoint.chain, chain);
            assert_eq!(checkpoint.height, interval);
        }
        _ => panic!("unexpected rpc action"),
    }

    assert!(timeout(Duration::from_millis(100), sign_rx.recv())
        .await
        .is_err());
}

/// The sweep fires each entry once, and the two legs share a sign id, so only
/// clearing the dispatch flag on re-entry keeps a fired leg 1 from suppressing
/// leg 2.
#[tokio::test]
async fn publish_failover_fires_once_per_leg() {
    let backlog = Backlog::new();
    let tx = mock_tx(21);
    let sign_id = tx.sign_id();

    let bidi = backlog
        .insert_mock_bidirectional(sign_id, Chain::Solana)
        .await;
    let (pk, output) = mock_signature_output(&bidi.request().args);
    let pub1 = bidi
        .advance(pk, &output, mock_participants(), false)
        .await
        .unwrap();

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let (ctx, mut rpc_rx) = make_test_stream_context_with_rpc(
        backlog.clone(),
        sign_tx,
        true,
        ProjectivePoint::GENERATOR.to_affine(),
    );
    // No observe lag: this test is about the once-per-leg property, not the gate.
    let ctx = ctx.with_observe_lag(Some(Duration::ZERO));

    publish_failover_due(&ctx, Chain::Solana).await;
    assert!(
        next_publish(&mut rpc_rx).await.is_some(),
        "leg 1 publishes once past its deadline"
    );

    publish_failover_due(&ctx, Chain::Solana).await;
    assert!(
        next_publish(&mut rpc_rx).await.is_none(),
        "the same entry does not fire twice"
    );

    // Advance through execution into final response publishing (leg 2)
    let exec = pub1.advance(Arc::new(tx)).await.unwrap();
    let fin_gen = exec
        .advance(ExecutionOutcome::Success { output: vec![] })
        .await
        .unwrap();
    let (pk2, output2) = mock_signature_output(&fin_gen.request().args);
    fin_gen
        .advance(pk2, &output2, mock_participants(), false)
        .await
        .unwrap();

    publish_failover_due(&ctx, Chain::Solana).await;
    assert!(
        next_publish(&mut rpc_rx).await.is_some(),
        "leg 2 fires on its own episode, not leg 1's history"
    );
}

/// The rpc channel is fed from a spawned task, so a publish is not visible the
/// instant the sweep returns.
async fn next_publish(rx: &mut mpsc::Receiver<RpcAction>) -> Option<RpcAction> {
    tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
        .await
        .ok()
        .flatten()
}

/// A restarting proposer republishes from the catchup resume, and its deadline is
/// long past by then. The resume records what it sent, so the next block does not
/// put a second copy of the same response on chain.
#[tokio::test]
async fn catchup_resume_suppresses_the_sweep_for_the_same_entry() {
    let backlog = Backlog::new();
    let sign_id = mpc_primitives::SignId::new([22u8; 32]);

    let sign = backlog.insert_mock_sign(sign_id, Chain::Solana).await;
    let (pk, output) = mock_signature_output(&sign.request().args);
    sign.advance(pk, &output, mock_participants(), true)
        .await
        .unwrap();

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let (ctx, mut rpc_rx) = make_test_stream_context_with_rpc(
        backlog.clone(),
        sign_tx,
        true,
        ProjectivePoint::GENERATOR.to_affine(),
    );
    let ctx = ctx.with_observe_lag(Some(Duration::ZERO));

    resume_pending_publish_requests(&ctx, Chain::Solana).await;
    assert!(
        next_publish(&mut rpc_rx).await.is_some(),
        "the proposer republishes on catchup"
    );

    publish_failover_due(&ctx, Chain::Solana).await;
    assert!(
        next_publish(&mut rpc_rx).await.is_none(),
        "the sweep must not republish what the resume already dispatched"
    );
}

/// Put an entry in pending-publish with a deadline in the past, whatever the draw.
async fn insert_publishable(backlog: &Backlog, seed: u8) {
    let sign_id = mpc_primitives::SignId::new([seed; 32]);
    let sign = backlog.insert_mock_sign(sign_id, Chain::Solana).await;
    let (pk, output) = mock_signature_output(&sign.request().args);
    sign.advance(pk, &output, mock_participants(), false)
        .await
        .unwrap();
}

/// The deadline being past is not enough: a node that has not caught up is not
/// reading its chain, so it holds fire rather than guessing.
#[tokio::test]
async fn publish_failover_needs_catchup() {
    let backlog = Backlog::new();
    insert_publishable(&backlog, 23).await;

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let (mut ctx, mut rpc_rx) = make_test_stream_context_with_rpc(
        backlog.clone(),
        sign_tx,
        false,
        ProjectivePoint::GENERATOR.to_affine(),
    );
    ctx.observe_lag = Some(Duration::ZERO);

    publish_failover_due(&ctx, Chain::Solana).await;
    assert!(
        next_publish(&mut rpc_rx).await.is_none(),
        "a node that has not caught up does not fail over"
    );

    ctx.caught_up = true;
    publish_failover_due(&ctx, Chain::Solana).await;
    assert!(
        next_publish(&mut rpc_rx).await.is_some(),
        "the deadline was past all along; catchup is what held it back"
    );
}
