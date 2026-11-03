use super::*;
use crate::backlog::mock::{
    block_at, mock_bidi_request, mock_bidi_response_request, mock_participants, mock_root_pk,
    mock_sign_request, mock_signature_output, mock_tx, BacklogTestExt,
};
use crate::backlog::{Backlog, Bidirectional, Final, Generating};
use crate::mesh::connection::NodeStatus;
use crate::mesh::{wait_threshold_active, MeshState};
use crate::protocol::contract::primitives::ParticipantInfo;
use crate::rpc::{ContractStateWatcher, RpcAction};
use crate::sign_bidirectional::derive_user_address;
use crate::sign_bidirectional::{BidirectionalProgress, SignProgress, SignStatus};
use crate::sign_bidirectional::{SDK_ALGO, SDK_DEST, SDK_PARAMS};
use crate::storage::checkpoint_storage::CheckpointStorage;
use crate::stream::ops::process_execution_confirmed;
use crate::stream::test_utils::{
    make_test_stream_context, make_test_stream_context_with_generator_pk,
    make_test_stream_context_with_rpc, test_bidirectional_tx,
    test_canton_sign_bidirectional_request, test_sign_args,
};
use crate::types::SignCommand;
use alloy::primitives::B256;
use cait_sith::protocol::Participant;
use k256::{ProjectivePoint, Scalar};
use mpc_chain_canton::CantonChainCtx;
use mpc_chain_integration_core::{NoopChainTelemetry, StateManager};
use mpc_primitives::{
    AttestedBlock, BidirectionalTx, BidirectionalTxId, IndexedSignRequest, SignArgs,
    SignBidirectionalEvent, SignKind, Signature,
};
use mpc_tron_wire::{
    pb::{Message as _, RawTransaction, TriggerSmartContract},
    TronAddress,
};
use mpc_utils::time::current_unix_timestamp;
use near_primitives::types::AccountId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

/// Returns a test root public key derived from a fixed secret key.
fn test_root_pk() -> mpc_primitives::PublicKey {
    k256::SecretKey::from_slice(&[1; 32])
        .unwrap()
        .public_key()
        .into()
}

/// TRON_RAW_HEX with `owner_address` set to the event's derived key.
fn owned_tron_bytes(root_pk: mpc_primitives::PublicKey, event: &SignBidirectionalEvent) -> Vec<u8> {
    let owner = TronAddress::from_evm(derive_user_address(
        root_pk,
        event.epsilon().expect("a valid event derives its epsilon"),
    ));
    let mut raw = RawTransaction::parse(&hex::decode(TRON_RAW_HEX).unwrap()).unwrap();
    let any = raw.contract[0].parameter.as_mut().unwrap();
    let mut trigger = TriggerSmartContract::decode(any.value.as_slice()).unwrap();
    trigger.owner_address = owner.as_bytes().to_vec();
    any.value = trigger.encode_to_vec();
    raw.encode_to_vec()
}

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
    wait_threshold_active(&mut mesh_rx, threshold)
        .await
        .unwrap();
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    backlog
        .recover_by_checkpoint(&checkpoint, mock_root_pk())
        .await
        .unwrap();

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

#[tokio::test]
async fn recovered_midnight_requests_require_current_attestation_semantics_before_signing() {
    let backlog = Backlog::new();
    let initial = mock_bidi_request(SignId::new([41; 32]), Chain::Midnight);
    let legacy_final = mock_bidi_response_request(
        SignId::new([42; 32]),
        BidirectionalTxId([42; 32]),
        Chain::Midnight,
    );
    let mut current_final = mock_bidi_response_request(
        SignId::new([43; 32]),
        BidirectionalTxId([43; 32]),
        Chain::Midnight,
    );
    let metadata = mpc_primitives::AttestationMetadata {
        key_version: 1,
        block_height: 456,
        outcome_kind: mpc_primitives::AttestationOutcomeKind::Executed,
    };
    let current = Arc::make_mut(&mut current_final);
    let SignKind::RespondBidirectional(response) = &mut current.kind else {
        unreachable!()
    };
    response.attestation = Some(metadata);
    current.args.payload = <Scalar as mpc_primitives::ScalarExt>::from_bytes(
        mpc_compact_hashing::compute_attestation_hash(
            &current.id.request_id,
            &metadata,
            &response.output,
        )
        .unwrap(),
    )
    .unwrap();
    let mut mixed_final = current_final.as_ref().clone();
    mixed_final.id = SignId::new([44; 32]);
    // Changing rid without changing the payload models a mixed persisted representation.
    let mixed_final = Arc::new(mixed_final);
    for request in [&initial, &legacy_final, &current_final, &mixed_final] {
        backlog.insert(Arc::clone(request)).await;
    }
    let checkpoint = backlog.checkpoint(Chain::Midnight).await.unwrap();
    let mut encoded = Vec::new();
    ciborium::into_writer(&checkpoint, &mut encoded).unwrap();
    let before = ciborium::from_reader(encoded.as_slice()).unwrap();
    let recovered = Backlog::new();
    recovered
        .recover_by_checkpoint(&before, mock_root_pk())
        .await
        .unwrap();
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(recovered, sign_tx, false);
    requeue_pending_sign_requests(&ctx, Chain::Midnight)
        .await
        .unwrap();
    assert_eq!(
        before.digest(),
        ctx.backlog
            .checkpoint(Chain::Midnight)
            .await
            .unwrap()
            .digest()
    );
    let mut queued_ids = Vec::new();
    for _ in 0..2 {
        let SignCommand::Request(queued) = sign_rx.try_recv().expect("valid request is queued")
        else {
            panic!("expected signing command")
        };
        queued_ids.push(queued.sign_id());
    }
    assert!(queued_ids.contains(&initial.id));
    assert!(queued_ids.contains(&current_final.id));
    assert!(
        sign_rx.try_recv().is_err(),
        "inconsistent response reached signer"
    );
    for id in [legacy_final.id, mixed_final.id] {
        let entry = ctx.backlog.get(Chain::Midnight, &id).await.unwrap();
        assert!(entry.state().is_pending_generation());
        assert!(!entry.state().is_pending_execution());
        assert!(entry.state().publishing().is_none());
    }
    assert!(ctx
        .backlog
        .get(Chain::Midnight, &current_final.id)
        .await
        .is_some());
}

/// A Solana request whose transaction bytes do not decode.
fn undecodable_bidi_request(sign_id: SignId) -> Arc<IndexedSignRequest> {
    let mut request = (*mock_bidi_request(sign_id, Chain::Solana)).clone();
    if let SignKind::SignBidirectional(event) = &mut request.kind {
        event.serialized_transaction = vec![1, 2, 3];
    }
    Arc::new(request)
}

async fn seed_executing_entry(
    backlog: &Backlog,
    request: Arc<IndexedSignRequest>,
    tx: Arc<BidirectionalTx>,
) {
    let (chain, id) = (request.chain, request.id);
    backlog.insert_bidirectional(request).await;
    backlog
        .get_by::<Bidirectional<Initial<AnyProgress>>>(chain, &id)
        .await
        .expect("inserted")
        .advance(tx)
        .await
        .expect("advance to executing");
}

/// A confirmation whose outcome cannot be recorded leaves the transaction watched, so the
/// next confirmation answers it.
#[tokio::test]
async fn an_outcome_that_cannot_be_recorded_keeps_the_watch() {
    let backlog = Backlog::persisted(CheckpointStorage::failing());
    let tx = test_bidirectional_tx(1, Chain::Solana, Chain::Ethereum);
    backlog.insert_mock_executing(&tx).await;
    let (sign_tx, _sign_rx) = mpsc::channel(8);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    let answered = process_execution_confirmed(
        tx.id,
        block_at(123),
        ExecutionOutcome::Failed,
        &ctx,
        Chain::Ethereum,
        test_root_pk(),
    )
    .await;

    assert!(answered.is_err());
    let watched = ctx.backlog.get_execution_watchers(Chain::Ethereum).await;
    assert!(watched.contains_key(&tx.id));
    let entry = ctx.backlog.get(Chain::Solana, &tx.sign_id()).await.unwrap();
    assert_matches!(
        entry.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Executing)
    );
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
        block_at(123u64),
        ExecutionOutcome::Success { output: vec![] },
        &ctx,
        tx.target_chain,
        test_root_pk(),
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
                assert_eq!(res.origin_indexed_at, Some(0));
            } else {
                panic!("Expected RespondBidirectional request");
            }
        }
        _ => panic!("Expected SignCommand::Request"),
    }
}

/// Request `id` from the test account at `path` on `source_chain`: an unsigned legacy
/// Ethereum transfer at `nonce`, whose `value` sets its bytes apart.
fn nonce_request(
    id: u8,
    source_chain: Chain,
    path: &str,
    nonce: u64,
    value: u64,
) -> Arc<IndexedSignRequest> {
    let mut rlp = rlp::RlpStream::new_list(9);
    rlp.append(&nonce);
    rlp.append(&0u64); // gasPrice
    rlp.append(&0u64); // gasLimit
    rlp.append(&vec![0x11u8; 20]); // to
    rlp.append(&value);
    rlp.append(&Vec::<u8>::new()); // data
    rlp.append(&1u64); // chain id
    rlp.append(&0u64);
    rlp.append(&0u64);
    let event = SignBidirectionalEvent {
        serialized_transaction: rlp.out().to_vec(),
        path: path.to_string(),
        chain: source_chain,
        ..bidirectional_event(Vec::new())
    };
    Arc::new(IndexedSignRequest::sign_bidirectional(
        SignId::from_u8(id),
        test_sign_args(id),
        source_chain,
        0,
        event,
    ))
}

/// `request`'s transaction under some signature, which gives it a tx id other than the
/// request id; the path stands in for the account.
fn signed_tx(request: &IndexedSignRequest, nonce: u64) -> Arc<BidirectionalTx> {
    let SignKind::SignBidirectional(event) = &request.kind else {
        panic!("expected a first leg");
    };
    Arc::new(BidirectionalTx {
        id: BidirectionalTxId([request.id.request_id[0].wrapping_add(100); 32]),
        sender: event.sender,
        serialized_transaction: event.serialized_transaction.clone(),
        source_chain: event.chain,
        target_chain: Chain::Ethereum,
        caip2_id: event.caip2_id.clone(),
        key_version: event.key_version,
        deposit: event.deposit,
        path: event.path.clone(),
        algo: event.algo.clone(),
        dest: event.dest.clone(),
        params: event.params.clone(),
        output_deserialization_schema: event.output_deserialization_schema.clone(),
        respond_serialization_schema: event.respond_serialization_schema.clone(),
        request_id: request.id.request_id,
        from_address: [event.path.as_bytes()[0]; 20],
        nonce,
    })
}

/// The sign ids of the requests `sign_rx` holds.
fn queued_requests(sign_rx: &mut mpsc::Receiver<SignCommand>) -> Vec<SignId> {
    let mut queued = Vec::new();
    while let Ok(command) = sign_rx.try_recv() {
        if let SignCommand::Request(entry) = command {
            queued.push(entry.sign_id());
        }
    }
    queued
}

/// An executed transaction answers its signed and unsigned siblings at its height, Unviable on
/// Midnight and Failed elsewhere, each named by its own transaction or else its request id.
#[tokio::test]
async fn execution_answers_the_nonce_siblings_of_its_transaction() {
    for source_chain in [Chain::Midnight, Chain::Solana] {
        let backlog = Backlog::new();
        backlog.mark_caught_up(source_chain);
        let taker = nonce_request(1, source_chain, "p", 7, 1);
        let taker_tx = signed_tx(&taker, 7);
        seed_executing_entry(&backlog, taker, Arc::clone(&taker_tx)).await;
        let sibling = nonce_request(2, source_chain, "p", 7, 2);
        let sibling_tx = signed_tx(&sibling, 7);
        seed_executing_entry(&backlog, Arc::clone(&sibling), Arc::clone(&sibling_tx)).await;
        let unsigned = nonce_request(3, source_chain, "p", 7, 3);
        backlog.insert_bidirectional(Arc::clone(&unsigned)).await;
        let untouched = [
            nonce_request(4, source_chain, "p", 7, 1), // the taker's bytes (M3)
            nonce_request(5, source_chain, "p", 8, 2),
            nonce_request(6, source_chain, "q", 7, 2),
        ];
        let mut still_watched = Vec::new();
        for (request, nonce) in untouched.iter().zip([7, 8, 7]) {
            let tx = signed_tx(request, nonce);
            still_watched.push(tx.id);
            seed_executing_entry(&backlog, Arc::clone(request), tx).await;
        }
        // Already answered: its own outcome stands.
        let parked = nonce_request(7, source_chain, "p", 7, 4);
        let parked_tx = signed_tx(&parked, 7);
        seed_executing_entry(&backlog, Arc::clone(&parked), Arc::clone(&parked_tx)).await;
        backlog
            .unwatch_execution(Chain::Ethereum, &parked_tx.id)
            .await
            .unwrap()
            .park()
            .await
            .unwrap();

        let (sign_tx, mut sign_rx) = mpsc::channel(8);
        let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
        process_execution_confirmed(
            taker_tx.id,
            block_at(123),
            ExecutionOutcome::Failed,
            &ctx,
            Chain::Ethereum,
            test_root_pk(),
        )
        .await
        .unwrap();

        let expected = if source_chain == Chain::Midnight {
            mpc_primitives::AttestationOutcomeKind::Unviable
        } else {
            mpc_primitives::AttestationOutcomeKind::Failed
        };
        for (request, named) in [
            (&sibling, sibling_tx.id),
            (&unsigned, BidirectionalTxId(unsigned.id.request_id)),
        ] {
            let entry = ctx.backlog.get(source_chain, &request.id).await.unwrap();
            let SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request,
                progress: SignProgress::Generating,
            }) = entry.status()
            else {
                panic!("{source_chain}: sibling not answered: {:?}", entry.status());
            };
            let SignKind::RespondBidirectional(response) = &respond_request.kind else {
                panic!("{source_chain}: expected a response");
            };
            assert_eq!(response.outcome_kind, Some(expected), "{source_chain}");
            assert_eq!(response.tx_id, named, "{source_chain}");
            assert_eq!(
                respond_request.args.entropy,
                crate::respond_bidirectional::response_entropy(&[7; 32], &request.id.request_id),
                "derived from the taker's block hash"
            );
            if let Some(attestation) = response.attestation {
                assert_eq!(attestation.block_height, 123, "{source_chain}");
            }
        }
        for request in &untouched {
            let entry = ctx.backlog.get(source_chain, &request.id).await.unwrap();
            assert_matches!(
                entry.status(),
                SignStatus::Bidirectional(BidirectionalProgress::Executing)
            );
        }
        let entry = ctx.backlog.get(source_chain, &parked.id).await.unwrap();
        assert_matches!(
            entry.status(),
            SignStatus::Bidirectional(BidirectionalProgress::Parked)
        );
        let mut watched = ctx
            .backlog
            .get_execution_watchers(Chain::Ethereum)
            .await
            .into_keys()
            .collect::<Vec<_>>();
        watched.sort_by_key(|id| id.0);
        assert_eq!(watched, still_watched, "{source_chain}");
        let mut queued = queued_requests(&mut sign_rx);
        queued.sort_by_key(|id| id.request_id);
        assert_eq!(
            queued,
            vec![SignId::from_u8(1), sibling.id, unsigned.id],
            "{source_chain}"
        );
    }
}

/// A sibling whose answer cannot be recorded holds the taker's answer, so that the next report
/// of the execution retries it.
#[tokio::test]
async fn a_sibling_whose_answer_cannot_be_recorded_holds_the_taker() {
    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let taker = nonce_request(1, Chain::Solana, "p", 7, 1);
    let taker_tx = signed_tx(&taker, 7);
    seed_executing_entry(&backlog, Arc::clone(&taker), Arc::clone(&taker_tx)).await;
    let sibling = nonce_request(2, Chain::Solana, "p", 7, 2);
    backlog.insert_bidirectional(Arc::clone(&sibling)).await;
    let (sign_tx, _sign_rx) = mpsc::channel(8);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
    let answered = |id| {
        let backlog = &ctx.backlog;
        async move {
            matches!(
                backlog.get(Chain::Solana, &id).await.unwrap().status(),
                SignStatus::Bidirectional(BidirectionalProgress::Final { .. })
            )
        }
    };
    let report = || {
        process_execution_confirmed(
            taker_tx.id,
            block_at(123),
            ExecutionOutcome::Failed,
            &ctx,
            Chain::Ethereum,
            test_root_pk(),
        )
    };

    storage.fail_next_put_local(1);
    assert!(report().await.is_err());
    assert!(!answered(taker.id).await);
    assert!(!answered(sibling.id).await);
    let watched: Vec<_> = ctx
        .backlog
        .get_execution_watchers(Chain::Ethereum)
        .await
        .into_keys()
        .collect();
    assert_eq!(watched, vec![taker_tx.id]);

    report().await.unwrap();
    assert!(answered(taker.id).await);
    assert!(answered(sibling.id).await);
}

/// A sibling answered by its own Response meanwhile needs no retry, so it holds nothing back;
/// a Signature event that lands during the answer leaves no watch behind.
#[tokio::test]
async fn a_sibling_answer_that_races_the_source_chain() {
    let backlog = Backlog::new();
    let taker = nonce_request(1, Chain::Solana, "p", 7, 1);
    let SignKind::SignBidirectional(taker_event) = &taker.kind else {
        unreachable!()
    };
    let gone = nonce_request(2, Chain::Solana, "p", 7, 2);
    backlog.insert_bidirectional(Arc::clone(&gone)).await;
    let signed = nonce_request(3, Chain::Solana, "p", 7, 3);
    backlog.insert_bidirectional(Arc::clone(&signed)).await;
    let (sign_tx, _sign_rx) = mpsc::channel(8);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    let taken = ctx
        .backlog
        .take_nonce_siblings(Chain::Solana, taker_event, test_root_pk())
        .await;
    assert_eq!(taken.len(), 2);
    ctx.backlog.remove(Chain::Solana, &gone.id).await;
    ctx.backlog.add_published_tx(signed_tx(&signed, 9)).await;

    for sibling in taken {
        let id = sibling.execution_tx().id;
        let sign_id = sibling.sign_id();
        let answered =
            answer_execution(sibling, id, block_at(123), ExecutionOutcome::Failed, &ctx).await;
        if sign_id == gone.id {
            assert!(left_the_backlog(&answered.unwrap_err()));
        } else {
            answered.unwrap();
        }
    }
    assert!(ctx
        .backlog
        .get_execution_watchers(Chain::Ethereum)
        .await
        .is_empty());
}

/// A Response's sibling whose answer cannot be recorded is answered when the block hash is
/// reported next.
#[tokio::test]
async fn a_marked_sibling_whose_answer_cannot_be_recorded_is_retried() {
    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let taker = nonce_request(1, Chain::Solana, "p", 7, 1);
    let SignKind::SignBidirectional(taker_event) = &taker.kind else {
        unreachable!()
    };
    let sibling = nonce_request(2, Chain::Solana, "p", 7, 2);
    backlog.insert_bidirectional(Arc::clone(&sibling)).await;
    let slot = NonceSlot::of_request(taker_event).unwrap().unwrap();
    backlog.mark_unviable(Chain::Solana, &slot, 500).await;
    let (sign_tx, _sign_rx) = mpsc::channel(8);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
    let block = block_at(500);

    storage.fail_next_put_local(1);
    process_block_hash(Chain::Ethereum, block, &ctx, test_root_pk()).await;
    assert_eq!(
        ctx.backlog.get_block_hash_lookups(Chain::Ethereum).await,
        vec![500]
    );

    process_block_hash(Chain::Ethereum, block, &ctx, test_root_pk()).await;
    assert!(ctx
        .backlog
        .get_block_hash_lookups(Chain::Ethereum)
        .await
        .is_empty());
}

/// The requests the sign queue holds, in arrival order.
fn queued_entries(sign_rx: &mut mpsc::Receiver<SignCommand>) -> Vec<SignEntry<Generating>> {
    let mut queued = Vec::new();
    while let Ok(command) = sign_rx.try_recv() {
        if let SignCommand::Request(entry) = command {
            queued.push(entry);
        }
    }
    queued
}

fn sorted(mut ids: Vec<BidirectionalTxId>) -> Vec<BidirectionalTxId> {
    ids.sort_by_key(|id| id.0);
    ids
}

/// An execution under a second published signature is found, also by a node that lists the
/// entry from a checkpoint, and the response names that transaction.
#[tokio::test]
async fn an_execution_under_a_later_signature_is_answered_and_named() {
    let backlog = Backlog::new();
    backlog.mark_caught_up(Chain::Solana);
    let request = nonce_request(1, Chain::Solana, "p", 7, 1);
    let first = signed_tx(&request, 7);
    seed_executing_entry(&backlog, Arc::clone(&request), Arc::clone(&first)).await;
    let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
    let signature = mpc_crypto::generate_signature(&root_sk, &request.args);
    let SignKind::SignBidirectional(event) = &request.kind else {
        unreachable!()
    };
    let second = event
        .to_bidirectional_tx(request.id.request_id, signature, test_root_pk())
        .unwrap();

    let (sign_tx, mut sign_rx) = mpsc::channel(8);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
    let published = SignatureRespondedEvent {
        request_id: request.id.request_id,
        signature,
        chain: Chain::Solana,
    };
    process_respond_event(published, &ctx, test_root_pk())
        .await
        .unwrap();

    let both = sorted(vec![first.id, second.id]);
    let watched = ctx.backlog.get_execution_watchers(Chain::Ethereum).await;
    assert_eq!(sorted(watched.into_keys().collect()), both);
    let checkpoint = ctx.backlog.checkpoint(Chain::Solana).await.unwrap();
    let listing = Backlog::new();
    listing
        .recover_by_checkpoint(&checkpoint, test_root_pk())
        .await
        .unwrap();
    let relisted = listing.get_execution_watchers(Chain::Ethereum).await;
    assert_eq!(sorted(relisted.into_keys().collect()), both);

    process_execution_confirmed(
        second.id,
        block_at(123),
        ExecutionOutcome::Failed,
        &ctx,
        Chain::Ethereum,
        test_root_pk(),
    )
    .await
    .unwrap();
    let queued = queued_entries(&mut sign_rx);
    let [answered] = queued.as_slice() else {
        panic!("expected one response, got {queued:?}");
    };
    let SignKind::RespondBidirectional(response) = &answered.request().kind else {
        panic!("expected a response");
    };
    assert_eq!(response.tx_id, second.id);
    assert!(ctx
        .backlog
        .get_execution_watchers(Chain::Ethereum)
        .await
        .is_empty());
}

/// A node restarted after storing its signature publishes that one instead of signing again.
#[tokio::test]
async fn a_restarted_node_does_not_sign_again() {
    let storage = crate::storage::checkpoint_storage::CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let request = nonce_request(1, Chain::Solana, "p", 7, 1);
    let (pk, output) = mock_signature_output(&request.args);
    backlog
        .insert_bidirectional(Arc::clone(&request))
        .await
        .advance(pk, &output, vec![], true)
        .await
        .unwrap();
    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

    let restarted = Backlog::persisted(storage);
    restarted
        .recover_by_checkpoint(&checkpoint, pk)
        .await
        .unwrap();
    assert!(restarted
        .requeueable_requests(Chain::Solana)
        .await
        .is_empty());
    assert_eq!(restarted.publishable_requests(Chain::Solana).await.len(), 1);
}

/// A signature issued after the restart's checkpoint survives into replay, so the node does not
/// sign again; an older record whose request is gone was answered and is dropped.
#[tokio::test]
async fn a_signature_issued_after_the_checkpoint_survives_a_restart() {
    let storage = crate::storage::checkpoint_storage::CheckpointStorage::in_memory();
    let answered = SignId::from_u8(1);
    let stale = crate::backlog::LocalRecord {
        status: SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Generating)),
        at: 5,
    };
    storage
        .put_local(Chain::Solana, answered, &stale)
        .await
        .unwrap();
    let backlog = Backlog::persisted(storage.clone());
    backlog
        .set_processed_block_interval(Chain::Solana, 10, 0)
        .await;
    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();
    let request = nonce_request(2, Chain::Solana, "p", 7, 1);
    let (pk, output) = mock_signature_output(&request.args);
    backlog
        .insert_bidirectional(Arc::clone(&request))
        .await
        .advance(pk, &output, vec![], true)
        .await
        .unwrap();

    let restarted = Backlog::persisted(storage.clone());
    restarted
        .recover_by_checkpoint(&checkpoint, pk)
        .await
        .unwrap();
    let (_, to_sign) = restarted.insert(Arc::clone(&request)).await;
    assert!(!to_sign, "the replayed request keeps its signature");
    assert!(restarted
        .requeueable_requests(Chain::Solana)
        .await
        .is_empty());
    assert_eq!(restarted.publishable_requests(Chain::Solana).await.len(), 1);
    let records = storage.load_local(Chain::Solana).await.unwrap();
    assert!(!records.contains_key(&answered));
}

/// While the stream catches up, the processed height stays at the checkpoint, so a record is
/// stamped with the block being replayed; a rebase onto a later checkpoint then keeps it.
#[tokio::test]
async fn a_record_written_during_catch_up_carries_the_replayed_height() {
    let storage = crate::storage::checkpoint_storage::CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    backlog
        .set_processed_block_interval(Chain::Solana, 100, 0)
        .await;
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, false);
    process_block_event(Chain::Solana, 700, &ctx, &NoopChainTelemetry)
        .await
        .unwrap();
    let request = nonce_request(2, Chain::Solana, "p", 7, 1);
    let (pk, output) = mock_signature_output(&request.args);
    ctx.backlog
        .insert_bidirectional(Arc::clone(&request))
        .await
        .advance(pk, &output, vec![], true)
        .await
        .unwrap();
    let records = storage.load_local(Chain::Solana).await.unwrap();
    assert_eq!(records[&request.id].at, 700);

    let peer = Backlog::new();
    peer.set_processed_block_interval(Chain::Solana, 600, 0)
        .await;
    let checkpoint = peer.checkpoint(Chain::Solana).await.unwrap();
    let restarted = Backlog::persisted(storage);
    restarted
        .recover_by_checkpoint(&checkpoint, pk)
        .await
        .unwrap();
    let (_, to_sign) = restarted.insert(Arc::clone(&request)).await;
    assert!(!to_sign, "the replayed request keeps its signature");
}

/// `request`'s published response, signed under its response key by `root_sk`.
fn signed_response(
    request: &IndexedSignRequest,
    root_sk: &k256::SecretKey,
    attestation: Option<mpc_primitives::PublishedAttestation>,
    output: Option<Vec<u8>>,
) -> RespondBidirectionalEvent {
    let SignKind::SignBidirectional(event) = &request.kind else {
        unreachable!()
    };
    let mut response = RespondBidirectionalEvent {
        request_id: request.id.request_id,
        signature: mpc_crypto::generate_signature(root_sk, &request.args),
        chain: request.chain,
        attestation,
        output,
    };
    let (epsilon, payload) = crate::respond_bidirectional::published_signing_args(
        event,
        &request.id.request_id,
        &response,
    )
    .unwrap();
    let args = SignArgs {
        epsilon,
        payload,
        ..request.args.clone()
    };
    response.signature = mpc_crypto::generate_signature(root_sk, &args);
    response
}

/// A node that never signed a request removes it on reading its Response.
#[tokio::test]
async fn a_response_removes_an_entry_without_a_signature() {
    let backlog = Backlog::new();
    let request = nonce_request(1, Chain::Solana, "p", 7, 1);
    backlog.insert_bidirectional(Arc::clone(&request)).await;
    let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
    let response = signed_response(&request, &root_sk, None, Some(vec![1; 32]));

    let (sign_tx, mut sign_rx) = mpsc::channel(8);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
    process_respond_bidirectional_event(response, &ctx, test_root_pk())
        .await
        .unwrap();
    assert!(ctx.backlog.get(Chain::Solana, &request.id).await.is_none());
    assert_matches!(sign_rx.try_recv(), Ok(SignCommand::Completion(id)) if id == request.id);
}

/// A Response saying Executed marks its siblings, signed or not, with the height (#1430);
/// checkpoints carry it, and with that block's hash each is answered Unviable.
#[tokio::test]
async fn a_response_answers_the_requests_it_left_unexecutable() {
    let backlog = Backlog::new();
    backlog.mark_caught_up(Chain::Midnight);
    let taker = nonce_request(1, Chain::Midnight, "p", 7, 1);
    backlog.insert_bidirectional(Arc::clone(&taker)).await;
    let unsigned = nonce_request(2, Chain::Midnight, "p", 7, 2);
    backlog.insert_bidirectional(Arc::clone(&unsigned)).await;
    let signed = nonce_request(3, Chain::Midnight, "p", 7, 3);
    let signed_sibling = signed_tx(&signed, 7);
    seed_executing_entry(&backlog, Arc::clone(&signed), Arc::clone(&signed_sibling)).await;
    let other_nonce = nonce_request(4, Chain::Midnight, "p", 8, 2);
    backlog.insert_bidirectional(Arc::clone(&other_nonce)).await;

    let output_hash = mpc_compact_hashing::compute_attested_output_hash(&[]);
    let metadata = mpc_primitives::AttestationMetadata {
        key_version: 0,
        block_height: 500,
        outcome_kind: AttestationOutcomeKind::Executed,
    };
    let attestation = mpc_primitives::PublishedAttestation {
        block_height: 500,
        outcome_kind: AttestationOutcomeKind::Executed,
        serialized_output_length: 0,
        output_hash,
        digest: mpc_compact_hashing::compute_attestation_digest(
            &taker.id.request_id,
            &metadata,
            0,
            &output_hash,
        ),
    };
    let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
    let response = signed_response(&taker, &root_sk, Some(attestation), None);

    let (sign_tx, mut sign_rx) = mpsc::channel(8);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
    process_respond_bidirectional_event(response, &ctx, test_root_pk())
        .await
        .unwrap();
    assert!(ctx.backlog.get(Chain::Midnight, &taker.id).await.is_none());
    for (request, marked) in [(&unsigned, true), (&signed, true), (&other_nonce, false)] {
        let entry = ctx
            .backlog
            .entry(Chain::Midnight, &request.id)
            .await
            .unwrap();
        assert_eq!(entry.unviable_at, marked.then_some(500), "{:?}", request.id);
    }
    assert_eq!(
        ctx.backlog.get_block_hash_lookups(Chain::Ethereum).await,
        vec![500]
    );
    let checkpoint = ctx.backlog.checkpoint(Chain::Midnight).await.unwrap();
    let listing = Backlog::new();
    listing
        .recover_by_checkpoint(&checkpoint, test_root_pk())
        .await
        .unwrap();
    assert_eq!(
        listing.get_block_hash_lookups(Chain::Ethereum).await,
        vec![500]
    );

    let _ = queued_entries(&mut sign_rx);
    process_block_hash(
        Chain::Ethereum,
        AttestedBlock {
            height: 500,
            hash: [9; 32],
        },
        &ctx,
        test_root_pk(),
    )
    .await;
    let queued = queued_entries(&mut sign_rx);
    assert_eq!(queued.len(), 2);
    for (request, named) in [
        (&unsigned, BidirectionalTxId(unsigned.id.request_id)),
        (&signed, signed_sibling.id),
    ] {
        let answered = queued
            .iter()
            .find(|entry| entry.sign_id() == request.id)
            .expect("answered");
        let SignKind::RespondBidirectional(response) = &answered.request().kind else {
            panic!("expected a response");
        };
        assert_eq!(
            response.outcome_kind,
            Some(AttestationOutcomeKind::Unviable)
        );
        assert_eq!(response.tx_id, named);
        assert_eq!(response.attestation.unwrap().block_height, 500);
        assert_eq!(
            answered.request().args.entropy,
            crate::respond_bidirectional::response_entropy(&[9; 32], &request.id.request_id)
        );
    }
    assert!(ctx
        .backlog
        .get_block_hash_lookups(Chain::Ethereum)
        .await
        .is_empty());
}

#[tokio::test]
async fn process_execution_confirmed_is_idempotent_after_first_processing() {
    let backlog = Backlog::new();
    let tx = test_bidirectional_tx(7, Chain::Solana, Chain::Ethereum);
    backlog.insert_mock_executing(&tx).await;

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);

    process_execution_confirmed(
        tx.id,
        block_at(123u64),
        ExecutionOutcome::Success { output: vec![] },
        &ctx,
        tx.target_chain,
        test_root_pk(),
    )
    .await
    .unwrap();

    process_execution_confirmed(
        tx.id,
        block_at(124u64),
        ExecutionOutcome::Success { output: vec![] },
        &ctx,
        tx.target_chain,
        test_root_pk(),
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
        block_at(444u64),
        ExecutionOutcome::Success { output: vec![] },
        &ctx,
        tx.target_chain,
        test_root_pk(),
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
    wait_threshold_active(&mut mesh_rx, threshold)
        .await
        .unwrap();
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let recovered = Backlog::persisted(storage.clone());

    let checkpoint = recovered
        .checkpoints()
        .storage()
        .load_latest(tx.source_chain)
        .await
        .unwrap()
        .unwrap();
    recovered
        .recover_by_checkpoint(&checkpoint, mock_root_pk())
        .await
        .unwrap();

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
    rlp_s.append(&vec![0x11u8; 20]);
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
                dest: SDK_DEST.to_string(),
                caip2_id: "not-a-chain".to_string(),
                key_version: 1,
                deposit: 0,
                path: "m/0".to_string(),
                algo: SDK_ALGO.to_string(),
                params: SDK_PARAMS.to_string(),
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
    let err = process_sign_request(request, &ctx, test_root_pk())
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
    let req = undecodable_bidi_request(sign_id);

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

/// A node that answered an entry as a sibling quarantines it on its first signature, like a
/// node that has not: otherwise their checkpoints differ from then on.
#[tokio::test]
async fn process_respond_event_quarantines_an_answered_entry_that_cannot_advance() {
    let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
    let taker = nonce_request(1, Chain::Solana, "p", 7, 1);
    let SignKind::SignBidirectional(taker_event) = &taker.kind else {
        unreachable!()
    };
    let mut poison = (*nonce_request(2, Chain::Solana, "p", 7, 2)).clone();
    let SignKind::SignBidirectional(event) = &mut poison.kind else {
        unreachable!()
    };
    event.respond_serialization_schema = b"not a schema".to_vec();
    assert!(event.validate().is_err());
    let poison = Arc::new(poison);

    let backlog = Backlog::new();
    backlog.insert_bidirectional(Arc::clone(&poison)).await;
    let (sign_tx, mut sign_rx) = mpsc::channel(8);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
    let mut taken = ctx
        .backlog
        .take_nonce_siblings(Chain::Solana, taker_event, test_root_pk())
        .await;
    let sibling = taken.pop().expect("a sibling");
    let id = sibling.execution_tx().id;
    answer_execution(sibling, id, block_at(123), ExecutionOutcome::Failed, &ctx)
        .await
        .unwrap();
    let _ = queued_entries(&mut sign_rx);

    let event = SignatureRespondedEvent {
        request_id: poison.id.request_id,
        signature: mpc_crypto::generate_signature(&root_sk, &poison.args),
        chain: Chain::Solana,
    };
    process_respond_event(event, &ctx, test_root_pk())
        .await
        .unwrap();

    assert!(ctx.backlog.get(Chain::Solana, &poison.id).await.is_none());
    assert!(matches!(
        sign_rx.try_recv(),
        Ok(SignCommand::Completion(id)) if id == poison.id
    ));
}

/// A Solana-sourced bidirectional event targeting Ethereum; `serialized_transaction`
/// is the part the admission tests vary.
fn bidirectional_event(serialized_transaction: Vec<u8>) -> SignBidirectionalEvent {
    SignBidirectionalEvent {
        sender: [0u8; 32],
        serialized_transaction,
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: 1,
        deposit: 0,
        path: String::new(),
        algo: SDK_ALGO.to_string(),
        dest: SDK_DEST.to_string(),
        params: SDK_PARAMS.to_string(),
        chain: Chain::Solana,
        chain_ctx: None,
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
    }
}

/// Off-spec fields only warn until the applications send the SDK fields.
#[tokio::test]
async fn process_sign_request_admits_off_spec_fields_for_now() {
    let backlog = Backlog::new();
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);
    let root_pk = test_root_pk();
    let unowned = SignBidirectionalEvent {
        dest: "ethereum".to_string(),
        ..tron_bidirectional_event(Vec::new())
    };
    let event = SignBidirectionalEvent {
        serialized_transaction: owned_tron_bytes(root_pk, &unowned),
        ..unowned
    };
    let sign_id = SignId::new([24u8; 32]);
    let request = Arc::new(IndexedSignRequest::sign_bidirectional(
        sign_id,
        test_sign_args(24),
        Chain::Solana,
        current_unix_timestamp(),
        event,
    ));

    process_sign_request(request, &ctx, root_pk)
        .await
        .expect("off-spec fields only warn for now");
    assert!(backlog.get(Chain::Solana, &sign_id).await.is_some());
}

/// Respond validates entries restored from a checkpoint too, and off-spec fields
/// only warn there as well: the entry advances instead of being quarantined.
#[tokio::test]
async fn process_respond_event_keeps_an_off_spec_bidirectional_entry() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([25u8; 32]);
    let args = test_sign_args(25);
    backlog
        .insert(Arc::new(IndexedSignRequest::sign_bidirectional(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
            SignBidirectionalEvent {
                dest: "ethereum".to_string(),
                ..bidirectional_event(legacy_contract_call(1))
            },
        )))
        .await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let event = SignatureRespondedEvent {
        request_id: sign_id.request_id,
        signature: mpc_crypto::generate_signature(&root_sk, &args),
        chain: Chain::Solana,
    };
    let public_key = root_sk.public_key().into();
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let (ctx, _cp, _mesh, _rpc_rx) =
        make_test_stream_context(backlog, sign_tx, true, public_key, 1);

    process_respond_event(event, &ctx, public_key)
        .await
        .expect("off-spec fields only warn for now");
    assert!(ctx.backlog.get(Chain::Solana, &sign_id).await.is_some());
}

/// Recorded mainnet USDT transfer (chain-tron fixture `usdt-transfer-1.json`),
/// the same bytes the `sign_bidirectional` tests pin.
const TRON_RAW_HEX: &str = "0a02db6f220815ff9c9c504ad4a8409a80f5a491345aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a154120eb85916a10d2c6542613e4c9517b5e99b2dee9121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2244a9059cbb000000000000000000000000d9e02baf48ed306afc63cfa816a2b6be8442036a0000000000000000000000000000000000000000000000000000000008f428f870bad8e2a49134900180e1eb17";

fn tron_bidirectional_event(serialized_transaction: Vec<u8>) -> SignBidirectionalEvent {
    SignBidirectionalEvent {
        caip2_id: Chain::Tron.caip2_chain_id().to_string(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: vec![],
        ..bidirectional_event(serialized_transaction)
    }
}

/// Tron's txID covers neither signature nor derived key, so identical raw
/// bytes from two distinct requests name one destination transaction: the
/// second must be rejected while the first is pending, or its watch
/// silently replaces the first's and neither request can resolve cleanly.
#[tokio::test]
async fn process_sign_request_rejects_a_duplicate_tron_destination_id() {
    let backlog = Backlog::new();
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);

    // Create a closure to generate test requests with a given seed; both
    // carry the request's derived key as owner.
    let root_pk = test_root_pk();
    let bytes = owned_tron_bytes(root_pk, &tron_bidirectional_event(Vec::new()));
    let request = |seed: u8| {
        Arc::new(IndexedSignRequest::sign_bidirectional(
            SignId::new([seed; 32]),
            test_sign_args(seed),
            Chain::Solana,
            current_unix_timestamp(),
            tron_bidirectional_event(bytes.clone()),
        ))
    };

    // Process the first request to ensure it is admitted and pending.
    process_sign_request(request(19), &ctx, root_pk)
        .await
        .expect("the first Tron request is admitted");

    assert!(backlog
        .get(Chain::Solana, &SignId::new([19; 32]))
        .await
        .is_some());

    // Process the second request, which should be rejected due to a duplicate Tron destination ID.
    let err = process_sign_request(request(20), &ctx, root_pk)
        .await
        .expect_err("identical bytes must be rejected while the first is pending");

    // Check that the error message indicates the request was rejected due to a duplicate Tron destination ID.
    assert!(
        format!("{err:#}").contains("already pending"),
        "unexpected error: {err:#}"
    );

    // Ensure that the second request is not present in the backlog.
    assert!(backlog
        .get(Chain::Solana, &SignId::new([20; 32]))
        .await
        .is_none());
}

/// A Tron request must name its own derived key as owner - copied or misbuilt
/// bytes are rejected before they can collide with another requester's
/// pending transaction.
#[tokio::test]
async fn process_sign_request_rejects_unowned_tron_bytes() {
    let backlog = Backlog::new();
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);
    let root_pk = test_root_pk();
    let request = |seed: u8, event| {
        Arc::new(IndexedSignRequest::sign_bidirectional(
            SignId::new([seed; 32]),
            test_sign_args(seed),
            Chain::Solana,
            current_unix_timestamp(),
            event,
        ))
    };

    let unowned = tron_bidirectional_event(hex::decode(TRON_RAW_HEX).unwrap());
    let err = process_sign_request(request(21, unowned.clone()), &ctx, root_pk)
        .await
        .expect_err("bytes naming a foreign owner must be rejected");
    assert!(format!("{err:#}").contains("owner_address"));
    assert!(backlog
        .get(Chain::Solana, &SignId::new([21; 32]))
        .await
        .is_none());

    let owned = tron_bidirectional_event(owned_tron_bytes(root_pk, &unowned));
    process_sign_request(request(22, owned), &ctx, root_pk)
        .await
        .expect("bytes naming the request's own derived key are admitted");
    assert!(backlog
        .get(Chain::Solana, &SignId::new([22; 32]))
        .await
        .is_some());
}

#[test]
fn owned_by_requester_binds_only_tron_targets() {
    let root_pk = test_root_pk();
    let unowned = tron_bidirectional_event(hex::decode(TRON_RAW_HEX).unwrap());
    assert!(
        !owned_by_requester(&unowned, root_pk),
        "recorded mainnet bytes name a foreign owner"
    );

    let owned = tron_bidirectional_event(owned_tron_bytes(root_pk, &unowned));
    assert!(owned_by_requester(&owned, root_pk));

    let ethereum = bidirectional_event(legacy_contract_call(1));
    assert!(
        owned_by_requester(&ethereum, root_pk),
        "ethereum recovers the sender from the signature"
    );
}

/// An unsigned legacy contract call on `chain_id`.
fn legacy_contract_call(chain_id: u64) -> Vec<u8> {
    legacy_contract_call_on(&chain_id)
}

/// An unsigned legacy contract call whose chain id field encodes `chain_id`.
fn legacy_contract_call_on<E: rlp::Encodable>(chain_id: &E) -> Vec<u8> {
    let mut rlp = rlp::RlpStream::new_list(9);
    rlp.append(&0u64); // nonce
    rlp.append(&0u64); // gasPrice
    rlp.append(&0u64); // gasLimit
    rlp.append(&vec![0x11u8; 20]); // to
    rlp.append(&0u64); // value
    rlp.append(&vec![0xa9u8, 0x05, 0x9c, 0xbb]); // data
    rlp.append(chain_id);
    rlp.append(&0u64);
    rlp.append(&0u64);
    rlp.out().to_vec()
}

/// Admitted, a request whose output schema extraction refuses is signed and
/// executed, and only then fails as `ExtractionFailed`.
#[tokio::test]
async fn process_sign_request_rejects_an_unprocessable_output_schema() {
    let backlog = Backlog::new();
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);
    let request = |seed: u8, output_schema: &[u8]| {
        Arc::new(IndexedSignRequest::sign_bidirectional(
            SignId::new([seed; 32]),
            test_sign_args(seed),
            Chain::Solana,
            current_unix_timestamp(),
            SignBidirectionalEvent {
                output_deserialization_schema: output_schema.to_vec(),
                ..bidirectional_event(legacy_contract_call(1))
            },
        ))
    };

    let refused = SignId::new([15u8; 32]);
    let err = process_sign_request(request(15, b"{"), &ctx, test_root_pk())
        .await
        .expect_err("a malformed output schema should be rejected at ingestion");
    assert!(format!("{err:#}").contains("unprocessable output schemas"));
    assert!(backlog.get(Chain::Solana, &refused).await.is_none());

    let admitted = SignId::new([16u8; 32]);
    process_sign_request(request(16, b"[]"), &ctx, test_root_pk())
        .await
        .expect("an empty output schema should be admitted");
    assert!(backlog.get(Chain::Solana, &admitted).await.is_some());
}

/// The big-endian chain id 2^64, which `validate` admits and no u64 holds.
const WIDE_CHAIN_ID: [u8; 9] = [1, 0, 0, 0, 0, 0, 0, 0, 0];

/// `eip155:1` names every Ethereum network, so the transaction's own chain id
/// decides where it executes: signed for another network, it never executes here.
#[tokio::test]
async fn process_sign_request_rejects_another_networks_chain_id() {
    let backlog = Backlog::new();
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let mut ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);
    let request = |seed: u8, chain_id: u64| {
        Arc::new(IndexedSignRequest::sign_bidirectional(
            SignId::new([seed; 32]),
            test_sign_args(seed),
            Chain::Solana,
            current_unix_timestamp(),
            bidirectional_event(legacy_contract_call(chain_id)),
        ))
    };

    ctx.ethereum_chain_id = None;
    process_sign_request(request(17, 11_155_111), &ctx, test_root_pk())
        .await
        .expect("without Ethereum configured the check is skipped");

    ctx.ethereum_chain_id = Some(1);
    let err = process_sign_request(request(18, 11_155_111), &ctx, test_root_pk())
        .await
        .expect_err("another network's chain id should be rejected at ingestion");
    assert!(format!("{err:#}").contains("this node executes on 1"));
    assert!(backlog
        .get(Chain::Solana, &SignId::new([18; 32]))
        .await
        .is_none());

    // 2^64: valid on Ethereum, but no network this node can watch.
    let wide = Arc::new(IndexedSignRequest::sign_bidirectional(
        SignId::new([20; 32]),
        test_sign_args(20),
        Chain::Solana,
        current_unix_timestamp(),
        bidirectional_event(legacy_contract_call_on(&WIDE_CHAIN_ID.to_vec())),
    ));
    let err = process_sign_request(wide, &ctx, test_root_pk())
        .await
        .expect_err("a chain id wider than u64 should be rejected at ingestion");
    assert!(format!("{err:#}").contains("chain id None"), "{err:#}");
    assert!(backlog
        .get(Chain::Solana, &SignId::new([20; 32]))
        .await
        .is_none());

    process_sign_request(request(19, 1), &ctx, test_root_pk())
        .await
        .expect("the configured network's chain id should be admitted");
    assert!(backlog
        .get(Chain::Solana, &SignId::new([19; 32]))
        .await
        .is_some());
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
    let request = undecodable_bidi_request(sign_id);

    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);
    let err = process_sign_request(request, &ctx, test_root_pk())
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
    let err = process_sign_request(request, &ctx, test_root_pk())
        .await
        .expect_err("empty serialized_transaction should be rejected at ingestion");
    assert!(format!("{err:#}").contains("empty serialized_transaction"));

    // The poison-pill request must not have entered the backlog.
    assert!(
        backlog.get(Chain::Solana, &sign_id).await.is_none(),
        "rejected request must not be stored in the backlog"
    );
}

/// Plain `sign` takes a free-text path and never reaches `validate`, so without
/// this check a contract asks for its own chain's attestation path with a payload
/// of keccak(request_id || output) and gets a valid attestation for any outcome.
#[tokio::test]
async fn process_sign_request_rejects_the_reserved_attestation_path() {
    let backlog = Backlog::new();
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, false);

    let mut reserved = mock_sign_request(SignId::new([31u8; 32]), Chain::Solana);
    Arc::make_mut(&mut reserved).args.path = "solana response key".to_string();
    let err = process_sign_request(reserved, &ctx, test_root_pk())
        .await
        .expect_err("a sign request on the attestation path must be rejected");
    assert!(err.to_string().contains("reserved attestation path"));
    assert_eq!(
        backlog.len(),
        0,
        "a rejected request must not reach the backlog"
    );

    // Only this request's own source chain's path is reserved. Another chain's
    // cannot derive this one's attestation key, so it stays admitted, which is
    // what distinguishes the check from one that matches all four strings.
    let foreign_id = SignId::new([32u8; 32]);
    let mut foreign = mock_sign_request(foreign_id, Chain::Solana);
    Arc::make_mut(&mut foreign).args.path = "canton response key".to_string();
    process_sign_request(foreign, &ctx, test_root_pk())
        .await
        .expect("another chain's attestation path must still be admitted");
    assert!(backlog.get(Chain::Solana, &foreign_id).await.is_some());
}

#[tokio::test]
async fn process_sign_request_duplicate_is_idempotent() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([9u8; 32]);
    let request = mock_sign_request(sign_id, Chain::Ethereum);

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, false);

    // First emission inserts a new entry.
    let was_new = process_sign_request(Arc::clone(&request), &ctx, test_root_pk())
        .await
        .expect("first sign request should be accepted");
    assert!(was_new, "first insert must report a new entry");
    assert_eq!(backlog.len(), 1);

    // Replay: the indexer re-emitted the same SignId
    // backlog.insert is keyed on SignId, so the replay is absorbed, not duplicated.
    let is_new = process_sign_request(request, &ctx, test_root_pk())
        .await
        .expect("replayed sign request should be accepted");
    assert!(!is_new, "replayed insert must report an existing entry");
    assert_eq!(
        backlog.len(),
        1,
        "replaying the same SignId must not grow the backlog"
    );

    // Same idempotence for a pending Tron request: its own bytes already sit
    // in the backlog, and the duplicate scan must skip them rather than
    // reject the replay as "already pending".
    let root_pk = test_root_pk();
    let bytes = owned_tron_bytes(root_pk, &tron_bidirectional_event(Vec::new()));
    let tron = |seed: u8| {
        Arc::new(IndexedSignRequest::sign_bidirectional(
            SignId::new([seed; 32]),
            test_sign_args(seed),
            Chain::Solana,
            current_unix_timestamp(),
            tron_bidirectional_event(bytes.clone()),
        ))
    };
    assert!(process_sign_request(Arc::clone(&tron(41)), &ctx, root_pk)
        .await
        .expect("first Tron request is admitted"));
    assert!(
        !process_sign_request(tron(41), &ctx, root_pk)
            .await
            .expect("replaying a pending Tron request is absorbed, not rejected"),
        "the replay must not report a new entry"
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
async fn process_sign_request_replay_keeps_an_advanced_entry() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([21u8; 32]);
    let request = mock_sign_request(sign_id, Chain::Ethereum);
    let (pk, output) = mock_signature_output(&request.args);

    // The entry is past Generating: it holds a signature and waits to publish.
    backlog
        .insert_sign(Arc::clone(&request))
        .await
        .advance(pk, &output, mock_participants(), true)
        .await
        .expect("advance to pending publish");

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);

    // The same request id is emitted again while the first is in flight.
    let is_new = process_sign_request(request, &ctx, test_root_pk())
        .await
        .expect("a replayed sign request is accepted");

    assert!(!is_new, "the replay must not report a new entry");
    assert_eq!(backlog.len(), 1, "the entry must still be there");
    assert!(
        backlog
            .requeueable_requests(Chain::Ethereum)
            .await
            .is_empty(),
        "the replay must not reset the entry to pending generation"
    );
    assert!(
        timeout(Duration::from_millis(100), sign_rx.recv())
            .await
            .is_err(),
        "the replay must not enqueue a second signing task"
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
    let request = backlog
        .entry(Chain::Solana, &sign_id)
        .await
        .unwrap()
        .request;
    let SignKind::RespondBidirectional(own) = &entry.request().kind else {
        panic!("expected a response");
    };

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let duplicate_event0 = signed_response(&request, &root_sk, None, Some(own.output.clone()));
    let duplicate_event1 = duplicate_event0.clone();

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
    let request = backlog
        .entry(Chain::Solana, &sign_id)
        .await
        .unwrap()
        .request;
    let SignKind::RespondBidirectional(own) = &entry.request().kind else {
        panic!("expected a response");
    };

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let mut event = signed_response(&request, &root_sk, None, Some(own.output.clone()));
    event.signature.s += Scalar::ONE;

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
    let tx = test_bidirectional_tx(14, Chain::Ethereum, Chain::Ethereum);
    let sign_id = tx.sign_id();
    let args = test_sign_args(14);

    let mut rlp_s = rlp::RlpStream::new_list(9);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    rlp_s.append(&vec![0x11u8; 20]);
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
            dest: String::new(),
            caip2_id: tx.caip2_id.clone(),
            key_version: tx.key_version,
            deposit: tx.deposit,
            path: tx.path.clone(),
            algo: tx.algo.clone(),
            params: String::new(),
            chain: Chain::Solana,
            chain_ctx: Some(Pubkey::new_unique().to_bytes().to_vec()),
            output_deserialization_schema: tx.output_deserialization_schema.clone(),
            respond_serialization_schema: tx.respond_serialization_schema.clone(),
        },
    ));
    let (public_key, output) = mock_signature_output(&req.args);
    let published = backlog
        .insert_bidirectional(req)
        .await
        .advance(public_key, &output, vec![], true)
        .await
        .unwrap();

    // The signature this node issued is the one published.
    let event = SignatureRespondedEvent {
        request_id: sign_id.request_id,
        signature: *published.signature(),
        chain: Chain::Ethereum,
    };

    let account_id: AccountId = "test.near".parse().unwrap();
    let (_contract_watcher, _tx) =
        ContractStateWatcher::with_running(&account_id, public_key, 1, Default::default());

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    // Not caught up: stop events bypass the gate that holds back new requests.
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, false);

    process_respond_event(event, &ctx, public_key)
        .await
        .expect("respond event should advance pending publish bidirectional entries");

    // The finished leg holds the sign id the next one reuses.
    match sign_rx
        .try_recv()
        .expect("leg completion should be enqueued")
    {
        SignCommand::LegCompleted { sign_id: id, kind } => {
            assert_eq!(id, sign_id);
            assert_eq!(kind, RequestKind::SignBidirectional);
        }
        other => panic!("unexpected sign command: {other:?}"),
    }

    let entry = ctx
        .backlog
        .get(Chain::Ethereum, &sign_id)
        .await
        .expect("entry should remain in backlog");
    assert_matches!(
        entry.status(),
        SignStatus::Bidirectional(BidirectionalProgress::Executing)
    );
    let execution_tx_id = ctx
        .backlog
        .get_executing(Chain::Ethereum, &sign_id)
        .await
        .expect("pending execution entries should store the execution transaction")
        .execution_tx()
        .id;

    let watchers = ctx.backlog.get_execution_watchers(Chain::Ethereum).await;
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
        block_at(456u64),
        ExecutionOutcome::Failed,
        &ctx,
        tx.target_chain,
        test_root_pk(),
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
async fn process_execution_confirmed_waits_for_source_catchup() {
    let backlog = Backlog::new();

    let tx = test_bidirectional_tx(4, Chain::Solana, Chain::Ethereum);
    backlog.insert_mock_executing(&tx).await;

    // Restarted: caught up on the target chain, still behind on the source chain.
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let mut ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, false);
    ctx.backlog.set_caught_up(Chain::Ethereum, true);
    process_execution_confirmed(
        tx.id,
        block_at(789u64),
        ExecutionOutcome::Failed,
        &ctx,
        tx.target_chain,
        test_root_pk(),
    )
    .await
    .unwrap();
    assert!(
        sign_rx.try_recv().is_err(),
        "second leg signed before source catchup"
    );

    crate::stream::handle_chain_event(
        mpc_primitives::ChainEvent::CatchupCompleted,
        &mut ctx,
        &NoopChainTelemetry,
        ProjectivePoint::GENERATOR.to_affine(),
        Chain::Solana,
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
        other => panic!("expected the second leg at source catchup, got {other:?}"),
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
        block_at(456u64),
        ExecutionOutcome::Success { output: vec![1] },
        &ctx,
        tx.target_chain,
        test_root_pk(),
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
    let interval = crate::backlog::checkpoint_interval(chain).unwrap();
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
    let interval = crate::backlog::checkpoint_interval(chain).unwrap();

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
        .advance(ExecutionOutcome::Success { output: vec![] }, block_at(456))
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

/// A stream restart clears `caught_up` while the sign loop still runs the
/// request's task, and the completed entry is gone from the backlog, so a
/// completion dropped during replay would leave that task running.
#[tokio::test]
async fn process_respond_bidirectional_event_sends_completion_before_catchup() {
    let backlog = Backlog::new();
    let tx = test_bidirectional_tx(82, Chain::Solana, Chain::Ethereum);
    let sign_id = tx.sign_id();
    let entry = backlog.insert_mock_final(&tx).await;
    let request = backlog
        .entry(Chain::Solana, &sign_id)
        .await
        .unwrap()
        .request;
    let SignKind::RespondBidirectional(own) = &entry.request().kind else {
        panic!("expected a response");
    };

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let event = signed_response(&request, &root_sk, None, Some(own.output.clone()));
    let public_key = root_sk.public_key().into();

    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, false);

    process_respond_bidirectional_event(event, &ctx, public_key)
        .await
        .expect("respond event should complete the request");

    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_matches!(msg, SignCommand::Completion(id) if id == sign_id);
}

#[tokio::test]
async fn midnight_execution_response_binds_receipt_height_and_outcome() {
    for (result, kind, expected_output) in [
        (
            ExecutionOutcome::Success {
                output: vec![0xde, 0xad, 0xbe, 0xef],
            },
            mpc_primitives::AttestationOutcomeKind::Executed,
            vec![0xde, 0xad, 0xbe, 0xef],
        ),
        (
            ExecutionOutcome::Failed,
            mpc_primitives::AttestationOutcomeKind::Failed,
            vec![],
        ),
        (
            ExecutionOutcome::Unviable,
            mpc_primitives::AttestationOutcomeKind::Unviable,
            vec![],
        ),
    ] {
        let backlog = Backlog::new();
        let tx = test_bidirectional_tx(92, Chain::Midnight, Chain::Ethereum);
        backlog.insert_mock_executing(&tx).await;
        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
        process_execution_confirmed(
            tx.id,
            block_at(7123),
            result,
            &ctx,
            Chain::Ethereum,
            test_root_pk(),
        )
        .await
        .unwrap();
        let SignCommand::Request(entry) = sign_rx.try_recv().unwrap() else {
            panic!("expected signing request")
        };
        let SignKind::RespondBidirectional(response) = &entry.request().kind else {
            panic!("expected response")
        };
        assert_eq!(response.output, expected_output);
        assert_eq!(
            response.attestation,
            Some(mpc_primitives::AttestationMetadata {
                key_version: tx.key_version,
                block_height: 7123,
                outcome_kind: kind,
            })
        );
        assert!(ctx
            .backlog
            .get_execution_watchers(Chain::Ethereum)
            .await
            .is_empty());
    }
}

/// A node that already computed its response settles on the published attestation, even one
/// that differs from its own, as long as the signature covers it under this request's key.
#[tokio::test]
async fn midnight_completion_requires_the_published_metadata_to_match_the_signature() {
    for case in 0..9 {
        let backlog = Backlog::new();
        let tx = test_bidirectional_tx(94, Chain::Midnight, Chain::Ethereum);
        let entry = backlog.insert_mock_final(&tx).await;
        let SignKind::RespondBidirectional(response) = &entry.request().kind else {
            unreachable!()
        };
        let metadata = response.attestation.unwrap();
        let digest = mpc_compact_hashing::compute_attestation_hash(
            &tx.request_id,
            &metadata,
            &response.output,
        )
        .unwrap();
        let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
        let signature = mpc_crypto::generate_signature(&root_sk, &entry.request().args);
        let mut event = RespondBidirectionalEvent {
            output: None,
            request_id: tx.request_id,
            signature,
            chain: Chain::Midnight,
            attestation: Some(mpc_primitives::PublishedAttestation {
                block_height: metadata.block_height,
                outcome_kind: metadata.outcome_kind,
                serialized_output_length: response.output.len() as u64,
                output_hash: mpc_compact_hashing::compute_attested_output_hash(&response.output),
                digest,
            }),
        };
        match case {
            0 => event.attestation = None,
            1 => event.attestation.as_mut().unwrap().block_height += 1,
            2 => {
                event.attestation.as_mut().unwrap().outcome_kind =
                    mpc_primitives::AttestationOutcomeKind::Failed
            }
            3 => event.attestation.as_mut().unwrap().serialized_output_length += 1,
            4 => event.attestation.as_mut().unwrap().digest[0] ^= 1,
            5 => {}
            6 => event.attestation.as_mut().unwrap().output_hash[0] ^= 1,
            7 => {
                let published = event.attestation.as_mut().unwrap();
                published.block_height += 1;
                let signed = mpc_primitives::AttestationMetadata {
                    block_height: published.block_height,
                    ..metadata
                };
                published.digest = mpc_compact_hashing::compute_attestation_digest(
                    &tx.request_id,
                    &signed,
                    published.serialized_output_length,
                    &published.output_hash,
                );
                let mut args = entry.request().args.clone();
                args.payload =
                    <Scalar as mpc_primitives::ScalarExt>::from_bytes(published.digest).unwrap();
                event.signature = mpc_crypto::generate_signature(&root_sk, &args);
            }
            8 => {
                let mut args = entry.request().args.clone();
                args.epsilon += Scalar::ONE;
                event.signature = mpc_crypto::generate_signature(&root_sk, &args);
            }
            _ => unreachable!(),
        }
        let settles = case == 5 || case == 7;
        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
        let result =
            process_respond_bidirectional_event(event, &ctx, root_sk.public_key().into()).await;
        assert_eq!(result.is_ok(), settles, "case {case}");
        assert_eq!(
            ctx.backlog
                .get(Chain::Midnight, &tx.sign_id())
                .await
                .is_none(),
            settles,
            "case {case}"
        );
        assert_eq!(sign_rx.try_recv().is_ok(), settles, "case {case}");
    }
}

#[tokio::test]
async fn recovered_midnight_final_publication_requires_canonical_metadata() {
    for compatible in [false, true] {
        // A restart keeps this node's record of the signature it is publishing.
        let storage = crate::storage::checkpoint_storage::CheckpointStorage::in_memory();
        let backlog = Backlog::persisted(storage.clone());
        let tx = test_bidirectional_tx(96, Chain::Midnight, Chain::Ethereum);
        let request = if compatible {
            backlog.insert_mock_final(&tx).await.request().clone()
        } else {
            mock_bidi_response_request(tx.sign_id(), tx.id, Chain::Midnight)
        };
        let entry = crate::backlog::SignEntry::generating(request.clone(), &backlog);
        if !compatible {
            backlog.insert(request.clone()).await;
        }
        let (pk, output) = mock_signature_output(&request.args);
        entry
            .advance(pk, &output, mock_participants(), true)
            .await
            .unwrap();
        let before = backlog.checkpoint(Chain::Midnight).await.unwrap();
        let restored = Backlog::persisted(storage);
        restored
            .recover_by_checkpoint(&before, mock_root_pk())
            .await
            .unwrap();
        let (sign_tx, _sign_rx) = mpsc::channel(4);
        let (ctx, mut rpc_rx) = make_test_stream_context_with_rpc(restored, sign_tx, true, pk);
        let ctx = ctx.with_observe_lag(Some(Duration::ZERO));
        resume_pending_publish_requests(&ctx, Chain::Midnight).await;
        assert_eq!(next_publish(&mut rpc_rx).await.is_some(), compatible);
        publish_failover_due(&ctx, Chain::Midnight).await;
        assert!(next_publish(&mut rpc_rx).await.is_none());
        assert_eq!(
            before.digest(),
            ctx.backlog
                .checkpoint(Chain::Midnight)
                .await
                .unwrap()
                .digest()
        );
    }
}

/// A terminal extraction failure means the transaction executed but its output
/// could not be interpreted. No sign request is queued.
#[tokio::test]
async fn decode_failure_parks_request_and_preserves_source_checkpoint() {
    for source_chain in [
        Chain::Midnight,
        Chain::Solana,
        Chain::Canton,
        Chain::Hydration,
    ] {
        for caught_up in [false, true] {
            let backlog = Backlog::new();
            let tx = test_bidirectional_tx(97, source_chain, Chain::Ethereum);
            backlog.insert_mock_executing(&tx).await;
            backlog
                .set_processed_block_interval(source_chain, 40, 0)
                .await;
            let before = backlog.checkpoint(source_chain).await.unwrap();
            // A restart keeps this node's record that it parked the request.
            let storage = crate::storage::checkpoint_storage::CheckpointStorage::in_memory();
            let observer = Backlog::persisted(storage.clone());
            observer
                .recover_by_checkpoint(&before, mock_root_pk())
                .await
                .unwrap();
            let (sign_tx, mut sign_rx) = mpsc::channel(4);
            let ctx = make_test_stream_context_with_generator_pk(observer, sign_tx, caught_up);
            process_execution_confirmed(
                tx.id,
                block_at(7123),
                ExecutionOutcome::ExtractionFailed,
                &ctx,
                Chain::Ethereum,
                test_root_pk(),
            )
            .await
            .unwrap();
            let after = ctx.backlog.checkpoint(source_chain).await.unwrap();
            assert_eq!(before.block_height, after.block_height);
            assert_eq!(
                before.digest(),
                after.digest(),
                "unequal target progress must not change the same source checkpoint"
            );
            assert_matches!(
                sign_rx.try_recv().expect("parked request must stop its signing task"),
                SignCommand::Completion(id) if id == tx.sign_id()
            );
            assert!(sign_rx.try_recv().is_err(), "no response should be signed");
            assert_matches!(
                ctx.backlog
                    .get(source_chain, &tx.sign_id())
                    .await
                    .unwrap()
                    .state(),
                SignStatus::Bidirectional(BidirectionalProgress::Parked)
            );
            assert_eq!(
                ctx.backlog
                    .get_execution_watchers(Chain::Ethereum)
                    .await
                    .len(),
                0,
                "terminal decode failure must stop watching before checkpoint recovery"
            );
            process_execution_confirmed(
                tx.id,
                block_at(7123),
                ExecutionOutcome::ExtractionFailed,
                &ctx,
                Chain::Ethereum,
                test_root_pk(),
            )
            .await
            .unwrap();
            assert!(
                sign_rx.try_recv().is_err(),
                "duplicate event must not complete again"
            );
            // Exercise the same CBOR representation used by durable checkpoints.
            let mut encoded = Vec::new();
            ciborium::into_writer(&after, &mut encoded).unwrap();
            let checkpoint: crate::backlog::Checkpoint =
                ciborium::from_reader(encoded.as_slice()).unwrap();
            assert_eq!(after, checkpoint);
            let restored = Backlog::persisted(storage);
            restored
                .recover_by_checkpoint(&checkpoint, mock_root_pk())
                .await
                .unwrap();
            assert_eq!(
                restored.get_execution_watchers(Chain::Ethereum).await.len(),
                0
            );
            assert_eq!(
                before.digest(),
                restored.checkpoint(source_chain).await.unwrap().digest()
            );
            assert!(restored.requeueable_requests(source_chain).await.is_empty());

            // Neither repeated target callbacks nor another initial signature may
            // re-enable a parked watch or start final response signing.
            let (sign_tx, mut sign_rx) = mpsc::channel(4);
            let restored_ctx =
                make_test_stream_context_with_generator_pk(restored, sign_tx, caught_up);
            process_execution_confirmed(
                tx.id,
                block_at(7123),
                ExecutionOutcome::ExtractionFailed,
                &restored_ctx,
                Chain::Ethereum,
                test_root_pk(),
            )
            .await
            .unwrap();
            let parked = restored_ctx
                .backlog
                .get(source_chain, &tx.sign_id())
                .await
                .unwrap();
            let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
            process_respond_event(
                SignatureRespondedEvent {
                    request_id: tx.request_id,
                    signature: mpc_crypto::generate_signature(&root_sk, &parked.request().args),
                    chain: source_chain,
                },
                &restored_ctx,
                root_sk.public_key().into(),
            )
            .await
            .unwrap();
            requeue_pending_sign_requests(&restored_ctx, source_chain)
                .await
                .unwrap();
            assert!(sign_rx.try_recv().is_err());
            assert!(restored_ctx
                .backlog
                .get_execution_watchers(Chain::Ethereum)
                .await
                .is_empty());
            // The second signature is the source chain's to record, and stays unwatched.
            let entry = restored_ctx
                .backlog
                .entry(source_chain, &tx.sign_id())
                .await
                .unwrap();
            assert_eq!(entry.txs.len(), 2);
            assert_matches!(
                entry.status,
                SignStatus::Bidirectional(BidirectionalProgress::Parked)
            );
        }
    }
}

/// Sign `outcome` at `height` the way a node that observed it does, and publish it.
async fn published_midnight_response(
    tx: &BidirectionalTx,
    outcome: ExecutionOutcome,
    height: u64,
    root_sk: &k256::SecretKey,
) -> (Backlog, RespondBidirectionalEvent) {
    let backlog = Backlog::new();
    backlog.insert_mock_executing(tx).await;
    backlog
        .set_processed_block_interval(Chain::Midnight, 40, 0)
        .await;
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let ctx = make_test_stream_context_with_generator_pk(backlog.clone(), sign_tx, true);
    process_execution_confirmed(
        tx.id,
        AttestedBlock {
            height,
            hash: [7; 32],
        },
        outcome,
        &ctx,
        Chain::Ethereum,
        test_root_pk(),
    )
    .await
    .unwrap();
    let Ok(SignCommand::Request(entry)) = sign_rx.try_recv() else {
        panic!("the observed outcome must be signed");
    };
    let event = RespondBidirectionalEvent {
        output: None,
        request_id: tx.request_id,
        signature: mpc_crypto::generate_signature(root_sk, &entry.request().args),
        chain: Chain::Midnight,
        attestation: Some(
            mpc_chain_midnight::validate_attestation_response(entry.request()).unwrap(),
        ),
    };
    (backlog, event)
}

/// The event carries the output's length and hash, so a response's digest follows from
/// the request and the event alone: a node that never observed the outcome, or attested
/// another one, settles it at the same source event as the nodes that attested it, and their
/// checkpoints agree.
#[tokio::test]
async fn midnight_response_settles_entries_that_missed_the_outcome() {
    let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
    for (outcome, parked) in [
        (ExecutionOutcome::Unviable, false),
        (ExecutionOutcome::Failed, false),
        (ExecutionOutcome::Success { output: vec![] }, false),
        (ExecutionOutcome::Success { output: vec![1] }, false),
        (
            ExecutionOutcome::Success {
                output: (0..100).collect(),
            },
            false,
        ),
        (ExecutionOutcome::Unviable, true),
        (ExecutionOutcome::Success { output: vec![1] }, true),
    ] {
        let case = format!("{outcome:?}, parked: {parked}");
        let tx = test_bidirectional_tx(101, Chain::Midnight, Chain::Ethereum);
        let (attested, event) = published_midnight_response(&tx, outcome, 7123, &root_sk).await;
        // A node that computed another outcome, at another height.
        let (disagreeing, _) =
            published_midnight_response(&tx, ExecutionOutcome::Failed, 7124, &root_sk).await;

        let lagging = Backlog::new();
        lagging.insert_mock_executing(&tx).await;
        if parked {
            lagging
                .unwatch_execution(Chain::Ethereum, &tx.id)
                .await
                .unwrap()
                .park()
                .await
                .unwrap();
        }
        lagging
            .set_processed_block_interval(Chain::Midnight, 40, 0)
            .await;

        let mut digests = Vec::new();
        for (node, backlog) in [
            ("attested", attested),
            ("disagreeing", disagreeing),
            ("lagging", lagging),
        ] {
            let (sign_tx, mut sign_rx) = mpsc::channel(4);
            let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
            process_respond_bidirectional_event(event.clone(), &ctx, root_sk.public_key().into())
                .await
                .unwrap_or_else(|error| panic!("{case}, {node}: {error:#}"));
            assert!(
                ctx.backlog
                    .get(Chain::Midnight, &tx.sign_id())
                    .await
                    .is_none(),
                "{case}, {node}"
            );
            assert!(
                ctx.backlog
                    .get_execution_watchers(Chain::Ethereum)
                    .await
                    .is_empty(),
                "{case}, {node}"
            );
            assert!(
                matches!(
                    sign_rx.try_recv(),
                    Ok(SignCommand::Completion(id)) if id == tx.sign_id()
                ),
                "{case}, {node}"
            );
            digests.push(
                ctx.backlog
                    .checkpoint(Chain::Midnight)
                    .await
                    .unwrap()
                    .digest(),
            );
        }
        assert_eq!(digests[0], digests[1], "{case}");
    }
}

/// Every response of one contract and key version is signed by the same attestation key, so
/// only a digest recomputed from this request and the event binds a response to it.
#[tokio::test]
async fn midnight_unobserved_entries_keep_responses_they_cannot_bind() {
    let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
    let pending = test_bidirectional_tx(103, Chain::Midnight, Chain::Ethereum);
    for case in [
        "another request's response",
        "altered height",
        "altered kind",
        "altered digest",
        "altered output length",
        "altered output hash",
        "forged signature",
    ] {
        let (tx, event) = match case {
            "another request's response" => {
                let other = test_bidirectional_tx(102, Chain::Midnight, Chain::Ethereum);
                let (_, mut event) =
                    published_midnight_response(&other, ExecutionOutcome::Unviable, 7123, &root_sk)
                        .await;
                event.request_id = pending.request_id;
                (pending.clone(), event)
            }
            _ => {
                let (_, mut event) = published_midnight_response(
                    &pending,
                    ExecutionOutcome::Unviable,
                    7123,
                    &root_sk,
                )
                .await;
                let attestation = event.attestation.as_mut().unwrap();
                match case {
                    "altered height" => attestation.block_height += 1,
                    "altered kind" => {
                        attestation.outcome_kind = mpc_primitives::AttestationOutcomeKind::Failed
                    }
                    "altered digest" => attestation.digest[0] ^= 1,
                    "altered output length" => attestation.serialized_output_length += 1,
                    "altered output hash" => attestation.output_hash[0] ^= 1,
                    "forged signature" => event.signature.s += Scalar::ONE,
                    _ => unreachable!(),
                }
                (pending.clone(), event)
            }
        };
        let backlog = Backlog::new();
        backlog.insert_mock_executing(&tx).await;
        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
        let result =
            process_respond_bidirectional_event(event, &ctx, root_sk.public_key().into()).await;
        assert!(result.is_err(), "{case}");
        assert!(
            ctx.backlog
                .get(tx.source_chain, &tx.sign_id())
                .await
                .is_some_and(|entry| entry.state().is_pending_execution()),
            "{case}"
        );
        assert_eq!(
            ctx.backlog
                .get_execution_watchers(Chain::Ethereum)
                .await
                .len(),
            1,
            "{case}"
        );
        assert!(sign_rx.try_recv().is_err(), "{case}");
    }
}

#[test]
fn network_mismatch_reports_only_foreign_chains() {
    let foreign = bidirectional_event(legacy_contract_call(11_155_111));
    assert_eq!(
        network_mismatch(&foreign, Some(1)),
        Some((Some(11_155_111), 1)),
        "a foreign chain id is evidence"
    );
    let wide = bidirectional_event(legacy_contract_call_on(&WIDE_CHAIN_ID.to_vec()));
    assert_eq!(
        network_mismatch(&wide, Some(1)),
        Some((None, 1)),
        "an undecodable chain id names no network this node watches"
    );

    let local = bidirectional_event(legacy_contract_call(1));
    assert_eq!(network_mismatch(&local, Some(1)), None);
    assert_eq!(
        network_mismatch(&foreign, None),
        None,
        "unconfigured: no check"
    );

    let tron = tron_bidirectional_event(hex::decode(TRON_RAW_HEX).unwrap());
    assert_eq!(
        network_mismatch(&tron, Some(1)),
        None,
        "the chain id check is Ethereum-only"
    );
}

/// `duplicate_destination` names the pending flat id, so identical Tron bytes
/// collide and differing bytes never do.
#[tokio::test]
async fn duplicate_destination_keys_on_the_flat_id() {
    let mut different = hex::decode(TRON_RAW_HEX).unwrap();
    different[5] ^= 1; // inside ref_block_hash: still canonical, different txID
    let first = tron_bidirectional_event(hex::decode(TRON_RAW_HEX).unwrap());
    let second = tron_bidirectional_event(hex::decode(TRON_RAW_HEX).unwrap());
    let other = tron_bidirectional_event(different);

    let backlog = Backlog::new();
    assert_eq!(
        duplicate_destination(&first, SignId::new([9; 32]), &backlog).await,
        None,
        "an empty backlog has nothing to collide with"
    );

    let request = |event, seed: u8| {
        Arc::new(IndexedSignRequest::sign_bidirectional(
            SignId::new([seed; 32]),
            test_sign_args(seed),
            Chain::Solana,
            current_unix_timestamp(),
            event,
        ))
    };
    let expected = second.flat_destination_id();
    backlog.insert(request(second, 1)).await;

    assert_eq!(
        duplicate_destination(&first, SignId::new([1; 32]), &backlog).await,
        None,
        "the request's own pending entry is skipped — indexer replays stay idempotent"
    );
    assert_eq!(
        duplicate_destination(&first, SignId::new([9; 32]), &backlog).await,
        expected,
        "identical raw bytes under another request collide"
    );
    assert_eq!(
        duplicate_destination(&other, SignId::new([9; 32]), &backlog).await,
        None,
        "different bytes never collide"
    );
}

/// A node that has not seen the execution yet removes the request when the response checks out.
#[tokio::test]
async fn unobserved_response_settles_when_it_verifies() {
    let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
    let success = || ExecutionOutcome::Success { output: vec![] };
    for (source_chain, outcome, parked, published, settles) in [
        (
            Chain::Solana,
            ExecutionOutcome::Failed,
            false,
            "none",
            false,
        ),
        (Chain::Solana, success(), false, "none", false),
        (
            Chain::Solana,
            ExecutionOutcome::Failed,
            false,
            "signed",
            true,
        ),
        (
            Chain::Canton,
            ExecutionOutcome::Failed,
            true,
            "signed",
            true,
        ),
        (Chain::Solana, success(), false, "signed", true),
        (Chain::Solana, success(), true, "signed", true),
        (Chain::Hydration, success(), false, "signed", true),
        (Chain::Canton, success(), false, "signed", true),
        (Chain::Solana, success(), false, "altered", false),
    ] {
        let case = format!("{source_chain} {outcome:?}, parked: {parked}, output: {published}");
        let tx = test_bidirectional_tx(105, source_chain, Chain::Ethereum);

        let attested = Backlog::new();
        attested.insert_mock_executing(&tx).await;
        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let ctx = make_test_stream_context_with_generator_pk(attested, sign_tx, true);
        process_execution_confirmed(
            tx.id,
            block_at(7123),
            outcome,
            &ctx,
            Chain::Ethereum,
            test_root_pk(),
        )
        .await
        .unwrap();
        let Ok(SignCommand::Request(entry)) = sign_rx.try_recv() else {
            panic!("{case}: the observed outcome must be signed");
        };
        let SignKind::RespondBidirectional(response) = &entry.request().kind else {
            panic!("{case}: the outcome is signed as a response");
        };
        let output = match published {
            "none" => None,
            "signed" => Some(response.output.clone()),
            "altered" => Some([response.output.as_slice(), &[1]].concat()),
            _ => unreachable!(),
        };
        let event = RespondBidirectionalEvent {
            output,
            attestation: None,
            request_id: tx.request_id,
            signature: mpc_crypto::generate_signature(&root_sk, &entry.request().args),
            chain: source_chain,
        };

        let lagging = Backlog::new();
        lagging.insert_mock_executing(&tx).await;
        if parked {
            lagging
                .unwatch_execution(Chain::Ethereum, &tx.id)
                .await
                .unwrap()
                .park()
                .await
                .unwrap();
        }
        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let ctx = make_test_stream_context_with_generator_pk(lagging, sign_tx, true);
        let result =
            process_respond_bidirectional_event(event, &ctx, root_sk.public_key().into()).await;
        // A response that cannot be checked from the event is an error, and the request stays.
        assert_eq!(
            result.is_err(),
            matches!(published, "none" | "altered"),
            "{case}: {result:?}"
        );

        assert_eq!(
            ctx.backlog.get(source_chain, &tx.sign_id()).await.is_none(),
            settles,
            "{case}"
        );
        assert_eq!(
            ctx.backlog
                .get_execution_watchers(Chain::Ethereum)
                .await
                .is_empty(),
            settles || parked,
            "{case}"
        );
        assert_eq!(
            matches!(sign_rx.try_recv(), Ok(SignCommand::Completion(id)) if id == tx.sign_id()),
            settles,
            "{case}"
        );
    }
}

/// The round trip's latency is labelled from the outcome this node recorded, so a successful
/// output that begins with the failure prefix is still `ok`.
#[tokio::test]
async fn final_response_latency_follows_the_recorded_outcome() {
    let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
    let count = |status| {
        crate::metrics::requests::request_latency_count(
            Chain::Hydration,
            SignRequestStep::BidirectionalTotal,
            status,
            RequestKind::RespondBidirectional,
        )
    };
    // No other test records a Hydration `bidirectional_total` latency, so the counts below
    // are this test's. The cases share one test for the same reason.
    for (seed, outcome, status) in [
        (
            107,
            ExecutionOutcome::Success {
                output: vec![0xde, 0xad, 0xbe, 0xef, 1],
            },
            "ok",
        ),
        (108, ExecutionOutcome::Failed, "execution_failed"),
    ] {
        let tx = test_bidirectional_tx(seed, Chain::Hydration, Chain::Ethereum);
        let backlog = Backlog::new();
        backlog.insert_mock_executing(&tx).await;
        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
        process_execution_confirmed(
            tx.id,
            block_at(7123),
            outcome,
            &ctx,
            Chain::Ethereum,
            test_root_pk(),
        )
        .await
        .unwrap();
        let Ok(SignCommand::Request(entry)) = sign_rx.try_recv() else {
            panic!("{status}: the observed outcome must be signed");
        };
        let SignKind::RespondBidirectional(own) = &entry.request().kind else {
            panic!("{status}: the outcome is signed as a response");
        };
        let event = RespondBidirectionalEvent {
            output: Some(own.output.clone()),
            attestation: None,
            request_id: tx.request_id,
            signature: mpc_crypto::generate_signature(&root_sk, &entry.request().args),
            chain: Chain::Hydration,
        };
        let (ok, failed) = (count("ok"), count("execution_failed"));

        process_respond_bidirectional_event(event, &ctx, root_sk.public_key().into())
            .await
            .unwrap();

        let recorded = (count("ok") - ok, count("execution_failed") - failed);
        let expected = if status == "ok" { (1, 0) } else { (0, 1) };
        assert_eq!(recorded, expected, "{status}");
    }
}

/// A node that computed a different output than the network signed settles on the published
/// one, so it removes the request at the same event as the others.
#[tokio::test]
async fn final_response_settles_on_the_published_output() {
    let root_sk = k256::SecretKey::from_slice(&[1; 32]).unwrap();
    for (published, settles) in [("same", true), ("signed", true), ("unsigned", false)] {
        let tx = test_bidirectional_tx(106, Chain::Solana, Chain::Ethereum);
        let backlog = Backlog::new();
        backlog.insert_mock_executing(&tx).await;
        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let ctx = make_test_stream_context_with_generator_pk(backlog, sign_tx, true);
        let outcome = ExecutionOutcome::Success { output: vec![] };
        process_execution_confirmed(
            tx.id,
            block_at(7123),
            outcome,
            &ctx,
            Chain::Ethereum,
            test_root_pk(),
        )
        .await
        .unwrap();
        let Ok(SignCommand::Request(entry)) = sign_rx.try_recv() else {
            panic!("{published}: the observed outcome must be signed");
        };

        let SignKind::RespondBidirectional(own) = &entry.request().kind else {
            panic!("{published}: the outcome is signed as a response");
        };
        let output = if published == "same" {
            own.output.clone()
        } else {
            vec![7]
        };
        let mut args = entry.request().args.clone();
        if published == "signed" {
            args.payload = crate::respond_bidirectional::published_output_payload(
                Chain::Solana,
                &tx.request_id,
                &output,
            )
            .unwrap();
        }
        let event = RespondBidirectionalEvent {
            output: Some(output),
            attestation: None,
            request_id: tx.request_id,
            signature: mpc_crypto::generate_signature(&root_sk, &args),
            chain: Chain::Solana,
        };
        let result =
            process_respond_bidirectional_event(event, &ctx, root_sk.public_key().into()).await;

        assert_eq!(result.is_ok(), settles, "{published}");
        assert_eq!(
            ctx.backlog
                .get(Chain::Solana, &tx.sign_id())
                .await
                .is_none(),
            settles,
            "{published}"
        );
    }
}
