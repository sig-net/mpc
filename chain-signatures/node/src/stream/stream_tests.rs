use super::supervisor::run_supervised;
use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::rpc::{ContractStateWatcher, RpcAction};
use crate::storage::checkpoint_storage::CheckpointStorage;
use crate::stream::test_utils::{
    run_stream_with_two_node_mesh, signature_responded_event, test_bidirectional_tx,
    test_rpc_channel, test_sign_args,
};
use crate::util::current_unix_timestamp;
use async_trait::async_trait;
use k256::{AffinePoint, Scalar};
use mpc_chain_integration_core::{ChainIndexer, StateManager};
use mpc_chain_solana::Pubkey;
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, SignArgs, SignCommand, SignId, Signature,
};
use near_primitives::types::AccountId;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// A mock `ChainIndexer` that emits a scripted sequence of `ChainEvent`s, then
/// exits `Ok` (shutting the supervisor down). A `None` entry terminates early.
macro_rules! impl_test_indexer {
    ($indexer:ident, $chain:expr) => {
        pub struct $indexer {
            events: Vec<Option<ChainEvent>>,
        }

        impl $indexer {
            pub fn new(events: Vec<Option<ChainEvent>>) -> Self {
                Self { events }
            }
        }

        #[async_trait]
        impl ChainIndexer for $indexer {
            const CHAIN: Chain = $chain;

            async fn run(
                &self,
                events_tx: mpsc::Sender<ChainEvent>,
                cancel: CancellationToken,
            ) -> anyhow::Result<()> {
                for event in &self.events {
                    let Some(event) = event else {
                        return Ok(());
                    };
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        res = events_tx.send(event.clone()) => {
                            if res.is_err() {
                                return Ok(());
                            }
                        }
                    }
                }
                Ok(())
            }
        }
    };
}

impl_test_indexer!(SolanaTestIndexer, Chain::Solana);
impl_test_indexer!(EthereumTestIndexer, Chain::Ethereum);

#[tokio::test]
async fn test_stream_handles_sign_and_respond() {
    let backlog = Backlog::new();
    let sign_id = SignId::new([1u8; 32]);

    // construct an IndexedSignRequest
    let args = test_sign_args(0);

    let request = IndexedSignRequest::sign(
        sign_id,
        args.clone(),
        Chain::Solana,
        current_unix_timestamp(),
    );

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let root_pk = root_sk.public_key().to_projective().to_affine();

    // Prepare a respond event that matches the sign id
    let mpc_sig = mpc_crypto::generate_signature(&root_sk, &args);
    let sig_responded = signature_responded_event(sign_id, mpc_sig, Chain::Solana);
    let indexer = SolanaTestIndexer::new(vec![
        Some(ChainEvent::CatchupCompleted),
        Some(ChainEvent::SignRequest {
            request: request.clone(),
            block_timestamp: None,
        }),
        Some(ChainEvent::Respond(sig_responded)),
        None,
    ]);

    let (sign_tx, mut sign_rx) = mpsc::channel(4);

    let (contract_watcher, _tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        root_pk,
        0,
        Default::default(),
    );
    let (_mesh_state_tx, mesh_state_rx) = watch::channel(MeshState::default());
    let (_cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());
    let (rpc, _rpc_rx) = test_rpc_channel(4);

    // Run the indexer
    run_supervised(
        indexer,
        crate::stream::StreamContext::new(
            backlog.clone(),
            sign_tx.clone(),
            rpc,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        ),
        mpc_chain_integration_core::NoopChainTelemetry,
    )
    .await;

    // We should have received the Request then Completion
    let msg1 = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg1 {
        SignCommand::Request(req) => assert_eq!(req.id, sign_id),
        _ => panic!("expected request"),
    }

    let msg2 = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg2 {
        SignCommand::Completion(id) => assert_eq!(id, sign_id),
        _ => panic!("expected completion"),
    }
}

/// Build a `SignKind::SignBidirectional` request from Solana to Ethereum.
/// Returns `(IndexedSignRequest, SignArgs, SecretKey)`
fn build_solana_to_ethereum_bidirectional_request(
    seed: u8,
) -> (IndexedSignRequest, SignArgs, k256::SecretKey) {
    // Minimal legacy unsigned Ethereum tx encoded as RLP so sign_and_hash can parse it
    let mut rlp_s = rlp::RlpStream::new_list(9);
    rlp_s.append(&0u64); // nonce
    rlp_s.append(&0u64); // gasPrice
    rlp_s.append(&0u64); // gasLimit
    rlp_s.append(&Vec::<u8>::new()); // to
    rlp_s.append(&0u64); // value
    rlp_s.append(&Vec::<u8>::new()); // data
    rlp_s.append(&1u64); // chain_id
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    let unsigned_rlp = rlp_s.out().to_vec();

    build_solana_to_ethereum_bidirectional_request_with_tx(seed, unsigned_rlp)
}

/// Like [`build_solana_to_ethereum_bidirectional_request`] but with a
/// caller-supplied `serialized_transaction`, so tests can exercise malformed
/// (e.g. empty) transaction bytes through the real lifecycle.
fn build_solana_to_ethereum_bidirectional_request_with_tx(
    seed: u8,
    serialized_transaction: Vec<u8>,
) -> (IndexedSignRequest, SignArgs, k256::SecretKey) {
    use mpc_primitives::SignBidirectionalEvent as SBE;

    let sign_id = SignId::new([seed; 32]);
    let args = test_sign_args(seed);

    let sign_bidir = SBE {
        sender: Default::default(),
        serialized_transaction,
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: 0,
        deposit: 0,
        path: "".to_string(),
        algo: "".to_string(),
        dest: Chain::Ethereum.to_string(),
        params: "".to_string(),
        chain: Chain::Solana,
        chain_ctx: Some(Pubkey::new_unique().to_bytes().to_vec()),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
    };

    let request = IndexedSignRequest::sign_bidirectional(
        sign_id,
        args.clone(),
        Chain::Solana,
        current_unix_timestamp(),
        sign_bidir,
    );

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    (request, args, root_sk)
}

/// Receiving a `ChainEvent::SignRequest` with a bidirectional event should
/// insert it into the backlog and enqueue a `SignCommand`.
#[tokio::test]
async fn test_bidirectional_sign_request_enqueues_command() {
    let backlog = Backlog::new();
    let (request, _args, root_sk) = build_solana_to_ethereum_bidirectional_request(42);
    let sign_id = request.id;
    let root_pk = root_sk.public_key().to_projective().to_affine();
    let indexer = SolanaTestIndexer::new(vec![
        Some(ChainEvent::CatchupCompleted),
        Some(ChainEvent::SignRequest {
            request: request.clone(),
            block_timestamp: None,
        }),
        None,
    ]);

    let (sign_tx, mut sign_rx) = mpsc::channel(8);
    let (contract_watcher, _tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        root_pk,
        0,
        Default::default(),
    );
    let (_mesh_state_tx, mesh_state_rx) = watch::channel(MeshState::default());
    let (_cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());
    let (rpc, _rpc_rx) = test_rpc_channel(8);

    run_supervised(
        indexer,
        crate::stream::StreamContext::new(
            backlog.clone(),
            sign_tx,
            rpc,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        ),
        mpc_chain_integration_core::NoopChainTelemetry,
    )
    .await;

    // A SignCommand::Request should have been emitted for the bidirectional request
    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();

    match msg {
        SignCommand::Request(req) => assert_eq!(req.id, sign_id),
        other => panic!("expected SignCommand::Request, got {other:?}"),
    }

    // The request should be persisted in the backlog after the sign request is processed
    let entry = backlog
        .get(Chain::Solana, &sign_id)
        .await
        .expect("bidirectional sign request should be tracked in the backlog");

    assert!(matches!(
        entry.request.kind,
        mpc_primitives::SignKind::SignBidirectional(_)
    ));
}

/// A `ChainEvent::Respond` against an entry that is already in `PendingPublish`
/// should advance it to `PendingExecution` and register an execution watcher on
/// the target chain.
#[tokio::test]
async fn test_respond_event_advances_to_pending_execution() {
    use crate::sign_bidirectional::{PublishState, SignStatus};

    let backlog = Backlog::new();
    let (request, args, root_sk) = build_solana_to_ethereum_bidirectional_request(7);
    let sign_id = request.id;
    let root_pk = root_sk.public_key().to_projective().to_affine();

    // Pre-seed the backlog with the bidirectional entry and mark it as already
    // published so the incoming respond event advances it into execution pending.
    backlog.insert(request).await;
    let mpc_sig = mpc_crypto::generate_signature(&root_sk, &args);
    backlog
        .set_status(
            Chain::Solana,
            &sign_id,
            SignStatus::PendingPublish {
                publish: PublishState {
                    signature: mpc_sig,
                    participants: vec![],
                    is_proposer: true,
                },
            },
        )
        .await;

    let sig_responded = signature_responded_event(sign_id, mpc_sig, Chain::Solana);
    let indexer = SolanaTestIndexer::new(vec![
        Some(ChainEvent::CatchupCompleted),
        Some(ChainEvent::Respond(sig_responded)),
        None,
    ]);

    let (sign_tx, _sign_rx) = mpsc::channel(8);
    let (contract_watcher, _tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        root_pk,
        0,
        Default::default(),
    );
    let (_mesh_state_tx, mesh_state_rx) = watch::channel(MeshState::default());
    let (_cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());
    let (rpc, _rpc_rx) = test_rpc_channel(8);

    run_supervised(
        indexer,
        crate::stream::StreamContext::new(
            backlog.clone(),
            sign_tx,
            rpc,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        ),
        mpc_chain_integration_core::NoopChainTelemetry,
    )
    .await;

    // The respond event should have advanced the entry to PendingExecution and
    // registered an execution watcher for the derived bidirectional tx on the
    // target chain (Ethereum).
    let entry = backlog
        .get(Chain::Solana, &sign_id)
        .await
        .expect("entry should remain in backlog after respond event");
    assert!(
        matches!(entry.status(), SignStatus::PendingExecution { .. }),
        "expected PendingExecution, got {:?}",
        entry.status()
    );

    let watchers = backlog.get_execution_watchers(Chain::Ethereum).await;
    assert_eq!(watchers.len(), 1, "expected exactly one execution watcher");
    let (watched_sign_id, _watched_tx) = watchers.values().next().unwrap();
    assert_eq!(*watched_sign_id, sign_id);
}

/// Regression / vulnerability repro: a bidirectional sign request whose
/// `serialized_transaction` is empty panics the chain's event loop when the
/// respond event advances it to `PendingExecution`.
///
/// This drives the *real* lifecycle: a Solana→Ethereum `SignBidirectional`
/// entry sits in the backlog as `PendingPublish`, then a valid (honestly
/// generated) `ChainEvent::Respond` arrives and is processed by
/// `handle_chain_event` → `process_respond_event` →
/// `advance_bidirectional_to_execution` → `sign_and_hash_transaction`. That last
/// call hits `is_eip1559`, which indexes `unsigned_rlp[0]` with no length check,
/// so the empty tx panics with an index-out-of-bounds.
///
/// Crucially, `handle_chain_event` runs *inline* in the `run_supervised` select
/// loop, guarded only by `if let Err(..)` — which catches `anyhow::Error` but
/// NOT panics. So the panic escapes the guard and unwinds out of
/// `run_supervised`, which this test awaits directly (hence `#[should_panic]`).
/// In production this permanently kills that chain's supervised indexer task.
#[tokio::test]
#[should_panic(expected = "index out of bounds")]
async fn test_empty_serialized_transaction_panics_on_respond() {
    use crate::sign_bidirectional::{PublishState, SignStatus};

    let backlog = Backlog::new();
    // Empty serialized_transaction — as an attacker (or a misconfigured client)
    // could submit; note the Canton publish test already uses `vec![]` here.
    let (request, args, root_sk) =
        build_solana_to_ethereum_bidirectional_request_with_tx(7, vec![]);
    let sign_id = request.id;
    let root_pk = root_sk.public_key().to_projective().to_affine();

    // Pre-seed the backlog with the bidirectional entry, marked as already
    // published, so the incoming respond event advances it toward execution.
    backlog.insert(request).await;
    let mpc_sig = mpc_crypto::generate_signature(&root_sk, &args);
    backlog
        .set_status(
            Chain::Solana,
            &sign_id,
            SignStatus::PendingPublish {
                publish: PublishState {
                    signature: mpc_sig,
                    participants: vec![],
                    is_proposer: true,
                },
            },
        )
        .await;

    let sig_responded = signature_responded_event(sign_id, mpc_sig, Chain::Solana);
    let indexer = SolanaTestIndexer::new(vec![
        Some(ChainEvent::CatchupCompleted),
        Some(ChainEvent::Respond(sig_responded)),
        None,
    ]);

    let (sign_tx, _sign_rx) = mpsc::channel(8);
    let (contract_watcher, _tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        root_pk,
        0,
        Default::default(),
    );
    let (_mesh_state_tx, mesh_state_rx) = watch::channel(MeshState::default());
    let (_cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());
    let (rpc, _rpc_rx) = test_rpc_channel(8);

    // Panics inside handle_chain_event while processing the Respond event.
    run_supervised(
        indexer,
        crate::stream::StreamContext::new(
            backlog.clone(),
            sign_tx,
            rpc,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        ),
        mpc_chain_integration_core::NoopChainTelemetry,
    )
    .await;
}

/// `process_execution_confirmed` on a watched bidirectional tx should advance the
/// source-chain entry into a follow-up `RespondBidirectional` request and enqueue
/// a new `SignCommand::Request` carrying that request.
#[tokio::test]
async fn test_execution_confirmation_advances_to_respond_bidirectional() {
    use mpc_primitives::{ExecutionOutcome, SignKind};

    let backlog = Backlog::new();
    let seed = 42;
    let sign_id = SignId::new([seed; 32]);

    // Pre-seed the backlog with a bidirectional request
    let (request, _args, _root_sk) = build_solana_to_ethereum_bidirectional_request(seed);
    let program_id_bytes = match &request.kind {
        mpc_primitives::SignKind::SignBidirectional(event) => event.chain_ctx.clone(),
        _ => unreachable!("helper always produces a SignBidirectional request"),
    };
    backlog.insert(request).await;

    // Register an execution watcher for the derived bidirectional tx on the target chain (Ethereum)
    let tx = test_bidirectional_tx(seed, Chain::Solana, Chain::Ethereum);
    let tx_id = tx.id;
    backlog.watch_execution(Chain::Ethereum, sign_id, tx).await;

    let (sign_tx, mut sign_rx) = mpsc::channel(8);
    let ctx = crate::stream::test_utils::make_test_stream_context_with_generator_pk(
        backlog.clone(),
        sign_tx,
        true,
    );

    crate::stream::ops::process_execution_confirmed(
        tx_id,
        sign_id,
        Chain::Solana,
        123u64,
        ExecutionOutcome::Success { output: vec![] },
        &ctx,
        Chain::Ethereum,
    )
    .await
    .expect("execution confirmation should advance to a RespondBidirectional request");

    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg {
        SignCommand::Request(req) => {
            assert_eq!(
                req.id, sign_id,
                "follow-up request should reuse the sign id"
            );
            match req.kind {
                SignKind::RespondBidirectional(rb) => {
                    assert_eq!(rb.tx_id, tx_id, "tx_id should match the watched tx");
                    assert_eq!(
                        rb.chain_ctx, program_id_bytes,
                        "chain_ctx should be forwarded from the originating request",
                    );
                }
                other => panic!("expected RespondBidirectional, got {other:?}"),
            }
        }
        other => panic!("expected SignCommand::Request, got {other:?}"),
    }

    // The watcher should have been consumed by the handler.
    assert!(
        ctx.backlog
            .get_execution_watchers(Chain::Ethereum)
            .await
            .is_empty(),
        "execution watcher should be removed after confirmation"
    );
}

#[tokio::test]
async fn test_stream_suppresses_pre_catchup_ethereum_completion() {
    let storage = CheckpointStorage::in_memory();
    let seeded_backlog = Backlog::persisted(storage.clone());
    let sign_id = SignId::new([99u8; 32]);
    let args = test_sign_args(9);

    seeded_backlog
        .insert(IndexedSignRequest::sign(
            sign_id,
            args.clone(),
            Chain::Ethereum,
            current_unix_timestamp(),
        ))
        .await;
    seeded_backlog
        .set_processed_block(Chain::Ethereum, 100)
        .await;
    seeded_backlog.checkpoint(Chain::Ethereum).await;

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let root_pk = root_sk.public_key().to_projective().to_affine();
    let mpc_sig = mpc_crypto::generate_signature(&root_sk, &args);

    let respond = signature_responded_event(sign_id, mpc_sig, Chain::Ethereum);

    let indexer = EthereumTestIndexer::new(vec![
        Some(ChainEvent::Respond(respond)),
        Some(ChainEvent::CatchupCompleted),
        None,
    ]);

    let backlog = Backlog::persisted(storage);
    let (sign_tx, mut sign_rx) = mpsc::channel(8);

    run_stream_with_two_node_mesh(indexer, sign_tx, backlog.clone(), root_pk).await;

    match timeout(Duration::from_millis(100), sign_rx.recv()).await {
        Err(_) | Ok(None) => {}
        Ok(Some(msg)) => panic!("unexpected sign message during catchup: {msg:?}"),
    }
    assert!(backlog.get(Chain::Ethereum, &sign_id).await.is_none());
}

#[tokio::test]
async fn test_stream_requeues_replaced_ethereum_recovery_entry_after_catchup() {
    let storage = CheckpointStorage::in_memory();
    let seeded_backlog = Backlog::persisted(storage.clone());
    let sign_id = SignId::new([100u8; 32]);
    let args = test_sign_args(5);
    let recovered_timestamp = current_unix_timestamp();
    let replayed_timestamp = recovered_timestamp.saturating_add(1);

    seeded_backlog
        .insert(IndexedSignRequest::sign(
            sign_id,
            args.clone(),
            Chain::Ethereum,
            recovered_timestamp,
        ))
        .await;
    seeded_backlog
        .set_processed_block(Chain::Ethereum, 100)
        .await;
    seeded_backlog.checkpoint(Chain::Ethereum).await;

    let replacement =
        IndexedSignRequest::sign(sign_id, args.clone(), Chain::Ethereum, replayed_timestamp);
    let indexer = EthereumTestIndexer::new(vec![
        Some(ChainEvent::SignRequest {
            request: replacement,
            block_timestamp: None,
        }),
        Some(ChainEvent::CatchupCompleted),
        None,
    ]);

    let backlog = Backlog::persisted(storage);
    let (sign_tx, mut sign_rx) = mpsc::channel(8);

    run_stream_with_two_node_mesh(
        indexer,
        sign_tx,
        backlog.clone(),
        k256::ProjectivePoint::GENERATOR.to_affine(),
    )
    .await;

    let msg = timeout(Duration::from_secs(1), sign_rx.recv())
        .await
        .expect("recv should not timeout")
        .expect("replacement request should be requeued");
    match msg {
        SignCommand::Request(req) => {
            assert_eq!(req.id, sign_id);
            assert_eq!(req.unix_timestamp_indexed, replayed_timestamp);
        }
        other => panic!("expected replacement request after catchup, got {other:?}"),
    }

    let entry = backlog
        .get(Chain::Ethereum, &sign_id)
        .await
        .expect("replayed entry should remain in backlog");
    assert_eq!(entry.request.unix_timestamp_indexed, replayed_timestamp);
}

#[tokio::test]
async fn test_stream_resumes_pending_publish_after_catchup() {
    use crate::sign_bidirectional::SignStatus;

    let backlog = Backlog::new();
    let sign_id = SignId::new([77u8; 32]);
    let signature = Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0);

    backlog
        .insert(IndexedSignRequest::sign(
            sign_id,
            test_sign_args(9),
            Chain::Solana,
            current_unix_timestamp(),
        ))
        .await;
    backlog
        .set_status(
            Chain::Solana,
            &sign_id,
            SignStatus::PendingPublish {
                publish: crate::sign_bidirectional::PublishState {
                    signature,
                    participants: vec![cait_sith::protocol::Participant::from(0u32)],
                    is_proposer: true,
                },
            },
        )
        .await;

    let indexer = SolanaTestIndexer::new(vec![Some(ChainEvent::CatchupCompleted), None]);
    let (sign_tx, mut sign_rx) = mpsc::channel(4);
    let (rpc, mut rpc_rx) = test_rpc_channel(4);
    let (contract_watcher, _tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        k256::ProjectivePoint::GENERATOR.to_affine(),
        0,
        Default::default(),
    );
    let (_mesh_state_tx, mesh_state_rx) = watch::channel(MeshState::default());
    let (_cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());

    let run_handle = tokio::spawn(async move {
        run_supervised(
            indexer,
            crate::stream::StreamContext::new(
                backlog,
                sign_tx,
                rpc,
                contract_watcher,
                mesh_state_rx,
                node_client,
                cp_rx,
            ),
            mpc_chain_integration_core::NoopChainTelemetry,
        )
        .await;
    });

    match timeout(Duration::from_millis(100), sign_rx.recv()).await {
        Err(_) | Ok(None) => {}
        Ok(Some(msg)) => panic!("unexpected sign message during publish resume: {msg:?}"),
    }

    let action = timeout(Duration::from_secs(1), rpc_rx.recv())
        .await
        .expect("publish resume should not timeout")
        .expect("publish resume should enqueue an RPC action");
    match action {
        RpcAction::Publish(action) => {
            assert_eq!(action.request.id, sign_id);
            assert_eq!(action.request.chain, Chain::Solana);
            assert_eq!(action.signature, signature);
        }
    }

    run_handle.abort();
}

#[tokio::test]
async fn test_stream_does_not_resume_non_proposer_pending_publish_after_catchup() {
    use crate::sign_bidirectional::SignStatus;

    let backlog = Backlog::new();
    let sign_id = SignId::new([78u8; 32]);
    let signature = Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0);

    backlog
        .insert(IndexedSignRequest::sign(
            sign_id,
            test_sign_args(10),
            Chain::Solana,
            current_unix_timestamp(),
        ))
        .await;
    backlog
        .set_status(
            Chain::Solana,
            &sign_id,
            SignStatus::PendingPublish {
                publish: crate::sign_bidirectional::PublishState {
                    signature,
                    participants: vec![cait_sith::protocol::Participant::from(0u32)],
                    is_proposer: false,
                },
            },
        )
        .await;

    let indexer = SolanaTestIndexer::new(vec![Some(ChainEvent::CatchupCompleted), None]);
    let (sign_tx, _sign_rx) = mpsc::channel(4);
    let (rpc, mut rpc_rx) = test_rpc_channel(4);
    let (contract_watcher, _tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        k256::ProjectivePoint::GENERATOR.to_affine(),
        0,
        Default::default(),
    );
    let (_mesh_state_tx, mesh_state_rx) = watch::channel(MeshState::default());
    let (_cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());

    let run_handle = tokio::spawn(async move {
        run_supervised(
            indexer,
            crate::stream::StreamContext::new(
                backlog,
                sign_tx,
                rpc,
                contract_watcher,
                mesh_state_rx,
                node_client,
                cp_rx,
            ),
            mpc_chain_integration_core::NoopChainTelemetry,
        )
        .await;
    });

    let no_publish = timeout(Duration::from_millis(100), rpc_rx.recv()).await;
    assert!(matches!(no_publish, Err(_) | Ok(None)));

    run_handle.abort();
}
