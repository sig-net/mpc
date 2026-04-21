use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::IndexedSignRequest;
use crate::protocol::{Chain, Sign};
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::BidirectionalTxId;
use crate::stream::ops::{
    process_execution_confirmed, process_respond_bidirectional_event, process_respond_event,
    process_sign_request, recover_backlog, requeue_recovered_sign_requests,
    RespondBidirectionalEvent, SignatureRespondedEvent,
};

use tokio::sync::mpsc;
use tokio::sync::watch;

pub mod ops;

pub const CHAIN_EVENT_STREAM_SIZE: usize = 16384;

pub fn channel() -> (mpsc::Sender<ChainEvent>, mpsc::Receiver<ChainEvent>) {
    mpsc::channel(CHAIN_EVENT_STREAM_SIZE)
}

/// Unified event produced by a chain stream
#[allow(clippy::large_enum_variant)]
pub enum ChainEvent {
    SignRequest(IndexedSignRequest),
    Respond(SignatureRespondedEvent),
    RespondBidirectional(RespondBidirectionalEvent),

    /// The stream has finished replaying catch-up data for this chain.
    CatchupCompleted,

    /// Block height indicating the client has observed/processed up to `u64` (slot/block)
    Block(u64),

    /// A watched bidirectional execution has been observed on the target chain.
    /// The client detected the execution, performed chain-specific extraction, and
    /// carries either the serialized output (Success) or a failure indicator.
    ExecutionConfirmed {
        tx_id: BidirectionalTxId,
        sign_id: mpc_primitives::SignId,
        source_chain: Chain,
        block_height: u64,
        result: ExecutionOutcome,
    },
}

impl std::fmt::Debug for ChainEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainEvent::SignRequest(r) => f
                .debug_tuple("SignRequest")
                .field(&r.id)
                .field(&r.chain.as_str())
                .finish(),
            ChainEvent::Respond(ev) => f
                .debug_tuple("Respond")
                .field(&ev.request_id())
                .field(&ev.source_chain().as_str())
                .finish(),
            ChainEvent::RespondBidirectional(ev) => f
                .debug_tuple("RespondBidirectional")
                .field(&ev.request_id())
                .field(&ev.source_chain().as_str())
                .finish(),
            ChainEvent::CatchupCompleted => f.debug_tuple("CatchupCompleted").finish(),
            ChainEvent::Block(b) => write!(f, "Block({b})"),
            ChainEvent::ExecutionConfirmed {
                tx_id,
                sign_id,
                source_chain,
                block_height,
                result,
            } => f
                .debug_struct("ExecutionConfirmed")
                .field("tx_id", tx_id)
                .field("sign_id", sign_id)
                .field("source_chain", source_chain)
                .field("block_height", block_height)
                .field("result", result)
                .finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ExecutionOutcome {
    Success { output: Vec<u8> },
    Failed,
}

#[allow(async_fn_in_trait)]
pub trait ChainStream: Send + 'static {
    const CHAIN: Chain;
    async fn start(&mut self) {}
    async fn next_event(&mut self) -> Option<ChainEvent>;
}

/// Shared indexer loop: recovers backlog then processes events from the stream
pub async fn run_stream<S: ChainStream>(
    mut stream: S,
    sign_tx: mpsc::Sender<Sign>,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) {
    let chain = S::CHAIN;

    tracing::info!(%chain, "starting indexer loop");

    let requeue_mode = recover_backlog(
        &backlog,
        &mut contract_watcher,
        &mut mesh_state,
        &node_client,
        chain,
        sign_tx.clone(),
    )
    .await;

    // NOTE: we need to start after we recover entries from backlog and starting the run_stream task
    // such that we can guarantee getting the CatchupCompleted event from this task to modify the
    // recovered entries.
    stream.start().await;

    while let Some(event) = stream.next_event().await {
        match event {
            ChainEvent::SignRequest(req) => {
                // process sign request (insert into backlog + send sign request)
                if let Err(err) = process_sign_request(req, sign_tx.clone(), backlog.clone()).await
                {
                    tracing::error!(?err, chain = %chain, "failed to process sign request");
                }
            }
            ChainEvent::Respond(ev) => {
                if let Err(err) =
                    process_respond_event(ev, sign_tx.clone(), &mut contract_watcher, &backlog)
                        .await
                {
                    tracing::error!(?err, chain = %chain, "failed to process respond event");
                }
            }
            ChainEvent::RespondBidirectional(ev) => {
                if let Err(err) =
                    process_respond_bidirectional_event(ev, sign_tx.clone(), &backlog).await
                {
                    tracing::error!(?err, chain = %chain, "failed to process respond bidirectional event");
                }
            }
            ChainEvent::CatchupCompleted => {
                if requeue_mode == crate::backlog::RecoveryRequeueMode::AfterCatchup {
                    requeue_recovered_sign_requests(&backlog, chain, sign_tx.clone()).await;
                }
            }
            ChainEvent::Block(block) => {
                // central checkpointing for all chains
                if let Some(checkpoint) = backlog.set_processed_block(S::CHAIN, block).await {
                    tracing::info!(block, ?checkpoint, chain = %chain, "created checkpoint");
                }
                crate::metrics::indexers::LATEST_BLOCK_NUMBER
                    .with_label_values(&[S::CHAIN.as_str(), "finalized"])
                    .set(block as i64);
            }
            ChainEvent::ExecutionConfirmed {
                tx_id,
                sign_id,
                source_chain,
                block_height,
                result,
            } => {
                if let Err(err) = process_execution_confirmed(
                    tx_id,
                    sign_id,
                    source_chain,
                    block_height,
                    result,
                    &backlog,
                    sign_tx.clone(),
                    S::CHAIN,
                )
                .await
                {
                    tracing::error!(?err, chain = %chain, "failed to process execution confirmation");
                }
            }
        }
    }

    tracing::warn!(%chain, "indexer shut down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use crate::mesh::{connection::NodeStatus, MeshState};
    use crate::node_client::NodeClient;
    use crate::protocol::ParticipantInfo;
    use crate::protocol::Sign;
    use crate::protocol::{Chain, IndexedSignRequest, SignKind};
    use crate::rpc::ContractStateWatcher;
    use crate::storage::checkpoint_storage::CheckpointStorage;
    use crate::stream::ops::{EthereumSignatureRespondedEvent, SignatureRespondedEvent};
    use crate::util::current_unix_timestamp;
    use alloy::primitives::Address;
    use k256::Scalar;
    use mockito::Server;
    use mpc_primitives::SignArgs;
    use mpc_primitives::SignId;
    use mpc_primitives::Signature;
    use near_primitives::types::AccountId;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    struct TestEventStream {
        events: Vec<Option<ChainEvent>>,
    }

    impl ChainStream for TestEventStream {
        const CHAIN: Chain = Chain::Solana;
        async fn next_event(&mut self) -> Option<ChainEvent> {
            if self.events.is_empty() {
                return None;
            }
            self.events.remove(0)
        }
    }

    #[tokio::test]
    async fn test_stream_handles_sign_and_respond() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([1u8; 32]);

        // construct an IndexedSignRequest
        let args = SignArgs {
            entropy: [0u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        let indexed = IndexedSignRequest::sign(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
        );

        // Prepare a respond event that matches the sign id
        let sig_responded =
            SignatureRespondedEvent::Solana(signet_program::SignatureRespondedEvent {
                request_id: sign_id.request_id,
                responder: solana_sdk::pubkey::Pubkey::new_unique(),
                signature: signet_program::Signature {
                    big_r: signet_program::AffinePoint {
                        x: [0u8; 32],
                        y: [0u8; 32],
                    },
                    s: [0u8; 32],
                    recovery_id: 0,
                },
            });
        let client = TestEventStream {
            events: vec![
                Some(ChainEvent::SignRequest(indexed.clone())),
                Some(ChainEvent::Respond(sig_responded)),
                None,
            ],
        };

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            0,
            Default::default(),
        );
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());

        // Run the indexer
        run_stream(
            client,
            sign_tx.clone(),
            backlog.clone(),
            contract_watcher,
            mesh_state_rx,
            node_client,
        )
        .await;

        // We should have received the Request then Completion
        let msg1 = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg1 {
            Sign::Request(req) => assert_eq!(req.id, sign_id),
            _ => panic!("expected request"),
        }

        let msg2 = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg2 {
            Sign::Completion(id) => assert_eq!(id, sign_id),
            _ => panic!("expected completion"),
        }
    }

    #[tokio::test]
    async fn test_run_stream_starts_stream_before_polling() {
        struct StartAwareStream {
            started: bool,
            event: Option<ChainEvent>,
        }

        impl ChainStream for StartAwareStream {
            const CHAIN: Chain = Chain::Solana;

            async fn start(&mut self) {
                self.started = true;
            }

            async fn next_event(&mut self) -> Option<ChainEvent> {
                assert!(self.started, "stream polled before start() was called");
                self.event.take()
            }
        }

        let backlog = Backlog::new();
        let sign_id = SignId::new([7u8; 32]);
        let args = SignArgs {
            entropy: [0u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
        let indexed = IndexedSignRequest {
            id: sign_id,
            args: args.clone(),
            chain: Chain::Solana,
            unix_timestamp_indexed: current_unix_timestamp(),
            kind: SignKind::Sign,
        };

        let stream = StartAwareStream {
            started: false,
            event: Some(ChainEvent::SignRequest(indexed)),
        };

        let (sign_tx, mut sign_rx) = mpsc::channel(4);
        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            0,
            Default::default(),
        );
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());

        run_stream(
            stream,
            sign_tx,
            backlog,
            contract_watcher,
            mesh_state_rx,
            node_client,
        )
        .await;

        match timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Sign::Request(req) => {
                assert_eq!(req.id, sign_id);
                assert_eq!(req.args, args);
            }
            other => panic!("expected request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_stream_handles_sign_bidirectional_block_and_recover() {
        use crate::sign_bidirectional::SignStatus;
        use crate::stream::ops::RespondBidirectionalEvent as RBE;
        use crate::stream::ops::SignBidirectionalEvent as SBE;
        use crate::stream::ops::SignatureRespondedEvent as SRE;
        use signet_program::SignBidirectionalEvent;

        // shared storage so checkpoint persistence is visible to recovered backlog
        let storage = crate::storage::checkpoint_storage::CheckpointStorage::in_memory();
        let backlog = Backlog::persisted(storage.clone());

        // client implemented with a channel so the test can control pacing
        struct LocalStream {
            rx: mpsc::Receiver<ChainEvent>,
        }

        impl ChainStream for LocalStream {
            const CHAIN: Chain = Chain::Solana;
            async fn next_event(&mut self) -> Option<ChainEvent> {
                self.rx.recv().await
            }
        }

        let (events_tx, rx) = mpsc::channel(8);
        let client = LocalStream { rx };

        let (sign_tx, mut sign_rx) = mpsc::channel(8);

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            0,
            Default::default(),
        );
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());

        // Start indexer in background (clone backlog so the test retains ownership)
        let backlog_for_run = backlog.clone();
        let run_handle = tokio::spawn(async move {
            run_stream(
                client,
                sign_tx,
                backlog_for_run,
                contract_watcher,
                mesh_state_rx,
                node_client,
            )
            .await;
        });

        // prepare a SignBidirectional request
        let sign_id = SignId::new([42u8; 32]);
        let args = SignArgs {
            entropy: [0u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
        let program_id = solana_sdk::pubkey::Pubkey::new_unique();
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

        let sign_bidir = SignBidirectionalEvent {
            sender: Default::default(),
            serialized_transaction: unsigned_rlp,
            dest: Chain::Ethereum.to_string(),
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 0,
            deposit: 0,
            path: "".to_string(),
            algo: "".to_string(),
            params: "".to_string(),
            program_id,
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
        };

        let indexed = IndexedSignRequest::sign_bidirectional(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
            SBE::Solana(sign_bidir.clone()),
        );

        // push SignRequest
        events_tx
            .send(ChainEvent::SignRequest(indexed.clone()))
            .await
            .unwrap();

        // we should receive a Sign::Request
        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Sign::Request(req) => assert_eq!(req.id, sign_id),
            _ => panic!("expected sign request"),
        }

        // Prepare a SignatureRespondedEvent that will advance to bidirectional and register watcher
        // Construct a valid signature (use generator point for big_r and small s)
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let enc = k256::ProjectivePoint::GENERATOR.to_encoded_point(false);
        let x_bytes = enc.x().unwrap().as_slice();
        let y_bytes = enc.y().unwrap().as_slice();
        let mut big_r_x = [0u8; 32];
        let mut big_r_y = [0u8; 32];
        big_r_x.copy_from_slice(x_bytes);
        big_r_y.copy_from_slice(y_bytes);
        let s_bytes = k256::Scalar::from(1u64).to_bytes();
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&s_bytes);

        let sig_responded = SRE::Solana(signet_program::SignatureRespondedEvent {
            request_id: sign_id.request_id,
            responder: solana_sdk::pubkey::Pubkey::new_unique(),
            signature: signet_program::Signature {
                big_r: signet_program::AffinePoint {
                    x: big_r_x,
                    y: big_r_y,
                },
                s: s_arr,
                recovery_id: 0,
            },
        });
        events_tx
            .send(ChainEvent::Respond(sig_responded))
            .await
            .unwrap();

        // wait for the indexer to register an execution watcher for the target chain
        let target_chain = Chain::Ethereum;
        timeout(Duration::from_secs(1), async {
            loop {
                let watchers = backlog.pending_execution(target_chain).await;
                if watchers.values().any(|(s, _)| *s == sign_id) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        // mark status as PendingExecution so it will be included in checkpoints
        backlog
            .set_status(Chain::Solana, &sign_id, SignStatus::PendingExecution)
            .await;

        // send a block event for this chain and ensure checkpoint is persisted
        let block = Chain::Solana.checkpoint_interval().unwrap_or(1);
        events_tx.send(ChainEvent::Block(block)).await.unwrap();

        // give the indexer a brief moment to persist the checkpoint
        tokio::time::sleep(Duration::from_millis(50)).await;
        let checkpoint = backlog
            .latest_checkpoint(Chain::Solana)
            .await
            .expect("checkpoint should exist");

        // recover into a new backlog and verify watchers restored
        let recovered = Backlog::persisted(storage.clone());
        recovered
            .recover_by_checkpoint(checkpoint.clone())
            .await
            .expect("recovery failed");

        let old_watchers = backlog.pending_execution(target_chain).await;
        let new_watchers = recovered.pending_execution(target_chain).await;
        assert_eq!(old_watchers.len(), new_watchers.len());
        for (tx_id, (s, _)) in old_watchers {
            assert!(new_watchers.contains_key(&tx_id));
            assert_eq!(new_watchers.get(&tx_id).unwrap().0, s);
        }

        // now send a RespondBidirectional event to complete the request
        // RespondBidirectional should also carry a valid signature
        let respond_bidirectional = RBE::Solana(signet_program::RespondBidirectionalEvent {
            request_id: sign_id.request_id,
            responder: solana_sdk::pubkey::Pubkey::new_unique(),
            serialized_output: vec![],
            signature: signet_program::Signature {
                big_r: signet_program::AffinePoint {
                    x: big_r_x,
                    y: big_r_y,
                },
                s: s_arr,
                recovery_id: 0,
            },
        });
        events_tx
            .send(ChainEvent::RespondBidirectional(respond_bidirectional))
            .await
            .unwrap();

        // we should receive completion
        let msg2 = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg2 {
            Sign::Completion(id) => assert_eq!(id, sign_id),
            _ => panic!("expected completion"),
        }

        // backlog entry should be removed
        assert!(backlog.get(Chain::Solana, &sign_id).await.is_none());

        // stop the client and wait for the indexer to finish
        drop(events_tx);
        run_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_stream_defers_local_ethereum_requeue_until_after_catchup() {
        let storage = CheckpointStorage::in_memory();
        let seeded_backlog = Backlog::persisted(storage.clone());
        let sign_id = SignId::new([99u8; 32]);
        let args = SignArgs {
            entropy: [9u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

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

        struct EthereumLocalStream {
            events: Vec<Option<ChainEvent>>,
        }

        impl ChainStream for EthereumLocalStream {
            const CHAIN: Chain = Chain::Ethereum;

            async fn next_event(&mut self) -> Option<ChainEvent> {
                if self.events.is_empty() {
                    return None;
                }
                self.events.remove(0)
            }
        }

        let respond = SignatureRespondedEvent::Ethereum(EthereumSignatureRespondedEvent {
            request_id: sign_id.request_id,
            responder: Address::ZERO,
            signature: Signature::new(k256::ProjectivePoint::GENERATOR.to_affine(), Scalar::ONE, 0),
        });

        let client = EthereumLocalStream {
            events: vec![
                Some(ChainEvent::Respond(respond)),
                Some(ChainEvent::CatchupCompleted),
                None,
            ],
        };

        let backlog = Backlog::persisted(storage);
        let (sign_tx, mut sign_rx) = mpsc::channel(8);

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            2,
            Default::default(),
        );

        let mut servers = Vec::new();
        for _ in 0..2 {
            let mut server = Server::new_async().await;
            let mut body = Vec::new();
            ciborium::ser::into_writer(
                &std::collections::HashMap::<Chain, crate::backlog::Checkpoint>::new(),
                &mut body,
            )
            .unwrap();
            server
                .mock("GET", "/checkpoint")
                .with_status(200)
                .with_body(body)
                .create_async()
                .await;
            servers.push(server);
        }

        let mut mesh_state = MeshState::default();
        for (index, server) in servers.iter().enumerate() {
            let mut info = ParticipantInfo::new(index as u32);
            info.url = server.url();
            mesh_state.update(
                cait_sith::protocol::Participant::from(index as u32),
                NodeStatus::Active,
                info,
            );
        }
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(mesh_state);
        let node_client = NodeClient::new(&Default::default());

        run_stream(
            client,
            sign_tx,
            backlog.clone(),
            contract_watcher,
            mesh_state_rx,
            node_client,
        )
        .await;

        let first = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match first {
            Sign::Completion(id) => assert_eq!(id, sign_id),
            other => panic!("expected completion before any recovered requeue, got {other:?}"),
        }

        match timeout(Duration::from_millis(100), sign_rx.recv()).await {
            Err(_) | Ok(None) => {}
            Ok(Some(msg)) => panic!("unexpected extra sign message after catchup: {msg:?}"),
        }
        assert!(backlog.get(Chain::Ethereum, &sign_id).await.is_none());
    }

    #[tokio::test]
    async fn test_stream_does_not_requeue_replaced_ethereum_recovery_entry_after_catchup() {
        let storage = CheckpointStorage::in_memory();
        let seeded_backlog = Backlog::persisted(storage.clone());
        let sign_id = SignId::new([100u8; 32]);
        let args = SignArgs {
            entropy: [5u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
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

        struct EthereumLocalStream {
            events: Vec<Option<ChainEvent>>,
        }

        impl ChainStream for EthereumLocalStream {
            const CHAIN: Chain = Chain::Ethereum;

            async fn next_event(&mut self) -> Option<ChainEvent> {
                if self.events.is_empty() {
                    return None;
                }
                self.events.remove(0)
            }
        }

        let replacement =
            IndexedSignRequest::sign(sign_id, args.clone(), Chain::Ethereum, replayed_timestamp);
        let client = EthereumLocalStream {
            events: vec![
                Some(ChainEvent::SignRequest(replacement)),
                Some(ChainEvent::CatchupCompleted),
                None,
            ],
        };

        let backlog = Backlog::persisted(storage);
        let (sign_tx, mut sign_rx) = mpsc::channel(8);

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            2,
            Default::default(),
        );

        let mut servers = Vec::new();
        for _ in 0..2 {
            let mut server = Server::new_async().await;
            let mut body = Vec::new();
            ciborium::ser::into_writer(
                &std::collections::HashMap::<Chain, crate::backlog::Checkpoint>::new(),
                &mut body,
            )
            .unwrap();
            server
                .mock("GET", "/checkpoint")
                .with_status(200)
                .with_body(body)
                .create_async()
                .await;
            servers.push(server);
        }

        let mut mesh_state = MeshState::default();
        for (index, server) in servers.iter().enumerate() {
            let mut info = ParticipantInfo::new(index as u32);
            info.url = server.url();
            mesh_state.update(
                cait_sith::protocol::Participant::from(index as u32),
                NodeStatus::Active,
                info,
            );
        }
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(mesh_state);
        let node_client = NodeClient::new(&Default::default());

        run_stream(
            client,
            sign_tx,
            backlog.clone(),
            contract_watcher,
            mesh_state_rx,
            node_client,
        )
        .await;

        let first = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match first {
            Sign::Request(req) => {
                assert_eq!(req.id, sign_id);
                assert_eq!(req.unix_timestamp_indexed, replayed_timestamp);
            }
            other => panic!("expected replayed sign request, got {other:?}"),
        }

        match timeout(Duration::from_millis(100), sign_rx.recv()).await {
            Err(_) | Ok(None) => {}
            Ok(Some(msg)) => panic!("unexpected extra sign message after catchup: {msg:?}"),
        }

        let entry = backlog
            .get(Chain::Ethereum, &sign_id)
            .await
            .expect("replayed entry should remain in backlog");
        assert_eq!(entry.request.unix_timestamp_indexed, replayed_timestamp);
    }
}
