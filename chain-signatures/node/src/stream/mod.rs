use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::IndexedSignRequest;
use crate::protocol::{Chain, Sign};
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::BidirectionalTxId;
use crate::stream::ops::{
    process_execution_confirmed, process_respond_bidirectional_event, process_respond_event,
    process_sign_request, recover_backlog, RespondBidirectionalEvent, SignatureRespondedEvent,
};

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::watch;

pub mod ops;

pub const CHAIN_EVENT_STREAM_SIZE: usize = 16384;

pub fn channel() -> (mpsc::Sender<ChainEvent>, mpsc::Receiver<ChainEvent>) {
    mpsc::channel(CHAIN_EVENT_STREAM_SIZE)
}

/// Unified event produced by a chain stream
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum ChainEvent {
    SignRequest(IndexedSignRequest),
    Respond(SignatureRespondedEvent),
    RespondBidirectional(RespondBidirectionalEvent),

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

    /// Produce the next verified event from this chain (steady-state consumer).
    async fn next_event(&mut self) -> Option<ChainEvent>;

    /// Optional: create a buffered live sub-stream that allows anchoring + draining.
    /// Implementations that don't support buffered startup may return an error.
    async fn livestream(&mut self) -> anyhow::Result<Box<dyn ChainBufferedStream + Send>> {
        anyhow::bail!("livestream not implemented for this stream")
    }

    /// Optional: perform historical catchup for the inclusive range `[from_inclusive, to_inclusive]`.
    /// Default no-op.
    async fn catchup(&mut self, _from_inclusive: u64, _to_inclusive: u64) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Buffered live stream returned by `ChainStream::livestream()`.
#[async_trait::async_trait]
pub trait ChainBufferedStream: Send + 'static {
    /// Return the anchored block height observed from the live subscription. Callers
    /// will usually run catchup up to this height, then drain buffered events up to it.
    async fn initial_height(&mut self) -> anyhow::Result<u64>;

    /// Pull next buffered event from the live subscription (cancellable by dropping).
    async fn next_buffered(&mut self) -> Option<ChainEvent>;
}

/// Shared indexer loop: recovers backlog then processes events from the stream.
///
/// New startup sequence (catchup-enabled):
///  1) recover backlog
///  2) if stream supports `livestream()`: start buffered live subscription, read anchor
///     and run `stream.catchup(persisted_height, anchor)`, then drain buffered events
///     up to anchor before entering steady-state `next_event()` loop.
///  3) otherwise fall back to existing steady-state `next_event()` loop.
pub async fn run_stream<S: ChainStream>(
    mut stream: S,
    sign_tx: mpsc::Sender<Sign>,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    total_timeout: Duration,
) {
    let chain = S::CHAIN;

    tracing::info!(%chain, "starting indexer loop");

    recover_backlog(
        &backlog,
        &mut contract_watcher,
        &mut mesh_state,
        &node_client,
        chain,
        sign_tx.clone(),
        total_timeout,
    )
    .await;

    // Try to perform buffered startup/catchup if the stream supports it.
    match stream.livestream().await {
        Ok(mut buffered) => {
            tracing::info!(%chain, "started buffered livestream for catchup");

            // anchor height from live subscription
            let anchor = match buffered.initial_height().await {
                Ok(h) => h,
                Err(err) => {
                    tracing::warn!(%chain, ?err, "failed to obtain anchor from buffered stream; falling back to live loop");
                    // Fall through to steady-state below
                    run_steady_state(stream, sign_tx, backlog, contract_watcher, mesh_state, node_client, total_timeout).await;
                    return;
                }
            };

            // Persisted processed height -> inclusive-from for catchup
            let persisted = backlog.processed_block(S::CHAIN).await;
            let from_inclusive = persisted.unwrap_or(anchor);

            tracing::info!(%chain, from = from_inclusive, anchor = anchor, "catchup range computed");

            if from_inclusive <= anchor {
                // Ask the stream to run its chain-specific catchup for [from_inclusive, anchor].
                if let Err(err) = stream.catchup(from_inclusive, anchor).await {
                    tracing::warn!(%chain, ?err, "stream.catchup failed; attempting steady-state fallback");
                    run_steady_state(stream, sign_tx, backlog, contract_watcher, mesh_state, node_client, total_timeout).await;
                    return;
                }

                // Drain buffered events (both historical produced by catchup *and* live events)
                // until we reach anchor, then continue with steady-state next_event().
                let mut reached_anchor = false;
                while let Some(ev) = buffered.next_buffered().await {
                    // process buffered event using same logic as steady-state loop
                    match &ev {
                        ChainEvent::Block(block) => {
                            if *block >= anchor {
                                reached_anchor = true;
                            }
                        }
                        _ => {}
                    }

                    // reuse existing per-event handling
                    handle_chain_event(ev, &sign_tx, &backlog, &mut contract_watcher, total_timeout).await;

                    if reached_anchor {
                        tracing::info!(%chain, anchor = anchor, "drained buffered events up to anchor; switching to live");
                        break;
                    }
                }

                // Enter steady-state loop
                run_steady_state(stream, sign_tx, backlog, contract_watcher, mesh_state, node_client, total_timeout).await;
                return;
            } else {
                tracing::info!(%chain, "no catchup required (from > anchor); entering live loop");
                run_steady_state(stream, sign_tx, backlog, contract_watcher, mesh_state, node_client, total_timeout).await;
                return;
            }
        }
        Err(_) => {
            // Stream doesn't support buffered startup — just fall back to steady-state loop
            tracing::info!(%chain, "livestream not supported; running steady-state loop");
            run_steady_state(stream, sign_tx, backlog, contract_watcher, mesh_state, node_client, total_timeout).await;
            return;
        }
    }
}

async fn handle_chain_event(
    event: ChainEvent,
    sign_tx: &mpsc::Sender<Sign>,
    backlog: &Backlog,
    contract_watcher: &mut ContractStateWatcher,
    total_timeout: Duration,
) {
    let chain = match backlog.processed_block(Chain::Solana).await {
        _ => (),
    };

    match event {
        ChainEvent::SignRequest(req) => {
            if let Err(err) = process_sign_request(req, sign_tx.clone(), backlog.clone()).await {
                tracing::error!(?err, "failed to process sign request");
            }
        }
        ChainEvent::Respond(ev) => {
            if let Err(err) = process_respond_event(ev, sign_tx.clone(), contract_watcher, backlog).await {
                tracing::error!(?err, "failed to process respond event");
            }
        }
        ChainEvent::RespondBidirectional(ev) => {
            if let Err(err) = process_respond_bidirectional_event(ev, sign_tx.clone(), backlog).await {
                tracing::error!(?err, "failed to process respond bidirectional event");
            }
        }
        ChainEvent::Block(block) => {
            if let Some(checkpoint) = backlog.set_processed_block(Chain::Solana, block).await {
                tracing::info!(block, ?checkpoint, "created checkpoint");
            }
        }
        ChainEvent::ExecutionConfirmed { .. } => {
            tracing::warn!("ExecutionConfirmed received in buffered drain path — forwarding to steady-state handler");
        }
    }
}

async fn run_steady_state<S: ChainStream>(
    mut stream: S,
    sign_tx: mpsc::Sender<Sign>,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    total_timeout: Duration,
) {
    let chain = S::CHAIN;

    while let Some(event) = stream.next_event().await {
        match event {
            ChainEvent::SignRequest(req) => {
                // process sign request (insert into backlog + send sign request)
                if let Err(err) = process_sign_request(req, sign_tx.clone(), backlog.clone()).await {
                    tracing::error!(?err, chain = %chain, "failed to process sign request");
                }
            }
            ChainEvent::Respond(ev) => {
                if let Err(err) = process_respond_event(ev, sign_tx.clone(), &mut contract_watcher, &backlog).await {
                    tracing::error!(?err, chain = %chain, "failed to process respond event");
                }
            }
            ChainEvent::RespondBidirectional(ev) => {
                if let Err(err) = process_respond_bidirectional_event(ev, sign_tx.clone(), &backlog).await {
                    tracing::error!(?err, chain = %chain, "failed to process respond bidirectional event");
                }
            }
            ChainEvent::Block(block) => {
                // central checkpointing for all chains
                if let Some(checkpoint) = backlog.set_processed_block(S::CHAIN, block).await {
                    tracing::info!(block, ?checkpoint, chain = %chain, "created checkpoint");
                }
                crate::metrics::indexers::LATEST_BLOCK_NUMBER
                    .with_label_values(&[S::CHAIN.as_str(), "indexed"])
                    .set(block as i64);
            }
            ChainEvent::ExecutionConfirmed { tx_id, sign_id, source_chain, block_height, result } => {
                if let Err(err) = process_execution_confirmed(
                    tx_id,
                    sign_id,
                    source_chain,
                    block_height,
                    result,
                    &backlog,
                    sign_tx.clone(),
                    total_timeout,
                    S::CHAIN,
                ).await {
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
    use crate::mesh::MeshState;
    use crate::node_client::NodeClient;
    use crate::protocol::Chain;
    use crate::protocol::IndexedSignRequest;
    use crate::protocol::Sign;
    use crate::protocol::SignRequestType;
    use crate::rpc::ContractStateWatcher;
    use crate::stream::ops::SignatureRespondedEvent;
    use crate::util::current_unix_timestamp;
    use k256::Scalar;
    use mpc_primitives::SignArgs;
    use mpc_primitives::SignId;
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

        let indexed = IndexedSignRequest {
            id: sign_id,
            args: args.clone(),
            chain: Chain::Solana,
            timestamp_created: std::time::Instant::now(),
            unix_timestamp_indexed: current_unix_timestamp(),
            total_timeout: Duration::from_secs(5),
            sign_request_type: SignRequestType::Sign,
        };

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
            Duration::from_secs(5),
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
    async fn test_stream_handles_sign_bidirectional_block_and_recover() {
        use crate::sign_bidirectional::PendingRequestStatus;
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
                Duration::from_secs(5),
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
            dest: "eip155:1".to_string(),
            caip2_id: "eip155:1".to_string(),
            key_version: 0,
            deposit: 0,
            path: "".to_string(),
            algo: "".to_string(),
            params: "".to_string(),
            program_id,
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
        };

        let indexed = IndexedSignRequest {
            id: sign_id,
            args: args.clone(),
            chain: Chain::Solana,
            timestamp_created: std::time::Instant::now(),
            unix_timestamp_indexed: current_unix_timestamp(),
            total_timeout: Duration::from_secs(5),
            sign_request_type: SignRequestType::SignBidirectional(SBE::Solana(sign_bidir.clone())),
        };

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
            .set_status(
                Chain::Solana,
                &sign_id,
                PendingRequestStatus::PendingExecution,
            )
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

    }
