use super::*;
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
use mpc_chain_integration_core::{NoopChainTelemetry, StateManager};
use mpc_chain_solana::Pubkey;
use mpc_primitives::{
    Chain, CheckpointDigest, IndexedSignRequest, SignArgs, SignCommand, SignId, Signature,
};
use near_primitives::types::AccountId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

struct VecEventStreamState {
    started: bool,
    events: Vec<Option<ChainEvent>>,
}

impl VecEventStreamState {
    fn new(events: Vec<Option<ChainEvent>>) -> Self {
        Self {
            started: false,
            events,
        }
    }
}

macro_rules! impl_vec_event_stream {
    ($stream:ident, $indexer:ident, $chain:expr) => {
        struct $stream(VecEventStreamState);

        impl $stream {
            pub fn new(events: Vec<Option<ChainEvent>>) -> Self {
                Self(VecEventStreamState::new(events))
            }
        }

        struct $indexer {
            events_tx: Option<mpsc::Sender<ChainEvent>>,
        }

        impl $indexer {
            pub fn silent() -> Self {
                Self { events_tx: None }
            }
        }

        #[async_trait]
        impl ChainIndexer for $indexer {
            const CHAIN: Chain = $chain;

            type Block = ();
            type Iter = futures_util::stream::Empty<Self::Block>;

            async fn next(&mut self) -> Option<Self::Block> {
                None
            }

            async fn catchup_range(&self, _anchor_height: u64) -> Self::Iter {
                futures_util::stream::empty()
            }

            async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
                if let Some(events_tx) = &self.events_tx {
                    events_tx.send(ChainEvent::CatchupCompleted).await?;
                }

                Ok(())
            }
        }

        #[async_trait::async_trait]
        impl ChainStream for $stream {
            type Indexer = $indexer;

            async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
                self.0.started = true;
                Ok($indexer::silent())
            }

            async fn next_event(&mut self) -> Option<ChainEvent> {
                if self.0.events.is_empty() {
                    return None;
                }

                self.0.events.remove(0)
            }
        }
    };
}

impl_vec_event_stream!(SolanaTestStream, DisabledSolanaIndexer, Chain::Solana);
impl_vec_event_stream!(EthereumTestStream, DisabledEthereumIndexer, Chain::Ethereum);

#[derive(Clone)]
struct TestLinearControl {
    persisted_height: Option<u64>,
    live_items: Vec<u64>,
    catchup_failures: Arc<Mutex<HashMap<u64, usize>>>,
    live_failures: Arc<Mutex<HashMap<u64, usize>>>,
}

impl TestLinearControl {
    fn new(persisted_height: Option<u64>, live_items: Vec<u64>) -> Self {
        Self {
            persisted_height,
            live_items,
            catchup_failures: Arc::new(Mutex::new(HashMap::new())),
            live_failures: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn fail_catchup_once(self, height: u64) -> Self {
        self.catchup_failures.lock().unwrap().insert(height, 1);
        self
    }

    fn fail_live_once(self, height: u64) -> Self {
        self.live_failures.lock().unwrap().insert(height, 1);
        self
    }

    fn consume_failure(map: &Mutex<HashMap<u64, usize>>, height: u64) -> bool {
        let mut failures = map.lock().unwrap();
        let Some(remaining) = failures.get_mut(&height) else {
            return false;
        };
        if *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        true
    }
}

struct TestLinearStream {
    control: TestLinearControl,
    rx: mpsc::Receiver<ChainEvent>,
    tx: mpsc::Sender<ChainEvent>,
}

impl TestLinearStream {
    fn new(control: TestLinearControl) -> Self {
        let (tx, rx) = mpsc::channel(16);
        Self { control, rx, tx }
    }
}

struct TestLinearIndexer {
    control: TestLinearControl,
    tx: mpsc::Sender<ChainEvent>,
    live_items: Vec<u64>,
    pending_live_block: Option<u64>,
}

#[async_trait]
impl ChainIndexer for TestLinearIndexer {
    const CHAIN: Chain = Chain::Ethereum;
    type Block = u64;
    type Iter = futures_util::stream::Iter<std::vec::IntoIter<Self::Block>>;

    const RETRY_DELAY: Duration = Duration::from_millis(1);

    async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
        self.live_items = self.control.live_items.clone().into_iter().collect();
        Ok(self.control.live_items.first().copied())
    }

    async fn next(&mut self) -> Option<Self::Block> {
        if let Some(block) = self.pending_live_block {
            return Some(block);
        }

        let block = self.live_items.first().copied()?;
        self.pending_live_block = Some(block);
        Some(block)
    }

    async fn catchup_range(&self, anchor_height: u64) -> Self::Iter {
        let start = self
            .control
            .persisted_height
            .map(|height| height + 1)
            .unwrap_or(anchor_height);
        let items: Vec<Self::Block> = (start..anchor_height).collect();
        futures_util::stream::iter(items.into_iter())
    }

    async fn process_catchup(&mut self, &height: &Self::Block) -> anyhow::Result<()> {
        if TestLinearControl::consume_failure(&self.control.catchup_failures, height) {
            anyhow::bail!("synthetic catchup failure at height {height}");
        }
        self.tx.send(ChainEvent::Block(height)).await?;
        Ok(())
    }

    async fn process(&mut self, block: &Self::Block) -> anyhow::Result<()> {
        if TestLinearControl::consume_failure(&self.control.live_failures, *block) {
            anyhow::bail!("synthetic live failure at height {block}");
        }
        self.tx.send(ChainEvent::Block(*block)).await?;
        self.pending_live_block = None;
        if !self.live_items.is_empty() {
            self.live_items.remove(0);
        }
        Ok(())
    }
}

#[async_trait]
impl ChainStream for TestLinearStream {
    type Indexer = TestLinearIndexer;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
        Ok(TestLinearIndexer {
            control: self.control.clone(),
            tx: self.tx.clone(),
            live_items: Vec::new(),
            pending_live_block: None,
        })
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        self.rx.recv().await
    }
}

#[tokio::test]
async fn test_run_linearized_source_orders_catchup_before_live() {
    let mut stream = TestLinearStream::new(TestLinearControl::new(Some(1), vec![4, 5]));
    let mut indexer = stream.start().await.unwrap();
    indexer.livestream().await.unwrap();
    let (_cp_tx, cp_rx) = watch::channel(None);
    let (_m_tx, m_rx) = watch::channel(MeshState::default());
    let (pipeline, _state_rx) = ChainPipeline::from_state(
        ChainStreaming::Catchup { anchor_height: 4 },
        indexer,
        cp_rx,
        Backlog::new(),
        test_rpc_channel(1).0,
        m_rx,
        NodeClient::new(&Default::default()),
        0,
        "test.near".parse().unwrap(),
    );

    pipeline.run().await;

    let mut observed = Vec::new();
    while let Some(event) = timeout(Duration::from_millis(20), stream.next_event())
        .await
        .ok()
        .flatten()
    {
        observed.push(event);
    }

    assert!(matches!(observed[0], ChainEvent::Block(2)));
    assert!(matches!(observed[1], ChainEvent::Block(3)));
    assert!(matches!(observed[2], ChainEvent::Block(4)));
    assert!(matches!(observed[3], ChainEvent::Block(5)));
}

#[tokio::test]
async fn test_run_linearized_source_retries_without_reordering() {
    let mut stream = TestLinearStream::new(
        TestLinearControl::new(Some(1), vec![4, 5])
            .fail_catchup_once(3)
            .fail_live_once(4),
    );
    let mut indexer = stream.start().await.unwrap();
    indexer.livestream().await.unwrap();
    let (_cp_tx, cp_rx) = watch::channel(None);
    let (_m_tx, m_rx) = watch::channel(MeshState::default());
    let (pipeline, _state_rx) = ChainPipeline::from_state(
        ChainStreaming::Catchup { anchor_height: 4 },
        indexer,
        cp_rx,
        Backlog::new(),
        test_rpc_channel(1).0,
        m_rx,
        NodeClient::new(&Default::default()),
        0,
        "test.near".parse().unwrap(),
    );
    pipeline.run().await;

    let mut observed = Vec::new();
    while let Some(event) = timeout(Duration::from_millis(20), stream.next_event())
        .await
        .ok()
        .flatten()
    {
        observed.push(event);
    }

    assert!(matches!(observed[0], ChainEvent::Block(2)));
    assert!(matches!(observed[1], ChainEvent::Block(3)));
    assert!(matches!(observed[2], ChainEvent::Block(4)));
    assert!(matches!(observed[3], ChainEvent::Block(5)));
}

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
    let client = SolanaTestStream::new(vec![
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
    run_stream(
        client,
        StreamContext::new(
            backlog.clone(),
            sign_tx.clone(),
            rpc,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        ),
        NoopChainTelemetry,
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
    use mpc_primitives::SignBidirectionalEvent as SBE;

    let sign_id = SignId::new([seed; 32]);
    let args = test_sign_args(seed);

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

    let sign_bidir = SBE {
        sender: Default::default(),
        serialized_transaction: unsigned_rlp,
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
    let client = SolanaTestStream::new(vec![
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

    run_stream(
        client,
        StreamContext::new(
            backlog.clone(),
            sign_tx,
            rpc,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        ),
        NoopChainTelemetry,
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
    let client = SolanaTestStream::new(vec![
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

    run_stream(
        client,
        StreamContext::new(
            backlog.clone(),
            sign_tx,
            rpc,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        ),
        NoopChainTelemetry,
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

    let client = EthereumTestStream::new(vec![
        Some(ChainEvent::Respond(respond)),
        Some(ChainEvent::CatchupCompleted),
        None,
    ]);

    let backlog = Backlog::persisted(storage);
    let (sign_tx, mut sign_rx) = mpsc::channel(8);

    run_stream_with_two_node_mesh(client, sign_tx, backlog.clone(), root_pk).await;

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
    let client = EthereumTestStream::new(vec![
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
        client,
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

    let client = SolanaTestStream::new(vec![Some(ChainEvent::CatchupCompleted), None]);
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
        run_stream(
            client,
            StreamContext::new(
                backlog,
                sign_tx,
                rpc,
                contract_watcher,
                mesh_state_rx,
                node_client,
                cp_rx,
            ),
            NoopChainTelemetry,
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
        RpcAction::VoteCheckpoint(checkpoint) => {
            panic!("unexpected checkpoint vote: {checkpoint:?}");
        }
        RpcAction::AbortChain(chain) => {
            panic!("unexpected chain abort: {chain:?}");
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

    let client = SolanaTestStream::new(vec![Some(ChainEvent::CatchupCompleted), None]);
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
        run_stream(
            client,
            StreamContext::new(
                backlog,
                sign_tx,
                rpc,
                contract_watcher,
                mesh_state_rx,
                node_client,
                cp_rx,
            ),
            NoopChainTelemetry,
        )
        .await;
    });

    let no_publish = timeout(Duration::from_millis(100), rpc_rx.recv()).await;
    assert!(matches!(no_publish, Err(_) | Ok(None)));

    run_handle.abort();
}

#[tokio::test]
async fn test_recovery_transitions_to_catchup() {
    struct MockCatchupIndexer {
        catchup_started_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    #[async_trait]
    impl ChainIndexer for MockCatchupIndexer {
        const CHAIN: Chain = Chain::Solana;
        type Block = u64;
        type Iter = futures_util::stream::Iter<std::vec::IntoIter<Self::Block>>;
        const RETRY_DELAY: Duration = Duration::from_millis(1);

        async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
            Ok(Some(10))
        }

        async fn next(&mut self) -> Option<Self::Block> {
            None
        }

        async fn catchup_range(&self, _anchor_height: u64) -> Self::Iter {
            futures_util::stream::iter(vec![1].into_iter())
        }

        async fn process_catchup(&mut self, _block: &Self::Block) -> anyhow::Result<()> {
            if let Some(tx) = self.catchup_started_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let sign_id = SignId::new([111u8; 32]);
    let args = test_sign_args(1);

    backlog
        .insert(IndexedSignRequest::sign(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
        ))
        .await;
    backlog.set_processed_block(Chain::Solana, 5).await;
    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();

    let (_cp_tx, cp_rx) = watch::channel(Some(CheckpointDigest {
        height: checkpoint.block_height,
        digest: checkpoint.digest(),
    }));
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());

    let (catchup_tx, catchup_rx) = oneshot::channel();
    let indexer = MockCatchupIndexer {
        catchup_started_tx: Arc::new(Mutex::new(Some(catchup_tx))),
    };

    let (pipeline, state_rx) = ChainPipeline::new(
        indexer,
        cp_rx,
        backlog,
        test_rpc_channel(1).0,
        mesh_rx,
        NodeClient::new(&Default::default()),
        0,
        "test.near".parse().unwrap(),
    );
    let task_handle = tokio::spawn(pipeline.run());

    timeout(Duration::from_secs(1), catchup_rx)
        .await
        .expect("should reach catchup processing")
        .unwrap();

    let state = *state_rx.borrow();
    assert_eq!(state, ChainStreaming::Catchup { anchor_height: 10 });
    task_handle.abort();
}

#[tokio::test]
async fn test_runtime_regression_triggers_recovery() {
    struct MockLiveIndexer {
        next_called_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    #[async_trait]
    impl ChainIndexer for MockLiveIndexer {
        const CHAIN: Chain = Chain::Solana;
        type Block = u64;
        type Iter = futures_util::stream::Iter<std::vec::IntoIter<Self::Block>>;
        const RETRY_DELAY: Duration = Duration::from_millis(1);

        async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
            Ok(Some(10))
        }

        async fn next(&mut self) -> Option<Self::Block> {
            if let Some(tx) = self.next_called_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            std::future::pending::<Option<Self::Block>>().await
        }

        async fn catchup_range(&self, _anchor_height: u64) -> Self::Iter {
            futures_util::stream::iter(vec![].into_iter())
        }
    }

    let storage = CheckpointStorage::in_memory();
    let backlog = Backlog::persisted(storage.clone());
    let sign_id = SignId::new([222u8; 32]);
    let args = test_sign_args(2);

    backlog
        .insert(IndexedSignRequest::sign(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
        ))
        .await;
    backlog.set_processed_block(Chain::Solana, 10).await;
    let checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();
    let digest = checkpoint.digest();

    let (cp_tx, cp_rx) = watch::channel(Some(CheckpointDigest { height: 10, digest }));
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let (next_called_tx, next_called_rx) = oneshot::channel();
    let indexer = MockLiveIndexer {
        next_called_tx: Arc::new(Mutex::new(Some(next_called_tx))),
    };

    let (pipeline, mut state_rx) = ChainPipeline::from_state(
        ChainStreaming::Live,
        indexer,
        cp_rx,
        backlog,
        test_rpc_channel(1).0,
        mesh_rx,
        NodeClient::new(&Default::default()),
        1,
        "test.near".parse().unwrap(),
    );
    let task_handle = tokio::spawn(pipeline.run());

    timeout(Duration::from_secs(1), next_called_rx)
        .await
        .expect("should call next() in Live loop")
        .unwrap();

    let mismatched_digest = [99u8; 32];
    cp_tx
        .send(Some(CheckpointDigest {
            height: 8,
            digest: mismatched_digest,
        }))
        .unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            let s = *state_rx.borrow_and_update();
            if matches!(s, ChainStreaming::Recovery { .. }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("should transition back to Recovery state upon regression");

    task_handle.abort();
}

#[tokio::test]
async fn test_regression_triggers_full_recovery_cycle() {
    struct E2EIndexer;

    #[async_trait]
    impl ChainIndexer for E2EIndexer {
        const CHAIN: Chain = Chain::Ethereum;
        type Block = u64;
        type Iter = futures_util::stream::Empty<Self::Block>;
        const RETRY_DELAY: Duration = Duration::from_millis(1);

        async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
            Ok(Some(10))
        }

        async fn next(&mut self) -> Option<Self::Block> {
            std::future::pending::<Option<Self::Block>>().await
        }

        async fn catchup_range(&self, _anchor_height: u64) -> Self::Iter {
            futures_util::stream::empty()
        }
    }

    let chain = Chain::Ethereum;
    let backlog = Backlog::new();
    backlog.set_processed_block(chain, 10).await;
    let cp = backlog.checkpoint(chain).await.unwrap();
    let matching_digest = cp.digest();

    let (cp_tx, cp_rx) = watch::channel(Some(CheckpointDigest {
        height: 10,
        digest: matching_digest,
    }));
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let indexer = E2EIndexer;
    let (pipeline, mut state_rx) = ChainPipeline::new(
        indexer,
        cp_rx,
        backlog,
        test_rpc_channel(1).0,
        mesh_rx,
        NodeClient::new(&Default::default()),
        0,
        "test.near".parse().unwrap(),
    );

    let handle = tokio::spawn(pipeline.run());

    // 1st cycle: Recovery (load_local: true) → Catchup → Live
    timeout(Duration::from_secs(5), async {
        loop {
            if *state_rx.borrow() == ChainStreaming::Live {
                break;
            }
            let _ = state_rx.changed().await;
        }
    })
    .await
    .expect("should reach Live after 1st Recovery → Catchup");

    // Trigger regression: send a digest that doesn't match local.
    // This causes wait_detected_regression → Recovery { load_local: false }.
    cp_tx
        .send(Some(CheckpointDigest {
            height: 100,
            digest: [99u8; 32],
        }))
        .unwrap();

    timeout(Duration::from_secs(5), async {
        loop {
            let s = *state_rx.borrow_and_update();
            if matches!(s, ChainStreaming::Recovery { load_local: false }) {
                break;
            }
            let _ = state_rx.changed().await;
        }
    })
    .await
    .expect("should transition to Recovery { load_local: false } upon regression");

    // Restore matching digest so the 2nd Recovery passes alignment.
    // If align_backlog_with_consensus already read the mismatched value,
    // find_consensus_checkpoint will abort via consensus_rx.changed() when
    // it sees the digest change (may take ~3s due to no-peer retry sleep).
    cp_tx
        .send(Some(CheckpointDigest {
            height: 10,
            digest: matching_digest,
        }))
        .unwrap();

    // 2nd cycle: Recovery (load_local: false) → Catchup → Live
    timeout(Duration::from_secs(6), async {
        loop {
            if *state_rx.borrow() == ChainStreaming::Live {
                break;
            }
            let _ = state_rx.changed().await;
        }
    })
    .await
    .expect("should reach Live after 2nd Recovery → Catchup (load_local: false)");

    handle.abort();
}
