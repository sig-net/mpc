pub mod ops;
pub mod pipeline;

use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::{Chain, Sign};
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::stream::ops::{
    process_block_event, process_execution_confirmed, process_respond_bidirectional_event,
    process_respond_event, process_sign_request, requeue_pending_sign_requests,
    resume_pending_publish_requests,
};
pub use crate::stream::pipeline::ChainPipeline;

use async_trait::async_trait;
use futures_util::Stream;
use mpc_primitives::{ChainEvent, ChainTelemetry, CheckpointDigest};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

pub const CHAIN_EVENT_STREAM_SIZE: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStreaming {
    Recovery { load_local: bool },
    Catchup { anchor_height: u64 },
    Live,
}

pub fn channel() -> (mpsc::Sender<ChainEvent>, mpsc::Receiver<ChainEvent>) {
    mpsc::channel(CHAIN_EVENT_STREAM_SIZE)
}

#[async_trait]
pub trait ChainIndexer: Send + 'static {
    const CHAIN: Chain;
    type Block: Send;
    type Iter: Stream<Item = Self::Block> + Send + Unpin + 'static;

    const RETRY_DELAY: Duration = Duration::from_millis(500);

    async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
        Ok(None)
    }

    async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn catchup_range(&self, anchor_height: u64) -> Self::Iter;

    async fn process_catchup(&mut self, item: &Self::Block) -> anyhow::Result<()> {
        let _ = item;
        Ok(())
    }

    async fn next(&mut self) -> Option<Self::Block> {
        None
    }

    async fn process(&mut self, block: &Self::Block) -> anyhow::Result<()> {
        let _ = block;
        Ok(())
    }

    /// Process the next block, return true for success, false for shutdown.
    async fn process_next_block(&mut self) -> bool {
        let Some(block) = self.next().await else {
            return false;
        };

        while let Err(err) = self.process(&block).await {
            tracing::warn!(?err, "live block processing failed; retrying");
            tokio::time::sleep(Self::RETRY_DELAY).await;
        }
        true
    }
}

#[async_trait]
pub trait ChainStream: Send + 'static {
    type Indexer: ChainIndexer + Send;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer>;
    async fn next_event(&mut self) -> Option<ChainEvent>;
}

/// Shared indexer loop: recovers backlog then processes events from the stream
#[allow(clippy::too_many_arguments)]
pub async fn run_stream<S: ChainStream, T: ChainTelemetry>(
    mut stream: S,
    sign_tx: mpsc::Sender<Sign>,
    rpc: RpcChannel,
    backlog: Backlog,
    telemetry: T,
    mut contract_watcher: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    checkpoints_rx: watch::Receiver<CheckpointDigest>,
) {
    let chain = S::Indexer::CHAIN;
    tracing::info!(%chain, "starting stream");

    let threshold = contract_watcher.wait_threshold().await;

    let indexer = match stream.start().await {
        Ok(indexer) => indexer,
        Err(err) => {
            tracing::error!(?err, %chain, "failed to start stream");
            return;
        }
    };

    let (pipeline, mut state_rx) = ChainPipeline::new(
        indexer,
        checkpoints_rx.clone(),
        backlog.clone(),
        mesh_state.clone(),
        node_client,
        threshold,
        contract_watcher.account_id().clone(),
    );
    let indexer_task = tokio::spawn(pipeline.run());

    let root_pk = contract_watcher.wait_public_key().await;

    let mut caught_up = false;
    loop {
        tokio::select! {
            event = stream.next_event() => {
                let Some(event) = event else {
                    break;
                };
                match event {
                    ChainEvent::CatchupCompleted => {
                        if caught_up {
                            continue;
                        }
                        caught_up = true;

                        requeue_pending_sign_requests(&backlog, chain, sign_tx.clone()).await;
                        resume_pending_publish_requests(&backlog, chain, &contract_watcher, &rpc).await;
                    }
                    ChainEvent::SignRequest(req) => {
                        if let Err(err) =
                            process_sign_request(req, sign_tx.clone(), backlog.clone(), caught_up).await
                        {
                            tracing::error!(?err, %chain, "failed to process sign request");
                        }
                    }
                    ChainEvent::Respond(ev) => {
                        if let Err(err) = process_respond_event(
                            ev,
                            sign_tx.clone(),
                            root_pk,
                            &backlog,
                            caught_up,
                        )
                        .await
                        {
                            tracing::error!(?err, %chain, "failed to process respond event");
                        }
                    }
                    ChainEvent::RespondBidirectional(ev) => {
                        if let Err(err) =
                            process_respond_bidirectional_event(ev, sign_tx.clone(), root_pk, &backlog, caught_up)
                                .await
                        {
                            tracing::error!(?err, %chain, "failed to process respond bidirectional event");
                        }
                    }
                    ChainEvent::Block(block) => {
                        process_block_event(chain, block, &backlog, &sign_tx, caught_up, &telemetry).await;
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
                            chain,
                            caught_up,
                        )
                        .await
                        {
                            tracing::error!(?err, %chain, "failed to process execution confirmation");
                        }
                    }
                }
            }
            _ = state_rx.changed() => {
                let state = *state_rx.borrow_and_update();
                if matches!(state, ChainStreaming::Recovery { .. } | ChainStreaming::Catchup { .. }) {
                    caught_up = false;
                }
            }
        }
    }

    tracing::warn!(%chain, "stream shutting down");
    indexer_task.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use crate::mesh::{connection::NodeStatus, MeshState};
    use crate::node_client::NodeClient;
    use crate::protocol::{ParticipantInfo, Sign};
    use crate::rpc::{ContractStateWatcher, RpcAction, RpcChannel};
    use crate::storage::checkpoint_storage::CheckpointStorage;
    use crate::util::current_unix_timestamp;
    use k256::{AffinePoint, Scalar};
    use mockito::Server;
    use mpc_primitives::{
        CheckpointDigest, IndexedSignRequest, NoopChainTelemetry, SignArgs, SignId, Signature,
        SignatureRespondedEvent, StateManager,
    };
    use near_primitives::types::AccountId;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot, watch};
    use tokio::time::timeout;

    fn test_rpc_channel(buffer: usize) -> (RpcChannel, mpsc::Receiver<RpcAction>) {
        let (tx, rx) = mpsc::channel(buffer);
        (RpcChannel { tx }, rx)
    }

    use crate::kdf::valid_signature;

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

            #[async_trait]
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
        let (_cp_tx, cp_rx) = watch::channel(CheckpointDigest::default());
        let (_m_tx, m_rx) = watch::channel(MeshState::default());
        let (pipeline, _state_rx) = ChainPipeline::from_state(
            ChainStreaming::Catchup { anchor_height: 4 },
            indexer,
            cp_rx,
            Backlog::new(),
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
        let (_cp_tx, cp_rx) = watch::channel(CheckpointDigest::default());
        let (_m_tx, m_rx) = watch::channel(MeshState::default());
        let (pipeline, _state_rx) = ChainPipeline::from_state(
            ChainStreaming::Catchup { anchor_height: 4 },
            indexer,
            cp_rx,
            Backlog::new(),
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

        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let root_pk = root_sk.public_key().to_projective().to_affine();

        // Prepare a respond event that matches the sign id
        let mpc_sig = valid_signature(&root_sk, &args);
        let sig_responded = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature: mpc_sig,
            chain: Chain::Solana,
        };
        let client = SolanaTestStream::new(vec![
            Some(ChainEvent::CatchupCompleted),
            Some(ChainEvent::SignRequest(indexed.clone())),
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
        let (_cp_tx, cp_rx) = watch::channel(CheckpointDigest::default());
        let node_client = NodeClient::new(&Default::default());
        let (rpc, _rpc_rx) = test_rpc_channel(4);

        // Run the indexer
        run_stream(
            client,
            sign_tx.clone(),
            rpc,
            backlog.clone(),
            NoopChainTelemetry,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
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
        let _ = tracing_subscriber::fmt::try_init();
        use crate::sign_bidirectional::SignStatus;
        use mpc_primitives::SignBidirectionalEvent as SBE;

        // shared storage so checkpoint persistence is visible to recovered backlog
        let storage = crate::storage::checkpoint_storage::CheckpointStorage::in_memory();
        let backlog = Backlog::persisted(storage.clone());

        // client implemented with a channel so the test can control pacing
        struct LocalStream {
            rx: mpsc::Receiver<ChainEvent>,
        }

        #[async_trait]
        impl ChainStream for LocalStream {
            type Indexer = DisabledChainIndexer;

            async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
                Ok(DisabledChainIndexer::silent())
            }

            async fn next_event(&mut self) -> Option<ChainEvent> {
                self.rx.recv().await
            }
        }

        pub struct DisabledChainIndexer {
            events_tx: Option<mpsc::Sender<ChainEvent>>,
        }

        impl DisabledChainIndexer {
            pub fn silent() -> Self {
                Self { events_tx: None }
            }
        }

        #[async_trait]
        impl ChainIndexer for DisabledChainIndexer {
            const CHAIN: Chain = Chain::Solana;
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

        let (events_tx, rx) = mpsc::channel(8);
        let client = LocalStream { rx };

        let (sign_tx, mut sign_rx) = mpsc::channel(8);

        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let root_pk = root_sk.public_key().to_projective().to_affine();

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            root_pk,
            0,
            Default::default(),
        );
        let (_mesh_state_tx, mesh_state_rx) = watch::channel(MeshState::default());
        let (_cp_tx, cp_rx) = watch::channel(CheckpointDigest::default());
        let node_client = NodeClient::new(&Default::default());
        let (rpc, _rpc_rx) = test_rpc_channel(8);

        // Start indexer in background (clone backlog so the test retains ownership)
        let backlog_for_run = backlog.clone();
        let sign_tx_for_run = sign_tx.clone();
        let run_handle = tokio::spawn(async move {
            run_stream(
                client,
                sign_tx_for_run,
                rpc,
                backlog_for_run,
                NoopChainTelemetry,
                contract_watcher,
                mesh_state_rx,
                node_client,
                cp_rx,
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
            chain_ctx: Some(program_id.to_bytes().to_vec()),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        };

        let indexed = IndexedSignRequest::sign_bidirectional(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
            sign_bidir,
        );

        events_tx.send(ChainEvent::CatchupCompleted).await.unwrap();

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

        let mpc_sig = valid_signature(&root_sk, &args);

        backlog
            .set_status(
                Chain::Solana,
                &sign_id,
                SignStatus::PendingPublish {
                    publish: crate::sign_bidirectional::PublishState {
                        signature: mpc_sig,
                        participants: vec![cait_sith::protocol::Participant::from(0u32)],
                        is_proposer: true,
                    },
                },
            )
            .await;

        // Prepare a SignatureRespondedEvent that will advance to bidirectional and register watcher
        let sig_responded = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature: mpc_sig,
            chain: Chain::Solana,
        };
        events_tx
            .send(ChainEvent::Respond(sig_responded))
            .await
            .unwrap();

        // wait for the indexer to register an execution watcher for the target chain
        let target_chain = Chain::Ethereum;
        timeout(Duration::from_secs(1), async {
            loop {
                let watchers = backlog.get_execution_watchers(target_chain).await;
                if watchers.values().any(|(s, _)| *s == sign_id) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        // mark status as PendingExecution so it will be included in checkpoints
        let execution = backlog
            .get_execution_watchers(target_chain)
            .await
            .into_iter()
            .find_map(|(_, (watched_sign_id, watched_tx))| {
                (watched_sign_id == sign_id).then_some(watched_tx)
            })
            .expect("expected execution watcher to exist");
        let execution_id = execution.id;
        backlog
            .set_status(
                Chain::Solana,
                &sign_id,
                SignStatus::PendingExecution { tx: execution },
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

        let old_watchers = backlog.get_execution_watchers(target_chain).await;
        let new_watchers = recovered.get_execution_watchers(target_chain).await;
        assert_eq!(old_watchers.len(), new_watchers.len());
        for (tx_id, (s, _)) in old_watchers {
            assert!(new_watchers.contains_key(&tx_id));
            assert_eq!(new_watchers.get(&tx_id).unwrap().0, s);
        }

        // now send an execution confirmation event to advance to RespondBidirectional
        crate::stream::ops::process_execution_confirmed(
            execution_id,
            sign_id,
            Chain::Solana,
            block,
            mpc_primitives::ExecutionOutcome::Success { output: vec![] },
            &backlog,
            sign_tx.clone(),
            Chain::Ethereum,
            true,
        )
        .await
        .unwrap();

        // we should receive a Sign::Request because of the execution being confirmed
        let check = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(check);
        loop {
            tokio::select! {
                _ = &mut check => panic!("expected sign request for RespondBidirectional"),
                msg_req = sign_rx.recv() => match msg_req {
                    Some(Sign::Request(req)) => {
                        assert_eq!(req.id, sign_id);
                        break;
                    }
                    Some(Sign::Checkpoint(_)) => continue,
                    _ => panic!("expected sign request for RespondBidirectional"),
                }
            }
        }

        // Fetch the updated request from the backlog to get the new epsilon and payload
        let entry = backlog.get(Chain::Solana, &sign_id).await.unwrap();
        let new_args = &entry.request.args;
        let new_mpc_sig = valid_signature(&root_sk, new_args);

        // now send a RespondBidirectional event to complete the request
        // RespondBidirectional should also carry a valid signature
        let respond_bidirectional = mpc_primitives::RespondBidirectionalEvent {
            request_id: sign_id.request_id,
            signature: new_mpc_sig,
            chain: Chain::Solana,
        };
        events_tx
            .send(ChainEvent::RespondBidirectional(respond_bidirectional))
            .await
            .unwrap();

        // we should receive completion
        let mut msg2 = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        while matches!(msg2, Sign::Checkpoint(_)) {
            msg2 = timeout(Duration::from_secs(1), sign_rx.recv())
                .await
                .unwrap()
                .unwrap();
        }
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
    async fn test_stream_suppresses_pre_catchup_ethereum_completion() {
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

        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let root_pk = root_sk.public_key().to_projective().to_affine();
        let mpc_sig = valid_signature(&root_sk, &args);

        let respond = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature: mpc_sig,
            chain: Chain::Ethereum,
        };

        let client = EthereumTestStream::new(vec![
            Some(ChainEvent::Respond(respond)),
            Some(ChainEvent::CatchupCompleted),
            None,
        ]);

        let backlog = Backlog::persisted(storage);
        let (sign_tx, mut sign_rx) = mpsc::channel(8);

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            root_pk,
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
        let (_mesh_state_tx, mesh_state_rx) = watch::channel(mesh_state);
        let (_cp_tx, cp_rx) = watch::channel(CheckpointDigest::default());
        let node_client = NodeClient::new(&Default::default());
        let (rpc, _rpc_rx) = test_rpc_channel(8);

        run_stream(
            client,
            sign_tx,
            rpc,
            backlog.clone(),
            NoopChainTelemetry,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        )
        .await;

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

        let replacement =
            IndexedSignRequest::sign(sign_id, args.clone(), Chain::Ethereum, replayed_timestamp);
        let client = EthereumTestStream::new(vec![
            Some(ChainEvent::SignRequest(replacement)),
            Some(ChainEvent::CatchupCompleted),
            None,
        ]);

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
        let (_mesh_state_tx, mesh_state_rx) = watch::channel(mesh_state);
        let (_cp_tx, cp_rx) = watch::channel(CheckpointDigest::default());
        let node_client = NodeClient::new(&Default::default());
        let (rpc, _rpc_rx) = test_rpc_channel(8);

        run_stream(
            client,
            sign_tx,
            rpc,
            backlog.clone(),
            NoopChainTelemetry,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        )
        .await;

        let msg = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .expect("recv should not timeout")
            .expect("replacement request should be requeued");
        match msg {
            Sign::Request(req) => {
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
                SignArgs {
                    entropy: [9u8; 32],
                    epsilon: Scalar::from(1u64),
                    payload: Scalar::from(2u64),
                    path: "test".to_string(),
                    key_version: 1,
                },
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
        let (_cp_tx, cp_rx) = watch::channel(CheckpointDigest::default());
        let node_client = NodeClient::new(&Default::default());

        let run_handle = tokio::spawn(async move {
            run_stream(
                client,
                sign_tx,
                rpc,
                backlog,
                NoopChainTelemetry,
                contract_watcher,
                mesh_state_rx,
                node_client,
                cp_rx,
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
                assert_eq!(action.indexed.id, sign_id);
                assert_eq!(action.indexed.chain, Chain::Solana);
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
                SignArgs {
                    entropy: [10u8; 32],
                    epsilon: Scalar::from(1u64),
                    payload: Scalar::from(2u64),
                    path: "test".to_string(),
                    key_version: 1,
                },
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
        let (_cp_tx, cp_rx) = watch::channel(CheckpointDigest::default());
        let node_client = NodeClient::new(&Default::default());

        let run_handle = tokio::spawn(async move {
            run_stream(
                client,
                sign_tx,
                rpc,
                backlog,
                NoopChainTelemetry,
                contract_watcher,
                mesh_state_rx,
                node_client,
                cp_rx,
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
        let args = SignArgs {
            entropy: [1u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        backlog
            .insert(IndexedSignRequest::sign(
                sign_id,
                args.clone(),
                Chain::Solana,
                current_unix_timestamp(),
            ))
            .await;
        backlog.set_processed_block(Chain::Solana, 5).await;
        let checkpoint = backlog.checkpoint(Chain::Solana).await;

        let (_cp_tx, cp_rx) = watch::channel(CheckpointDigest {
            height: 5,
            digest: checkpoint.digest(),
        });
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());

        let (catchup_tx, catchup_rx) = oneshot::channel();
        let indexer = MockCatchupIndexer {
            catchup_started_tx: Arc::new(Mutex::new(Some(catchup_tx))),
        };

        let (pipeline, state_rx) = ChainPipeline::new(
            indexer,
            cp_rx,
            backlog,
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
        let args = SignArgs {
            entropy: [2u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        backlog
            .insert(IndexedSignRequest::sign(
                sign_id,
                args.clone(),
                Chain::Solana,
                current_unix_timestamp(),
            ))
            .await;
        backlog.set_processed_block(Chain::Solana, 10).await;
        let checkpoint = backlog.checkpoint(Chain::Solana).await;
        let digest = checkpoint.digest();

        let (cp_tx, cp_rx) = watch::channel(CheckpointDigest { height: 10, digest });
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
            .send(CheckpointDigest {
                height: 8,
                digest: mismatched_digest,
            })
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
}
