use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::IndexedSignRequest;
use crate::protocol::{Chain, Sign};
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::sign_bidirectional::BidirectionalTxId;
use crate::stream::ops::{
    process_execution_confirmed, process_respond_bidirectional_event, process_respond_event,
    process_sign_request, recover_backlog, requeue_pending_sign_requests,
    resume_pending_publish_requests, RespondBidirectionalEvent, SignatureRespondedEvent,
};

pub mod ops;

use async_trait::async_trait;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::watch;

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

    /// Catchup has completed and live events may be forwarded to the signer.
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
            ChainEvent::CatchupCompleted => write!(f, "CatchupCompleted"),
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

#[async_trait]
pub trait AsyncCatchupIter: Send + 'static {
    type Item: Send;

    async fn next(&mut self) -> Option<Self::Item>;
}

#[async_trait]
impl<I> AsyncCatchupIter for I
where
    I: Iterator + Send + 'static,
    I::Item: Send,
{
    type Item = I::Item;

    async fn next(&mut self) -> Option<Self::Item> {
        Iterator::next(self)
    }
}

#[async_trait]
pub trait ChainIndexer: Send + 'static {
    const CHAIN: Chain;
    type Block: Send;
    type Iter: AsyncCatchupIter<Item = Self::Block> + Send + 'static;

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

pub async fn catchup_then_livestream<I: ChainIndexer>(mut indexer: I) {
    let chain = I::CHAIN;
    tracing::info!(%chain, "starting ChainStream catchup then livestream");

    let anchor_height = match indexer.livestream().await {
        Ok(anchor_height) => anchor_height,
        Err(err) => {
            tracing::error!(?err, %chain, "failed to initialize livestream");
            return;
        }
    };
    let Some(anchor_height) = anchor_height else {
        if let Err(err) = indexer.notify_catchup_completed().await {
            tracing::warn!(?err, %chain, "failed to signal catchup completion");
        }
        return;
    };

    tracing::info!(%chain, anchor_height, "livestream initialized => starting catchup");
    let mut catchup_iter = indexer.catchup_range(anchor_height).await;
    while let Some(catchup_item) = catchup_iter.next().await {
        while let Err(err) = indexer.process_catchup(&catchup_item).await {
            tracing::warn!(?err, %chain, "catchup item processing failed; retrying");
            tokio::time::sleep(I::RETRY_DELAY).await;
        }
    }

    tracing::info!(%chain, "catchup completed => processing livestream");
    if let Err(err) = indexer.notify_catchup_completed().await {
        tracing::warn!(?err, %chain, "failed to signal catchup completion");
        return;
    }

    while indexer.process_next_block().await {}
}

/// Shared indexer loop: recovers backlog then processes events from the stream
pub async fn run_stream<S: ChainStream>(
    mut stream: S,
    sign_tx: mpsc::Sender<Sign>,
    rpc: RpcChannel,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) {
    let chain = S::Indexer::CHAIN;
    tracing::info!(%chain, "starting stream");

    recover_backlog(
        &backlog,
        &mut contract_watcher,
        &mut mesh_state,
        &node_client,
        chain,
    )
    .await;

    let indexer = match stream.start().await {
        Ok(indexer) => indexer,
        Err(err) => {
            tracing::error!(?err, %chain, "failed to start stream");
            return;
        }
    };
    let indexer_task = tokio::spawn(catchup_then_livestream(indexer));

    let mut caught_up = false;
    while let Some(event) = stream.next_event().await {
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
                    &mut contract_watcher,
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
                    process_respond_bidirectional_event(ev, sign_tx.clone(), &backlog, caught_up)
                        .await
                {
                    tracing::error!(?err, %chain, "failed to process respond bidirectional event");
                }
            }
            ChainEvent::Block(block) => {
                if let Some(checkpoint) = backlog.set_processed_block(chain, block).await {
                    tracing::info!(block, ?checkpoint, %chain, "created checkpoint");
                }
                crate::metrics::indexers::LATEST_BLOCK_NUMBER
                    .with_label_values(&[chain.as_str(), "finalized"])
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

    tracing::warn!(%chain, "stream shutting down");
    indexer_task.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use crate::mesh::{connection::NodeStatus, MeshState};
    use crate::node_client::NodeClient;
    use crate::protocol::ParticipantInfo;
    use crate::protocol::Sign;
    use crate::protocol::{Chain, IndexedSignRequest};
    use crate::rpc::{ContractStateWatcher, RpcAction, RpcChannel};
    use crate::storage::checkpoint_storage::CheckpointStorage;
    use crate::stream::ops::{EthereumSignatureRespondedEvent, SignatureRespondedEvent};
    use crate::util::current_unix_timestamp;
    use alloy::primitives::Address;
    use k256::{AffinePoint, Scalar};
    use mockito::Server;
    use mpc_primitives::SignArgs;
    use mpc_primitives::SignId;
    use mpc_primitives::Signature;
    use near_primitives::types::AccountId;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    fn test_rpc_channel(buffer: usize) -> (RpcChannel, mpsc::Receiver<RpcAction>) {
        let (tx, rx) = mpsc::channel(buffer);
        (RpcChannel { tx }, rx)
    }

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
                type Iter = std::iter::Empty<Self::Block>;

                async fn next(&mut self) -> Option<Self::Block> {
                    None
                }

                async fn catchup_range(&self, _anchor_height: u64) -> Self::Iter {
                    std::iter::empty()
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
        type Iter = std::vec::IntoIter<Self::Block>;

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
            items.into_iter()
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
        let indexer = stream.start().await.unwrap();
        catchup_then_livestream(indexer).await;

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
        let indexer = stream.start().await.unwrap();
        catchup_then_livestream(indexer).await;

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
        let client = SolanaTestStream::new(vec![
            Some(ChainEvent::CatchupCompleted),
            Some(ChainEvent::SignRequest(indexed.clone())),
            Some(ChainEvent::Respond(sig_responded)),
            None,
        ]);

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            0,
            Default::default(),
        );
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());
        let (rpc, _rpc_rx) = test_rpc_channel(4);

        // Run the indexer
        run_stream(
            client,
            sign_tx.clone(),
            rpc,
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
            type Iter = std::iter::Empty<Self::Block>;

            async fn next(&mut self) -> Option<Self::Block> {
                None
            }

            async fn catchup_range(&self, _anchor_height: u64) -> Self::Iter {
                std::iter::empty()
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

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            0,
            Default::default(),
        );
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());
        let (rpc, _rpc_rx) = test_rpc_channel(8);

        // Start indexer in background (clone backlog so the test retains ownership)
        let backlog_for_run = backlog.clone();
        let run_handle = tokio::spawn(async move {
            run_stream(
                client,
                sign_tx,
                rpc,
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
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        };

        let indexed = IndexedSignRequest::sign_bidirectional(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
            SBE::Solana(sign_bidir.clone()),
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

        backlog
            .set_status(
                Chain::Solana,
                &sign_id,
                SignStatus::PendingPublish {
                    publish: crate::sign_bidirectional::PublishState {
                        signature: Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0),
                        participants: vec![cait_sith::protocol::Participant::from(0u32)],
                        is_proposer: true,
                    },
                },
            )
            .await;

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
                let watchers = backlog.execution_watchers(target_chain).await;
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
            .execution_watchers(target_chain)
            .await
            .into_iter()
            .find_map(|(_, (watched_sign_id, watched_tx))| {
                (watched_sign_id == sign_id).then_some(watched_tx)
            })
            .expect("expected execution watcher to exist");
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

        let old_watchers = backlog.execution_watchers(target_chain).await;
        let new_watchers = recovered.execution_watchers(target_chain).await;
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

        let respond = SignatureRespondedEvent::Ethereum(EthereumSignatureRespondedEvent {
            request_id: sign_id.request_id,
            responder: Address::ZERO,
            signature: Signature::new(k256::ProjectivePoint::GENERATOR.to_affine(), Scalar::ONE, 0),
        });

        let client = EthereumTestStream::new(vec![
            Some(ChainEvent::Respond(respond)),
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
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(mesh_state);
        let node_client = NodeClient::new(&Default::default());
        let (rpc, _rpc_rx) = test_rpc_channel(8);

        run_stream(
            client,
            sign_tx,
            rpc,
            backlog.clone(),
            contract_watcher,
            mesh_state_rx,
            node_client,
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
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(mesh_state);
        let node_client = NodeClient::new(&Default::default());
        let (rpc, _rpc_rx) = test_rpc_channel(8);

        run_stream(
            client,
            sign_tx,
            rpc,
            backlog.clone(),
            contract_watcher,
            mesh_state_rx,
            node_client,
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
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());

        let run_handle = tokio::spawn(async move {
            run_stream(
                client,
                sign_tx,
                rpc,
                backlog,
                contract_watcher,
                mesh_state_rx,
                node_client,
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
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());

        let run_handle = tokio::spawn(async move {
            run_stream(
                client,
                sign_tx,
                rpc,
                backlog,
                contract_watcher,
                mesh_state_rx,
                node_client,
            )
            .await;
        });

        let no_publish = timeout(Duration::from_millis(100), rpc_rx.recv()).await;
        assert!(matches!(no_publish, Err(_) | Ok(None)));

        run_handle.abort();
    }
}
