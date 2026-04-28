use crate::backlog::{Backlog, RecoveryRequeueMode};
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

use async_trait::async_trait;
use std::ops::Range;
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
pub trait ChainIndexer: Send + 'static {
    type Block: Send + 'static;

    const RETRY_DELAY: Duration = Duration::from_millis(500);

    async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
        Ok(None)
    }

    async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn catchup_range(&mut self, anchor_height: u64) -> Range<u64> {
        let _ = anchor_height;
        // TODO: this disables the catchup range, will be removed in the future once
        // all chains like solana support catchup & livestream.
        0..0
    }

    async fn process_catchup_on_height(&mut self, height: u64) -> anyhow::Result<()> {
        let _ = height;
        Ok(())
    }

    async fn next(&mut self) -> Option<Self::Block>;

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

/// Type used to denote a disabled stream (i.e. Solana, Hydration) that does
/// not yet support the flow for general catchup & livestream.
pub struct DisabledChainIndexer {
    events_tx: Option<mpsc::Sender<ChainEvent>>,
}

impl DisabledChainIndexer {
    pub fn new(events_tx: mpsc::Sender<ChainEvent>) -> Self {
        Self {
            events_tx: Some(events_tx),
        }
    }

    pub fn silent() -> Self {
        Self { events_tx: None }
    }
}

#[async_trait]
impl ChainIndexer for DisabledChainIndexer {
    type Block = ();

    async fn next(&mut self) -> Option<Self::Block> {
        None
    }

    async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
        if let Some(events_tx) = &self.events_tx {
            events_tx.send(ChainEvent::CatchupCompleted).await?;
        }
        Ok(())
    }
}

#[async_trait]
pub trait ChainStream: Send + 'static {
    const CHAIN: Chain;
    type Indexer: ChainIndexer;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer>;
    async fn next_event(&mut self) -> Option<ChainEvent>;
}

pub async fn catchup_then_livestream<I: ChainIndexer>(chain: Chain, mut indexer: I) {
    tracing::info!(%chain, "starting ChainStream catchup then livestream");

    // TODO: on failure, we currently send catchup_completed due to some streams not enabling
    // this particular catchup_then_livestream function (i.e. Solana & Hydration). Once
    // those are implemented, we can remove the catchup_completed sending on error here.
    let anchor_height = match indexer.livestream().await {
        Ok(anchor_height) => anchor_height,
        Err(err) => {
            if let Err(err) = indexer.notify_catchup_completed().await {
                tracing::warn!(?err, %chain, "failed to signal catchup completion");
            }
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

    let catchup_range = indexer.catchup_range(anchor_height).await;
    for height in catchup_range {
        while let Err(err) = indexer.process_catchup_on_height(height).await {
            tracing::warn!(?err, %chain, height, "catchup height processing failed; retrying");
            tokio::time::sleep(I::RETRY_DELAY).await;
        }
    }

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
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) {
    let chain = S::CHAIN;
    tracing::info!(%chain, "starting stream");

    let requeue_mode = recover_backlog(
        &backlog,
        &mut contract_watcher,
        &mut mesh_state,
        &node_client,
        chain,
        sign_tx.clone(),
    )
    .await;

    let indexer = match stream.start().await {
        Ok(indexer) => indexer,
        Err(err) => {
            tracing::error!(?err, %chain, "failed to start stream");
            return;
        }
    };
    let indexer_task = tokio::spawn(catchup_then_livestream(chain, indexer));

    let mut caught_up = false;
    while let Some(event) = stream.next_event().await {
        match event {
            ChainEvent::CatchupCompleted => {
                if caught_up {
                    continue;
                }
                caught_up = true;
                if requeue_mode == RecoveryRequeueMode::AfterCatchup {
                    requeue_recovered_sign_requests(&backlog, chain, sign_tx.clone()).await;
                }
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
                if let Some(checkpoint) = backlog.set_processed_block(S::CHAIN, block).await {
                    tracing::info!(block, ?checkpoint, %chain, "created checkpoint");
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    struct VecEventStreamState {
        started: bool,
        rx: mpsc::Receiver<ChainEvent>,
    }

    impl VecEventStreamState {
        fn new() -> (Self, mpsc::Sender<ChainEvent>) {
            let (tx, rx) = mpsc::channel(CHAIN_EVENT_STREAM_SIZE);
            (
                Self {
                    started: false,
                    rx,
                },
                tx,
            )
        }
    }

    macro_rules! impl_vec_event_stream {
        ($name:ident, $chain:expr) => {
            struct $name(VecEventStreamState);

            impl $name {
                pub fn new() -> (Self, mpsc::Sender<ChainEvent>) {
                    let (state, tx) = VecEventStreamState::new();
                    (Self(state), tx)
                }
            }

            #[async_trait]
            impl ChainStream for $name {
                const CHAIN: Chain = $chain;

                type Indexer = DisabledChainIndexer;

                async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
                    self.0.started = true;
                    Ok(DisabledChainIndexer::silent())
                }

                async fn next_event(&mut self) -> Option<ChainEvent> {
                    self.0.rx.recv().await
                }
            }
        };
    }

    impl_vec_event_stream!(SolanaTestStream, Chain::Solana);
    impl_vec_event_stream!(EthereumTestStream, Chain::Ethereum);

    #[derive(Clone)]
    struct TestLinearControl {
        persisted_height: Option<u64>,
        live_items: Vec<u64>,
        catchup_failures: Arc<Mutex<HashMap<u64, usize>>>,
        live_failures: Arc<Mutex<HashMap<u64, usize>>>,
    }

    impl TestLinearControl {
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
        type Block = u64;

        const RETRY_DELAY: Duration = Duration::from_millis(1);

        async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
            self.live_items = self
                .control
                .live_items
                .clone()
                .into_iter()
                .collect();
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

        async fn catchup_range(&mut self, anchor_height: u64) -> Range<u64> {
            let start = self
                .control
                .persisted_height
                .map(|height| height + 1)
                .unwrap_or(anchor_height);
            start..anchor_height
        }

        async fn process_catchup_on_height(&mut self, height: u64) -> anyhow::Result<()> {
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
        const CHAIN: Chain = Chain::Ethereum;
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

    #[derive(Default)]
    struct LinearHarness {
        persisted_height: Option<u64>,
        live_items: Vec<u64>,
        catchup_failures: HashMap<u64, usize>,
        live_failures: HashMap<u64, usize>,
        stream: Option<TestLinearStream>,
    }

    #[derive(Debug)]
    enum LinearOp {
        SetPersistedHeight(Option<u64>),
        SetLiveItems(Vec<u64>),
        FailCatchupOnce(u64),
        FailLiveOnce(u64),
        Run,
        ExpectBlocks(Vec<u64>),
    }

    impl LinearOp {
        async fn apply(self, harness: &mut LinearHarness) {
            match self {
                LinearOp::SetPersistedHeight(persisted_height) => {
                    harness.persisted_height = persisted_height;
                }
                LinearOp::SetLiveItems(live_items) => {
                    harness.live_items = live_items;
                }
                LinearOp::FailCatchupOnce(height) => {
                    *harness.catchup_failures.entry(height).or_insert(0) += 1;
                }
                LinearOp::FailLiveOnce(height) => {
                    *harness.live_failures.entry(height).or_insert(0) += 1;
                }
                LinearOp::Run => {
                    let control = TestLinearControl {
                        persisted_height: harness.persisted_height,
                        live_items: std::mem::take(&mut harness.live_items),
                        catchup_failures: Arc::new(Mutex::new(std::mem::take(
                            &mut harness.catchup_failures,
                        ))),
                        live_failures: Arc::new(Mutex::new(std::mem::take(
                            &mut harness.live_failures,
                        ))),
                    };
                    let mut stream = TestLinearStream::new(control);
                    let indexer = stream.start().await.unwrap();
                    catchup_then_livestream(Chain::Ethereum, indexer).await;
                    harness.stream = Some(stream);
                }
                LinearOp::ExpectBlocks(expected_blocks) => {
                    let stream = harness
                        .stream
                        .as_mut()
                        .expect("run must happen before expectations");
                    let mut observed_blocks = Vec::new();
                    while let Some(event) = timeout(Duration::from_millis(20), stream.next_event())
                        .await
                        .ok()
                        .flatten()
                    {
                        match event {
                            ChainEvent::Block(block) => observed_blocks.push(block),
                            other => panic!("unexpected event: {other:?}"),
                        }
                    }
                    assert_eq!(observed_blocks, expected_blocks);
                }
            }
        }
    }

    async fn run_linear_case(ops: Vec<LinearOp>) {
        let mut harness = LinearHarness::default();
        for op in ops {
            op.apply(&mut harness).await;
        }
    }

    #[derive(Debug)]
    enum RunOp {
        Send(ChainEvent),
        Start,
        ExpectRequest(SignId),
        ExpectCompletion(SignId),
        ExpectNoSign(Duration),
        WaitForWatcher {
            chain: Chain,
            sign_id: SignId,
        },
        SetStatus {
            chain: Chain,
            sign_id: SignId,
            status: crate::sign_bidirectional::SignStatus,
        },
        Sleep(Duration),
        CaptureCheckpoint(Chain),
        RecoverBacklog,
        AssertRecoveredWatchers(Chain),
        AssertBacklogMissing {
            chain: Chain,
            sign_id: SignId,
        },
        AssertBacklogTimestamp {
            chain: Chain,
            sign_id: SignId,
            timestamp: u64,
        },
        CloseEvents,
        AwaitRun,
    }

    struct RunHarness<S: ChainStream> {
        stream: Option<S>,
        events_tx: Option<mpsc::Sender<ChainEvent>>,
        backlog: Backlog,
        sign_tx: Option<mpsc::Sender<Sign>>,
        sign_rx: mpsc::Receiver<Sign>,
        contract_watcher: Option<ContractStateWatcher>,
        mesh_state_rx: Option<watch::Receiver<MeshState>>,
        node_client: Option<NodeClient>,
        run_handle: Option<tokio::task::JoinHandle<()>>,
        storage: Option<CheckpointStorage>,
        checkpoint: Option<crate::backlog::Checkpoint>,
        recovered_backlog: Option<Backlog>,
    }

    impl<S: ChainStream> RunHarness<S> {
        async fn apply(&mut self, op: RunOp) {
            match op {
                RunOp::Send(event) => {
                    let events_tx = self.events_tx.as_ref().expect("events sender not available");
                    events_tx.send(event).await.unwrap();
                }
                RunOp::Start => {
                    let stream = self.stream.take().expect("stream already started");
                    let sign_tx = self.sign_tx.take().expect("sign tx not available");
                    let contract_watcher = self
                        .contract_watcher
                        .take()
                        .expect("contract watcher not available");
                    let mesh_state_rx = self
                        .mesh_state_rx
                        .take()
                        .expect("mesh state receiver not available");
                    let node_client = self.node_client.take().expect("node client not available");
                    let backlog = self.backlog.clone();
                    self.run_handle = Some(tokio::spawn(async move {
                        run_stream(
                            stream,
                            sign_tx,
                            backlog,
                            contract_watcher,
                            mesh_state_rx,
                            node_client,
                        )
                        .await;
                    }));
                }
                RunOp::ExpectRequest(sign_id) => {
                    let message = timeout(Duration::from_secs(1), self.sign_rx.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    match message {
                        Sign::Request(request) => assert_eq!(request.id, sign_id),
                        other => panic!("expected request, got {other:?}"),
                    }
                }
                RunOp::ExpectCompletion(sign_id) => {
                    let message = timeout(Duration::from_secs(1), self.sign_rx.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    match message {
                        Sign::Completion(completed_id) => assert_eq!(completed_id, sign_id),
                        other => panic!("expected completion, got {other:?}"),
                    }
                }
                RunOp::ExpectNoSign(duration) => {
                    match timeout(duration, self.sign_rx.recv()).await {
                        Err(_) | Ok(None) => {}
                        Ok(Some(message)) => panic!("unexpected sign message: {message:?}"),
                    }
                }
                RunOp::WaitForWatcher { chain, sign_id } => {
                    timeout(Duration::from_secs(1), async {
                        loop {
                            let watchers = self.backlog.pending_execution(chain).await;
                            if watchers.values().any(|(existing, _)| *existing == sign_id) {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    })
                    .await
                    .unwrap();
                }
                RunOp::SetStatus {
                    chain,
                    sign_id,
                    status,
                } => {
                    self.backlog.set_status(chain, &sign_id, status).await;
                }
                RunOp::Sleep(duration) => {
                    tokio::time::sleep(duration).await;
                }
                RunOp::CaptureCheckpoint(chain) => {
                    let checkpoint = self
                        .backlog
                        .latest_checkpoint(chain)
                        .await
                        .expect("checkpoint should exist");
                    self.checkpoint = Some(checkpoint);
                }
                RunOp::RecoverBacklog => {
                    let storage = self.storage.as_ref().expect("storage not available").clone();
                    let checkpoint = self.checkpoint.as_ref().expect("checkpoint not captured");
                    let recovered = Backlog::persisted(storage);
                    recovered
                        .recover_by_checkpoint(checkpoint.clone())
                        .await
                        .expect("recovery failed");
                    self.recovered_backlog = Some(recovered);
                }
                RunOp::AssertRecoveredWatchers(chain) => {
                    let recovered = self
                        .recovered_backlog
                        .as_ref()
                        .expect("recovered backlog not available");
                    let original_watchers = self.backlog.pending_execution(chain).await;
                    let recovered_watchers = recovered.pending_execution(chain).await;
                    assert_eq!(original_watchers.len(), recovered_watchers.len());
                    for (tx_id, (status, _)) in original_watchers {
                        assert!(recovered_watchers.contains_key(&tx_id));
                        assert_eq!(recovered_watchers.get(&tx_id).unwrap().0, status);
                    }
                }
                RunOp::AssertBacklogMissing { chain, sign_id } => {
                    assert!(self.backlog.get(chain, &sign_id).await.is_none());
                }
                RunOp::AssertBacklogTimestamp {
                    chain,
                    sign_id,
                    timestamp,
                } => {
                    let entry = self
                        .backlog
                        .get(chain, &sign_id)
                        .await
                        .expect("backlog entry should exist");
                    assert_eq!(entry.request.unix_timestamp_indexed, timestamp);
                }
                RunOp::CloseEvents => {
                    self.events_tx.take();
                }
                RunOp::AwaitRun => {
                    self.run_handle
                        .take()
                        .expect("run handle not available")
                        .await
                        .unwrap();
                }
            }
        }
    }

    async fn run_script<S: ChainStream>(mut harness: RunHarness<S>, ops: Vec<RunOp>) {
        for op in ops {
            harness.apply(op).await;
        }
    }

    #[tokio::test]
    async fn test_run_linearized_source_orders_catchup_before_live() {
        run_linear_case(vec![
            LinearOp::SetPersistedHeight(Some(1)),
            LinearOp::SetLiveItems(vec![4, 5]),
            LinearOp::Run,
            LinearOp::ExpectBlocks(vec![2, 3, 4, 5]),
        ])
        .await;
    }

    #[tokio::test]
    async fn test_run_linearized_source_retries_without_reordering() {
        run_linear_case(vec![
            LinearOp::SetPersistedHeight(Some(1)),
            LinearOp::SetLiveItems(vec![4, 5]),
            LinearOp::FailCatchupOnce(3),
            LinearOp::FailLiveOnce(4),
            LinearOp::Run,
            LinearOp::ExpectBlocks(vec![2, 3, 4, 5]),
        ])
        .await;
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
        let (sign_tx, sign_rx) = mpsc::channel(4);

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            0,
            Default::default(),
        );
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());

        let (client, events_tx) = SolanaTestStream::new();
        let harness = RunHarness {
            stream: Some(client),
            events_tx: Some(events_tx),
            backlog,
            sign_tx: Some(sign_tx),
            sign_rx,
            contract_watcher: Some(contract_watcher),
            mesh_state_rx: Some(mesh_state_rx),
            node_client: Some(node_client),
            run_handle: None,
            storage: None,
            checkpoint: None,
            recovered_backlog: None,
        };

        run_script(
            harness,
            vec![
                RunOp::Send(ChainEvent::CatchupCompleted),
                RunOp::Send(ChainEvent::SignRequest(indexed.clone())),
                RunOp::Send(ChainEvent::Respond(sig_responded)),
                RunOp::Start,
                RunOp::ExpectRequest(sign_id),
                RunOp::ExpectCompletion(sign_id),
                RunOp::CloseEvents,
                RunOp::AwaitRun,
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_stream_handles_sign_bidirectional_block_and_recover() {
        use crate::stream::ops::RespondBidirectionalEvent as RBE;
        use crate::stream::ops::SignBidirectionalEvent as SBE;
        use crate::stream::ops::SignatureRespondedEvent as SRE;
        use signet_program::SignBidirectionalEvent;

        let storage = crate::storage::checkpoint_storage::CheckpointStorage::in_memory();
        let backlog = Backlog::persisted(storage.clone());

        let (sign_tx, sign_rx) = mpsc::channel(8);

        let (contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            0,
            Default::default(),
        );
        let (_mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());

        let (client, events_tx) = SolanaTestStream::new();
        let harness = RunHarness {
            stream: Some(client),
            events_tx: Some(events_tx),
            backlog,
            sign_tx: Some(sign_tx),
            sign_rx,
            contract_watcher: Some(contract_watcher),
            mesh_state_rx: Some(mesh_state_rx),
            node_client: Some(node_client),
            run_handle: None,
            storage: Some(storage),
            checkpoint: None,
            recovered_backlog: None,
        };

        let sign_id = SignId::new([42u8; 32]);
        let args = SignArgs {
            entropy: [0u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };
        let program_id = solana_sdk::pubkey::Pubkey::new_unique();
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

        let sign_bidir = SignBidirectionalEvent {
            sender: Default::default(),
            serialized_transaction: unsigned_rlp,
            dest: Chain::Ethereum.to_string(),
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

        let indexed = IndexedSignRequest::sign_bidirectional(
            sign_id,
            args.clone(),
            Chain::Solana,
            current_unix_timestamp(),
            SBE::Solana(sign_bidir.clone()),
        );

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

        run_script(
            harness,
            vec![
                RunOp::Start,
                RunOp::Send(ChainEvent::CatchupCompleted),
                RunOp::Send(ChainEvent::SignRequest(indexed.clone())),
                RunOp::ExpectRequest(sign_id),
                RunOp::Send(ChainEvent::Respond(sig_responded)),
                RunOp::WaitForWatcher {
                    chain: Chain::Ethereum,
                    sign_id,
                },
                RunOp::SetStatus {
                    chain: Chain::Solana,
                    sign_id,
                    status: crate::sign_bidirectional::SignStatus::PendingExecution,
                },
                RunOp::Send(ChainEvent::Block(Chain::Solana.checkpoint_interval().unwrap_or(1))),
                RunOp::Sleep(Duration::from_millis(50)),
                RunOp::CaptureCheckpoint(Chain::Solana),
                RunOp::RecoverBacklog,
                RunOp::AssertRecoveredWatchers(Chain::Ethereum),
                RunOp::Send(ChainEvent::RespondBidirectional(respond_bidirectional)),
                RunOp::ExpectCompletion(sign_id),
                RunOp::AssertBacklogMissing {
                    chain: Chain::Solana,
                    sign_id,
                },
                RunOp::CloseEvents,
                RunOp::AwaitRun,
            ],
        )
        .await;
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

        let respond = SignatureRespondedEvent::Ethereum(EthereumSignatureRespondedEvent {
            request_id: sign_id.request_id,
            responder: Address::ZERO,
            signature: Signature::new(k256::ProjectivePoint::GENERATOR.to_affine(), Scalar::ONE, 0),
        });

        let (client, events_tx) = EthereumTestStream::new();
        let (sign_tx, sign_rx) = mpsc::channel(8);

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

        let harness = RunHarness {
            stream: Some(client),
            events_tx: Some(events_tx),
            backlog: Backlog::persisted(storage),
            sign_tx: Some(sign_tx),
            sign_rx,
            contract_watcher: Some(contract_watcher),
            mesh_state_rx: Some(mesh_state_rx),
            node_client: Some(node_client),
            run_handle: None,
            storage: None,
            checkpoint: None,
            recovered_backlog: None,
        };

        run_script(
            harness,
            vec![
                RunOp::Send(ChainEvent::Respond(respond)),
                RunOp::Send(ChainEvent::CatchupCompleted),
                RunOp::Start,
                RunOp::ExpectNoSign(Duration::from_millis(100)),
                RunOp::AssertBacklogMissing {
                    chain: Chain::Ethereum,
                    sign_id,
                },
                RunOp::CloseEvents,
                RunOp::AwaitRun,
            ],
        )
        .await;
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

        let replacement =
            IndexedSignRequest::sign(sign_id, args.clone(), Chain::Ethereum, replayed_timestamp);
        let (client, events_tx) = EthereumTestStream::new();
        let (sign_tx, sign_rx) = mpsc::channel(8);

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

        let harness = RunHarness {
            stream: Some(client),
            events_tx: Some(events_tx),
            backlog: Backlog::persisted(storage),
            sign_tx: Some(sign_tx),
            sign_rx,
            contract_watcher: Some(contract_watcher),
            mesh_state_rx: Some(mesh_state_rx),
            node_client: Some(node_client),
            run_handle: None,
            storage: None,
            checkpoint: None,
            recovered_backlog: None,
        };

        run_script(
            harness,
            vec![
                RunOp::Send(ChainEvent::SignRequest(replacement)),
                RunOp::Send(ChainEvent::CatchupCompleted),
                RunOp::Start,
                RunOp::ExpectNoSign(Duration::from_millis(100)),
                RunOp::AssertBacklogTimestamp {
                    chain: Chain::Ethereum,
                    sign_id,
                    timestamp: replayed_timestamp,
                },
                RunOp::CloseEvents,
                RunOp::AwaitRun,
            ],
        )
        .await;
    }
}
