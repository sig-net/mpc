//! Midnight stream + indexer: contractEvents subscription → reassembly →
//! finality gate → ChainEvents, driven by the generic `run_stream` pipeline.

use crate::config::MidnightConfig;
use crate::convert::group_to_chain_event;
use crate::finality::FinalityGate;
use crate::graphql::{EventSubscription, MidnightGraphql, RawContractEvent};
use crate::reassembly::{CompletedGroup, Reassembler, ReassemblyOutput};

use async_trait::async_trait;
use futures_util::stream;
use mpc_chain_integration_core::utils::stream::chain_event_channel;
use mpc_chain_integration_core::{ChainIndexer, ChainStream, ChainTelemetry, StateManager};
use mpc_primitives::{Chain, ChainEvent};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// How often the live loop wakes to drain the finality queue when no events
/// arrive (finality lags block production by a few seconds).
const DRAIN_TICK: Duration = Duration::from_secs(5);
/// Catchup considers the subscription drained after this much silence and
/// falls back to the maxId poll (Canton's ledger-end pattern).
const CATCHUP_QUIET: Duration = Duration::from_secs(2);

pub struct MidnightStream<S: StateManager, T: ChainTelemetry> {
    config: MidnightConfig,
    state_manager: S,
    telemetry: T,
    events_rx: mpsc::Receiver<ChainEvent>,
    events_tx: Option<mpsc::Sender<ChainEvent>>,
}

impl<S: StateManager, T: ChainTelemetry> MidnightStream<S, T> {
    pub fn new(config: MidnightConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        config.sender_raw32()?; // fail fast on a malformed contract address
        let (events_tx, events_rx) = chain_event_channel();
        Ok(Self {
            config,
            state_manager,
            telemetry,
            events_rx,
            events_tx: Some(events_tx),
        })
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainStream for MidnightStream<S, T> {
    type Indexer = MidnightIndexer<S, T>;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
        let Some(events_tx) = self.events_tx.take() else {
            anyhow::bail!("midnight stream already started");
        };
        Ok(MidnightIndexer::new(
            self.config.clone(),
            self.state_manager.clone(),
            self.telemetry.clone(),
            events_tx,
        ))
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        self.events_rx.recv().await
    }
}

enum Gated {
    Group(CompletedGroup),
    Marker { id: u64, block_height: u64 },
}

impl Gated {
    fn block_height(&self) -> u64 {
        match self {
            Gated::Group(g) => g.block_height,
            Gated::Marker { block_height, .. } => *block_height,
        }
    }

    fn last_id(&self) -> u64 {
        match self {
            Gated::Group(g) => g.last_id,
            Gated::Marker { id, .. } => *id,
        }
    }
}

pub struct MidnightIndexer<S: StateManager, T: ChainTelemetry> {
    config: MidnightConfig,
    graphql: MidnightGraphql,
    finality: FinalityGate,
    state_manager: S,
    telemetry: T,
    events_tx: mpsc::Sender<ChainEvent>,
    subscription: Option<EventSubscription>,
    reassembler: Reassembler,
    pending_finality: VecDeque<Gated>,
    sender_raw32: [u8; 32],
}

impl<S: StateManager, T: ChainTelemetry> MidnightIndexer<S, T> {
    fn new(
        config: MidnightConfig,
        state_manager: S,
        telemetry: T,
        events_tx: mpsc::Sender<ChainEvent>,
    ) -> Self {
        let graphql = MidnightGraphql::new(
            &config.indexer_graphql_url,
            &config.indexer_graphql_ws_url,
            &config.contract_address,
        );
        let finality = FinalityGate::new(&config.node_rpc_url);
        let sender_raw32 = config
            .sender_raw32()
            .expect("validated in MidnightStream::new");
        Self {
            config,
            graphql,
            finality,
            state_manager,
            telemetry,
            events_tx,
            subscription: None,
            reassembler: Reassembler::new(0),
            pending_finality: VecDeque::new(),
            sender_raw32,
        }
    }

    async fn reconnect(&mut self) {
        if let Some(mut sub) = self.subscription.take() {
            sub.close().await;
        }
        self.reassembler.reset();
        let start = Reassembler::overfetch_start(self.reassembler.processed());
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.graphql.subscribe(start).await {
                Ok(sub) => {
                    tracing::info!(resume_id = start, "midnight subscription (re)connected");
                    self.subscription = Some(sub);
                    return;
                }
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        backoff_secs = backoff.as_secs(),
                        "midnight subscribe failed; retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    /// Next raw event; reconnects internally on socket close/stall.
    async fn next_raw(&mut self) -> RawContractEvent {
        loop {
            if self.subscription.is_none() {
                self.reconnect().await;
            }
            match self
                .subscription
                .as_mut()
                .expect("subscription")
                .next()
                .await
            {
                Some(ev) => return ev,
                None => {
                    self.subscription = None;
                }
            }
        }
    }

    async fn process_raw(&mut self, ev: &RawContractEvent) {
        for output in self.reassembler.push(ev) {
            let gated = match output {
                ReassemblyOutput::Group(g) => Gated::Group(g),
                ReassemblyOutput::Marker { id, block_height } => Gated::Marker { id, block_height },
            };
            self.pending_finality.push_back(gated);
        }
        self.drain_finality().await;
    }

    /// Release queued items whose block is finalized, in id order. Errors from
    /// the node RPC leave the queue intact for the next tick.
    async fn drain_finality(&mut self) {
        if self.pending_finality.is_empty() {
            return;
        }
        let finalized = match self.finality.finalized_height().await {
            Ok(h) => h,
            Err(err) => {
                tracing::warn!(?err, "finality check failed; holding events");
                return;
            }
        };
        // Peek by value (the `front()` borrow ends at the condition) so the
        // body can `pop_front` mutably.
        while let Some(front_height) = self.pending_finality.front().map(Gated::block_height) {
            if front_height > finalized {
                break;
            }
            let item = self.pending_finality.pop_front().expect("non-empty");
            let last_id = item.last_id();
            if let Gated::Group(group) = item {
                match group_to_chain_event(
                    group.kind,
                    group.request_id,
                    &group.parts,
                    &self.config.contract_address,
                    self.sender_raw32,
                    current_unix_timestamp(),
                ) {
                    Ok(event) => {
                        if matches!(event, ChainEvent::SignRequest { .. }) {
                            self.telemetry.request_indexed();
                        }
                        if self.events_tx.send(event).await.is_err() {
                            tracing::error!("midnight event channel closed");
                            return;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(?err, request_id = %hex::encode(group.request_id), "dropping invalid midnight request group");
                    }
                }
            }
            self.telemetry.block_indexed(last_id);
            if self
                .events_tx
                .send(ChainEvent::Block(last_id))
                .await
                .is_err()
            {
                tracing::error!("midnight event channel closed");
                return;
            }
        }
    }
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for MidnightIndexer<S, T> {
    const CHAIN: Chain = Chain::Midnight;
    type Block = u64;
    type Iter = stream::Iter<std::vec::IntoIter<u64>>;

    async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
        let checkpoint = self
            .state_manager
            .get_processed_block(Chain::Midnight)
            .await
            .unwrap_or(0);
        self.reassembler = Reassembler::new(checkpoint);
        self.pending_finality.clear();
        // Subscribe first, then anchor — the id cursor makes the window gapless.
        self.reconnect().await;
        let anchor = self.graphql.latest_max_id().await?;
        tracing::info!(checkpoint, anchor, "midnight livestream started");
        Ok(Some(anchor))
    }

    async fn catchup_range(&self, anchor_height: u64) -> Self::Iter {
        // A single target: event ids are sparse per contract and the
        // subscription has no periodic checkpoint messages, so per-id
        // iteration would stall 2s per foreign id.
        let targets = if anchor_height > self.reassembler.processed() {
            vec![anchor_height]
        } else {
            Vec::new()
        };
        stream::iter(targets)
    }

    async fn process_catchup(&mut self, &target: &Self::Block) -> anyhow::Result<()> {
        loop {
            if self.reassembler.processed() >= target {
                return Ok(());
            }
            match timeout(CATCHUP_QUIET, self.next_raw()).await {
                Ok(ev) => self.process_raw(&ev).await,
                Err(_) => {
                    // Quiet subscription: if the global ledger end has reached
                    // the target, everything of ours below it was delivered.
                    let ledger_end = self.graphql.latest_max_id().await?;
                    if ledger_end >= target {
                        // Force through anything still gated on finality before
                        // declaring catchup complete.
                        self.drain_finality().await;
                        if self.pending_finality.is_empty() {
                            tracing::info!(
                                target,
                                ledger_end,
                                "midnight catchup complete on quiet subscription"
                            );
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
        self.events_tx.send(ChainEvent::CatchupCompleted).await?;
        Ok(())
    }

    async fn process_next_block(&mut self) -> bool {
        match timeout(DRAIN_TICK, self.next_raw()).await {
            Ok(ev) => self.process_raw(&ev).await,
            Err(_) => self.drain_finality().await,
        }
        true
    }
}
