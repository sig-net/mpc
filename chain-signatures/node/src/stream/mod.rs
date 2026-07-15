pub mod ops;
pub mod pipeline;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::stream::ops::{
    process_block_event, process_execution_confirmed, process_respond_bidirectional_event,
    process_respond_event, process_sign_request, requeue_pending_sign_requests,
    resume_pending_publish_requests,
};
use crate::types::CheckpointWatcher;

pub use crate::stream::pipeline::ChainPipeline;

use anyhow::Context;
use mpc_chain_integration_core::{ChainIndexer, ChainStream, ChainTelemetry};
use mpc_primitives::{Chain, ChainEvent, SignCommand};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStreaming {
    Recovery { load_local: bool },
    Catchup { anchor_height: u64 },
    Live,
    Reconnect,
}

/// Shared, per-chain dependencies
pub struct StreamContext {
    pub backlog: Backlog,
    pub sign_tx: mpsc::Sender<SignCommand>,
    pub rpc: RpcChannel,
    pub contract_watcher: ContractStateWatcher,
    pub mesh_state: watch::Receiver<MeshState>,
    pub node_client: NodeClient,
    pub checkpoints_rx: CheckpointWatcher,
    /// In-band caught-up flag, toggled by the `CatchupInProgress` /
    /// `CatchupCompleted` markers dequeued from the event stream. Ordered
    /// with chain events, so it drives requeue/resume timing.
    pub caught_up: bool,
    /// Out-of-band flag shared with the pipeline to immediately veto forwarding
    /// during regression recovery. The pipeline sets this to `false` at the top
    /// of `handle_recovery()` — before any async work — so `run_stream` stops
    /// forwarding buffered events that may be from a diverged fork, even before
    /// the in-band `CatchupInProgress` marker is dequeued from the event channel.
    /// The pipeline sets it back to `true` when catchup completes.
    ///
    /// Starts as `false` because the pipeline always begins in Recovery state —
    /// it will store `true` once the initial catchup completes.
    ///
    /// Reconnect does NOT clear this flag: buffered events during a reconnect
    /// are from valid blocks and safe to forward. Reconnect relies solely on the
    /// in-band `CatchupInProgress` marker for its caught-up gating.
    ///
    /// The pipeline is the sole writer; `run_stream` and the event processors
    /// only ever read it.
    pub pipeline_caught_up: Arc<AtomicBool>,
}

impl StreamContext {
    pub fn new(
        backlog: Backlog,
        sign_tx: mpsc::Sender<SignCommand>,
        rpc: RpcChannel,
        contract_watcher: ContractStateWatcher,
        mesh_state: watch::Receiver<MeshState>,
        node_client: NodeClient,
        checkpoints_rx: CheckpointWatcher,
    ) -> Self {
        Self {
            backlog,
            sign_tx,
            rpc,
            contract_watcher,
            mesh_state,
            node_client,
            checkpoints_rx,
            caught_up: false,
            pipeline_caught_up: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Events are only forwarded to signing when both the in-band `caught_up`
    /// flag and the pipeline's out-of-band veto agree.
    pub fn effectively_caught_up(&self) -> bool {
        self.caught_up && self.pipeline_caught_up.load(Ordering::Acquire)
    }
}

/// Shared indexer loop: recovers backlog then processes events from the stream
pub async fn run_stream<S: ChainStream, T: ChainTelemetry>(
    mut stream: S,
    mut ctx: StreamContext,
    telemetry: T,
) {
    let chain = S::Indexer::CHAIN;
    tracing::info!(%chain, "starting stream");

    let threshold = ctx.contract_watcher.wait_threshold().await;

    let indexer = match stream.start().await {
        Ok(indexer) => indexer,
        Err(err) => {
            tracing::error!(?err, %chain, "failed to start stream");
            return;
        }
    };

    let (pipeline, _state_rx) = ChainPipeline::new(
        indexer,
        ctx.checkpoints_rx.clone(),
        ctx.backlog.clone(),
        ctx.sign_tx.clone(),
        ctx.mesh_state.clone(),
        ctx.node_client.clone(),
        threshold,
        ctx.contract_watcher.account_id().clone(),
        ctx.pipeline_caught_up.clone(),
    );
    let indexer_task = tokio::spawn(pipeline.run());

    let root_pk = ctx.contract_watcher.wait_public_key().await;

    loop {
        let Some(event) = stream.next_event().await else {
            break;
        };
        if let Err(err) = handle_chain_event(event, &mut ctx, &telemetry, root_pk, chain).await {
            tracing::error!(?err, %chain, "failed to process chain event");
        }
    }

    tracing::warn!(%chain, "stream shutting down");
    indexer_task.abort();
}

/// Dispatch a single chain event to the appropriate processor.
async fn handle_chain_event<T: ChainTelemetry>(
    event: ChainEvent,
    ctx: &mut StreamContext,
    telemetry: &T,
    root_pk: mpc_primitives::PublicKey,
    chain: Chain,
) -> anyhow::Result<()> {
    match event {
        ChainEvent::CatchupInProgress => {
            ctx.caught_up = false;
        }
        ChainEvent::CatchupCompleted => {
            if ctx.caught_up {
                return Ok(());
            }
            ctx.caught_up = true;

            requeue_pending_sign_requests(ctx, chain)
                .await
                .context("failed to requeue pending sign requests")?;
            resume_pending_publish_requests(ctx, chain).await;
        }
        ChainEvent::SignRequest {
            request,
            block_timestamp,
        } => {
            // Handle metrics reporting for the sign request event
            if let Some(ts) = block_timestamp {
                // Report the request was indexed at the given block timestamp is currently used for Ethereum due to ~15 min finality delay
                telemetry.request_indexed_at(ts);
            } else {
                // Other faster chains (e.g. for Solana, Canton, or Hydration) report that a request was indexed without a block timestamp
                telemetry.request_indexed();
            }

            process_sign_request(request, ctx)
                .await
                .context("failed to process sign request")?;
        }
        ChainEvent::Respond(ev) => {
            process_respond_event(ev, ctx, root_pk)
                .await
                .context("failed to process respond event")?;
        }
        ChainEvent::RespondBidirectional(ev) => {
            process_respond_bidirectional_event(ev, ctx, root_pk)
                .await
                .context("failed to process respond bidirectional event")?;
        }
        ChainEvent::Block(block) => {
            process_block_event(chain, block, ctx, telemetry)
                .await
                .context("failed to process block event")?;
        }
        ChainEvent::ExecutionConfirmed {
            tx_id,
            sign_id,
            source_chain,
            block_height,
            result,
        } => {
            process_execution_confirmed(
                tx_id,
                sign_id,
                source_chain,
                block_height,
                result,
                ctx,
                chain,
            )
            .await
            .context("failed to process execution confirmation")?;
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "test_utils.rs"]
mod test_utils;

#[cfg(test)]
#[path = "stream_tests.rs"]
mod stream_tests;
