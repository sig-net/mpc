pub mod ops;
pub(crate) mod recovery;
pub mod supervisor;

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

use anyhow::Context;
use mpc_chain_integration_core::ChainTelemetry;
use mpc_primitives::{Chain, ChainEvent, SignCommand};
use tokio::sync::{mpsc, watch};

/// Shared, per-chain dependencies
pub struct StreamContext {
    pub backlog: Backlog,
    pub sign_tx: mpsc::Sender<SignCommand>,
    pub rpc: RpcChannel,
    pub contract_watcher: ContractStateWatcher,
    pub mesh_state: watch::Receiver<MeshState>,
    pub node_client: NodeClient,
    pub checkpoints_rx: CheckpointWatcher,
    pub caught_up: bool,
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
        }
    }

    /// Forward a sign command to the signing pipeline, but only when caught up.
    /// Pre-catchup commands are dropped: the backlog retains the request and re-enqueues it on `CatchupCompleted`.
    pub async fn try_enqueue(&self, cmd: SignCommand) -> anyhow::Result<()> {
        if self.caught_up {
            self.sign_tx
                .send(cmd)
                .await
                .context("sign command channel closed")?;
        }
        Ok(())
    }
}

/// Dispatch a single chain event to the appropriate processor.
pub(crate) async fn handle_chain_event<T: ChainTelemetry>(
    event: ChainEvent,
    ctx: &mut StreamContext,
    telemetry: &T,
    root_pk: mpc_primitives::PublicKey,
    chain: Chain,
) -> anyhow::Result<()> {
    match event {
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
