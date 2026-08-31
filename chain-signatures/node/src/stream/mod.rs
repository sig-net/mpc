pub mod ops;
pub(crate) mod recovery;
pub mod supervisor;

use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::stream::ops::{
    process_block_event, process_execution_confirmed, process_respond_bidirectional_event,
    process_respond_event, process_sign_request, publish_failover_due,
    requeue_pending_sign_requests, resume_pending_publish_requests,
};
use crate::types::CheckpointWatcher;

use crate::rpc::PublishKind;
use anyhow::Context;
use mpc_chain_integration_core::ChainTelemetry;
use mpc_primitives::{Chain, ChainEvent, SignCommand, SignId};
use std::collections::HashSet;
use std::time::Duration;
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
    /// Overrides the failover schedule's observe lag; `None` is production. Fixtures
    /// pin it.
    pub observe_lag: Option<Duration>,
    /// Entries this node has dispatched a publish for, from the catchup resume or
    /// the failover sweep, so a per-block sweep fires each one once. Pruned against
    /// the pending set each sweep, so an entry that leaves and returns is scheduled
    /// afresh. Keyed by publish kind too: the two legs share a sign id.
    pub(crate) published: HashSet<(SignId, PublishKind)>,
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
            observe_lag: None,
            published: HashSet::new(),
        }
    }

    /// Pin the publish failover schedule's observe lag, for fixtures that assert
    /// the failover itself rather than its production timing.
    pub fn with_observe_lag(mut self, lag: Option<Duration>) -> Self {
        self.observe_lag = lag;
        self
    }

    /// Forward a sign command to the signing pipeline, but only when caught up.
    /// Pre-catchup commands are dropped: the backlog retains the request and re-enqueues it on `CatchupCompleted`.
    pub async fn try_enqueue(&self, cmd: SignCommand) -> anyhow::Result<()> {
        if self.caught_up {
            self.sign_tx
                .send(cmd)
                .await
                .context("sign command channel closed")?;
        } else {
            tracing::warn!(
                ?cmd,
                "dropping sign command until catchup completes; the backlog requeues it on CatchupCompleted"
            );
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
            // Record the request's indexed timestamp if it's a new request
            let is_new = process_sign_request(request, ctx)
                .await
                .context("failed to process sign request")?;

            if is_new {
                if let Some(ts) = block_timestamp {
                    // Ethereum (~15 min finality) reports the block timestamp.
                    telemetry.request_indexed_at(ts);
                } else {
                    // Faster chains (Solana, Canton, Hydration) report no timestamp.
                    telemetry.request_indexed();
                }
            }
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
            // A block observed is what licenses concluding the response did not land.
            publish_failover_due(ctx, chain).await;
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
