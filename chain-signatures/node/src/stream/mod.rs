pub mod ops;
pub mod pipeline;

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

use mpc_chain_integration_core::{ChainIndexer, ChainStream, ChainTelemetry};
use mpc_primitives::{ChainEvent, SignCommand};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStreaming {
    Recovery { load_local: bool },
    Catchup { anchor_height: u64 },
    Live,
}

/// Shared indexer loop: recovers backlog then processes events from the stream
#[allow(clippy::too_many_arguments)]
pub async fn run_stream<S: ChainStream, T: ChainTelemetry>(
    mut stream: S,
    sign_tx: mpsc::Sender<SignCommand>,
    rpc: RpcChannel,
    backlog: Backlog,
    telemetry: T,
    mut contract_watcher: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    checkpoints_rx: CheckpointWatcher,
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
        sign_tx.clone(),
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
                    ChainEvent::SignRequest { request, block_timestamp } => {
                        // Handle metrics reporting for the sign request event
                        if let Some(ts) = block_timestamp {
                            // Report the request was indexed at the given block timestamp is currently used for Ethereum due to ~15 min finality delay
                            telemetry.request_indexed_at(ts);
                        } else {
                            // Other faster chains (e.g. for Solana, Canton, or Hydration) report that a request was indexed without a block timestamp
                            telemetry.request_indexed();
                        }

                        if let Err(err) =
                            process_sign_request(request, sign_tx.clone(), backlog.clone(), caught_up).await
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
#[path = "stream_tests.rs"]
mod stream_tests;
