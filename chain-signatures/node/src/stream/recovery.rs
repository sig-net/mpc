use crate::backlog::consensus;
use crate::mesh;
use crate::stream::StreamContext;

use mpc_primitives::{Chain, SignCommand};
use near_account_id::AccountId;

/// Node-side checkpoint recovery:
/// waits for an active mesh, optionally loads the latest local checkpoint into the
/// backlog, then aligns the backlog with the consensus checkpoint feed, aborting
/// in-flight signature tasks for this chain if a regression occurred.
pub(crate) async fn recover_backlog(
    chain: Chain,
    load_local: bool,
    ctx: &mut StreamContext,
    threshold: usize,
    my_account_id: &AccountId,
) {
    tracing::info!(%chain, load_local, "starting checkpoint recovery or regression");
    mesh::wait_threshold_active(&mut ctx.mesh_state, threshold).await;

    if load_local {
        match ctx.backlog.storage.load_latest(chain).await {
            Ok(Some(checkpoint)) => {
                tracing::info!(
                    ?chain,
                    height = checkpoint.block_height,
                    "loaded local checkpoint"
                );
                if let Err(err) = ctx.backlog.recover_by_checkpoint(checkpoint).await {
                    tracing::warn!(?chain, %err, "failed to recover from local checkpoint");
                }
            }
            Ok(None) => {
                tracing::info!(?chain, "no local checkpoint found");
            }
            Err(err) => {
                tracing::warn!(?chain, %err, "failed to load local checkpoint");
            }
        }
    }

    // Returns None when no alignment is needed (the normal case); Some(height) when
    // the backlog was regressed. On regression, abort all in-flight signature tasks
    // for this chain so stale tasks don't complete and publish abandoned
    // signatures/checkpoints.
    if consensus::align_backlog_with_consensus(
        chain,
        &ctx.backlog,
        &mut ctx.checkpoints_rx,
        &mut ctx.mesh_state,
        &ctx.node_client,
        my_account_id,
    )
    .await
    .is_some()
    {
        tracing::warn!(%chain, "backlog regressed via consensus checkpoint; aborting in-flight tasks");
        let _ = ctx.sign_tx.send(SignCommand::AbortChain(chain)).await;
    }
}
