use crate::backlog::{consensus, Backlog};
use crate::mesh::{self, MeshState};
use crate::node_client::NodeClient;
use crate::types::CheckpointWatcher;

use mpc_primitives::Chain;
use near_account_id::AccountId;
use tokio::sync::watch;

/// Node-side checkpoint recovery:
/// waits for an active mesh, optionally loads the latest local checkpoint into the
/// backlog, then aligns the backlog with the consensus checkpoint feed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn recover_backlog(
    chain: Chain,
    load_local: bool,
    backlog: &Backlog,
    checkpoints_rx: &mut CheckpointWatcher,
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    threshold: usize,
    my_account_id: &AccountId,
) {
    tracing::info!(%chain, load_local, "starting checkpoint recovery or regression");
    mesh::wait_threshold_active(mesh_state, threshold).await;

    if load_local {
        match backlog.storage.load_latest(chain).await {
            Ok(Some(checkpoint)) => {
                tracing::info!(
                    ?chain,
                    height = checkpoint.block_height,
                    "loaded local checkpoint"
                );
                if let Err(err) = backlog.recover_by_checkpoint(checkpoint).await {
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
    // the backlog was regressed.
    if consensus::align_backlog_with_consensus(
        chain,
        backlog,
        checkpoints_rx,
        mesh_state,
        node_client,
        my_account_id,
    )
    .await
    .is_some()
    {
        tracing::warn!(%chain, "backlog regressed via consensus checkpoint");
    }
}
