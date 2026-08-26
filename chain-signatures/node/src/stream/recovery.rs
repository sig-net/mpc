use crate::backlog::{consensus, Backlog};
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::types::CheckpointWatcher;

use mpc_primitives::Chain;
use near_account_id::AccountId;
use tokio::sync::watch;

/// Node-side checkpoint recovery:
/// loads the local checkpoint into the backlog (it only touches local storage),
/// then aligns the backlog with the consensus checkpoint feed. Mesh availability
/// is handled inside `align_backlog_with_consensus` when it needs to fetch a
/// checkpoint from peers.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn recover_backlog(
    chain: Chain,
    load_local: bool,
    backlog: &Backlog,
    checkpoints_rx: &mut CheckpointWatcher,
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    my_account_id: &AccountId,
) {
    tracing::info!(%chain, load_local, "starting checkpoint recovery or regression");

    // Hydrate the local checkpoint before aligning: the web server (spawned
    // independently) can then serve durable pending bodies to peers during
    // startup. `load_local` only reads local storage and does not need the mesh.
    if load_local {
        match backlog.load_local(chain).await {
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

    match consensus::align_backlog_with_consensus(
        chain,
        backlog,
        checkpoints_rx,
        mesh_state,
        node_client,
        my_account_id,
    )
    .await
    {
        consensus::Alignment::Aligned => {}
        consensus::Alignment::Regressed(height) => {
            tracing::warn!(%chain, height, "backlog regressed via consensus checkpoint");
        }
        consensus::Alignment::ResetApplied(height) => {
            tracing::warn!(%chain, height, "contract checkpoint reset applied");
        }
        consensus::Alignment::ResetFailed(height) => {
            tracing::error!(
                %chain,
                height,
                "failed to apply contract checkpoint reset; will retry"
            );
        }
    }
}
