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

    // Hydrate local checkpoint state before aligning: initializes the pending count
    // and recovers from the latest durable checkpoint if one exists.
    if load_local {
        match backlog.hydrate(chain).await {
            Ok(Some(checkpoint)) => {
                tracing::info!(
                    ?chain,
                    height = checkpoint.block_height,
                    "hydrated local checkpoint"
                );
            }
            Ok(None) => {
                tracing::info!(?chain, "no local checkpoint found");
            }
            Err(err) => {
                tracing::warn!(?chain, %err, "failed to hydrate local checkpoint");
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
