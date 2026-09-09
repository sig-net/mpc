use crate::backlog::consensus_watcher::ConsensusCheckpointWatcher;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;

use mpc_primitives::Chain;
use near_account_id::AccountId;
use tokio::sync::watch;

/// Node-side checkpoint recovery:
/// loads the local checkpoint into the backlog (it only touches local storage),
/// then aligns the backlog with the consensus checkpoint feed via the watcher.
/// Peer fetching happens inside the watcher when it needs a diverged
/// consensus checkpoint body.
pub(crate) async fn recover_backlog(
    chain: Chain,
    load_local: bool,
    watcher: &mut ConsensusCheckpointWatcher,
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    my_account_id: &AccountId,
) {
    tracing::info!(%chain, load_local, "starting checkpoint recovery or regression");

    // Hydrate the local checkpoint before aligning: the web server (spawned
    // independently) can then serve durable pending bodies to peers during
    // startup. `load_local` only reads local storage and does not need the mesh.
    if load_local {
        let backlog = watcher.backlog();
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

    // The watcher alerts (rich log + metric) on regression itself; here we only
    // need to know whether one happened so the supervisor restarts cleanly.
    watcher
        .align_with_consensus(mesh_state, node_client, my_account_id)
        .await;
}
