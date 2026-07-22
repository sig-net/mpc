use crate::backlog::{consensus, Backlog};
use crate::mesh::{self, MeshState};
use crate::node_client::NodeClient;
use crate::rpc::RpcChannel;
use crate::types::CheckpointWatcher;

use mpc_primitives::Chain;
use near_account_id::AccountId;
use tokio::sync::watch;

/// Node-side checkpoint recovery:
/// waits for an active mesh, optionally loads the latest local checkpoint into the
/// backlog, then aligns the backlog with the consensus checkpoint feed, aborting
/// in-flight RPC tasks for this chain if a regression occurred.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn recover_backlog(
    chain: Chain,
    load_local: bool,
    backlog: &Backlog,
    checkpoints_rx: &mut CheckpointWatcher,
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    rpc: &RpcChannel,
    threshold: usize,
    my_account_id: &AccountId,
) {
    tracing::info!(%chain, load_local, "starting checkpoint recovery or regression");
    mesh::wait_threshold_active(&mut mesh_state.clone(), threshold).await;

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

    // A recovery without local loading is triggered by a regression or watchdog
    // restart. Abort stale RPC work before alignment so failed peer lookup or
    // backlog recovery cannot leave retries running indefinitely.
    if !load_local {
        rpc.abort_chain(chain).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use crate::mesh::MeshState;
    use crate::node_client::NodeClient;
    use crate::rpc::RpcAction;
    use crate::stream::test_utils::test_rpc_channel;
    use mpc_primitives::CheckpointDigest;
    use std::time::Duration;
    use tokio::sync::watch;

    #[tokio::test]
    async fn recovery_aborts_rpc_before_failed_alignment() {
        let chain = Chain::Ethereum;
        let backlog = Backlog::new();
        backlog.set_processed_block(chain, 100).await;
        let checkpoint = backlog.checkpoint(chain).await.unwrap();
        let (_checkpoint_tx, mut checkpoints_rx) = watch::channel(Some(CheckpointDigest {
            height: checkpoint.block_height,
            digest: [9; 32],
        }));
        let (_mesh_tx, mut mesh_state) = watch::channel(MeshState::default());
        let (rpc, mut rpc_rx) = test_rpc_channel(1);
        let node_client = NodeClient::new(&Default::default());
        let account_id: AccountId = "test.near".parse().unwrap();

        let action = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                action = rpc_rx.recv() => action,
                _ = recover_backlog(
                    chain,
                    false,
                    &backlog,
                    &mut checkpoints_rx,
                    &mut mesh_state,
                    &node_client,
                    &rpc,
                    0,
                    &account_id,
                ) => panic!("recovery should wait for peer alignment"),
            }
        })
        .await
        .expect("abort should be sent before alignment waits for peers")
        .expect("RPC channel should remain open");
        assert!(matches!(action, RpcAction::AbortChain(Chain::Ethereum)));
    }
}
