use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::ParticipantInfo;
use crate::protocol::Chain;

use cait_sith::protocol::Participant;
use mpc_primitives::Checkpoint;
use mpc_primitives::CheckpointDigest;
use near_account_id::AccountId;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::time::Duration;
use tokio::sync::watch;

pub async fn align_backlog_with_consensus(
    chain: Chain,
    backlog: &Backlog,
    checkpoints_rx: &mut watch::Receiver<CheckpointDigest>,
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    my_account_id: &AccountId,
) -> Option<u64> {
    let checkpoint_digest = checkpoints_rx.borrow_and_update().clone();
    // Ignore the default zero-digest (no consensus checkpoint observed yet).
    if checkpoint_digest.digest == [0u8; 32] {
        return None;
    }

    // If we have a local checkpoint, check if we're already aligned.
    // Use latest_checkpoint (read-only) instead of checkpoint() to avoid
    // creating a new checkpoint as a side-effect during alignment.
    if let Some(current_checkpoint) = backlog.latest_checkpoint(chain).await {
        if current_checkpoint.digest() == checkpoint_digest.digest {
            // Consensus matches our latest → confirm and persist it.
            backlog.on_consensus_confirmed(chain, &current_checkpoint).await;
            return None;
        }

        // If our current height is greater than consensus height,
        // check if we have a checkpoint in our pending set that matches
        // the consensus digest (we're ahead but aligned).
        if current_checkpoint.block_height > checkpoint_digest.height
            && backlog
                .find_checkpoint_by_digest(chain, checkpoint_digest.digest)
                .await
                .is_some()
        {
            tracing::info!(
                ?chain,
                local_height = current_checkpoint.block_height,
                consensus_height = checkpoint_digest.height,
                "local backlog is ahead of consensus and matches past consensus checkpoint; confirming"
            );
            if let Some(matched) = backlog
                .find_checkpoint_by_digest(chain, checkpoint_digest.digest)
                .await
            {
                backlog.on_consensus_confirmed(chain, &matched).await;
            }
            return None;
        }
    } else {
        tracing::info!(
            ?chain,
            ?checkpoint_digest,
            "no local checkpoint; consensus checkpoint exists, fetching..."
        );
    }

    tracing::warn!(
        ?chain,
        ?checkpoint_digest.digest,
        "Consensus checkpoint mismatch/divergence detected: triggering regression"
    );
    let fetched_checkpoint = find_consensus_checkpoint(
        mesh_state,
        node_client,
        chain,
        checkpoint_digest.digest,
        checkpoints_rx,
        my_account_id,
    )
    .await?;

    let height = fetched_checkpoint.block_height;

    // Persist the recovered checkpoint as the latest consensus checkpoint
    // before overwriting the local backlog, so the node has a fallback on restart.
    if let Err(err) = backlog.storage.persist(&fetched_checkpoint).await {
        tracing::warn!(?chain, %err, "failed to persist regressed checkpoint");
    }

    if let Err(err) = backlog.recover_by_checkpoint(fetched_checkpoint).await {
        tracing::error!(?err, %chain, "failed to recover backlog to checkpoint");
        return None;
    }

    Some(height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use crate::node_client::Options as NodeClientOptions;

    fn make_test_env(
        _chain: Chain,
        checkpoint_digest: CheckpointDigest,
    ) -> (
        Backlog,
        watch::Receiver<CheckpointDigest>,
        watch::Receiver<MeshState>,
        NodeClient,
        AccountId,
    ) {
        let backlog = Backlog::new();
        let (checkpoints_tx, checkpoints_rx) = watch::channel(checkpoint_digest);
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let node_client = NodeClient::new(&NodeClientOptions::default());
        let my_account_id: AccountId = "test.near".parse().unwrap();
        drop(checkpoints_tx);
        (backlog, checkpoints_rx, mesh_rx, node_client, my_account_id)
    }

    #[tokio::test]
    async fn test_align_zero_digest_returns_none() {
        let chain = Chain::Ethereum;
        let (backlog, mut checkpoints_rx, mut mesh_rx, node_client, my_account_id) =
            make_test_env(chain, CheckpointDigest { height: 0, digest: [0u8; 32] });

        let result = align_backlog_with_consensus(
            chain,
            &backlog,
            &mut checkpoints_rx,
            &mut mesh_rx,
            &node_client,
            &my_account_id,
        )
        .await;

        assert!(result.is_none(), "zero digest should return None");
    }

    #[tokio::test]
    async fn test_align_matching_latest_confirms() {
        let chain = Chain::Ethereum;
        let backlog = Backlog::new();

        backlog.set_processed_block(chain, 100).await;
        let cp = backlog.checkpoint(chain).await.unwrap();
        let digest = cp.digest();

        let (checkpoints_tx, mut checkpoints_rx) = watch::channel(CheckpointDigest {
            height: 100,
            digest,
        });
        let (_mesh_tx, mut mesh_rx) = watch::channel(MeshState::default());
        let node_client = NodeClient::new(&NodeClientOptions::default());
        let my_account_id: AccountId = "test.near".parse().unwrap();
        drop(checkpoints_tx);

        let result = align_backlog_with_consensus(
            chain,
            &backlog,
            &mut checkpoints_rx,
            &mut mesh_rx,
            &node_client,
            &my_account_id,
        )
        .await;

        assert!(result.is_none(), "matching latest should return None");

        // Checkpoint should be persisted as latest consensus checkpoint
        let persisted = backlog.storage.load_latest(chain).await.unwrap();
        assert!(persisted.is_some(), "matching checkpoint should be persisted");
        assert_eq!(persisted.unwrap().block_height, 100);
    }

    #[tokio::test]
    async fn test_align_ahead_with_pending_match_confirms() {
        let chain = Chain::Ethereum;
        let backlog = Backlog::new();

        // Create two checkpoints: at 100 and 200
        backlog.set_processed_block(chain, 100).await;
        let cp1 = backlog.checkpoint(chain).await.unwrap();
        backlog.set_processed_block(chain, 200).await;
        backlog.checkpoint(chain).await.unwrap();

        // Consensus matches the earlier checkpoint (height 100)
        let digest = cp1.digest();
        let (checkpoints_tx, mut checkpoints_rx) = watch::channel(CheckpointDigest {
            height: 100,
            digest,
        });
        let (_mesh_tx, mut mesh_rx) = watch::channel(MeshState::default());
        let node_client = NodeClient::new(&NodeClientOptions::default());
        let my_account_id: AccountId = "test.near".parse().unwrap();
        drop(checkpoints_tx);

        let result = align_backlog_with_consensus(
            chain,
            &backlog,
            &mut checkpoints_rx,
            &mut mesh_rx,
            &node_client,
            &my_account_id,
        )
        .await;

        assert!(result.is_none(), "ahead with pending match should return None");

        // The matching checkpoint should be persisted
        let persisted = backlog.storage.load_latest(chain).await.unwrap();
        assert!(persisted.is_some(), "matched checkpoint should be persisted");
        assert_eq!(persisted.unwrap().block_height, 100,
            "the persisted checkpoint should be the older matching one, not the latest");
    }

    #[tokio::test]
    async fn test_align_no_local_nonzero_digest_does_not_panic() {
        // This path falls through to find_consensus_checkpoint, which needs
        // actual peers to query. For a unit test we verify it doesn't panic
        // and returns None when no peers are available.
        let chain = Chain::Ethereum;
        let backlog = Backlog::new();

        let digest = [0x42u8; 32];
        let (checkpoints_tx, mut checkpoints_rx) = watch::channel(CheckpointDigest {
            height: 100,
            digest,
        });
        let (_mesh_tx, mut mesh_rx) = watch::channel(MeshState::default());
        let node_client = NodeClient::new(&NodeClientOptions::default());
        let my_account_id: AccountId = "test.near".parse().unwrap();
        drop(checkpoints_tx);

        let result = align_backlog_with_consensus(
            chain,
            &backlog,
            &mut checkpoints_rx,
            &mut mesh_rx,
            &node_client,
            &my_account_id,
        )
        .await;

        // No peers available → find_consensus_checkpoint returns None
        assert!(result.is_none(), "no peers available should return None");
    }
}

async fn fetch_peer_checkpoint(
    node_client: &NodeClient,
    url: &str,
    chain: Chain,
    target_digest: [u8; 32],
) -> Option<Checkpoint> {
    let result = node_client
        .fetch_checkpoint_by_digest(url, chain, target_digest)
        .await;
    match result {
        Ok(Some(checkpoint)) => {
            let digest = checkpoint.digest();
            if digest == target_digest {
                Some(checkpoint)
            } else {
                tracing::warn!(
                    ?url,
                    ?chain,
                    ?digest,
                    "peer checkpoint with mismatched digest; skipping"
                );
                None
            }
        }
        Ok(None) => {
            tracing::debug!(?url, ?chain, "peer does not have the checkpoint");
            None
        }
        Err(err) => {
            tracing::debug!(?url, ?chain, ?err, "failed to query peer for checkpoint");
            None
        }
    }
}

async fn query_peers_checkpoint(
    peers: &[(Participant, ParticipantInfo)],
    node_client: &NodeClient,
    chain: Chain,
    target_digest: [u8; 32],
) -> Option<Checkpoint> {
    for (peer, info) in peers {
        tracing::debug!(?peer, ?chain, "querying peer for checkpoint");
        let checkpoint = fetch_peer_checkpoint(node_client, &info.url, chain, target_digest).await;
        if let Some(checkpoint) = checkpoint {
            return Some(checkpoint);
        }
    }
    None
}

/// Find the consensus checkpoint from other nodes; this will keep retrying until
/// the checkpoint is found. If the consensus checkpoint changes during the querying
/// process, this function will return None.
pub(crate) async fn find_consensus_checkpoint(
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    chain: Chain,
    target_digest: [u8; 32],
    consensus_rx: &mut watch::Receiver<CheckpointDigest>,
    my_account_id: &AccountId,
) -> Option<Checkpoint> {
    let mut peers: Vec<_> = mesh_state
        .borrow()
        .active()
        .participants
        .clone()
        .into_iter()
        .filter(|(_, info)| &info.account_id != my_account_id)
        .collect();
    peers.shuffle(&mut thread_rng());

    loop {
        tokio::select! {
            // we should biased towards seeing whether the consensus digest has changed
            biased;

            changed = consensus_rx.changed() => {
                if changed.is_err() {
                    return None;
                }
                let checkpoint_digest = consensus_rx.borrow_and_update();
                if checkpoint_digest.digest != target_digest {
                    tracing::info!(?chain, "consensus digest changed during wait, aborting...");
                    return None;
                }
            }
            changed = mesh_state.changed() => {
                if changed.is_err() {
                    return None;
                }
                let active = mesh_state.borrow_and_update().active().participants.clone();
                peers = active
                    .into_iter()
                    .filter(|(_, info)| &info.account_id != my_account_id)
                    .collect();
                peers.shuffle(&mut thread_rng());
            }

            checkpoint = query_peers_checkpoint(
                &peers,
                node_client,
                chain,
                target_digest,
            ) => {
                let Some(checkpoint) = checkpoint else {
                    // this should not happen in normal circumstances, but just in case
                    // all nodes do not have the checkpoint, we will retry in 3 seconds.
                    // In that span of time, either the consensus digest must have changed
                    // or one of the nodes should have set the digest checkpoint.
                    tracing::warn!("all peers do not have the checkpoint, retrying in 3 seconds");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                };
                break Some(checkpoint);
            }
        }
    }
}
