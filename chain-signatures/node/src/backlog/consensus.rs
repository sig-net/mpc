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

pub(crate) async fn align_backlog_with_consensus(
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

    // No mismatch/divergence, we are aligned with the consensus.
    let current_checkpoint = backlog.checkpoint(chain).await;
    if current_checkpoint.digest() == checkpoint_digest.digest {
        return None;
    }

    // If our current height is greater than consensus height,
    // check if we have a historical checkpoint that matches the consensus digest.
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
                "local backlog is ahead of consensus and matches past consensus checkpoint; no regression needed"
            );
        return None;
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
    if let Err(err) = backlog.recover_by_checkpoint(fetched_checkpoint).await {
        tracing::error!(?err, %chain, "failed to recover backlog to checkpoint");
        return None;
    }

    Some(height)
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
