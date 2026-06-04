use crate::backlog::Backlog;
use crate::mesh::{wait_threshold_active, MeshState};
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::ParticipantInfo;
use crate::protocol::Chain;
use crate::rpc::{CheckpointDigest, ContractStateWatcher};

use cait_sith::protocol::Participant;
use mpc_primitives::Checkpoint;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::time::Duration;
use tokio::sync::watch;

pub(crate) async fn align_backlog_with_consensus(
    chain: Chain,
    backlog: &Backlog,
    checkpoints_rx: &mut watch::Receiver<CheckpointDigest>,
    mesh_state: &watch::Receiver<MeshState>,
    node_client: &NodeClient,
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

    tracing::warn!(
        ?chain,
        ?checkpoint_digest.digest,
        "Consensus checkpoint mismatch/divergence detected! Triggering regression."
    );
    let fetched_checkpoint = find_consensus_checkpoint(
        mesh_state,
        node_client,
        chain,
        checkpoint_digest.digest,
        checkpoints_rx,
    )
    .await?;

    let height = fetched_checkpoint.height;
    if let Err(err) = backlog.recover_by_checkpoint(fetched_checkpoint).await {
        tracing::error!(?err, %chain, "Failed to recover backlog to checkpoint");
        return None;
    }

    Some(height)
}

pub(crate) async fn recover_backlog(
    backlog: &Backlog,
    contract_watcher: &mut ContractStateWatcher,
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    source_chain: Chain,
    checkpoints_rx: &mut watch::Receiver<CheckpointDigest>,
) {
    // Recover backlog before doing anything.
    // Wait for threshold to be available
    let threshold = contract_watcher.wait_threshold().await;
    if threshold == 0 {
        return;
    }
    wait_threshold_active(mesh_state, threshold).await;

    // Load local checkpoint from storage first
    match backlog.storage.load_latest(source_chain).await {
        Ok(Some(checkpoint)) => {
            tracing::info!(
                ?source_chain,
                height = checkpoint.height,
                "loaded local checkpoint"
            );
            if let Err(err) = backlog.recover_by_checkpoint(checkpoint).await {
                tracing::warn!(?source_chain, %err, "failed to recover from local checkpoint");
            }
        }
        Ok(None) => {
            tracing::info!(?source_chain, "no local checkpoint found");
        }
        Err(err) => {
            tracing::warn!(?source_chain, %err, "failed to load local checkpoint");
        }
    }

    // Align with consensus
    let _ = align_backlog_with_consensus(
        source_chain,
        backlog,
        checkpoints_rx,
        mesh_state,
        node_client,
    )
    .await;
}

async fn fetch_checkpoint_from_peer(
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

async fn query_peers_until_consensus_change(
    peers: Vec<(Participant, ParticipantInfo)>,
    node_client: &NodeClient,
    chain: Chain,
    target_digest: [u8; 32],
    consensus_rx: &mut watch::Receiver<CheckpointDigest>,
) -> Result<Option<Checkpoint>, ()> {
    for (peer, info) in peers {
        if consensus_rx.borrow().digest != target_digest {
            return Err(());
        }

        tracing::debug!(?peer, ?chain, "querying peer for checkpoint");
        let fetch_fut = fetch_checkpoint_from_peer(node_client, &info.url, chain, target_digest);
        tokio::select! {
            checkpoint = fetch_fut => {
                if let Some(checkpoint) = checkpoint {
                    return Ok(Some(checkpoint));
                }
            }
            changed = consensus_rx.changed() => {
                if changed.is_err() {
                    return Err(());
                }
                let cp_digest = consensus_rx.borrow_and_update();
                if cp_digest.digest != target_digest {
                    tracing::info!(?chain, "consensus digest changed during query, aborting");
                    return Err(());
                }
            }
        }
    }
    Ok(None)
}

pub(crate) async fn find_consensus_checkpoint(
    mesh_state: &watch::Receiver<MeshState>,
    node_client: &NodeClient,
    chain: Chain,
    target_digest: [u8; 32],
    consensus_rx: &mut watch::Receiver<CheckpointDigest>,
) -> Option<Checkpoint> {
    loop {
        // Abort if consensus has moved to a different target digest.
        if consensus_rx.borrow().digest != target_digest {
            tracing::info!(?chain, "consensus digest changed, aborting fetch loop");
            return None;
        }

        let participants_info = mesh_state.borrow().active().participants.clone();
        let mut peers: Vec<_> = participants_info.into_iter().collect();
        peers.shuffle(&mut thread_rng());

        match query_peers_until_consensus_change(
            peers,
            node_client,
            chain,
            target_digest,
            consensus_rx,
        )
        .await
        {
            Ok(Some(checkpoint)) => return Some(checkpoint),
            Ok(None) => {}
            Err(()) => return None,
        }

        // Wait before retrying, but abort early if consensus moves.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = consensus_rx.changed() => {
                let _ = consensus_rx.borrow_and_update();
                if consensus_rx.borrow().digest != target_digest {
                    tracing::info!(?chain, "consensus digest changed during wait, aborting fetch");
                    return None;
                }
            }
        }
    }
}
