//! Node-based checkpoint selection
//!
//! This module implements checkpoint recovery through node selection rather than
//! querying the NEAR contract. Nodes query each other's `/checkpoint` endpoints,
//! collect checkpoints for each chain, and select the threshold-lowest block
//! height checkpoint.

use crate::backlog::Checkpoint;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::Chain;
use cait_sith::protocol::Participant;
use futures_util::{stream::FuturesUnordered, StreamExt};
use std::collections::HashMap;

/// Queries all participants for their checkpoints and returns a selected checkpoint
/// for each chain based on the threshold-lowest block height: select the checkpoint
/// at position (total_count - threshold), which ensures at least threshold nodes
/// have this checkpoint or a newer one
///
/// # Algorithm
/// 1. Query all active participants' /checkpoint endpoints
/// 2. For each chain, collect all checkpoints into a flat list
/// 3. Sort checkpoints by block height (ascending)
/// 4. Select checkpoint at position threshold-1 (the threshold-lowest checkpoint)
///
/// # Returns
/// Map of chains to selected checkpoints
pub async fn select_checkpoints(
    mesh_state: &MeshState,
    node_client: &NodeClient,
    threshold: usize,
    chains: &[Chain],
) -> HashMap<Chain, Checkpoint> {
    if threshold == 0 {
        tracing::warn!("threshold must be greater than 0");
        return HashMap::new();
    }
    if mesh_state.active.participants.is_empty() {
        tracing::warn!("no active participants available for checkpoint recovery");
        return HashMap::new();
    }

    tracing::info!(
        participant_count = mesh_state.active.participants.len(),
        ?chains,
        threshold,
        "starting checkpoint selection recovery"
    );

    // Query all active participants for their latest checkpoints
    let all_checkpoints = fetch_latest(mesh_state, node_client, chains).await;

    // For each chain, find selected checkpoint
    let mut selections = HashMap::new();
    for &chain in chains {
        let Some(checkpoint) =
            select_checkpoint_for_chain(&all_checkpoints, chain, threshold).await
        else {
            tracing::warn!(?chain, "no selected checkpoint found");
            continue;
        };

        tracing::info!(
            ?chain,
            block_height = checkpoint.block_height,
            "found selected checkpoint"
        );
        selections.insert(chain, checkpoint.clone());
    }

    // TODO: make sure that the selected checkpoint is present on all nodes via
    // all_checkpoints or by calling /checkpoint for each.

    selections
}

/// Query all active participants for their latest checkpoints for each chain specified.
async fn fetch_latest(
    mesh_state: &MeshState,
    node_client: &NodeClient,
    chains: &[Chain],
) -> HashMap<Participant, HashMap<Chain, Checkpoint>> {
    let mut all_checkpoints = HashMap::new();

    // Build query string for chains
    let chains_query = if chains.is_empty() {
        String::new()
    } else {
        format!(
            "?query={}",
            chains
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )
    };

    let mut requests = mesh_state
        .active
        .participants
        .iter()
        .map(|(participant_id, info)| {
            let client = node_client.clone();
            let participant = *participant_id;
            let base_url = info.url.clone();
            let query_suffix = chains_query.clone();
            async move {
                let base_for_request = base_url.clone();
                let request_url = if query_suffix.is_empty() {
                    base_for_request
                } else {
                    format!("{base_for_request}{query_suffix}")
                };
                let result = client.checkpoint(&request_url).await;
                (participant, base_url, request_url, result)
            }
        })
        .collect::<FuturesUnordered<_>>();

    while let Some((participant_id, base_url, request_url, result)) = requests.next().await {
        match result {
            Ok(checkpoints) => {
                tracing::debug!(
                    participant = ?participant_id,
                    checkpoint_count = checkpoints.len(),
                    "received checkpoints from participant"
                );
                all_checkpoints.insert(participant_id, checkpoints);
            }
            Err(err) => {
                tracing::warn!(
                    participant = ?participant_id,
                    base_url = %base_url,
                    request_url = %request_url,
                    %err,
                    "failed to query participant for checkpoints"
                );
            }
        }
    }

    all_checkpoints
}

/// Select a checkpoint for a specific chain
async fn select_checkpoint_for_chain(
    all_checkpoints: &HashMap<Participant, HashMap<Chain, Checkpoint>>,
    chain: Chain,
    threshold: usize,
) -> Option<&Checkpoint> {
    // Collect all checkpoints for this chain into a flat list
    let mut checkpoints = Vec::with_capacity(all_checkpoints.len());
    for node_checkpoints in all_checkpoints.values() {
        if let Some(checkpoint) = node_checkpoints.get(&chain) {
            checkpoints.push(checkpoint);
        }
    }

    if checkpoints.is_empty() {
        tracing::debug!(?chain, "no checkpoints found for chain");
        return None;
    }
    if checkpoints.len() < threshold {
        tracing::warn!(
            ?chain,
            checkpoint_count = checkpoints.len(),
            threshold,
            "not enough checkpoints to reach threshold"
        );
        return None;
    }

    // Sort checkpoints by block height (ascending)
    checkpoints.sort_by_key(|c| c.block_height);

    // Take the threshold-lowest checkpoint (at index n - threshold)
    let selected_checkpoint = checkpoints.swap_remove(checkpoints.len() - threshold);

    tracing::info!(
        ?chain,
        block_height = selected_checkpoint.block_height,
        total_checkpoints = checkpoints.len(),
        threshold,
        "selected threshold-lowest checkpoint"
    );

    Some(selected_checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_checkpoint_selects_threshold_lowest() {
        let mut checkpoints = HashMap::new();

        // Node 0: height 100
        let mut node0 = HashMap::new();
        node0.insert(
            Chain::Ethereum,
            Checkpoint {
                chain: Chain::Ethereum,
                block_height: 100,
                pending_requests: vec![],
            },
        );
        checkpoints.insert(Participant::from(0), node0);

        // Node 1: height 105
        let mut node1 = HashMap::new();
        node1.insert(
            Chain::Ethereum,
            Checkpoint {
                chain: Chain::Ethereum,
                block_height: 105,
                pending_requests: vec![],
            },
        );
        checkpoints.insert(Participant::from(1), node1);

        // Node 2: height 110
        let mut node2 = HashMap::new();
        node2.insert(
            Chain::Ethereum,
            Checkpoint {
                chain: Chain::Ethereum,
                block_height: 110,
                pending_requests: vec![],
            },
        );
        checkpoints.insert(Participant::from(2), node2.clone());
        checkpoints.insert(Participant::from(3), node2);

        // should select height 105 (3rd lowest)
        let threshold = 3;
        let result = select_checkpoint_for_chain(&checkpoints, Chain::Ethereum, threshold).await;
        assert_eq!(result.unwrap().block_height, 105);
    }

    #[tokio::test]
    async fn test_checkpoint_insufficient() {
        let mut all_checkpoints = HashMap::new();

        let mut node0 = HashMap::new();
        node0.insert(
            Chain::Ethereum,
            Checkpoint {
                chain: Chain::Ethereum,
                block_height: 100,
                pending_requests: vec![],
            },
        );
        all_checkpoints.insert(Participant::from(0), node0);

        // Only 1 checkpoint, threshold=2 should fail
        let result = select_checkpoint_for_chain(&all_checkpoints, Chain::Ethereum, 2).await;
        assert!(result.is_none());
    }
}
