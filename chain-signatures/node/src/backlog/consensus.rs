use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::ParticipantInfo;
use crate::types::CheckpointWatcher;

use cait_sith::protocol::Participant;
use mpc_primitives::{Chain, Checkpoint};
use near_account_id::AccountId;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::time::Duration;
use tokio::sync::watch;

/// Returns None if we are aligned, Some(<new_height>) if we have regressed.
pub async fn align_backlog_with_consensus(
    chain: Chain,
    backlog: &Backlog,
    checkpoints_rx: &mut CheckpointWatcher,
    mesh_state: &mut watch::Receiver<MeshState>,
    node_client: &NodeClient,
    my_account_id: &AccountId,
) -> Option<u64> {
    let checkpoint_digest = checkpoints_rx.borrow_and_update().as_ref()?.clone();

    // If we can find the consensus checkpoint locally, confirm it and return.
    if let Some(matched) = backlog
        .find_checkpoint_by_digest(chain, checkpoint_digest.digest)
        .await
    {
        tracing::info!(
            ?chain,
            matched_height = matched.block_height,
            consensus_height = checkpoint_digest.height,
            "consensus checkpoint matches a local checkpoint; confirming"
        );
        backlog.on_consensus_confirmed(chain, &matched).await;
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
    consensus_rx: &mut CheckpointWatcher,
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
                match &*checkpoint_digest {
                    None => {
                        tracing::info!(?chain, "consensus digest is empty, aborting...");
                        return None;
                    }
                    Some(cp) => {
                        if cp.digest != target_digest {
                            tracing::info!(?chain, "consensus digest changed during wait, aborting...");
                            return None;
                        }
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use crate::mesh::connection::NodeStatus;
    use crate::node_client::Options as NodeClientOptions;

    use mpc_primitives::{CheckpointDigest, IndexedSignRequest, PendingTx, SignArgs, SignId};
    use std::collections::HashMap;

    struct AlignFixture {
        chain: Chain,
        backlog: Backlog,
        checkpoints_tx: watch::Sender<Option<CheckpointDigest>>,
        checkpoints_rx: watch::Receiver<Option<CheckpointDigest>>,
        mesh_tx: watch::Sender<MeshState>,
        mesh_rx: watch::Receiver<MeshState>,
        node_client: NodeClient,
        my_account_id: AccountId,
    }

    impl AlignFixture {
        fn new(digest: Option<CheckpointDigest>) -> Self {
            let chain = Chain::Ethereum;
            let backlog = Backlog::new();
            let (checkpoints_tx, checkpoints_rx) = watch::channel(digest);
            let (mesh_tx, mesh_rx) = watch::channel(MeshState::default());
            let node_client = NodeClient::new(&NodeClientOptions::default());
            let my_account_id: AccountId = "test.near".parse().unwrap();
            Self {
                chain,
                backlog,
                checkpoints_tx,
                checkpoints_rx,
                mesh_tx,
                mesh_rx,
                node_client,
                my_account_id,
            }
        }

        async fn run(&mut self) -> Option<u64> {
            align_backlog_with_consensus(
                self.chain,
                &self.backlog,
                &mut self.checkpoints_rx,
                &mut self.mesh_rx,
                &self.node_client,
                &self.my_account_id,
            )
            .await
        }
    }

    struct TestCase {
        name: &'static str,
        // Local setup
        local_checkpoints: Vec<u64>,
        local_has_pending_tx: bool,
        // Remote consensus setup
        remote_height: u64,
        remote_use_local_digest_idx: Option<usize>,
        remote_use_peer_digest: bool,
        // Peer setup
        peer_has_checkpoint: bool,
        peer_checkpoint_height: u64,
        peer_checkpoint_has_pending_tx: bool,
        // Expected results
        expected_result: Option<u64>,
        expected_persisted_height: Option<u64>,
    }

    #[tokio::test]
    async fn test_consensus_alignment_matrix() {
        let cases = vec![
            TestCase {
                name: "Case 1: No Local, Has Remote",
                local_checkpoints: vec![],
                local_has_pending_tx: false,
                remote_height: 100,
                remote_use_local_digest_idx: None,
                remote_use_peer_digest: true,
                peer_has_checkpoint: true,
                peer_checkpoint_height: 100,
                peer_checkpoint_has_pending_tx: false,
                expected_result: Some(100),
                expected_persisted_height: Some(100),
            },
            TestCase {
                name: "Case 2: Has Local, No Remote",
                local_checkpoints: vec![100],
                local_has_pending_tx: false,
                remote_height: 0,
                remote_use_local_digest_idx: None,
                remote_use_peer_digest: false,
                peer_has_checkpoint: false,
                peer_checkpoint_height: 0,
                peer_checkpoint_has_pending_tx: false,
                expected_result: None,
                expected_persisted_height: None,
            },
            TestCase {
                name: "Case 3: No Local, No Remote",
                local_checkpoints: vec![],
                local_has_pending_tx: false,
                remote_height: 0,
                remote_use_local_digest_idx: None,
                remote_use_peer_digest: false,
                peer_has_checkpoint: false,
                peer_checkpoint_height: 0,
                peer_checkpoint_has_pending_tx: false,
                expected_result: None,
                expected_persisted_height: None,
            },
            TestCase {
                name: "Case 4: Both Present, Matches",
                local_checkpoints: vec![100],
                local_has_pending_tx: false,
                remote_height: 100,
                remote_use_local_digest_idx: Some(0),
                remote_use_peer_digest: false,
                peer_has_checkpoint: false,
                peer_checkpoint_height: 0,
                peer_checkpoint_has_pending_tx: false,
                expected_result: None,
                expected_persisted_height: Some(100),
            },
            TestCase {
                name: "Case 5: Ahead but Aligned",
                local_checkpoints: vec![100, 200],
                local_has_pending_tx: false,
                remote_height: 100,
                remote_use_local_digest_idx: Some(0),
                remote_use_peer_digest: false,
                peer_has_checkpoint: false,
                peer_checkpoint_height: 0,
                peer_checkpoint_has_pending_tx: false,
                expected_result: None,
                expected_persisted_height: Some(100),
            },
            TestCase {
                name: "Case 6: Both Present, Divergent. Take Remote",
                local_checkpoints: vec![100],
                local_has_pending_tx: true,
                remote_height: 100,
                remote_use_local_digest_idx: None,
                remote_use_peer_digest: true,
                peer_has_checkpoint: true,
                peer_checkpoint_height: 100,
                peer_checkpoint_has_pending_tx: false,
                expected_result: Some(100),
                expected_persisted_height: Some(100),
            },
        ];

        let chain = Chain::Ethereum;

        for case in cases {
            let mut fixture = AlignFixture::new(None);

            // 1. Setup local checkpoints
            let mut local_digests = Vec::new();
            if !case.local_checkpoints.is_empty() {
                if case.local_has_pending_tx {
                    let tx = IndexedSignRequest::sign(
                        SignId::new([1u8; 32]),
                        SignArgs {
                            entropy: [1u8; 32],
                            epsilon: k256::Scalar::ONE,
                            payload: k256::Scalar::ONE,
                            path: "test".to_string(),
                            key_version: 0,
                        },
                        chain,
                        0,
                    );
                    fixture.backlog.insert(tx).await;
                }

                for &height in &case.local_checkpoints {
                    fixture.backlog.set_processed_block(chain, height).await;
                    let cp = fixture.backlog.checkpoint(chain).await.unwrap();
                    local_digests.push(cp.digest());
                }
            }

            // 2. Setup Mock peer if needed
            let mut server = None;
            let mut mock_guard = None;
            let mut peer_digest = [0u8; 32];
            if case.peer_has_checkpoint {
                let peer_checkpoint = Checkpoint {
                    chain,
                    block_height: case.peer_checkpoint_height,
                    pending_requests: if case.peer_checkpoint_has_pending_tx {
                        vec![PendingTx {
                            sign_id: SignId::new([1u8; 32]),
                            transaction: vec![1, 2, 3],
                        }]
                    } else {
                        vec![]
                    },
                };
                peer_digest = peer_checkpoint.digest();

                let mut s = mockito::Server::new_async().await;
                let peer_url = s.url();

                let mut response_map = HashMap::new();
                response_map.insert(chain, peer_checkpoint);
                let mut body = Vec::new();
                ciborium::into_writer(&response_map, &mut body).unwrap();

                let mock = s
                    .mock("GET", "/checkpoint")
                    .match_query(mockito::Matcher::Any)
                    .with_status(200)
                    .with_header("content-type", "application/cbor")
                    .with_body(body)
                    .create_async()
                    .await;

                // Register the peer in the mesh state
                let mut mesh = MeshState::default();
                let participant = Participant::from(1u32);
                let mut info = ParticipantInfo::new(1);
                info.url = peer_url;
                mesh.update(participant, NodeStatus::Active, info);
                fixture.mesh_tx.send(mesh).unwrap();

                server = Some(s);
                mock_guard = Some(mock);
            }

            // 3. Setup remote consensus
            let mut remote_digest = None;
            if let Some(idx) = case.remote_use_local_digest_idx {
                remote_digest = Some(local_digests[idx]);
            } else if case.remote_use_peer_digest {
                remote_digest = Some(peer_digest);
            }

            let msg = remote_digest.map(|digest| CheckpointDigest {
                height: case.remote_height,
                digest,
            });

            fixture.checkpoints_tx.send(msg).unwrap();

            // 4. Run consensus alignment
            let result = fixture.run().await;

            // 5. Assert expected result
            assert_eq!(
                result, case.expected_result,
                "Test case failed: {}, expected result {:?}",
                case.name, case.expected_result
            );

            // 6. Assert persisted state
            let persisted = fixture.backlog.storage.load_latest(chain).await.unwrap();
            if let Some(expected_height) = case.expected_persisted_height {
                assert!(
                    persisted.is_some(),
                    "Test case failed: {}, expected checkpoint to be persisted",
                    case.name
                );
                assert_eq!(
                    persisted.unwrap().block_height,
                    expected_height,
                    "Test case failed: {}, expected persisted height to match",
                    case.name
                );
                if case.remote_use_peer_digest {
                    let latest = fixture.backlog.latest_checkpoint(chain).await.unwrap();
                    assert_eq!(
                        latest.digest(), remote_digest.unwrap(),
                        "Test case failed: {}, expected local backlog latest checkpoint digest to match consensus digest",
                        case.name
                    );
                }
            } else {
                if case.local_checkpoints.is_empty() {
                    assert!(persisted.is_none(), "Test case failed: {}", case.name);
                } else {
                    let latest = fixture.backlog.latest_checkpoint(chain).await;
                    assert!(latest.is_some(), "Test case failed: {}", case.name);
                    assert_eq!(
                        latest.unwrap().block_height,
                        *case.local_checkpoints.last().unwrap(),
                        "Test case failed: {}",
                        case.name
                    );
                }
            }

            // 7. Assert mock peer requests matched
            if let Some(mock) = mock_guard {
                mock.assert_async().await;
            }

            // Keep the mock server alive until iteration finishes
            drop(server);
        }
    }

    #[tokio::test]
    async fn test_align_mismatch_abort_on_consensus_change() {
        let chain = Chain::Ethereum;
        let fixture = AlignFixture::new(Some(CheckpointDigest {
            height: 100,
            digest: [0xabu8; 32],
        }));

        // Create a local checkpoint at 100
        fixture.backlog.set_processed_block(chain, 100).await;
        let _cp = fixture.backlog.checkpoint(chain).await.unwrap();

        let backlog_clone = fixture.backlog.clone();
        let node_client_clone = fixture.node_client.clone();
        let my_account_id_clone = fixture.my_account_id.clone();
        let mut checkpoints_rx_clone = fixture.checkpoints_rx.clone();
        let mut mesh_rx_clone = fixture.mesh_rx.clone();

        let handle = tokio::spawn(async move {
            align_backlog_with_consensus(
                chain,
                &backlog_clone,
                &mut checkpoints_rx_clone,
                &mut mesh_rx_clone,
                &node_client_clone,
                &my_account_id_clone,
            )
            .await
        });

        // Let it run and start querying, then update digest to zero to abort
        tokio::time::sleep(Duration::from_millis(50)).await;
        fixture.checkpoints_tx.send(None).unwrap();

        let result = handle.await.unwrap();
        assert!(result.is_none(), "aborted align should return None");
    }
}
