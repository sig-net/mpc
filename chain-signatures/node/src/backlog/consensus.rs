use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::ParticipantInfo;
use crate::types::{CheckpointDirective, CheckpointWatcher};

use crate::backlog::Checkpoint;
use cait_sith::protocol::Participant;
use mpc_primitives::Chain;
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
    let directive = checkpoints_rx.borrow_and_update().as_ref().cloned()?;

    let target_digest = match directive {
        CheckpointDirective::Consensus(digest) => digest.digest,
        CheckpointDirective::Restart(height) => {
            tracing::warn!(
                ?chain,
                height,
                "consensus checkpoints were reset; clearing local checkpoint state"
            );
            return match backlog.apply_reset(chain, height).await {
                Ok(()) => None,
                Err(err) => {
                    tracing::error!(?err, %chain, "failed to apply contract checkpoint reset");
                    Some(height)
                }
            };
        }
    };

    match backlog.confirm_consensus(chain, target_digest).await {
        Ok(found) => {
            if found {
                return None;
            }
        }
        Err(err) => {
            tracing::warn!(
                ?chain,
                %err,
                "transient storage error confirming consensus checkpoint; retrying later"
            );
            return None;
        }
    }

    tracing::warn!(
        ?chain,
        ?target_digest,
        "Consensus checkpoint mismatch/divergence detected: triggering regression"
    );
    let fetched_checkpoint = find_consensus_checkpoint(
        mesh_state,
        node_client,
        chain,
        target_digest,
        checkpoints_rx,
        my_account_id,
    )
    .await?;

    let height = fetched_checkpoint.block_height;

    if let Err(err) = backlog.regress(fetched_checkpoint).await {
        tracing::error!(?err, %chain, "failed to regress backlog to checkpoint");
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
    let checkpoint = node_client
        .fetch_checkpoint_by_digest(url, chain, target_digest)
        .await
        .inspect_err(|err| {
            tracing::warn!(?url, ?chain, ?err, "failed to query peer for checkpoint");
        })
        .ok()?;

    let Some(checkpoint) = checkpoint else {
        tracing::debug!(?url, ?chain, "peer does not have the checkpoint");
        return None;
    };

    let digest = checkpoint.digest();
    if digest != target_digest {
        tracing::warn!(
            ?url,
            ?chain,
            ?digest,
            "peer checkpoint returns mismatched digest"
        );
        return None;
    }
    Some(checkpoint)
}

async fn query_peers_checkpoint(
    peers: &[(Participant, ParticipantInfo)],
    node_client: &NodeClient,
    chain: Chain,
    target_digest: [u8; 32],
) -> Option<Checkpoint> {
    for (peer, info) in peers {
        tracing::debug!(?peer, ?chain, "querying peer for checkpoint");
        if let Some(checkpoint) =
            fetch_peer_checkpoint(node_client, &info.url, chain, target_digest).await
        {
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
                match consensus_rx.borrow_and_update().as_ref() {
                    None => {
                        tracing::info!(?chain, "consensus digest is empty, aborting...");
                        return None;
                    }
                    Some(CheckpointDirective::Restart(_)) => {
                        tracing::info!(?chain, "consensus checkpoints were reset during wait, aborting...");
                        return None;
                    }
                    Some(CheckpointDirective::Consensus(cp)) => {
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
                    // all nodes do not have the checkpoint.
                    tracing::warn!("all nodes do not have the checkpoint, retrying in 3 seconds");
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

    use crate::backlog::BacklogEntry;
    use crate::types::CheckpointDirective;
    use mpc_primitives::{ConsensusCheckpointDigest, IndexedSignRequest, SignArgs, SignId};
    use std::collections::HashMap;
    use std::sync::Arc;

    struct AlignFixture {
        chain: Chain,
        backlog: Backlog,
        checkpoints_tx: watch::Sender<Option<CheckpointDirective>>,
        checkpoints_rx: watch::Receiver<Option<CheckpointDirective>>,
        mesh_tx: watch::Sender<MeshState>,
        mesh_rx: watch::Receiver<MeshState>,
        node_client: NodeClient,
        my_account_id: AccountId,
    }

    impl AlignFixture {
        fn new(directive: Option<CheckpointDirective>) -> Self {
            let chain = Chain::Ethereum;
            let backlog = Backlog::new();
            let (checkpoints_tx, checkpoints_rx) = watch::channel(directive);
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

        for case in cases {
            let chain = Chain::Ethereum;
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
                    fixture.backlog.insert(Arc::new(tx)).await;
                }

                for &height in &case.local_checkpoints {
                    fixture
                        .backlog
                        .set_processed_block(chain, height)
                        .await
                        .unwrap();
                    let cp = fixture.backlog.checkpoint(chain).await.unwrap();
                    local_digests.push(cp.digest());
                }
            }

            // 2. Setup Mock peer if needed
            let mut server = None;
            let mut mock_guard = None;
            let mut peer_digest = [0u8; 32];
            if case.peer_has_checkpoint {
                let pending_requests = if case.peer_checkpoint_has_pending_tx {
                    vec![BacklogEntry::new(Arc::new(IndexedSignRequest::sign(
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
                    )))]
                } else {
                    vec![]
                };
                let peer_checkpoint = Checkpoint {
                    chain,
                    block_height: case.peer_checkpoint_height,
                    pending_requests,
                    cumulative_digest: Checkpoint::empty_cumulative_digest(),
                };
                peer_digest = peer_checkpoint.digest();

                let mut s = mockito::Server::new_async().await;
                let peer_url = s.url();

                let mut response_map = HashMap::new();
                response_map.insert(chain, peer_checkpoint);
                let response = crate::web::CheckpointResponse {
                    version: crate::CHECKPOINT_VERSION,
                    checkpoints: response_map,
                };
                let mut body = Vec::new();
                ciborium::into_writer(&response, &mut body).unwrap();

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

            let msg = remote_digest.map(|digest| {
                CheckpointDirective::Consensus(ConsensusCheckpointDigest::new(
                    Chain::Ethereum,
                    case.remote_height,
                    digest,
                ))
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
            let persisted = fixture
                .backlog
                .checkpoint_storage()
                .load_latest(chain)
                .await
                .unwrap();
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
            } else if case.local_checkpoints.is_empty() {
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

            // 7. Assert mock peer requests matched
            if let Some(mock) = mock_guard {
                mock.assert_async().await;
            }

            // Keep the mock server alive until iteration finishes
            drop(server);
        }
    }

    #[tokio::test]
    async fn test_skips_newer_checkpoint_peer() {
        let chain = Chain::Ethereum;
        let checkpoint = Checkpoint::empty(chain);
        let digest = checkpoint.digest();
        let mut newer_server = mockito::Server::new_async().await;
        let mut newer_body = Vec::new();
        ciborium::into_writer(
            &crate::web::CheckpointResponse {
                version: crate::CHECKPOINT_VERSION + 1,
                checkpoints: [(chain, checkpoint.clone())].into_iter().collect(),
            },
            &mut newer_body,
        )
        .unwrap();
        let newer_mock = newer_server
            .mock("GET", "/checkpoint")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/cbor")
            .with_body(newer_body)
            .create_async()
            .await;

        let mut current_server = mockito::Server::new_async().await;
        let mut current_body = Vec::new();
        ciborium::into_writer(
            &crate::web::CheckpointResponse {
                version: crate::CHECKPOINT_VERSION,
                checkpoints: [(chain, checkpoint)].into_iter().collect(),
            },
            &mut current_body,
        )
        .unwrap();
        let current_mock = current_server
            .mock("GET", "/checkpoint")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/cbor")
            .with_body(current_body)
            .create_async()
            .await;

        let peers = [
            (Participant::from(0u32), {
                let mut info = ParticipantInfo::new(0);
                info.url = newer_server.url();
                info
            }),
            (Participant::from(1u32), {
                let mut info = ParticipantInfo::new(1);
                info.url = current_server.url();
                info
            }),
        ];
        let result = query_peers_checkpoint(
            &peers,
            &NodeClient::new(&NodeClientOptions::default()),
            chain,
            digest,
        )
        .await;

        assert!(result.is_some());
        newer_mock.assert_async().await;
        current_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_align_mismatch_abort_on_consensus_change() {
        let chain = Chain::Ethereum;
        let fixture = AlignFixture::new(Some(CheckpointDirective::Consensus(
            ConsensusCheckpointDigest::new(Chain::Ethereum, 100, [0xabu8; 32]),
        )));

        // Create a local checkpoint at 100
        fixture
            .backlog
            .set_processed_block(chain, 100)
            .await
            .unwrap();
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

    #[tokio::test]
    async fn test_align_applies_contract_reset() {
        let chain = Chain::Ethereum;
        // Local state has a pre-reset checkpoint at height 100.
        let mut fixture = AlignFixture::new(None);
        fixture
            .backlog
            .set_processed_block(chain, 100)
            .await
            .unwrap();
        let stale = fixture.backlog.checkpoint(chain).await.unwrap();
        assert!(
            fixture
                .backlog
                .confirm_consensus(chain, stale.digest())
                .await
                .unwrap(),
            "local checkpoint should confirm"
        );

        // The contract was reset: indexers must restart from height 42.
        fixture
            .checkpoints_tx
            .send(Some(CheckpointDirective::Restart(42)))
            .unwrap();

        let result = fixture.run().await;

        assert_eq!(result, None, "applied reset is aligned, not a regression");
        assert_eq!(
            fixture
                .backlog
                .checkpoint_storage()
                .load_latest(chain)
                .await
                .unwrap(),
            None,
            "durable latest checkpoint should be cleared"
        );
        assert_eq!(
            fixture.backlog.latest_checkpoint(chain).await,
            None,
            "local checkpoint should be cleared"
        );

        use mpc_chain_integration_core::StateManager as _;
        assert_eq!(
            fixture.backlog.get_processed_block(chain).await,
            Some(42),
            "processed block should be re-anchored at the restart height"
        );
    }
}
