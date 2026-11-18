use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::ParticipantInfo;
use crate::types::CheckpointWatcher;
use mpc_chain_integration_core::StateManager;

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
    root_pk: mpc_primitives::PublicKey,
) -> Option<u64> {
    let checkpoint_digest = *checkpoints_rx.borrow_and_update().as_ref()?;

    match backlog
        .checkpoints()
        .confirm(chain, checkpoint_digest.digest)
        .await
    {
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

    // Below the consensus height the node cannot hold that checkpoint yet.
    let processed = backlog.get_processed_block(chain).await;
    let behind = processed.is_none_or(|height| height < checkpoint_digest.height);
    if behind {
        tracing::info!(
            ?chain,
            consensus_height = checkpoint_digest.height,
            ?processed,
            "behind the consensus checkpoint: catching up"
        );
    } else {
        tracing::warn!(
            ?chain,
            ?checkpoint_digest.digest,
            consensus_height = checkpoint_digest.height,
            ?processed,
            "Consensus checkpoint mismatch/divergence detected: triggering regression"
        );
    }
    // A reset settles this digest for a state no node has produced, so
    // `find_consensus_checkpoint` would poll peers forever. Rebuild it instead
    // and fall through to the ordinary regression path, which is what makes a
    // reset idempotent: once regressed, the local checkpoint matches the
    // settled digest and the next pass confirms it.
    let reset_checkpoint = Checkpoint::reset(chain, checkpoint_digest.height);
    let fetched_checkpoint = if reset_checkpoint.digest() == checkpoint_digest.digest {
        tracing::warn!(
            ?chain,
            height = checkpoint_digest.height,
            "consensus checkpoint was reset; rebuilding it locally"
        );
        reset_checkpoint
    } else {
        find_consensus_checkpoint(
            mesh_state,
            node_client,
            chain,
            checkpoint_digest.digest,
            checkpoints_rx,
            my_account_id,
        )
        .await?
    };

    if let Err(err) = backlog.regress(&fetched_checkpoint, root_pk).await {
        tracing::error!(error = %format_args!("{err:#}"), %chain, "failed to regress backlog to checkpoint");
        return None;
    }
    if behind {
        tracing::info!(%chain, "backlog rebased onto the consensus checkpoint");
    } else {
        tracing::warn!(%chain, "backlog regressed via consensus checkpoint");
    }

    Some(fetched_checkpoint.block_height)
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
            tracing::warn!(?url, ?chain, error = %format_args!("{err:#}"), "failed to query peer for checkpoint");
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
    use crate::backlog::consensus::{align_backlog_with_consensus, query_peers_checkpoint};
    use crate::backlog::mock::{mock_root_pk, mock_sign_request, BacklogTestExt};
    use crate::backlog::{Backlog, BacklogEntry, Checkpoint, Checkpoints};
    use crate::mesh::connection::NodeStatus;
    use crate::mesh::MeshState;
    use crate::node_client::NodeClient;
    use crate::protocol::ParticipantInfo;
    use crate::storage::checkpoint_storage::CheckpointStorage;
    use cait_sith::protocol::Participant;
    use mpc_chain_integration_core::StateManager;
    use mpc_primitives::{Chain, CheckpointDigest, SignId};
    use near_account_id::AccountId;
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::sync::watch;

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
            let node_client = NodeClient::new();
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
                k256::AffinePoint::GENERATOR,
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
                peer_checkpoint_has_pending_tx: true,
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
                peer_checkpoint_has_pending_tx: true,
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
                    fixture
                        .backlog
                        .insert_mock_sign(SignId::new([1u8; 32]), chain)
                        .await;
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
                    vec![BacklogEntry::new(mock_sign_request(
                        SignId::new([2u8; 32]),
                        chain,
                    ))]
                } else {
                    vec![]
                };
                let peer_checkpoint = Checkpoint {
                    chain,
                    block_height: case.peer_checkpoint_height,
                    pending_requests,
                    legacy_digest: None,
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

            let msg = remote_digest.map(|digest| CheckpointDigest {
                chain,
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
            let persisted = fixture
                .backlog
                .checkpoints()
                .storage()
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
                    let latest = fixture
                        .backlog
                        .checkpoints()
                        .latest(chain)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        latest.digest(), remote_digest.unwrap(),
                        "Test case failed: {}, expected local backlog latest checkpoint digest to match consensus digest",
                        case.name
                    );
                }
            } else if case.local_checkpoints.is_empty() {
                assert!(persisted.is_none(), "Test case failed: {}", case.name);
            } else {
                let latest = fixture.backlog.checkpoints().latest(chain).await.unwrap();
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
        let result = query_peers_checkpoint(&peers, &NodeClient::new(), chain, digest).await;

        assert!(result.is_some());
        newer_mock.assert_async().await;
        current_mock.assert_async().await;
    }

    #[tokio::test]
    async fn align_applies_a_reset_without_any_peer() {
        let chain = Chain::Ethereum;
        let mut fixture = AlignFixture::new(None);

        // Pre-reset state: a confirmed local checkpoint at height 100 and a
        // cursor to match.
        fixture.backlog.set_processed_block(chain, 100).await;
        let stale = fixture.backlog.checkpoint(chain).await.unwrap();
        assert!(fixture
            .backlog
            .checkpoints()
            .confirm(chain, stale.digest())
            .await
            .unwrap());

        // The contract settles the canonical reset checkpoint for height 42.
        // The mesh is empty, so any attempt to fetch this from a peer would
        // block forever; the node must rebuild it locally instead.
        fixture
            .checkpoints_tx
            .send(Some(CheckpointDigest {
                chain,
                height: 42,
                digest: mpc_primitives::reset_checkpoint_digest(chain, 42),
            }))
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), fixture.run())
            .await
            .expect("align must not wait on peers for a reset checkpoint");

        assert_eq!(result, Some(42));
        assert_eq!(
            fixture.backlog.checkpoints().latest(chain).await.unwrap(),
            Some(Checkpoint::reset(chain, 42)),
            "local state should be the canonical reset checkpoint"
        );
        assert_eq!(
            fixture.backlog.get_processed_block(chain).await,
            Some(42),
            "cursor re-anchored at the reset height; indexing resumes at 43"
        );

        // Re-running while the same reset is settled is a no-op: no "have I
        // applied this?" bookkeeping is needed, because the applied state
        // matches the settled digest.
        let again = tokio::time::timeout(Duration::from_secs(5), fixture.run())
            .await
            .expect("a re-applied reset must not wait on peers either");
        assert_eq!(again, None, "an already-applied reset reports aligned");
        assert_eq!(
            fixture.backlog.get_processed_block(chain).await,
            Some(42),
            "a second pass must not rewind the cursor again"
        );
    }

    #[tokio::test]
    async fn align_applies_a_reset_over_a_node_with_no_local_state() {
        use mpc_chain_integration_core::StateManager as _;

        let chain = Chain::Ethereum;
        let mut fixture = AlignFixture::new(None);
        fixture.backlog.set_processed_block(chain, 500).await;

        fixture
            .checkpoints_tx
            .send(Some(CheckpointDigest {
                chain,
                height: 42,
                digest: mpc_primitives::reset_checkpoint_digest(chain, 42),
            }))
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), fixture.run())
            .await
            .expect("align must not wait on peers for a reset checkpoint");

        assert_eq!(result, Some(42));
        assert_eq!(
            fixture.backlog.get_processed_block(chain).await,
            Some(42),
            "a node that never held a checkpoint must still re-anchor"
        );
    }

    /// Builds a mockito peer whose `/checkpoint` answer is exactly what the given
    /// `Checkpoints` can serve by digest — i.e. the real web-endpoint lookup path.
    async fn mock_peer_serving(
        checkpoints: &Checkpoints,
        chain: Chain,
        digest: [u8; 32],
    ) -> (mockito::ServerGuard, mockito::Mock) {
        let mut found = HashMap::new();
        if let Some(cp) = checkpoints.find(chain, digest).await {
            found.insert(chain, cp);
        }
        let mut body = Vec::new();
        ciborium::into_writer(
            &crate::web::CheckpointResponse {
                version: crate::CHECKPOINT_VERSION,
                checkpoints: found,
            },
            &mut body,
        )
        .unwrap();
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/checkpoint")
            .match_query(mockito::Matcher::Any)
            .expect_at_least(1)
            .with_status(200)
            .with_header("content-type", "application/cbor")
            .with_body(body)
            .create_async()
            .await;
        (server, mock)
    }

    fn peer_info(url: String) -> (Participant, ParticipantInfo) {
        let mut info = ParticipantInfo::new(1);
        info.url = url;
        (Participant::from(1u32), info)
    }

    /// A-style test: demonstrates the hazard the orphan store exists to mitigate.
    ///
    /// A pending checkpoint is created and its digest recorded as a simulated
    /// contract vote. Its body is then deleted WITHOUT an orphan store — the naive
    /// "just drop pending on restart" approach. When that digest settles, no node can
    /// serve it: the local `find` returns `None` and a peer fetch for the digest
    /// returns nothing. A correct node that needs the body to rebase stalls forever.
    /// This is why the discarded bodies must be retained serve-only (doc/checkpoints.md §6).
    #[tokio::test]
    async fn naive_discard_without_orphan_store_leaves_settled_digest_unservable() {
        let chain = Chain::Ethereum;
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let cp = Checkpoint {
            chain,
            block_height: 100,
            pending_requests: vec![BacklogEntry::new(mock_sign_request(
                SignId::new([7u8; 32]),
                chain,
            ))],
            legacy_digest: None,
        };
        checkpoints.persist_pending(&cp).await.unwrap();
        let digest = cp.digest();

        // Simulated contract vote recording the digest (in flight at the crash).
        let (_tx, digest_rx) = watch::channel(Some(CheckpointDigest {
            chain,
            height: 100,
            digest,
        }));
        assert_eq!(digest_rx.borrow().unwrap().digest, digest);

        // Naive cleanup: treat the body as stale at its own height, so the atomic
        // demote drops it without retaining a copy in the orphan store.
        let outcome = checkpoints.demote_to_orphan(chain, 100).await.unwrap();
        assert_eq!(outcome.demoted, 0);
        assert_eq!(outcome.dropped, 1);
        checkpoints.hydrate(chain).await.unwrap();

        // The settled digest can no longer be found locally ...
        assert_eq!(checkpoints.find(chain, digest).await, None);

        // ... and the peer fetch comes back empty, because its /checkpoint
        // endpoint delegates to the same `find`.
        let (server, mock) = mock_peer_serving(&checkpoints, chain, digest).await;
        let peers = [peer_info(server.url())];
        assert_eq!(
            query_peers_checkpoint(&peers, &NodeClient::new(), chain, digest).await,
            None,
            "no peer can serve a body that was discarded without an orphan store"
        );
        mock.assert_async().await;
    }

    /// B-style test: the same sequence with the orphan store in place.
    /// The discarded body is served by `find`, a peer is served, a node that does
    /// not hold the body aligns via `align_backlog_with_consensus`, and the orphan
    /// is cleared once a checkpoint at or above its height settles.
    #[tokio::test]
    async fn orphan_store_serves_discarded_checkpoint_through_alignment_until_settlement() {
        let chain = Chain::Ethereum;
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let cp = Checkpoint {
            chain,
            block_height: 100,
            pending_requests: vec![BacklogEntry::new(mock_sign_request(
                SignId::new([7u8; 32]),
                chain,
            ))],
            legacy_digest: None,
        };
        checkpoints.persist_pending(&cp).await.unwrap();
        let digest = cp.digest();

        // Startup discard: one atomic demote retains the body serve-only.
        checkpoints.persist_pending(&cp).await.unwrap();
        assert_eq!(
            checkpoints
                .demote_to_orphan(chain, 0)
                .await
                .unwrap()
                .demoted,
            1
        );
        checkpoints.hydrate(chain).await.unwrap();
        assert_eq!(checkpoints.find(chain, digest).await, Some(cp.clone()));

        // The peer is served from the orphan store.
        let (server, mock) = mock_peer_serving(&checkpoints, chain, digest).await;
        let peers = [peer_info(server.url())];
        let fetched = query_peers_checkpoint(&peers, &NodeClient::new(), chain, digest).await;
        assert_eq!(fetched, Some(cp.clone()));

        // A fresh node with no local state aligns onto the consensus digest by
        // fetching the discarded body from the peer.
        let mut fixture = AlignFixture::new(Some(CheckpointDigest {
            chain,
            height: 100,
            digest,
        }));
        let (peer, info) = peer_info(server.url());
        let mut mesh = MeshState::default();
        mesh.update(peer, NodeStatus::Active, info);
        fixture.mesh_tx.send(mesh).unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), fixture.run())
            .await
            .expect("alignment must not block: peer holds the discarded body");
        assert_eq!(result, Some(100));
        assert_eq!(
            fixture
                .backlog
                .checkpoints()
                .storage()
                .load_latest(chain)
                .await
                .unwrap(),
            Some(cp.clone())
        );

        // Once a checkpoint at 100 settles locally, the orphan is released.
        let settler = Checkpoint::reset(chain, 100);
        checkpoints.persist_pending(&settler).await.unwrap();
        assert!(checkpoints.confirm(chain, settler.digest()).await.unwrap());
        assert_eq!(checkpoints.find_orphan(chain, digest).await.unwrap(), None);
        assert_eq!(checkpoints.find(chain, digest).await, None);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn rebase_preserves_displaced_pending_body_in_orphan_store() {
        // A rebase to a lower consensus base used to wipe pending wholesale, losing
        // bodies whose votes could still settle. `regress` now demotes first.
        let chain = Chain::Ethereum;
        let storage = CheckpointStorage::in_memory();
        storage
            .persist(&Checkpoint::reset(chain, 90))
            .await
            .unwrap();
        let displaced = Checkpoint {
            chain,
            block_height: 110,
            pending_requests: vec![BacklogEntry::new(mock_sign_request(
                SignId::new([9u8; 32]),
                chain,
            ))],
            legacy_digest: None,
        };
        storage.persist_pending(&displaced).await.unwrap();
        let backlog = Backlog::persisted(storage);
        backlog.checkpoints().hydrate(chain).await.unwrap();
        assert_eq!(backlog.checkpoints().count(chain), 1);

        let new_base = Checkpoint::reset(chain, 100);
        backlog.regress(&new_base, mock_root_pk()).await.unwrap();

        assert!(backlog
            .checkpoints()
            .storage()
            .load_pending(chain)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            backlog
                .checkpoints()
                .find_orphan(chain, displaced.digest())
                .await
                .unwrap(),
            Some(displaced.clone())
        );
        assert_eq!(
            backlog.checkpoints().find(chain, displaced.digest()).await,
            Some(displaced)
        );
        assert_eq!(
            backlog.checkpoints().latest(chain).await.unwrap(),
            Some(new_base)
        );
    }

    #[tokio::test]
    async fn test_align_mismatch_abort_on_consensus_change() {
        let chain = Chain::Ethereum;
        let fixture = AlignFixture::new(Some(CheckpointDigest {
            chain,
            height: 100,
            digest: [0xabu8; 32],
        }));

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
                k256::AffinePoint::GENERATOR,
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
