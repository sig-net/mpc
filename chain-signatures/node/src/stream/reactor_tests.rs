use super::*;
use crate::backlog::{Backlog, BacklogEntry};
use crate::mesh::connection::NodeStatus;
use crate::node_client::Options as NodeClientOptions;
use crate::protocol::contract::primitives::ParticipantInfo;
use mpc_primitives::{IndexedSignRequest, SignArgs, SignId};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

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
        let mut reactor = StreamReactor::from_parts(
            self.chain,
            self.backlog.clone(),
            self.checkpoints_rx.clone(),
            self.mesh_rx.clone(),
            self.node_client.clone(),
            &self.my_account_id,
        );
        reactor.align_to_consensus().await.unwrap()
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
                    SignId::new([2u8; 32]),
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
async fn align_applies_a_reset_without_any_peer() {
    use mpc_chain_integration_core::StateManager as _;

    let chain = Chain::Ethereum;
    let mut fixture = AlignFixture::new(None);

    fixture.backlog.set_processed_block(chain, 100).await;
    let stale = fixture.backlog.checkpoint(chain).await.unwrap();
    assert!(fixture
        .backlog
        .checkpoints()
        .confirm(chain, stale.digest())
        .await
        .unwrap());

    fixture
        .checkpoints_tx
        .send(Some(CheckpointDigest {
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

#[tokio::test]
async fn test_align_mismatch_abort_on_consensus_change() {
    let chain = Chain::Ethereum;
    let fixture = AlignFixture::new(Some(CheckpointDigest {
        height: 100,
        digest: [0xabu8; 32],
    }));

    fixture
        .backlog
        .set_processed_block(chain, 100)
        .await
        .unwrap();
    let _cp = fixture.backlog.checkpoint(chain).await.unwrap();

    let backlog_clone = fixture.backlog.clone();
    let node_client_clone = fixture.node_client.clone();
    let my_account_id_clone = fixture.my_account_id.clone();
    let checkpoints_rx_clone = fixture.checkpoints_rx.clone();
    let mesh_rx_clone = fixture.mesh_rx.clone();

    let handle = tokio::spawn(async move {
        let mut reactor = StreamReactor::from_parts(
            chain,
            backlog_clone,
            checkpoints_rx_clone,
            mesh_rx_clone,
            node_client_clone,
            &my_account_id_clone,
        );
        reactor.align_to_consensus().await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    fixture.checkpoints_tx.send(None).unwrap();

    let result = handle.await.unwrap().unwrap();
    assert!(result.is_none(), "aborted align should return None");
}

fn make_reactor(
    chain: Chain,
    backlog: Backlog,
    rx: watch::Receiver<Option<CheckpointDigest>>,
) -> StreamReactor {
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let node_client = NodeClient::new(&NodeClientOptions::default());
    let account_id = "test.near".parse().unwrap();
    StreamReactor::from_parts(chain, backlog, rx, mesh_rx, node_client, &account_id)
}

fn make_digest(
    height: u64,
    digest: [u8; 32],
) -> (
    watch::Sender<Option<CheckpointDigest>>,
    watch::Receiver<Option<CheckpointDigest>>,
) {
    watch::channel(Some(CheckpointDigest { height, digest }))
}

#[tokio::test]
async fn test_empty_digest_returns_false() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;
    let (_tx, rx) = watch::channel(None);
    let mut reactor = make_reactor(chain, backlog, rx);

    let result = reactor.detect_regression().await;
    assert!(!result, "empty digest should not trigger regression");
}

#[tokio::test]
async fn test_matching_consensus_confirms_and_returns_false() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;

    backlog.set_processed_block(chain, 100).await.unwrap();
    let cp = backlog.checkpoint(chain).await.unwrap();
    let digest = cp.digest();

    let (_tx, rx) = make_digest(100, digest);
    let mut reactor = make_reactor(chain, backlog.clone(), rx);

    let result = reactor.detect_regression().await;
    assert!(!result, "matching digest should not trigger regression");

    let persisted = backlog
        .checkpoints()
        .storage()
        .load_latest(chain)
        .await
        .unwrap();
    assert!(
        persisted.is_some(),
        "matching consensus should confirm the checkpoint to storage"
    );
}

#[tokio::test]
async fn test_mismatch_triggers_regression() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;

    backlog.set_processed_block(chain, 100).await.unwrap();
    let cp1 = backlog.checkpoint(chain).await.unwrap();
    let digest1 = cp1.digest();

    let (_tx, rx) = make_digest(100, digest1);
    let mut reactor = make_reactor(chain, backlog.clone(), rx);
    assert!(!reactor.detect_regression().await);

    backlog.set_processed_block(chain, 200).await.unwrap();
    backlog.checkpoint(chain).await.unwrap();

    let different_digest = [0xabu8; 32];
    let (_tx, rx) = make_digest(200, different_digest);
    let mut reactor = make_reactor(chain, backlog, rx);

    let result = reactor.detect_regression().await;
    assert!(
        result,
        "divergent digest at same height should trigger regression"
    );
}

#[tokio::test]
async fn test_no_local_returns_false() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;
    let (_tx, rx) = make_digest(100, [0xabu8; 32]);
    let mut reactor = make_reactor(chain, backlog, rx);

    let result = reactor.detect_regression().await;
    assert!(!result, "no local checkpoint should not trigger regression");
}

#[tokio::test]
async fn test_reset_detected_without_a_local_checkpoint() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;
    let (_tx, rx) = make_digest(42, mpc_primitives::reset_checkpoint_digest(chain, 42));
    let mut reactor = make_reactor(chain, backlog, rx);

    let result = reactor.detect_regression().await;
    assert!(
        result,
        "a canonical reset must trigger regression even if this node has no local checkpoint"
    );
}

#[tokio::test]
async fn test_ahead_with_pending_match_confirms() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;

    backlog.set_processed_block(chain, 100).await.unwrap();
    let cp1 = backlog.checkpoint(chain).await.unwrap();
    let digest1 = cp1.digest();

    backlog.set_processed_block(chain, 200).await.unwrap();
    backlog.checkpoint(chain).await.unwrap();

    let (_tx, rx) = make_digest(100, digest1);
    let mut reactor = make_reactor(chain, backlog.clone(), rx);

    let result = reactor.detect_regression().await;
    assert!(
        !result,
        "consensus matching a pending checkpoint means node is ahead, not regressed"
    );

    let persisted = backlog
        .checkpoints()
        .storage()
        .load_latest(chain)
        .await
        .unwrap();
    assert!(persisted.is_some());
    assert_eq!(persisted.unwrap().block_height, 100);
}

#[tokio::test]
async fn test_applied_reset_is_not_a_regression() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;

    backlog
        .regress(&Checkpoint::reset(chain, 42))
        .await
        .unwrap();
    assert!(backlog
        .checkpoints()
        .confirm(chain, mpc_primitives::reset_checkpoint_digest(chain, 42))
        .await
        .unwrap());

    let (_tx, rx) = make_digest(42, mpc_primitives::reset_checkpoint_digest(chain, 42));
    let mut reactor = make_reactor(chain, backlog, rx);

    assert!(
        !reactor.detect_regression().await,
        "an already-applied reset must not keep restarting the indexer"
    );
}

#[tokio::test]
async fn test_wait_detects_regression_after_consumed() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;

    backlog.set_processed_block(chain, 100).await.unwrap();
    backlog.checkpoint(chain).await.unwrap();

    let (_tx, mut rx) = make_digest(200, [0xabu8; 32]);
    let _ = rx.borrow_and_update();
    let mut reactor = make_reactor(chain, backlog, rx);

    let result = tokio::time::timeout(Duration::from_millis(500), reactor.next_regression())
        .await
        .expect("should not hang — upfront check catches mismatch");
    assert_eq!(
        result,
        RegressionOutcome::Diverged,
        "should detect regression even when receiver state was consumed"
    );
}

#[tokio::test]
async fn test_wait_detects_regression_after_change() {
    let backlog = Backlog::new();
    let chain = Chain::Ethereum;

    backlog.set_processed_block(chain, 100).await.unwrap();
    let cp = backlog.checkpoint(chain).await.unwrap();
    let matching_digest = cp.digest();

    let (tx, rx) = make_digest(100, matching_digest);
    let mut reactor = make_reactor(chain, backlog, rx);

    let handle = tokio::spawn(async move { reactor.next_regression().await });

    tx.send(Some(CheckpointDigest {
        height: 200,
        digest: [0xabu8; 32],
    }))
    .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("timeout")
        .expect("task should not panic");

    assert_eq!(
        result,
        RegressionOutcome::Diverged,
        "should detect regression after new mismatched value"
    );
}
