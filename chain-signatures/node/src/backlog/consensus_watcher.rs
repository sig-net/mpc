//! Combines the contract's consensus checkpoint feed with the local
//! [`Checkpoints`] state into a single watcher. It exposes the merged view as a
//! [`ConsensusSnapshot`], blocks until divergence via [`next_regression`], and
//! owns the peer-fetch + in-place regress used to realign with consensus.
use crate::backlog::{Backlog, Checkpoint};
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::types::CheckpointWatcher;

use cait_sith::protocol::Participant;
use mpc_primitives::{Chain, CheckpointDigest};
use near_account_id::AccountId;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::time::Duration;
use tokio::sync::watch;

/// Details of a detected divergence between the local backlog and the
/// consensus checkpoint published on the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Regression {
    /// Digest consensus voted for.
    pub consensus_digest: [u8; 32],
    /// Height of the consensus checkpoint we must fall back to.
    pub target_height: u64,
    /// Height of our newest local checkpoint, if any.
    pub local_height: Option<u64>,
}

/// Combined view of the contract consensus checkpoint feed and local state.
#[derive(Debug, Clone)]
pub struct ConsensusSnapshot {
    /// Latest digest observed on the contract.
    pub consensus: Option<CheckpointDigest>,
    /// Newest locally known checkpoint (pending or confirmed).
    pub local: Option<Checkpoint>,
    /// Whether the two sources agree. Absent consensus, absent local state,
    /// and transient storage errors all count as aligned.
    pub aligned: bool,
}

enum Classification {
    NoConsensus,
    NoLocal,
    Aligned,
    Retry,
    Diverged(CheckpointDigest),
}

/// Watches the contract's consensus checkpoint digest against the local
/// backlog checkpoint state for one chain.
pub struct ConsensusCheckpointWatcher {
    chain: Chain,
    backlog: Backlog,
    checkpoints_rx: CheckpointWatcher,
}

impl ConsensusCheckpointWatcher {
    pub fn new(chain: Chain, backlog: &Backlog, checkpoints_rx: CheckpointWatcher) -> Self {
        Self {
            chain,
            backlog: backlog.clone(),
            checkpoints_rx,
        }
    }

    /// Local backlog handle, e.g. for loading durable checkpoints during recovery.
    pub fn backlog(&self) -> &Backlog {
        &self.backlog
    }

    /// Non-blocking merged view. Confirming a matching digest (promoting a
    /// pending checkpoint) happens as a side effect, mirroring detection.
    pub async fn snapshot(&mut self) -> ConsensusSnapshot {
        let consensus = self.checkpoints_rx.borrow_and_update().clone();
        let local = self.backlog.latest_checkpoint(self.chain).await;
        let aligned = match &consensus {
            None => true,
            Some(digest) => !matches!(
                self.classify_digest(digest.clone()).await,
                Classification::Diverged(_)
            ),
        };
        ConsensusSnapshot {
            consensus,
            local,
            aligned,
        }
    }

    /// Waits until the consensus digest diverges from the local backlog.
    ///
    /// Returns the regression details once, alerting (rich log + metric) as a
    /// side effect, or `None` when the contract checkpoint feed shut down.
    pub async fn next_regression(&mut self) -> Option<Regression> {
        loop {
            match self.classify().await {
                Classification::Diverged(digest) => {
                    return Some(self.alert_divergence(digest).await);
                }
                Classification::NoLocal => {
                    tracing::info!(
                        chain = ?self.chain,
                        "no local checkpoint; skipping regression check"
                    );
                }
                Classification::NoConsensus | Classification::Aligned | Classification::Retry => {}
            }
            if self.checkpoints_rx.changed().await.is_err() {
                return None;
            }
        }
    }

    /// Realigns the backlog with consensus at startup or after a regression.
    ///
    /// On divergence, fetches the consensus checkpoint body from peers and
    /// regresses the local backlog in place. Returns the regression details,
    /// `None` when already aligned or when alignment aborted (digest changed
    /// mid-fetch, no peer served the body).
    pub(crate) async fn align_with_consensus(
        &mut self,
        mesh_state: &mut watch::Receiver<MeshState>,
        node_client: &NodeClient,
        my_account_id: &AccountId,
    ) -> Option<Regression> {
        let digest = self.checkpoints_rx.borrow_and_update().as_ref().cloned()?;
        // Unlike steady-state detection (`next_regression`), a missing local
        // checkpoint counts as divergence here so a fresh node can bootstrap.
        let diverged = matches!(
            self.classify_digest(digest.clone()).await,
            Classification::Diverged(_) | Classification::NoLocal
        );
        if !diverged {
            return None;
        }

        tracing::warn!(
            chain = ?self.chain,
            digest = ?digest.digest,
            "Consensus checkpoint mismatch/divergence detected: triggering regression"
        );
        let fetched = find_consensus_checkpoint(
            mesh_state,
            node_client,
            self.chain,
            digest.digest,
            &mut self.checkpoints_rx,
            my_account_id,
        )
        .await?;

        Some(self.regress(fetched, digest).await)
    }

    /// Compares the newest consensus digest against the local backlog.
    async fn classify(&mut self) -> Classification {
        let Some(digest) = self.checkpoints_rx.borrow_and_update().as_ref().cloned() else {
            return Classification::NoConsensus;
        };
        self.classify_digest(digest).await
    }

    async fn classify_digest(&self, digest: CheckpointDigest) -> Classification {
        if self.backlog.latest_checkpoint(self.chain).await.is_none() {
            return Classification::NoLocal;
        }

        // A consensus digest can match either the latest checkpoint or a
        // retained pending checkpoint while this node is ahead of consensus.
        match self
            .backlog
            .confirm_consensus(self.chain, digest.digest)
            .await
        {
            Ok(true) => Classification::Aligned,
            Ok(false) => Classification::Diverged(digest),
            Err(err) => {
                tracing::warn!(
                    chain = ?self.chain,
                    %err,
                    "transient storage error confirming checkpoint; retrying"
                );
                Classification::Retry
            }
        }
    }

    /// Builds the regression payload for an unconfirmed digest and alerts.
    async fn alert_divergence(&mut self, digest: CheckpointDigest) -> Regression {
        let local_height = self
            .backlog
            .latest_checkpoint(self.chain)
            .await
            .map(|checkpoint| checkpoint.block_height);
        let regression = Regression {
            consensus_digest: digest.digest,
            target_height: digest.height,
            local_height,
        };
        alert_regression(self.chain, &regression);
        regression
    }

    /// Regresses the local backlog to a fetched consensus checkpoint.
    async fn regress(&mut self, checkpoint: Checkpoint, digest: CheckpointDigest) -> Regression {
        let local_height = self
            .backlog
            .latest_checkpoint(self.chain)
            .await
            .map(|checkpoint| checkpoint.block_height);
        if let Err(err) = self.backlog.regress(checkpoint.clone()).await {
            tracing::error!(chain = ?self.chain, %err, "failed to regress backlog to checkpoint");
        }
        let regression = Regression {
            consensus_digest: digest.digest,
            target_height: checkpoint.block_height,
            local_height,
        };
        alert_regression(self.chain, &regression);
        regression
    }
}

/// Central regression alert: rich structured log plus a Grafana-facing counter.
fn alert_regression(chain: Chain, regression: &Regression) {
    tracing::warn!(
        ?chain,
        consensus_digest = ?regression.consensus_digest,
        target_height = regression.target_height,
        local_height = ?regression.local_height,
        "backlog regression against consensus checkpoint"
    );
    crate::metrics::requests::CHECKPOINT_REGRESSIONS
        .with_label_values(&[chain.as_str()])
        .inc();
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
    peers: &[(
        Participant,
        crate::protocol::contract::primitives::ParticipantInfo,
    )],
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
async fn find_consensus_checkpoint(
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
    use super::*;
    use crate::backlog::BacklogEntry;
    use crate::mesh::connection::NodeStatus;
    use crate::node_client::Options as NodeClientOptions;

    use crate::web::CheckpointResponse;
    use mpc_primitives::{IndexedSignRequest, SignArgs, SignId};
    use std::collections::HashMap;
    use std::sync::Arc;

    struct Fixture {
        backlog: Backlog,
        watcher: ConsensusCheckpointWatcher,
        checkpoints_tx: watch::Sender<Option<CheckpointDigest>>,
        mesh_tx: watch::Sender<MeshState>,
        mesh_rx: watch::Receiver<MeshState>,
        node_client: NodeClient,
        my_account_id: AccountId,
    }

    impl Fixture {
        fn new(initial: Option<CheckpointDigest>) -> Self {
            let chain = Chain::Ethereum;
            let backlog = Backlog::new();
            let (checkpoints_tx, checkpoints_rx) = watch::channel(initial);
            let watcher = ConsensusCheckpointWatcher::new(chain, &backlog, checkpoints_rx);
            let (mesh_tx, mesh_rx) = watch::channel(MeshState::default());
            Self {
                backlog,
                watcher,
                checkpoints_tx,
                mesh_tx,
                mesh_rx,
                node_client: NodeClient::new(&NodeClientOptions::default()),
                my_account_id: "test.near".parse().unwrap(),
            }
        }

        async fn align(&mut self) -> Option<Regression> {
            self.watcher
                .align_with_consensus(&mut self.mesh_rx, &self.node_client, &self.my_account_id)
                .await
        }
    }

    fn digest(height: u64, bytes: [u8; 32]) -> Option<CheckpointDigest> {
        Some(CheckpointDigest {
            height,
            digest: bytes,
        })
    }

    #[tokio::test]
    async fn snapshot_reports_aligned_without_consensus_or_local() {
        let backlog = Backlog::new();
        let mut watcher =
            ConsensusCheckpointWatcher::new(Chain::Ethereum, &backlog, watch::channel(None).1);

        let snapshot = watcher.snapshot().await;
        assert!(snapshot.aligned);
        assert!(snapshot.consensus.is_none());
        assert!(snapshot.local.is_none());
    }

    #[tokio::test]
    async fn matching_consensus_confirms_and_stays_aligned() {
        let backlog = Backlog::new();
        backlog
            .set_processed_block(Chain::Ethereum, 100)
            .await
            .unwrap();
        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();
        let mut watcher = ConsensusCheckpointWatcher::new(
            Chain::Ethereum,
            &backlog,
            watch::channel(digest(100, checkpoint.digest())).1,
        );

        let snapshot = watcher.snapshot().await;
        assert!(snapshot.aligned);
        assert_eq!(snapshot.local.map(|cp| cp.block_height), Some(100));

        let persisted = backlog
            .checkpoint_storage()
            .load_latest(Chain::Ethereum)
            .await
            .unwrap();
        assert_eq!(persisted.map(|cp| cp.block_height), Some(100));
    }

    #[tokio::test]
    async fn ahead_with_pending_match_confirms() {
        let backlog = Backlog::new();
        backlog
            .set_processed_block(Chain::Ethereum, 100)
            .await
            .unwrap();
        let first = backlog.checkpoint(Chain::Ethereum).await.unwrap();
        backlog
            .set_processed_block(Chain::Ethereum, 200)
            .await
            .unwrap();
        backlog.checkpoint(Chain::Ethereum).await.unwrap();

        let mut watcher = ConsensusCheckpointWatcher::new(
            Chain::Ethereum,
            &backlog,
            watch::channel(digest(100, first.digest())).1,
        );

        let snapshot = watcher.snapshot().await;
        assert!(snapshot.aligned);
        let persisted = backlog
            .checkpoint_storage()
            .load_latest(Chain::Ethereum)
            .await
            .unwrap();
        assert_eq!(persisted.map(|cp| cp.block_height), Some(100));
    }

    #[tokio::test]
    async fn mismatch_is_reported_as_diverged() {
        let backlog = Backlog::new();
        backlog
            .set_processed_block(Chain::Ethereum, 100)
            .await
            .unwrap();
        backlog.checkpoint(Chain::Ethereum).await.unwrap();
        let mut watcher = ConsensusCheckpointWatcher::new(
            Chain::Ethereum,
            &backlog,
            watch::channel(digest(200, [0xab; 32])).1,
        );

        let snapshot = watcher.snapshot().await;
        assert!(!snapshot.aligned);
        assert_eq!(snapshot.local.map(|cp| cp.block_height), Some(100));
    }

    #[tokio::test]
    async fn no_local_checkpoint_counts_as_aligned_for_detection() {
        let backlog = Backlog::new();
        let mut watcher = ConsensusCheckpointWatcher::new(
            Chain::Ethereum,
            &backlog,
            watch::channel(digest(100, [0x42; 32])).1,
        );

        assert!(watcher.snapshot().await.aligned);
    }

    #[tokio::test]
    async fn next_regression_returns_upfront_mismatch() {
        let backlog = Backlog::new();
        backlog
            .set_processed_block(Chain::Ethereum, 100)
            .await
            .unwrap();
        backlog.checkpoint(Chain::Ethereum).await.unwrap();
        let mut watcher = ConsensusCheckpointWatcher::new(
            Chain::Ethereum,
            &backlog,
            watch::channel(digest(200, [0xab; 32])).1,
        );
        let _ = watcher.checkpoints_rx.borrow_and_update();

        let regression =
            tokio::time::timeout(Duration::from_millis(500), watcher.next_regression())
                .await
                .expect("should not hang — upfront check catches mismatch")
                .expect("should report regression");

        assert_eq!(regression.target_height, 200);
        assert_eq!(regression.local_height, Some(100));
        assert_eq!(regression.consensus_digest, [0xab; 32]);
    }

    #[tokio::test]
    async fn next_regression_detects_after_change() {
        let backlog = Backlog::new();
        backlog
            .set_processed_block(Chain::Ethereum, 100)
            .await
            .unwrap();
        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();
        let (tx, rx) = watch::channel(digest(100, checkpoint.digest()));
        let mut watcher = ConsensusCheckpointWatcher::new(Chain::Ethereum, &backlog, rx);

        let handle = tokio::spawn(async move { watcher.next_regression().await });
        tx.send(digest(200, [0xab; 32])).unwrap();

        let regression = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("timeout")
            .expect("task should not panic")
            .expect("should report regression");
        assert_eq!(regression.target_height, 200);
    }

    #[tokio::test]
    async fn next_regression_returns_none_when_feed_shuts_down() {
        let backlog = Backlog::new();
        backlog
            .set_processed_block(Chain::Ethereum, 100)
            .await
            .unwrap();
        let checkpoint = backlog.checkpoint(Chain::Ethereum).await.unwrap();
        let (tx, rx) = watch::channel(digest(100, checkpoint.digest()));
        let mut watcher = ConsensusCheckpointWatcher::new(Chain::Ethereum, &backlog, rx);

        let handle = tokio::spawn(async move { watcher.next_regression().await });
        drop(tx);

        let result = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("timeout")
            .expect("task should not panic");
        assert!(
            result.is_none(),
            "dropped sender should shut down the watcher"
        );
    }

    #[tokio::test]
    async fn next_regression_increments_regression_metric() {
        let backlog = Backlog::new();
        backlog
            .set_processed_block(Chain::Ethereum, 100)
            .await
            .unwrap();
        backlog.checkpoint(Chain::Ethereum).await.unwrap();
        let mut watcher = ConsensusCheckpointWatcher::new(
            Chain::Ethereum,
            &backlog,
            watch::channel(digest(200, [0xab; 32])).1,
        );

        let before = regression_count(Chain::Ethereum);
        watcher.next_regression().await.expect("should regress");
        assert!(regression_count(Chain::Ethereum) >= before + 1.0);
    }

    fn regression_count(chain: Chain) -> f64 {
        crate::metrics::requests::CHECKPOINT_REGRESSIONS
            .with_label_values(&[chain.as_str()])
            .get()
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
            let mut fixture = Fixture::new(None);

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
                let response = CheckpointResponse {
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
                let mut info = crate::protocol::contract::primitives::ParticipantInfo::new(1);
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
            let result = fixture.align().await;

            // 5. Assert expected result
            assert_eq!(
                result.as_ref().map(|r| r.target_height),
                case.expected_result,
                "Test case failed: {}, expected result {:?}",
                case.name,
                case.expected_result
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
                        latest.digest(),
                        remote_digest.unwrap(),
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
            &CheckpointResponse {
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
            &CheckpointResponse {
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
                let mut info = crate::protocol::contract::primitives::ParticipantInfo::new(0);
                info.url = newer_server.url();
                info
            }),
            (Participant::from(1u32), {
                let mut info = crate::protocol::contract::primitives::ParticipantInfo::new(1);
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
        let fixture = Fixture::new(digest(100, [0xabu8; 32]));

        // Create a local checkpoint at 100
        fixture
            .backlog
            .set_processed_block(chain, 100)
            .await
            .unwrap();
        let _cp = fixture.backlog.checkpoint(chain).await.unwrap();

        let Fixture {
            watcher,
            checkpoints_tx,
            mut mesh_rx,
            node_client,
            my_account_id,
            ..
        } = fixture;

        let handle = tokio::spawn(async move {
            let mut watcher = watcher;
            watcher
                .align_with_consensus(&mut mesh_rx, &node_client, &my_account_id)
                .await
        });

        // Let it run and start querying, then update digest to zero to abort
        tokio::time::sleep(Duration::from_millis(50)).await;
        checkpoints_tx.send(None).unwrap();

        let result = handle.await.unwrap();
        assert!(result.is_none(), "aborted align should return None");
    }
}
