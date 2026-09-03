use crate::backlog::consensus::find_consensus_checkpoint;
use crate::backlog::{Backlog, Checkpoint, CheckpointError};
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::stream::StreamContext;
use crate::types::CheckpointWatcher;

use mpc_primitives::{Chain, CheckpointDigest, SignCommand};
use near_account_id::AccountId;
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegressionOutcome {
    /// Consensus digest mismatches local backlog — transition to Recovery.
    Recovery,
    /// Local backlog is aligned with consensus, continue current state.
    Aligned,
    /// Consensus checkpoint feed shut down — pipeline should stop.
    Shutdown,
}

/// The active engine driving chain indexer stream reactions,
/// including checkpoint recovery and consensus alignment.
pub struct StreamReactor {
    pub chain: Chain,
    pub ctx: StreamContext,
}

impl StreamReactor {
    pub fn new(chain: Chain, ctx: StreamContext) -> Self {
        Self { chain, ctx }
    }

    /// Creates a lightweight test StreamReactor configured for alignment tests.
    #[cfg(any(test, feature = "test-feature"))]
    pub fn for_alignment(
        chain: Chain,
        backlog: Backlog,
        checkpoints_rx: CheckpointWatcher,
        mesh_state: watch::Receiver<MeshState>,
        node_client: NodeClient,
        account_id: &AccountId,
    ) -> Self {
        Self::new(
            chain,
            StreamContext::for_alignment(
                backlog,
                checkpoints_rx,
                mesh_state,
                node_client,
                account_id,
            ),
        )
    }

    /// Aligns this stream's backlog with network consensus, regressing if divergent.
    pub async fn align_backlog_with_consensus(&mut self) -> Result<Option<u64>, CheckpointError> {
        let Some(checkpoint_digest) = self.current_consensus_digest() else {
            return Ok(None);
        };

        if self.confirm_consensus(checkpoint_digest.digest).await? {
            return Ok(None);
        }

        tracing::warn!(
            chain = ?self.chain,
            ?checkpoint_digest.digest,
            "Consensus checkpoint mismatch/divergence detected: triggering regression"
        );
        let fetched_checkpoint = if self.is_consensus_reset(&checkpoint_digest) {
            tracing::warn!(
                chain = ?self.chain,
                height = checkpoint_digest.height,
                "consensus checkpoint was reset; rebuilding it locally"
            );
            Checkpoint::reset(self.chain, checkpoint_digest.height)
        } else {
            let my_account_id = self.ctx.contract_watcher.account_id().clone();
            let Some(checkpoint) = find_consensus_checkpoint(
                &mut self.ctx.mesh_state,
                &self.ctx.node_client,
                self.chain,
                checkpoint_digest.digest,
                &mut self.ctx.checkpoints_rx,
                &my_account_id,
            )
            .await
            else {
                return Ok(None);
            };
            checkpoint
        };

        self.ctx.backlog.regress(&fetched_checkpoint).await?;
        Ok(Some(fetched_checkpoint.block_height))
    }

    /// Hydrates the in-memory backlog from local persistent storage at startup.
    pub async fn hydrate(&mut self) -> Result<(), CheckpointError> {
        match self.ctx.backlog.hydrate(self.chain).await? {
            Some(checkpoint) => {
                tracing::info!(
                    chain = ?self.chain,
                    height = checkpoint.block_height,
                    "hydrated local checkpoint"
                );
            }
            None => {
                tracing::info!(chain = ?self.chain, "no local checkpoint found");
            }
        }
        Ok(())
    }

    /// Returns `true` if a regression is detected. When the consensus digest matches
    /// a local checkpoint (latest or historical), the checkpoint is confirmed via
    /// `confirm`. A transient storage error is treated as aligned so it is
    /// retried on the next checkpoint change. Returns `false` when the backlog is
    /// aligned (no regression).
    pub async fn detect_regression(&mut self) -> bool {
        let Some(checkpoint_digest) = self.current_consensus_digest() else {
            return false;
        };

        // A node holding no checkpoint still has to re-anchor its cursor on a
        // reset. Any other digest is unmatchable without one to compare against.
        if !self.is_consensus_reset(&checkpoint_digest) && !self.has_local_checkpoint().await {
            return false;
        }

        // A consensus digest can match either the latest checkpoint or a retained
        // pending checkpoint while this node is ahead of consensus.
        match self.confirm_consensus(checkpoint_digest.digest).await {
            Ok(found) => !found,
            Err(_) => false,
        }
    }

    /// Fetches the latest consensus checkpoint digest from the watch channel.
    fn current_consensus_digest(&mut self) -> Option<CheckpointDigest> {
        self.ctx
            .checkpoints_rx
            .borrow_and_update()
            .as_ref()
            .cloned()
    }

    /// Checks if a consensus digest represents a canonical genesis/reset checkpoint.
    fn is_consensus_reset(&self, digest: &CheckpointDigest) -> bool {
        Checkpoint::reset(self.chain, digest.height).digest() == digest.digest
    }

    /// Checks if this node holds a local checkpoint, logging any transient storage error.
    async fn has_local_checkpoint(&self) -> bool {
        match self.ctx.backlog.checkpoints().latest(self.chain).await {
            Ok(Some(_)) => true,
            Ok(None) => {
                tracing::info!(chain = ?self.chain, "no local checkpoint; skipping regression check");
                false
            }
            Err(err) => {
                tracing::warn!(
                    chain = ?self.chain,
                    %err,
                    "transient storage error checking latest checkpoint; retrying on next change"
                );
                false
            }
        }
    }

    /// Checks and confirms the consensus digest against local checkpoints (latest or pending).
    /// Returns `Ok(true)` if confirmed, `Ok(false)` if divergent, or `Err(err)` on storage failure.
    async fn confirm_consensus(&self, digest: [u8; 32]) -> Result<bool, CheckpointError> {
        match self
            .ctx
            .backlog
            .checkpoints()
            .confirm(self.chain, digest)
            .await
        {
            Ok(found) => Ok(found),
            Err(err) => {
                tracing::warn!(
                    chain = ?self.chain,
                    %err,
                    "transient storage error confirming consensus checkpoint; retrying later"
                );
                Err(err)
            }
        }
    }

    /// Waits for a consensus checkpoint digest change, then checks for regression.
    pub async fn next_regression(&mut self) -> RegressionOutcome {
        if self.detect_regression().await {
            return RegressionOutcome::Recovery;
        }
        if self.ctx.checkpoints_rx.changed().await.is_err() {
            return RegressionOutcome::Shutdown;
        }
        if self.detect_regression().await {
            return RegressionOutcome::Recovery;
        }
        RegressionOutcome::Aligned
    }

    /// Aborts in-flight sign tasks and pending RPC votes for the chain on regression.
    pub async fn abort_inflight(&self) {
        self.ctx.rpc.abort_checkpoints(self.chain).await;
        if let Err(err) = self
            .ctx
            .sign_tx
            .send(SignCommand::AbortChain(self.chain))
            .await
        {
            tracing::error!(?err, %self.chain, "failed to abort sign tasks on regression");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_client::Options as NodeClientOptions;
    use mpc_primitives::CheckpointDigest;
    use std::time::Duration;

    fn make_reactor(
        chain: Chain,
        backlog: Backlog,
        rx: watch::Receiver<Option<CheckpointDigest>>,
    ) -> StreamReactor {
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let node_client = NodeClient::new(&NodeClientOptions::default());
        let account_id = "test.near".parse().unwrap();
        StreamReactor::for_alignment(chain, backlog, rx, mesh_rx, node_client, &account_id)
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

        // Advance backlog to 200 with new checkpoint
        backlog.set_processed_block(chain, 200).await.unwrap();
        backlog.checkpoint(chain).await.unwrap();

        // Consensus arrives with a completely different digest for height 200
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
            RegressionOutcome::Recovery,
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
            RegressionOutcome::Recovery,
            "should detect regression after new mismatched value"
        );
    }
}
