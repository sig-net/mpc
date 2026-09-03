use crate::backlog::{Backlog, Checkpoint, CheckpointError};
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::contract::primitives::ParticipantInfo;
use crate::stream::StreamContext;
use crate::types::CheckpointWatcher;

use cait_sith::protocol::Participant;
use mpc_primitives::{reset_checkpoint_digest, Chain, CheckpointDigest, SignCommand};
use near_account_id::AccountId;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::time::Duration;
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegressionOutcome {
    /// Consensus digest mismatches local backlog — transition to recovery/restart.
    Diverged,
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

    /// Creates a StreamReactor from its component parts.
    #[cfg(any(test, feature = "test-feature"))]
    pub fn from_parts(
        chain: Chain,
        backlog: Backlog,
        checkpoints_rx: CheckpointWatcher,
        mesh_state: watch::Receiver<MeshState>,
        node_client: NodeClient,
        account_id: &AccountId,
    ) -> Self {
        Self::new(
            chain,
            StreamContext::from_parts(backlog, checkpoints_rx, mesh_state, node_client, account_id),
        )
    }

    /// Checks if the stream backlog has capacity for another pending checkpoint.
    pub fn has_checkpoint_slot(&self) -> bool {
        self.ctx.backlog.checkpoints().has_slot(self.chain)
    }

    /// Aligns this stream's backlog with network consensus, regressing if divergent.
    pub async fn align_to_consensus(&mut self) -> Result<Option<u64>, CheckpointError> {
        // Cleared before alignment, not after: checkpoint creation and publish
        // failover must not act on a backlog being recovered or replayed into.
        self.ctx.caught_up = false;

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
        let Some(checkpoint) = self.fetch_consensus_checkpoint(&checkpoint_digest).await else {
            return Ok(None);
        };

        self.ctx.backlog.regress(&checkpoint).await?;
        Ok(Some(checkpoint.block_height))
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
            Err(err) => {
                tracing::warn!(
                    chain = ?self.chain,
                    %err,
                    "transient storage error confirming consensus checkpoint; retrying on next change"
                );
                false
            }
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
        reset_checkpoint_digest(self.chain, digest.height) == digest.digest
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
        self.ctx
            .backlog
            .checkpoints()
            .confirm(self.chain, digest)
            .await
    }

    /// Fetches the consensus checkpoint to regress to, either by rebuilding a reset
    /// checkpoint locally or by querying peers over the mesh.
    async fn fetch_consensus_checkpoint(
        &mut self,
        digest: &CheckpointDigest,
    ) -> Option<Checkpoint> {
        if self.is_consensus_reset(digest) {
            tracing::warn!(
                chain = ?self.chain,
                height = digest.height,
                "consensus checkpoint was reset; rebuilding it locally"
            );
            return Some(Checkpoint::reset(self.chain, digest.height));
        }

        self.find_consensus_checkpoint(digest.digest).await
    }

    /// Collects and randomly shuffles active mesh peers excluding this node.
    fn active_peers(&mut self) -> Vec<(Participant, ParticipantInfo)> {
        let my_account_id = self.ctx.contract_watcher.account_id();
        let mut peers: Vec<_> = self
            .ctx
            .mesh_state
            .borrow_and_update()
            .active()
            .participants
            .clone()
            .into_iter()
            .filter(|(_, info)| &info.account_id != my_account_id)
            .collect();
        peers.shuffle(&mut thread_rng());
        peers
    }

    /// Finds the consensus checkpoint from active peers, retrying until found
    /// or until the consensus digest changes.
    pub async fn find_consensus_checkpoint(
        &mut self,
        target_digest: [u8; 32],
    ) -> Option<Checkpoint> {
        let mut peers = self.active_peers();

        loop {
            tokio::select! {
                biased;

                changed = self.ctx.checkpoints_rx.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                    let digest = self.ctx.checkpoints_rx.borrow_and_update();
                    if !digest.as_ref().is_some_and(|cp| cp.digest == target_digest) {
                        tracing::info!(chain = ?self.chain, "consensus digest changed during wait, aborting...");
                        return None;
                    }
                }
                changed = self.ctx.mesh_state.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                    peers = self.active_peers();
                }

                checkpoint = query_peers_checkpoint(
                    &peers,
                    &self.ctx.node_client,
                    self.chain,
                    target_digest,
                ) => {
                    let Some(checkpoint) = checkpoint else {
                        tracing::warn!(
                            chain = ?self.chain,
                            "all nodes do not have the checkpoint, retrying in 3 seconds"
                        );
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    };
                    break Some(checkpoint);
                }
            }
        }
    }

    /// Waits for a consensus checkpoint digest change, then checks for regression.
    pub async fn next_regression(&mut self) -> RegressionOutcome {
        if self.detect_regression().await {
            return RegressionOutcome::Diverged;
        }
        if self.ctx.checkpoints_rx.changed().await.is_err() {
            return RegressionOutcome::Shutdown;
        }
        if self.detect_regression().await {
            return RegressionOutcome::Diverged;
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

pub(crate) async fn query_peers_checkpoint(
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

#[cfg(test)]
#[path = "reactor_tests.rs"]
mod tests;
