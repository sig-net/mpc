use crate::backlog::consensus::find_consensus_checkpoint;
use crate::backlog::{Backlog, Checkpoint, CheckpointError};
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::stream::StreamContext;
use crate::types::CheckpointWatcher;

use mpc_primitives::Chain;
use near_account_id::AccountId;
use tokio::sync::watch;

/// The active engine driving chain indexer stream reactions,
/// including checkpoint recovery and consensus alignment.
pub struct StreamReactor {
    pub ctx: StreamContext,
}

impl StreamReactor {
    pub fn new(ctx: StreamContext) -> Self {
        Self { ctx }
    }

    /// Creates a lightweight test StreamReactor configured for alignment tests.
    #[cfg(any(test, feature = "test-feature"))]
    pub fn for_alignment(
        backlog: Backlog,
        checkpoints_rx: CheckpointWatcher,
        mesh_state: watch::Receiver<MeshState>,
        node_client: NodeClient,
        account_id: &AccountId,
    ) -> Self {
        Self::new(StreamContext::for_alignment(
            backlog,
            checkpoints_rx,
            mesh_state,
            node_client,
            account_id,
        ))
    }

    /// Aligns this stream's backlog with network consensus, regressing if divergent.
    pub async fn align_backlog_with_consensus(
        &mut self,
        chain: Chain,
    ) -> Result<Option<u64>, CheckpointError> {
        let Some(checkpoint_digest) = self
            .ctx
            .checkpoints_rx
            .borrow_and_update()
            .as_ref()
            .cloned()
        else {
            return Ok(None);
        };

        match self
            .ctx
            .backlog
            .checkpoints()
            .confirm(chain, checkpoint_digest.digest)
            .await
        {
            Ok(found) => {
                if found {
                    return Ok(None);
                }
            }
            Err(err) => {
                tracing::warn!(
                    ?chain,
                    %err,
                    "transient storage error confirming consensus checkpoint; retrying later"
                );
                return Err(err);
            }
        }

        tracing::warn!(
            ?chain,
            ?checkpoint_digest.digest,
            "Consensus checkpoint mismatch/divergence detected: triggering regression"
        );
        let reset_checkpoint = Checkpoint::reset(chain, checkpoint_digest.height);
        let fetched_checkpoint = if reset_checkpoint.digest() == checkpoint_digest.digest {
            tracing::warn!(
                ?chain,
                height = checkpoint_digest.height,
                "consensus checkpoint was reset; rebuilding it locally"
            );
            reset_checkpoint
        } else {
            let my_account_id = self.ctx.contract_watcher.account_id().clone();
            let Some(checkpoint) = find_consensus_checkpoint(
                &mut self.ctx.mesh_state,
                &self.ctx.node_client,
                chain,
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

    /// Node-side checkpoint recovery:
    /// loads the local checkpoint into the backlog (it only touches local storage),
    /// then aligns the backlog with the consensus checkpoint feed. Mesh availability
    /// is handled inside `align_backlog_with_consensus` when it needs to fetch a
    /// checkpoint from peers.
    pub async fn recover_backlog(
        &mut self,
        chain: Chain,
        load_local: bool,
    ) -> Result<(), CheckpointError> {
        tracing::info!(%chain, load_local, "starting checkpoint recovery or regression");

        // Hydrate local checkpoint state before aligning: initializes the pending count
        // and recovers from the latest durable checkpoint if one exists.
        if load_local {
            match self.ctx.backlog.hydrate(chain).await? {
                Some(checkpoint) => {
                    tracing::info!(
                        ?chain,
                        height = checkpoint.block_height,
                        "hydrated local checkpoint"
                    );
                }
                None => {
                    tracing::info!(?chain, "no local checkpoint found");
                }
            }
        }

        // Returns None when no alignment is needed (the normal case); Some(height) when
        // the backlog was regressed.
        if self.align_backlog_with_consensus(chain).await?.is_some() {
            tracing::warn!(%chain, "backlog regressed via consensus checkpoint");
        }

        Ok(())
    }
}
