use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::Chain;
use crate::stream::{ChainIndexer, ChainStreaming};
use futures_util::StreamExt;
use mpc_primitives::CheckpointDigest;
use near_account_id::AccountId;
use tokio::sync::watch;

pub struct ChainPipeline<I: ChainIndexer> {
    indexer: I,
    state_tx: watch::Sender<ChainStreaming>,
    state_rx: watch::Receiver<ChainStreaming>,
    checkpoints_rx: watch::Receiver<CheckpointDigest>,
    backlog: Backlog,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    threshold: usize,
    my_account_id: AccountId,
}

impl<I: ChainIndexer> ChainPipeline<I> {
    pub fn new(
        indexer: I,
        checkpoints_rx: watch::Receiver<CheckpointDigest>,
        backlog: Backlog,
        mesh_state: watch::Receiver<MeshState>,
        node_client: NodeClient,
        threshold: usize,
        my_account_id: AccountId,
    ) -> (Self, watch::Receiver<ChainStreaming>) {
        Self::from_state(
            ChainStreaming::Recovery { load_local: true },
            indexer,
            checkpoints_rx,
            backlog,
            mesh_state,
            node_client,
            threshold,
            my_account_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_state(
        state: ChainStreaming,
        indexer: I,
        checkpoints_rx: watch::Receiver<CheckpointDigest>,
        backlog: Backlog,
        mesh_state: watch::Receiver<MeshState>,
        node_client: NodeClient,
        threshold: usize,
        my_account_id: AccountId,
    ) -> (Self, watch::Receiver<ChainStreaming>) {
        let (state_tx, state_rx) = watch::channel(state);
        let this = Self {
            indexer,
            state_tx,
            state_rx: state_rx.clone(),
            backlog,
            checkpoints_rx,
            mesh_state,
            node_client,
            threshold,
            my_account_id,
        };
        (this, state_rx)
    }

    pub async fn run(mut self) {
        let chain = I::CHAIN;
        tracing::info!(%chain, "starting ChainStream pipeline");
        let mut current_state = *self.state_rx.borrow_and_update();

        loop {
            match current_state {
                ChainStreaming::Recovery { load_local } => {
                    if let Some(next_state) = self.handle_recovery(load_local).await {
                        current_state = next_state;
                    } else {
                        break;
                    }
                }
                ChainStreaming::Catchup { anchor_height } => {
                    if let Some(next_state) = self.handle_catchup(anchor_height).await {
                        current_state = next_state;
                    } else {
                        break;
                    }
                }
                ChainStreaming::Live => {
                    if let Some(next_state) = self.handle_live().await {
                        current_state = next_state;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    async fn handle_recovery(&mut self, load_local: bool) -> Option<ChainStreaming> {
        let chain = I::CHAIN;
        tracing::info!(%chain, load_local, "starting checkpoint recovery or regression");
        crate::mesh::wait_threshold_active(&mut self.mesh_state.clone(), self.threshold).await;

        if load_local {
            // Load local checkpoint from storage first
            match self.backlog.storage.load_latest(chain).await {
                Ok(Some(checkpoint)) => {
                    tracing::info!(
                        ?chain,
                        height = checkpoint.block_height,
                        "loaded local checkpoint"
                    );
                    if let Err(err) = self.backlog.recover_by_checkpoint(checkpoint).await {
                        tracing::warn!(?chain, %err, "failed to recover from local checkpoint");
                    }
                }
                Ok(None) => {
                    tracing::info!(?chain, "no local checkpoint found");
                }
                Err(err) => {
                    tracing::warn!(?chain, %err, "failed to load local checkpoint");
                }
            }

            // Load historical checkpoints from storage
            match self.backlog.storage.load_history(chain).await {
                Ok(history) => {
                    for checkpoint in history {
                        self.backlog.remember_checkpoint(checkpoint).await;
                    }
                }
                Err(err) => {
                    tracing::warn!(?chain, %err, "failed to load historical checkpoints");
                }
            }
        }

        // Perform consensus checkpoint alignment. Returns None when no alignment is
        // needed (the normal case); returns Some(height) when the backlog was aligned.
        // Either way, continue to livestream initialization.
        crate::backlog::consensus::align_backlog_with_consensus(
            chain,
            &self.backlog,
            &mut self.checkpoints_rx,
            &mut self.mesh_state,
            &self.node_client,
            &self.my_account_id,
        )
        .await;

        // Determine anchor height
        let anchor_height = loop {
            match self.indexer.livestream().await {
                Ok(anchor_height) => break anchor_height,
                Err(err) => {
                    tracing::error!(?err, %chain, "failed to initialize livestream; retrying");
                    tokio::time::sleep(I::RETRY_DELAY).await;
                }
            }
        };

        let next_state = ChainStreaming::Catchup {
            anchor_height: anchor_height.unwrap_or(0),
        };
        let _ = self.state_tx.send(next_state);
        Some(next_state)
    }

    async fn handle_catchup(&mut self, anchor_height: u64) -> Option<ChainStreaming> {
        let chain = I::CHAIN;
        tracing::info!(%chain, anchor_height, "starting/re-starting catchup");
        let mut catchup_iter = self.indexer.catchup_range(anchor_height).await;

        loop {
            tokio::select! {
                catchup_item = catchup_iter.next() => {
                    let Some(catchup_item) = catchup_item else {
                        break;
                    };
                    while let Err(err) = self.indexer.process_catchup(&catchup_item).await {
                        tracing::warn!(?err, %chain, "catchup item processing failed; retrying");
                        tokio::time::sleep(I::RETRY_DELAY).await;
                    }
                }
                new_state = wait_detected_regression(
                    &mut self.checkpoints_rx,
                    &self.state_tx,
                    &self.backlog,
                    chain,
                ) => {
                    return Some(new_state);
                }
            }
        }

        tracing::info!(%chain, "catchup completed => transitioning to livestream");
        if let Err(err) = self.indexer.notify_catchup_completed().await {
            tracing::warn!(?err, %chain, "failed to signal catchup completion");
        }
        let final_state = ChainStreaming::Live;
        let _ = self.state_tx.send(final_state);
        Some(final_state)
    }

    async fn handle_live(&mut self) -> Option<ChainStreaming> {
        let chain = I::CHAIN;
        loop {
            tokio::select! {
                alive = self.indexer.process_next_block() => {
                    if !alive {
                        return None; // shutdown
                    }
                }
                new_state = wait_detected_regression(
                    &mut self.checkpoints_rx,
                    &self.state_tx,
                    &self.backlog,
                    chain,
                ) => {
                    return Some(new_state);
                }
            }
        }
    }
}

async fn wait_detected_regression(
    checkpoints_rx: &mut watch::Receiver<CheckpointDigest>,
    state_tx: &watch::Sender<ChainStreaming>,
    backlog: &Backlog,
    chain: Chain,
) -> ChainStreaming {
    loop {
        if checkpoints_rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
        if let Some(new_state) = detect_regression(chain, backlog, checkpoints_rx).await {
            let _ = state_tx.send(new_state);
            return new_state;
        }
    }
}

/// Returns `Some(ChainStreaming::Recovery)` if a regression is detected
/// Otherwise returns `None` in the case we are normal.
async fn detect_regression(
    chain: Chain,
    backlog: &Backlog,
    checkpoints_rx: &mut watch::Receiver<CheckpointDigest>,
) -> Option<ChainStreaming> {
    let checkpoint_digest = checkpoints_rx.borrow_and_update().clone();
    if checkpoint_digest.digest == [0u8; 32] {
        return None;
    }

    let current_checkpoint = backlog.checkpoint(chain).await;
    if current_checkpoint.digest() == checkpoint_digest.digest {
        return None;
    }

    // Check if we are ahead of consensus and aligned
    if current_checkpoint.block_height > checkpoint_digest.height
        && backlog
            .find_checkpoint_by_digest(chain, checkpoint_digest.digest)
            .await
            .is_some()
    {
        tracing::info!(
                ?chain,
                local_height = current_checkpoint.block_height,
                consensus_height = checkpoint_digest.height,
                "local backlog is ahead of consensus and matches past consensus checkpoint; no regression needed"
            );
        return None;
    }

    Some(ChainStreaming::Recovery { load_local: false })
}
