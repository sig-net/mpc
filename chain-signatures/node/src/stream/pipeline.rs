use super::recovery::recover_backlog;
use super::ChainStreaming;
use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::types::CheckpointWatcher;

use futures_util::StreamExt;
use mpc_chain_integration_core::ChainIndexer;
use mpc_primitives::{Chain, ChainConfig as _, SignCommand};
use near_account_id::AccountId;
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;

/// Per-chain watchdog timeout. Chains whose `process_next_block` synchronously
/// waits for finality (Ethereum, ~12 min on mainnet) need a timeout that exceeds
/// their finality cadence to avoid false restarts. We derive it from the chain's
/// `expected_finality_time_secs` with a buffer, flooring at 300s for fast chains.
///
/// RPC rate-limiting is handled separately by the `max_finalized_failures`
/// budget in `wait_for_finalized_block`, which bails after ~200s — faster
/// than this watchdog for any chain.
pub(crate) fn live_block_timeout(chain: Chain) -> Duration {
    const FLOOR_SECS: u64 = 300;
    const BUFFER_SECS: u64 = 300;
    Duration::from_secs(
        chain
            .expected_finality_time_secs()
            .saturating_add(BUFFER_SECS)
            .max(FLOOR_SECS),
    )
}

pub struct ChainPipeline<I: ChainIndexer> {
    indexer: I,
    state_tx: watch::Sender<ChainStreaming>,
    state_rx: watch::Receiver<ChainStreaming>,
    checkpoints_rx: CheckpointWatcher,
    backlog: Backlog,
    sign_tx: mpsc::Sender<SignCommand>,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    threshold: usize,
    my_account_id: AccountId,
    /// Per-block watchdog timeout for `handle_live` and `handle_catchup`.
    watchdog_timeout: Duration,
}

impl<I: ChainIndexer> ChainPipeline<I> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        indexer: I,
        checkpoints_rx: CheckpointWatcher,
        backlog: Backlog,
        sign_tx: mpsc::Sender<SignCommand>,
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
            sign_tx,
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
        checkpoints_rx: CheckpointWatcher,
        backlog: Backlog,
        sign_tx: mpsc::Sender<SignCommand>,
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
            sign_tx,
            mesh_state,
            node_client,
            threshold,
            my_account_id,
            watchdog_timeout: live_block_timeout(I::CHAIN),
        };
        (this, state_rx)
    }

    /// Evaluate the outcome of a regression check and transition to Recovery if needed.
    fn evaluate_regression_outcome(
        &self,
        result: RegressionOutcome,
    ) -> Option<Option<ChainStreaming>> {
        match result {
            RegressionOutcome::Recovery => {
                let new_state = ChainStreaming::Recovery { load_local: false };
                let _ = self.state_tx.send(new_state);
                Some(Some(new_state))
            }
            RegressionOutcome::Aligned => None,
            RegressionOutcome::Shutdown => Some(None),
        }
    }

    /// Watchdog-timeout handler shared by `handle_catchup` and `handle_live`.
    async fn handle_watchdog_timeout(&mut self, context: &str) -> Option<ChainStreaming> {
        let chain = I::CHAIN;
        let timeout = self.watchdog_timeout;
        let has_slot = self.backlog.has_checkpoint_slot(chain).await;
        let pending = self.backlog.pending_checkpoint_count(chain).await;
        tracing::warn!(
            %chain, ?timeout, has_checkpoint_slot = has_slot,
            pending_checkpoints = pending, "{} processing timed out; restarting pipeline", context
        );
        let new_state = ChainStreaming::Recovery { load_local: false };
        let _ = self.state_tx.send(new_state);
        Some(new_state)
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
        recover_backlog(
            chain,
            load_local,
            &self.backlog,
            &mut self.checkpoints_rx,
            &mut self.mesh_state,
            &self.node_client,
            &self.sign_tx,
            self.threshold,
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
        let timeout = self.watchdog_timeout;

        loop {
            tokio::select! {
                catchup_item = catchup_iter.next(), if self.backlog.has_checkpoint_slot(chain).await => {
                    let Some(catchup_item) = catchup_item else {
                        break;
                    };

                    // Bound each processing attempt (parse + finality wait).
                    loop {
                        match tokio::time::timeout(
                            timeout,
                            self.indexer.process_catchup(&catchup_item),
                        )
                        .await
                        {
                            Ok(Ok(())) => break,
                            Ok(Err(err)) => {
                                tracing::warn!(
                                    ?err,
                                    %chain,
                                    "catchup item processing failed; retrying"
                                );
                                tokio::time::sleep(I::RETRY_DELAY).await;
                            }
                            Err(_) => {
                                return self
                                    .handle_watchdog_timeout("catchup block")
                                    .await;
                            }
                        }
                    }
                }
                result = wait_detected_regression(
                    &mut self.checkpoints_rx,
                    &self.backlog,
                    chain,
                ) => {
                    if let Some(ret) = self.evaluate_regression_outcome(result) {
                        return ret;
                    }
                }
                // Watchdog: if no catchup block is processed within the chain-specific timeout
                _ = tokio::time::sleep(timeout) => {
                    return self.handle_watchdog_timeout("catchup").await;
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
        let timeout = self.watchdog_timeout;
        loop {
            tokio::select! {
                alive = self.indexer.process_next_block(), if self.backlog.has_checkpoint_slot(chain).await => {
                    if !alive {
                        return None; // shutdown
                    }
                }
                result = wait_detected_regression(
                    &mut self.checkpoints_rx,
                    &self.backlog,
                    chain,
                ) => {
                    if let Some(ret) = self.evaluate_regression_outcome(result) {
                        return ret;
                    }
                }
                // Watchdog: if no block is processed within the chain-specific timeout,
                // the background producer is assumed stalled and the pipeline restarts.
                _ = tokio::time::sleep(timeout) => {
                    return self.handle_watchdog_timeout("live block").await;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegressionOutcome {
    /// Consensus digest mismatches local backlog — transition to Recovery.
    Recovery,
    /// Local backlog is aligned with consensus, continue current state.
    Aligned,
    /// Consensus checkpoint feed shut down — pipeline should stop.
    Shutdown,
}

/// Waits for a consensus checkpoint digest change, then checks for regression.
pub(crate) async fn wait_detected_regression(
    checkpoints_rx: &mut CheckpointWatcher,
    backlog: &Backlog,
    chain: Chain,
) -> RegressionOutcome {
    if detect_regression(chain, backlog, checkpoints_rx)
        .await
        .is_some()
    {
        return RegressionOutcome::Recovery;
    }
    if checkpoints_rx.changed().await.is_err() {
        return RegressionOutcome::Shutdown;
    }
    if detect_regression(chain, backlog, checkpoints_rx)
        .await
        .is_some()
    {
        return RegressionOutcome::Recovery;
    }
    RegressionOutcome::Aligned
}

/// Returns `Some(ChainStreaming::Recovery)` if a regression is detected.
/// When the consensus digest matches a local checkpoint (latest or historical),
/// the checkpoint is confirmed and persisted via `on_consensus_confirmed`.
/// Returns `None` when the backlog is aligned (no regression).
async fn detect_regression(
    chain: Chain,
    backlog: &Backlog,
    checkpoints_rx: &mut CheckpointWatcher,
) -> Option<ChainStreaming> {
    let checkpoint_digest = checkpoints_rx.borrow_and_update().as_ref()?.clone();

    // Use latest_checkpoint (read-only) instead of checkpoint() to avoid
    // creating a new checkpoint as a side-effect during regression detection.
    let Some(current_checkpoint) = backlog.latest_checkpoint(chain).await else {
        tracing::info!(?chain, "no local checkpoint; skipping regression check");
        return None;
    };

    // Consensus matches our latest local checkpoint → confirm and persist.
    if current_checkpoint.digest() == checkpoint_digest.digest {
        backlog
            .on_consensus_confirmed(chain, &current_checkpoint)
            .await;
        return None;
    }

    // Consensus matches an older checkpoint in our history → confirm and persist.
    if let Some(matched) = backlog
        .find_checkpoint_by_digest(chain, checkpoint_digest.digest)
        .await
    {
        tracing::info!(
            ?chain,
            local_height = current_checkpoint.block_height,
            consensus_height = checkpoint_digest.height,
            "local backlog is ahead of consensus and matches past consensus checkpoint; confirming"
        );
        backlog.on_consensus_confirmed(chain, &matched).await;
        return None;
    }

    // No match → regression detected.
    Some(ChainStreaming::Recovery { load_local: false })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use async_trait::async_trait;
    use mpc_primitives::CheckpointDigest;
    use std::time::Duration;

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
    async fn test_empty_digest_returns_none() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let (_tx, mut rx) = watch::channel(None);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert!(
            result.is_none(),
            "empty digest should not trigger regression"
        );
    }

    #[tokio::test]
    async fn test_matching_consensus_confirms_and_returns_none() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await;
        let cp = backlog.checkpoint(chain).await.unwrap();
        let digest = cp.digest();

        let (_tx, mut rx) = make_digest(100, digest);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert!(
            result.is_none(),
            "matching digest should not trigger regression"
        );

        // Checkpoint should have been persisted
        let persisted = backlog.storage.load_latest(chain).await.unwrap();
        assert!(
            persisted.is_some(),
            "matching checkpoint should be persisted"
        );
        assert_eq!(persisted.unwrap().block_height, 100);
    }

    #[tokio::test]
    async fn test_ahead_with_pending_match_confirms() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        // Create two checkpoints
        backlog.set_processed_block(chain, 100).await;
        let cp1 = backlog.checkpoint(chain).await.unwrap();
        backlog.set_processed_block(chain, 200).await;
        backlog.checkpoint(chain).await.unwrap();

        // Consensus matches the earlier one
        let digest1 = cp1.digest();
        let (_tx, mut rx) = make_digest(100, digest1);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert!(
            result.is_none(),
            "ahead with match should not trigger regression"
        );

        // The earlier checkpoint should be persisted
        let persisted = backlog.storage.load_latest(chain).await.unwrap();
        assert!(persisted.is_some());
        assert_eq!(persisted.unwrap().block_height, 100);
    }

    #[tokio::test]
    async fn test_mismatch_triggers_recovery() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await;
        backlog.checkpoint(chain).await.unwrap();

        // Completely different digest
        let different_digest = [0xabu8; 32];
        let (_tx, mut rx) = make_digest(200, different_digest);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert_eq!(
            result,
            Some(ChainStreaming::Recovery { load_local: false }),
            "mismatched digest should trigger recovery"
        );
    }

    #[tokio::test]
    async fn test_no_local_returns_none() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        let digest = [0x42u8; 32];
        let (_tx, mut rx) = make_digest(100, digest);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert!(
            result.is_none(),
            "no local checkpoint should not trigger regression"
        );
    }

    #[tokio::test]
    async fn test_wait_detects_regression_after_consumed() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await;
        backlog.checkpoint(chain).await.unwrap();

        let (mut _tx, mut rx) = make_digest(200, [0xabu8; 32]);

        // Simulate find_consensus_checkpoint having consumed the change event
        let _ = rx.borrow_and_update();

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            wait_detected_regression(&mut rx, &backlog, chain),
        )
        .await;

        let result = result.expect("should not hang — upfront check catches mismatch");
        assert_eq!(
            result,
            RegressionOutcome::Recovery,
            "should detect regression even when receiver state was consumed"
        );
    }

    #[tokio::test]
    async fn test_wait_detects_regression_after_change() {
        // Normal path: matching digest, then a mismatched digest arrives.
        // The upfront check passes; changed() catches the new value;
        // the post-change detect returns Recovery.
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await;
        let cp = backlog.checkpoint(chain).await.unwrap();
        let matching_digest = cp.digest();

        let (tx, mut rx) = make_digest(100, matching_digest);

        let handle =
            tokio::spawn(async move { wait_detected_regression(&mut rx, &backlog, chain).await });

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

    #[tokio::test]
    async fn test_catchup_watchdog_restarts_on_hung_process_catchup() {
        /// A `ChainIndexer` that simulates a hung `process_catchup` method.
        struct HungCatchupIndexer;

        #[async_trait]
        impl ChainIndexer for HungCatchupIndexer {
            const CHAIN: Chain = Chain::Ethereum;
            type Block = u64;
            type Iter = futures_util::stream::Iter<std::vec::IntoIter<Self::Block>>;
            const RETRY_DELAY: Duration = Duration::from_millis(1);

            async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
                Ok(Some(10))
            }

            async fn next(&mut self) -> Option<Self::Block> {
                None
            }

            async fn catchup_range(&self, _anchor_height: u64) -> Self::Iter {
                futures_util::stream::iter(vec![1u64].into_iter())
            }

            // Never returns
            async fn process_catchup(&mut self, _block: &Self::Block) -> anyhow::Result<()> {
                std::future::pending::<()>().await;
                Ok(())
            }
        }

        let backlog = Backlog::new();
        let (_cp_tx, cp_rx) = watch::channel(None);
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let (_stx, _srx) = mpsc::channel(1);

        let (mut pipeline, _state_rx) = ChainPipeline::from_state(
            ChainStreaming::Catchup { anchor_height: 10 },
            HungCatchupIndexer,
            cp_rx,
            backlog,
            _stx,
            mesh_rx,
            NodeClient::new(&Default::default()),
            0,
            "test.near".parse().unwrap(),
        );
        pipeline.watchdog_timeout = Duration::from_secs(1);

        // `handle_catchup` must escape the hung block via the watchdog and
        // return `Recovery`, instead of hanging forever
        let result = tokio::time::timeout(Duration::from_secs(5), pipeline.handle_catchup(10))
            .await
            .expect("hung process_catchup should be caught by watchdog, not hang");
        assert!(
            matches!(result, Some(ChainStreaming::Recovery { load_local: false })),
            "expected Recovery after catchup watchdog, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_catchup_watchdog_restarts_when_checkpoint_cap_full() {
        /// A `ChainIndexer` that never produces blocks, so `handle_catchup` can't make progress.
        struct EmptyCatchupIndexer;

        #[async_trait]
        impl ChainIndexer for EmptyCatchupIndexer {
            const CHAIN: Chain = Chain::Ethereum;
            type Block = u64;
            type Iter = futures_util::stream::Empty<Self::Block>;
            const RETRY_DELAY: Duration = Duration::from_millis(1);

            async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
                Ok(Some(10))
            }

            async fn next(&mut self) -> Option<Self::Block> {
                None
            }

            async fn catchup_range(&self, _anchor_height: u64) -> Self::Iter {
                futures_util::stream::empty()
            }
        }

        // Fill the pending-checkpoint cap so `has_checkpoint_slot` returns false
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let interval = chain.checkpoint_interval().unwrap();
        for i in 1..=crate::backlog::MAX_PENDING_CHECKPOINTS {
            let h = (i as u64) * interval;
            assert!(
                backlog.set_processed_block(chain, h).await.is_some(),
                "auto-checkpoint at height {h} should succeed"
            );
        }
        assert!(!backlog.has_checkpoint_slot(chain).await);

        // No consensus checkpoint changes => `wait_detected_regression` blocks.
        let (_cp_tx, cp_rx) = watch::channel(None);
        let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
        let (_stx, _srx) = mpsc::channel(1);

        let (mut pipeline, _state_rx) = ChainPipeline::from_state(
            ChainStreaming::Catchup { anchor_height: 10 },
            EmptyCatchupIndexer,
            cp_rx,
            backlog,
            _stx,
            mesh_rx,
            NodeClient::new(&Default::default()),
            0,
            "test.near".parse().unwrap(),
        );
        // Set fast timeout for test
        pipeline.watchdog_timeout = Duration::from_secs(1);

        // With the cap full and no consensus changes, `handle_catchup` can't
        // make progress and must restart via the watchdog
        let result = tokio::time::timeout(Duration::from_secs(5), pipeline.handle_catchup(10))
            .await
            .expect("full checkpoint cap should be caught by watchdog, not hang");
        assert!(
            matches!(result, Some(ChainStreaming::Recovery { load_local: false })),
            "expected Recovery after catchup watchdog, got {result:?}"
        );
    }
}
