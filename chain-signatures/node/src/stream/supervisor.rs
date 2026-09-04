// Supervised indexer loop: node-side recovery, then spawn the chain's
// `run()` and dispatch its events. Regression or a watchdog stall cancels
// `run()` and restarts it, re-running light recovery first.
use super::recovery::recover_backlog;
use super::{handle_chain_event, StreamContext};

use crate::backlog::{Backlog, Checkpoint};
use crate::types::CheckpointWatcher;
use mpc_chain_integration_core::utils::stream::chain_event_channel;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry};
use mpc_primitives::{Chain, ChainConfig as _, ChainEvent, SignCommand};
use std::sync::Arc;
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Per-chain watchdog timeout. Chains whose processing synchronously waits for
/// finality (Ethereum, ~12 min on mainnet) need a timeout that exceeds their
/// finality cadence to avoid false restarts. We derive it from the chain's
/// `expected_finality_time_secs` with a buffer, flooring at 300s for fast chains.
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
    if detect_regression(chain, backlog, checkpoints_rx).await {
        return RegressionOutcome::Recovery;
    }
    if checkpoints_rx.changed().await.is_err() {
        return RegressionOutcome::Shutdown;
    }
    if detect_regression(chain, backlog, checkpoints_rx).await {
        return RegressionOutcome::Recovery;
    }
    RegressionOutcome::Aligned
}

/// Returns `true` if a regression is detected. When the consensus digest matches
/// a local checkpoint (latest or historical), the checkpoint is confirmed via
/// `confirm_consensus`. A transient storage error is treated as aligned so it is
/// retried on the next checkpoint change. Returns `false` when the backlog is
/// aligned (no regression).
async fn detect_regression(
    chain: Chain,
    backlog: &Backlog,
    checkpoints_rx: &mut CheckpointWatcher,
) -> bool {
    let Some(checkpoint_digest) = checkpoints_rx.borrow_and_update().as_ref().cloned() else {
        return false;
    };

    // A node holding no checkpoint still has to re-anchor its cursor on a
    // reset. Any other digest is unmatchable without one to compare against.
    let is_reset =
        Checkpoint::reset(chain, checkpoint_digest.height).digest() == checkpoint_digest.digest;
    if !is_reset && backlog.latest_checkpoint(chain).await.is_none() {
        tracing::info!(?chain, "no local checkpoint; skipping regression check");
        return false;
    }

    // A consensus digest can match either the latest checkpoint or a retained
    // pending checkpoint while this node is ahead of consensus.
    match backlog
        .confirm_consensus(chain, checkpoint_digest.digest)
        .await
    {
        Ok(found) => {
            if found {
                return false;
            }
        }
        Err(err) => {
            tracing::warn!(
                ?chain,
                %err,
                "transient storage error confirming checkpoint; retrying on next change"
            );
            return false;
        }
    }

    // No match → regression detected.
    true
}

/// Delay before respawning a `run()` that returned an error.
const ERROR_RESTART_DELAY: Duration = Duration::from_secs(1);
/// How long a cancelled `run()` gets to drain before it is aborted.
const RUN_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Supervised indexer loop: node-side recovery, then spawn the chain's `run()`
/// loop and dispatch its events. Regression or a watchdog stall cancels `run()`
/// and restarts it, re-running light recovery (`load_local: false`) first.
pub async fn run_supervised<I: ChainIndexer, T: ChainTelemetry>(
    indexer: I,
    ctx: StreamContext,
    telemetry: T,
) {
    run_supervised_with_watchdog(indexer, ctx, telemetry, live_block_timeout(I::CHAIN)).await
}

async fn run_supervised_with_watchdog<I: ChainIndexer, T: ChainTelemetry>(
    indexer: I,
    mut ctx: StreamContext,
    telemetry: T,
    watchdog_timeout: Duration,
) {
    let chain = I::CHAIN;
    tracing::info!(%chain, "starting supervised chain indexer");

    let my_account_id = ctx.contract_watcher.account_id().clone();
    let root_pk = ctx.contract_watcher.wait_public_key().await;
    let indexer = Arc::new(indexer);

    enum Exit {
        Restart,
        Shutdown,
    }

    let mut load_local = true;
    loop {
        // Cleared before recovery, not after: checkpoint creation and publish
        // failover must not act on a backlog being recovered or replayed into.
        ctx.caught_up = false;
        recover_backlog(
            chain,
            load_local,
            &ctx.backlog,
            &mut ctx.checkpoints_rx,
            &mut ctx.mesh_state,
            &ctx.node_client,
            &my_account_id,
        )
        .await;
        load_local = false;

        let (events_tx, mut events_rx) = chain_event_channel();
        let cancel = CancellationToken::new();
        let mut run_handle = tokio::spawn({
            let indexer = indexer.clone();
            let cancel = cancel.clone();
            async move { indexer.run(events_tx, cancel).await }
        });

        let mut last_block_event = Instant::now();
        let mut run_finished = false;

        let exit = loop {
            tokio::select! {
                // Gate dispatch on checkpoint capacity: when the cap is full the
                // channel backs up and pauses the chain's `send().await`.
                event = events_rx.recv(), if ctx.backlog.has_checkpoint_slot(chain).await => {
                    let Some(event) = event else {
                        run_finished = true;
                        // `run()` exited on its own: Ok shuts the chain down,
                        // Err (or panic) is treated as a crash and restarted.
                        break match (&mut run_handle).await {
                            Ok(Ok(())) => Exit::Shutdown,
                            result => {
                                // anyhow error or JoinError::Panic — both can
                                // hot-loop, so back off before restarting.
                                tracing::warn!(?result, %chain, "chain run() failed; restarting");
                                tokio::time::sleep(ERROR_RESTART_DELAY).await;
                                Exit::Restart
                            }
                        };
                    };
                    if matches!(event, ChainEvent::Block(_)) {
                        last_block_event = Instant::now();
                    }
                    if let Err(err) =
                        handle_chain_event(event, &mut ctx, &telemetry, root_pk, chain).await
                    {
                        tracing::error!(?err, %chain, "failed to process chain event");
                    }
                }
                result = wait_detected_regression(&mut ctx.checkpoints_rx, &ctx.backlog, chain) => {
                    match result {
                        RegressionOutcome::Recovery => {
                            ctx.rpc.abort_checkpoints(chain).await;
                            if let Err(err) =
                                ctx.sign_tx.send(SignCommand::AbortChain(chain)).await
                            {
                                tracing::error!(?err, %chain, "failed to abort sign tasks on regression");
                            }
                            break Exit::Restart;
                        }
                        RegressionOutcome::Aligned => {}
                        RegressionOutcome::Shutdown => break Exit::Shutdown,
                    }
                }
                // Watchdog: restart when no `ChainEvent::Block` was observed within
                // the per-chain timeout (other event kinds do not count).
                _ = tokio::time::sleep_until(last_block_event + watchdog_timeout) => {
                    tracing::warn!(
                        %chain, ?watchdog_timeout,
                        "no block event within watchdog timeout; restarting chain indexer"
                    );
                    break Exit::Restart;
                }
            }
        };

        if !run_finished {
            cancel.cancel();
            if tokio::time::timeout(RUN_DRAIN_TIMEOUT, &mut run_handle)
                .await
                .is_err()
            {
                tracing::warn!(%chain, "run() did not drain after cancellation; aborting");
                run_handle.abort();
            }
        }

        if matches!(exit, Exit::Shutdown) {
            tracing::warn!(%chain, "supervised chain indexer shutting down");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use crate::mesh::MeshState;
    use crate::rpc::RpcAction;
    use crate::stream::test_utils::make_test_stream_context;

    use k256::ProjectivePoint;
    use mpc_chain_integration_core::{NoopChainTelemetry, StateManager};
    use mpc_primitives::{Chain, CheckpointDigest, SignCommand};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{mpsc, watch, Notify};

    /// Creates a test `StreamContext` along with channels for checkpoint and mesh state updates.
    fn test_ctx(
        backlog: Backlog,
        sign_tx: mpsc::Sender<SignCommand>,
    ) -> (
        StreamContext,
        watch::Sender<Option<CheckpointDigest>>,
        watch::Sender<MeshState>,
        mpsc::Receiver<RpcAction>,
    ) {
        // Threshold 0 for the test contract watcher.
        make_test_stream_context(
            backlog,
            sign_tx,
            false,
            ProjectivePoint::GENERATOR.to_affine(),
            0,
        )
    }

    fn make_digest(
        chain: Chain,
        height: u64,
        digest: [u8; 32],
    ) -> (
        watch::Sender<Option<CheckpointDigest>>,
        watch::Receiver<Option<CheckpointDigest>>,
    ) {
        watch::channel(Some(CheckpointDigest {
            chain,
            height,
            digest,
        }))
    }

    #[tokio::test]
    async fn test_empty_digest_returns_false() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;
        let (_tx, mut rx) = watch::channel(None);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert!(!result, "empty digest should not trigger regression");
    }

    #[tokio::test]
    async fn test_matching_consensus_confirms_and_returns_false() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await.unwrap();
        let cp = backlog.checkpoint(chain).await.unwrap();
        let digest = cp.digest();

        let (_tx, mut rx) = make_digest(chain, 100, digest);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert!(!result, "matching digest should not trigger regression");

        let persisted = backlog
            .checkpoint_storage()
            .load_latest(chain)
            .await
            .unwrap();
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

        backlog.set_processed_block(chain, 100).await.unwrap();
        let cp1 = backlog.checkpoint(chain).await.unwrap();
        backlog.set_processed_block(chain, 200).await.unwrap();
        backlog.checkpoint(chain).await.unwrap();

        let digest1 = cp1.digest();
        let (_tx, mut rx) = make_digest(chain, 100, digest1);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert!(!result, "ahead with match should not trigger regression");

        let persisted = backlog
            .checkpoint_storage()
            .load_latest(chain)
            .await
            .unwrap();
        assert!(persisted.is_some());
        assert_eq!(persisted.unwrap().block_height, 100);
    }

    #[tokio::test]
    async fn test_mismatch_triggers_regression() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await.unwrap();
        backlog.checkpoint(chain).await.unwrap();

        let different_digest = [0xabu8; 32];
        let (_tx, mut rx) = make_digest(chain, 200, different_digest);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert!(result, "mismatched digest should trigger regression");
    }

    #[tokio::test]
    async fn test_no_local_returns_false() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        let digest = [0x42u8; 32];
        let (_tx, mut rx) = make_digest(chain, 100, digest);

        let result = detect_regression(chain, &backlog, &mut rx).await;
        assert!(!result, "no local checkpoint should not trigger regression");
    }

    #[tokio::test]
    async fn test_reset_detected_without_a_local_checkpoint() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        // "I hold no checkpoint" is not evidence there is nothing to do.
        let (_tx, mut rx) = make_digest(
            chain,
            42,
            mpc_primitives::reset_checkpoint_digest(chain, 42),
        );

        assert!(
            detect_regression(chain, &backlog, &mut rx).await,
            "a reset must be applied even with no local checkpoint"
        );
    }

    #[tokio::test]
    async fn test_applied_reset_is_not_a_regression() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        // The state a node is left in once it has applied the reset: an empty
        // backlog confirmed at the reset height.
        backlog.set_processed_block(chain, 42).await;
        let applied = backlog.checkpoint(chain).await.unwrap();
        assert_eq!(
            applied.digest(),
            mpc_primitives::reset_checkpoint_digest(chain, 42)
        );
        assert!(backlog
            .confirm_consensus(chain, applied.digest())
            .await
            .unwrap());

        let (_tx, mut rx) = make_digest(
            chain,
            42,
            mpc_primitives::reset_checkpoint_digest(chain, 42),
        );

        assert!(
            !detect_regression(chain, &backlog, &mut rx).await,
            "an already-applied reset must not keep restarting the indexer"
        );
    }

    #[tokio::test]
    async fn test_wait_detects_regression_after_consumed() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await.unwrap();
        backlog.checkpoint(chain).await.unwrap();

        let (mut _tx, mut rx) = make_digest(chain, 200, [0xabu8; 32]);
        let _ = rx.borrow_and_update();

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            wait_detected_regression(&mut rx, &backlog, chain),
        )
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

        let (tx, mut rx) = make_digest(chain, 100, matching_digest);

        let handle =
            tokio::spawn(async move { wait_detected_regression(&mut rx, &backlog, chain).await });

        tx.send(Some(CheckpointDigest {
            chain,
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

    /// Emits CatchupCompleted + Block(100), then exits Ok.
    struct EventsThenExitIndexer;

    #[async_trait::async_trait]
    impl ChainIndexer for EventsThenExitIndexer {
        const CHAIN: Chain = Chain::Ethereum;

        async fn run(
            &self,
            events_tx: mpsc::Sender<ChainEvent>,
            _cancel: CancellationToken,
        ) -> anyhow::Result<()> {
            events_tx.send(ChainEvent::CatchupCompleted).await.unwrap();
            events_tx.send(ChainEvent::Block(100)).await.unwrap();
            Ok(())
        }
    }

    /// First `run()` stalls until cancelled; subsequent runs exit Ok.
    struct StalledRunIndexer {
        attempts: Arc<AtomicUsize>,
        first_cancel: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl ChainIndexer for StalledRunIndexer {
        const CHAIN: Chain = Chain::Ethereum;

        async fn run(
            &self,
            _events_tx: mpsc::Sender<ChainEvent>,
            cancel: CancellationToken,
        ) -> anyhow::Result<()> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                cancel.cancelled().await;
                self.first_cancel.notify_one();
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn dispatches_events_and_shuts_down_when_run_exits() {
        let backlog = Backlog::new();
        let (sign_tx, _sign_rx) = mpsc::channel(8);
        let (ctx, _cp_tx, _mesh_tx, _rpc_rx) = test_ctx(backlog.clone(), sign_tx);

        tokio::time::timeout(
            Duration::from_secs(5),
            run_supervised_with_watchdog(
                EventsThenExitIndexer,
                ctx,
                NoopChainTelemetry,
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("supervisor should shut down after run() exits");

        assert_eq!(
            backlog.get_processed_block(Chain::Ethereum).await,
            Some(100)
        );
    }

    #[tokio::test]
    async fn watchdog_cancels_and_restarts_stalled_run() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let first_cancel = Arc::new(Notify::new());
        let indexer = StalledRunIndexer {
            attempts: attempts.clone(),
            first_cancel: first_cancel.clone(),
        };
        let (sign_tx, _sign_rx) = mpsc::channel(8);
        let (ctx, _cp_tx, _mesh_tx, _rpc_rx) = test_ctx(Backlog::new(), sign_tx);

        tokio::time::timeout(
            Duration::from_secs(5),
            run_supervised_with_watchdog(
                indexer,
                ctx,
                NoopChainTelemetry,
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("supervisor should shut down after second run() exits");

        first_cancel.notified().await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn regression_cancels_and_restarts_run() {
        let chain = Chain::Ethereum;
        let backlog = Backlog::new();
        backlog.set_processed_block(chain, 100).await.unwrap();
        backlog.checkpoint(chain).await.unwrap();

        let attempts = Arc::new(AtomicUsize::new(0));
        let first_cancel = Arc::new(Notify::new());
        let indexer = StalledRunIndexer {
            attempts: attempts.clone(),
            first_cancel: first_cancel.clone(),
        };
        let (sign_tx, mut sign_rx) = mpsc::channel(8);
        let (ctx, cp_tx, _mesh_tx, mut rpc_rx) = test_ctx(backlog, sign_tx);

        let task = tokio::spawn(run_supervised_with_watchdog(
            indexer,
            ctx,
            NoopChainTelemetry,
            Duration::from_secs(60),
        ));

        while attempts.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        cp_tx
            .send(Some(CheckpointDigest {
                chain,
                height: 200,
                digest: [0xab; 32],
            }))
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), rpc_rx.recv())
                .await
                .expect("regression should abort RPC work immediately"),
            Some(RpcAction::AbortCheckpoints(Chain::Ethereum))
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), sign_rx.recv())
                .await
                .expect("regression should abort sign tasks immediately"),
            Some(SignCommand::AbortChain(Chain::Ethereum))
        ));
        first_cancel.notified().await;
        // Unblock the restart's consensus alignment (no peers serve the digest).
        cp_tx.send(None).unwrap();

        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("supervisor should shut down after second run() exits")
            .expect("supervisor task should not panic");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    /// End to end: a reset settled while the indexer is running must abort
    /// in-flight work, re-anchor the cursor during recovery with no peer
    /// reachable, and then settle rather than restarting on every pass.
    #[tokio::test]
    async fn reset_cancels_restarts_and_settles_without_peers() {
        let chain = Chain::Ethereum;
        let backlog = Backlog::new();
        backlog.set_processed_block(chain, 100).await.unwrap();
        let stale = backlog.checkpoint(chain).await.unwrap();
        assert!(backlog
            .confirm_consensus(chain, stale.digest())
            .await
            .unwrap());

        let attempts = Arc::new(AtomicUsize::new(0));
        let first_cancel = Arc::new(Notify::new());
        let indexer = StalledRunIndexer {
            attempts: attempts.clone(),
            first_cancel: first_cancel.clone(),
        };
        let (sign_tx, mut sign_rx) = mpsc::channel(8);
        let (ctx, cp_tx, _mesh_tx, mut rpc_rx) = test_ctx(backlog.clone(), sign_tx);

        let task = tokio::spawn(run_supervised_with_watchdog(
            indexer,
            ctx,
            NoopChainTelemetry,
            Duration::from_secs(60),
        ));

        while attempts.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        cp_tx
            .send(Some(CheckpointDigest {
                chain,
                height: 42,
                digest: mpc_primitives::reset_checkpoint_digest(chain, 42),
            }))
            .unwrap();

        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), rpc_rx.recv())
                .await
                .expect("reset should abort RPC work immediately"),
            Some(RpcAction::AbortCheckpoints(Chain::Ethereum))
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), sign_rx.recv())
                .await
                .expect("reset should abort sign tasks immediately"),
            Some(SignCommand::AbortChain(Chain::Ethereum))
        ));
        first_cancel.notified().await;

        // Deliberately nothing is sent to unblock the restart, unlike the
        // peer-served regression above: the reset checkpoint is rebuilt
        // locally, so recovery completes with the same digest still settled
        // and no peer reachable.
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("recovery must not wait on peers for a reset")
            .expect("supervisor task should not panic");

        assert_eq!(
            backlog.get_processed_block(chain).await,
            Some(42),
            "recovery must re-anchor the cursor at the reset height"
        );
        assert_eq!(
            backlog.latest_checkpoint(chain).await,
            Some(Checkpoint::reset(chain, 42)),
            "local state must be the canonical reset checkpoint"
        );
        // Exactly two runs: the stalled original and the post-reset rerun. A
        // third would mean the unchanged settled digest keeps restarting.
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn block_events_reset_watchdog() {
        /// Emits 5 block events, then exits Ok.
        struct TrickleIndexer {
            attempts: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl ChainIndexer for TrickleIndexer {
            const CHAIN: Chain = Chain::Ethereum;

            async fn run(
                &self,
                events_tx: mpsc::Sender<ChainEvent>,
                _cancel: CancellationToken,
            ) -> anyhow::Result<()> {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                for _ in 0..5 {
                    events_tx.send(ChainEvent::Block(1)).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
                Ok(())
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let indexer = TrickleIndexer {
            attempts: attempts.clone(),
        };
        let (sign_tx, _sign_rx) = mpsc::channel(8);
        let (ctx, _cp_tx, _mesh_tx, _rpc_rx) = test_ctx(Backlog::new(), sign_tx);

        tokio::time::timeout(
            Duration::from_secs(5),
            run_supervised_with_watchdog(
                indexer,
                ctx,
                NoopChainTelemetry,
                Duration::from_millis(100),
            ),
        )
        .await
        .expect("supervisor should shut down after run() exits");

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn full_checkpoint_cap_pauses_exit_and_watchdog_restarts() {
        let chain = Chain::Ethereum;
        let backlog = Backlog::new();

        let attempts = Arc::new(AtomicUsize::new(0));
        let indexer = StalledRunIndexer {
            attempts: attempts.clone(),
            first_cancel: Arc::new(Notify::new()),
        };
        let (sign_tx, _sign_rx) = mpsc::channel(8);
        let (ctx, _cp_tx, _mesh_tx, _rpc_rx) = test_ctx(backlog.clone(), sign_tx);

        let task = tokio::spawn(run_supervised_with_watchdog(
            indexer,
            ctx,
            NoopChainTelemetry,
            Duration::from_millis(50),
        ));

        while attempts.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Fill the pending-checkpoint cap so `has_checkpoint_slot` returns false.
        let interval = chain.checkpoint_interval().unwrap();
        for i in 1..=crate::backlog::MAX_PENDING_CHECKPOINTS {
            let h = (i as u64) * interval;
            assert!(backlog.set_processed_block(chain, h).await.is_some());
        }
        assert!(!backlog.has_checkpoint_slot(chain).await);

        // The first (stalled) run is restarted by the watchdog; afterwards the
        // instant-Ok exits cannot be observed while the cap is full, so the
        // supervisor must keep restarting instead of shutting down.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !task.is_finished(),
            "supervisor must not shut down while the checkpoint cap is full"
        );
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "watchdog should have restarted run()"
        );
        task.abort();
    }
}
