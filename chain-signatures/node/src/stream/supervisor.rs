// Supervised indexer loop: node-side recovery, then spawn the chain's
// `run()` and dispatch its events. Regression or a watchdog stall cancels
// `run()` and restarts it, re-running light recovery first.
use super::{handle_chain_event, RegressionOutcome, StreamContext, StreamReactor};

use mpc_chain_integration_core::utils::stream::chain_event_channel;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry};
use mpc_primitives::{Chain, ChainConfig as _, ChainEvent};
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

/// Delay before respawning a `run()` that returned an error.
const ERROR_RESTART_DELAY: Duration = Duration::from_secs(1);
/// How long a cancelled `run()` gets to drain before it is aborted.
const RUN_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Supervised indexer loop: hydrate local storage on startup, then spawn the chain's `run()`
/// loop and dispatch its events. Regression or a watchdog stall cancels `run()`
/// and restarts it, re-aligning the backlog with consensus first.
pub async fn run_supervised<I: ChainIndexer, T: ChainTelemetry>(
    indexer: I,
    ctx: StreamContext,
    telemetry: T,
) {
    run_supervised_with_watchdog(indexer, ctx, telemetry, live_block_timeout(I::CHAIN)).await
}

async fn run_supervised_with_watchdog<I: ChainIndexer, T: ChainTelemetry>(
    indexer: I,
    ctx: StreamContext,
    telemetry: T,
    watchdog_timeout: Duration,
) {
    let chain = I::CHAIN;
    tracing::info!(%chain, "starting supervised chain indexer");

    let mut reactor = StreamReactor::new(chain, ctx);
    let root_pk = reactor.ctx.contract_watcher.wait_public_key().await;
    let indexer = Arc::new(indexer);

    while let Err(err) = reactor.hydrate().await {
        tracing::error!(
            %chain,
            %err,
            "failed to hydrate local checkpoint; retrying in {ERROR_RESTART_DELAY:?}"
        );
        tokio::time::sleep(ERROR_RESTART_DELAY).await;
    }

    enum Exit {
        Restart,
        Shutdown,
    }

    loop {
        // Cleared before alignment, not after: checkpoint creation and publish
        // failover must not act on a backlog being recovered or replayed into.
        reactor.ctx.caught_up = false;
        if let Err(err) = reactor.align_to_consensus().await {
            tracing::error!(
                %chain,
                %err,
                "failed to align backlog with consensus; retrying in {ERROR_RESTART_DELAY:?}"
            );
            tokio::time::sleep(ERROR_RESTART_DELAY).await;
            continue;
        }

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
                event = events_rx.recv(), if reactor.ctx.backlog.checkpoints().has_slot(chain) => {
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
                        handle_chain_event(event, &mut reactor.ctx, &telemetry, root_pk, chain).await
                    {
                        tracing::error!(?err, %chain, "failed to process chain event");
                    }
                }
                result = reactor.next_regression() => {
                    match result {
                        RegressionOutcome::Recovery => {
                            reactor.abort_inflight().await;
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
    use crate::backlog::{Backlog, Checkpoint};
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
            .checkpoints()
            .confirm(chain, stale.digest())
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
            backlog.checkpoints().latest(chain).await.unwrap(),
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
        assert!(!backlog.checkpoints().has_slot(chain));

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
