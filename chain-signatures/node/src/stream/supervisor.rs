// Supervised indexer loop: node-side recovery, then spawn the chain's
// `run()` and dispatch its events. Regression or a watchdog stall cancels
// `run()` and restarts it, re-running light recovery first.
use super::recovery::recover_backlog;
use super::{handle_chain_event, StreamContext};

use crate::backlog::{Backlog, Checkpoint};
use crate::types::CheckpointWatcher;
use crate::types::SignCommand;
use mpc_chain_integration_core::utils::stream::chain_event_channel;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry};
use mpc_primitives::{Chain, ChainConfig as _, ChainEvent, CheckpointDigest};
use std::sync::Arc;
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::WatchStream;
use tokio_stream::{Stream, StreamExt as _};
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

/// One checked consensus digest per item, `true` when the local backlog has
/// regressed, starting with whichever digest is current at the first poll. That
/// first item is what re-checks a digest recovery consumed without aligning. The
/// stream owns the in-flight check, so a `select!` that drops the item future
/// resumes it rather than losing or restarting it. Ends when the feed shuts down.
///
/// Takes its inputs by value: a borrow of `ctx` would collide with the events arm,
/// which needs `&mut ctx`.
fn regression_stream(
    checkpoints_rx: CheckpointWatcher,
    backlog: Backlog,
    chain: Chain,
) -> impl Stream<Item = bool> {
    WatchStream::new(checkpoints_rx)
        .filter_map(|digest| digest)
        .then(move |digest| {
            let backlog = backlog.clone();
            async move { detect_regression(chain, &backlog, digest).await }
        })
}

/// Returns `true` if a regression is detected. When the consensus digest matches
/// a local checkpoint (latest or historical), the checkpoint is confirmed via
/// `confirm`. A transient storage error is treated as aligned so it is
/// retried on the next checkpoint change. Returns `false` when the backlog is
/// aligned (no regression).
async fn detect_regression(
    chain: Chain,
    backlog: &Backlog,
    checkpoint_digest: CheckpointDigest,
) -> bool {
    // A node holding no checkpoint still has to re-anchor its cursor on a
    // reset. Any other digest is unmatchable without one to compare against.
    let is_reset =
        Checkpoint::reset(chain, checkpoint_digest.height).digest() == checkpoint_digest.digest;
    if !is_reset {
        match backlog.checkpoints().has_checkpoint(chain).await {
            Ok(false) => {
                tracing::info!(?chain, "no local checkpoint; skipping regression check");
                return false;
            }
            Err(err) => {
                tracing::warn!(
                    ?chain,
                    %err,
                    "transient storage error checking for a local checkpoint; retrying on next change"
                );
                return false;
            }
            Ok(true) => {}
        }
    }

    // A consensus digest can match either the latest checkpoint or a retained
    // pending checkpoint while this node is ahead of consensus.
    match backlog
        .checkpoints()
        .confirm(chain, checkpoint_digest.digest)
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

/// Re-emits votes for the checkpoints pending in durable storage.
///
/// Vote tasks live only in memory, and after a process restart the indexer
/// resumes past the pending checkpoints, so nothing else votes them again.
/// Runs as part of startup recovery only; the dispatcher drops votes consensus
/// has already settled.
async fn resubmit_pending_checkpoint_votes(
    chain: Chain,
    ctx: &StreamContext,
) -> anyhow::Result<()> {
    let pending = ctx.backlog.checkpoints().load_pending(chain).await?;
    if pending.is_empty() {
        return Ok(());
    }

    tracing::info!(
        %chain,
        count = pending.len(),
        "resubmitting votes for pending checkpoints recovered at startup"
    );
    for checkpoint in &pending {
        ctx.rpc
            .vote_checkpoint(CheckpointDigest::from(checkpoint))
            .await?;
    }
    Ok(())
}

/// Delay before respawning a `run()` that returned an error.
const ERROR_RESTART_DELAY: Duration = Duration::from_secs(1);
/// Maximum delay between consecutive backlog recovery retry attempts during storage outages.
const MAX_RECOVERY_RETRY_DELAY: Duration = Duration::from_secs(30);
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
    // Startup recovery is complete only once the recovered pending checkpoints'
    // votes have been resubmitted.
    let mut resubmit_votes = true;
    let mut recovery_retry_delay = ERROR_RESTART_DELAY;
    loop {
        // Cleared before recovery, not after: checkpoint creation and publish
        // failover must not act on a backlog being recovered or replayed into.
        ctx.caught_up = false;
        let recovered = async {
            recover_backlog(
                chain,
                load_local,
                &ctx.backlog,
                &mut ctx.checkpoints_rx,
                &mut ctx.mesh_state,
                &ctx.node_client,
                &my_account_id,
            )
            .await?;
            load_local = false;

            if resubmit_votes {
                resubmit_pending_checkpoint_votes(chain, &ctx).await?;
                resubmit_votes = false;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(err) = recovered {
            tracing::error!(
                %chain,
                %err,
                ?recovery_retry_delay,
                "failed to recover backlog; retrying"
            );
            tokio::time::sleep(recovery_retry_delay).await;
            recovery_retry_delay = (recovery_retry_delay * 2).min(MAX_RECOVERY_RETRY_DELAY);
            continue;
        }
        recovery_retry_delay = ERROR_RESTART_DELAY;

        let (events_tx, mut events_rx) = chain_event_channel();
        let cancel = CancellationToken::new();
        let mut run_handle = tokio::spawn({
            let indexer = indexer.clone();
            let cancel = cancel.clone();
            async move { indexer.run(events_tx, cancel).await }
        });

        let mut last_block_event = Instant::now();
        let mut run_finished = false;
        // Built per run attempt, so it re-checks the digest recovery just consumed:
        // recovery can return without having aligned. Pinned outside the `select!`
        // so a dropped item future resumes its check instead of restarting it.
        let regression = regression_stream(ctx.checkpoints_rx.clone(), ctx.backlog.clone(), chain);
        tokio::pin!(regression);

        let exit = loop {
            tokio::select! {
                // Gate dispatch on checkpoint capacity: when the cap is full the
                // channel backs up and pauses the chain's `send().await`.
                event = events_rx.recv(), if ctx.backlog.checkpoints().has_slot(chain) => {
                    let Some(event) = event else {
                        run_finished = true;
                        // `run()` exited on its own: Ok shuts the chain down; an anyhow
                        // error or JoinError::Panic is a crash — either can hot-loop,
                        // so back off before restarting.
                        let result = match (&mut run_handle).await {
                            Ok(r) => r,
                            Err(e) => Err(anyhow::Error::from(e)),
                        };
                        break match result {
                            Ok(()) => Exit::Shutdown,
                            Err(e) => {
                                tracing::warn!(
                                    error = %format_args!("{e:#}"),
                                    %chain,
                                    "chain run() failed; restarting"
                                );
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
                        tracing::error!(error = %format_args!("{err:#}"), %chain, "failed to process chain event");
                    }
                }
                regressed = regression.next() => {
                    let Some(regressed) = regressed else { break Exit::Shutdown };
                    // Every checked digest resolves this branch, regressed or not,
                    // and that is what makes the next `select!` re-read the events
                    // branch's `has_slot` precondition.
                    if regressed {
                        ctx.rpc.abort_checkpoints(chain).await;
                        if let Err(err) = ctx.sign_tx.send(SignCommand::AbortChain(chain)).await {
                            tracing::error!(?err, %chain, "failed to abort sign tasks on regression");
                        }
                        break Exit::Restart;
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
    use crate::storage::checkpoint_storage::CheckpointStorage;
    use crate::stream::test_utils::make_test_stream_context;
    use crate::types::SignCommand;

    use k256::ProjectivePoint;
    use mpc_chain_integration_core::{NoopChainTelemetry, StateManager};
    use mpc_primitives::{Chain, CheckpointDigest};
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

    /// Fills the pending-checkpoint cap so `has_slot` is false, returning the
    /// newest checkpoint, whose digest confirms it and frees a slot again.
    async fn fill_checkpoint_cap(backlog: &Backlog, chain: Chain) -> Checkpoint {
        let interval = chain.checkpoint_interval().unwrap();
        let mut newest = None;
        for i in 1..=crate::backlog::MAX_PENDING_CHECKPOINTS {
            newest = backlog
                .set_processed_block(chain, i as u64 * interval)
                .await;
        }
        assert!(!backlog.checkpoints().has_slot(chain));
        newest.expect("filling the cap yields checkpoints")
    }

    fn digest_of(chain: Chain, height: u64, digest: [u8; 32]) -> CheckpointDigest {
        CheckpointDigest {
            chain,
            height,
            digest,
        }
    }

    /// Fails rather than hanging when the stream does not yield.
    async fn next_outcome(stream: &mut (impl Stream<Item = bool> + Unpin)) -> Option<bool> {
        tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("the stream must yield")
    }

    /// Whether the stream has nothing ready, decided by one poll rather than by
    /// waiting out a timer. `futures_util`'s `Next` is `Unpin`; `tokio_stream`'s
    /// is not, hence the qualified call.
    async fn nothing_ready(stream: &mut (impl Stream<Item = bool> + Unpin)) -> bool {
        futures_util::poll!(futures_util::StreamExt::next(stream)).is_pending()
    }

    #[tokio::test]
    async fn test_matching_consensus_confirms_and_returns_false() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await.unwrap();
        let cp = backlog.checkpoint(chain).await.unwrap();
        let digest = cp.digest();

        let result = detect_regression(chain, &backlog, digest_of(chain, 100, digest)).await;
        assert!(!result, "matching digest should not trigger regression");

        let persisted = backlog
            .checkpoints()
            .storage()
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
        let result = detect_regression(chain, &backlog, digest_of(chain, 100, digest1)).await;
        assert!(!result, "ahead with match should not trigger regression");

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
    async fn test_mismatch_triggers_regression() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await.unwrap();
        backlog.checkpoint(chain).await.unwrap();

        let different_digest = [0xabu8; 32];
        let result =
            detect_regression(chain, &backlog, digest_of(chain, 200, different_digest)).await;
        assert!(result, "mismatched digest should trigger regression");
    }

    #[tokio::test]
    async fn test_no_local_returns_false() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        let digest = [0x42u8; 32];
        let result = detect_regression(chain, &backlog, digest_of(chain, 100, digest)).await;
        assert!(!result, "no local checkpoint should not trigger regression");
    }

    #[tokio::test]
    async fn test_reset_detected_without_a_local_checkpoint() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        // "I hold no checkpoint" is not evidence there is nothing to do.
        let reset = digest_of(
            chain,
            42,
            mpc_primitives::reset_checkpoint_digest(chain, 42),
        );

        assert!(
            detect_regression(chain, &backlog, reset).await,
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
            .checkpoints()
            .confirm(chain, applied.digest())
            .await
            .unwrap());

        let reset = digest_of(
            chain,
            42,
            mpc_primitives::reset_checkpoint_digest(chain, 42),
        );

        assert!(
            !detect_regression(chain, &backlog, reset).await,
            "an already-applied reset must not keep restarting the indexer"
        );
    }

    /// One item per digest, starting with the one already current, which is what
    /// re-checks a digest recovery consumed without aligning. The feed ending ends
    /// the stream.
    #[tokio::test]
    async fn one_outcome_per_digest_until_the_feed_ends() {
        let backlog = Backlog::new();
        let chain = Chain::Ethereum;

        backlog.set_processed_block(chain, 100).await.unwrap();
        let cp = backlog.checkpoint(chain).await.unwrap();

        let (tx, mut rx) = watch::channel(Some(digest_of(chain, 100, cp.digest())));
        // Recovery consumes the digest before the stream is built.
        let _ = rx.borrow_and_update();
        let stream = regression_stream(rx, backlog, chain);
        tokio::pin!(stream);

        assert_eq!(
            next_outcome(&mut stream).await,
            Some(false),
            "the current digest is checked, and it is aligned"
        );

        tx.send(Some(digest_of(chain, 200, [0xabu8; 32]))).unwrap();
        assert_eq!(
            next_outcome(&mut stream).await,
            Some(true),
            "a changed digest that does not match is a regression"
        );
        assert!(
            nothing_ready(&mut stream).await,
            "one item per digest, not more"
        );

        drop(tx);
        assert_eq!(
            next_outcome(&mut stream).await,
            None,
            "the feed ending ends the stream"
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
    async fn startup_resubmits_pending_checkpoint_votes_once() {
        let chain = Chain::Ethereum;
        let backlog = Backlog::new();
        let mut expected = Vec::new();
        for height in [100, 200] {
            let checkpoint = backlog.set_processed_block(chain, height).await.unwrap();
            expected.push(CheckpointDigest {
                chain,
                height,
                digest: checkpoint.digest(),
            });
        }

        // The first run stalls until the watchdog restarts it; the in-process
        // restart must not resubmit what startup already resubmitted.
        let attempts = Arc::new(AtomicUsize::new(0));
        let indexer = StalledRunIndexer {
            attempts: attempts.clone(),
            first_cancel: Arc::new(Notify::new()),
        };
        let (sign_tx, _sign_rx) = mpsc::channel(8);
        let (ctx, _cp_tx, _mesh_tx, mut rpc_rx) = test_ctx(backlog, sign_tx);

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
        .expect("supervisor should shut down after the restarted run() exits");
        assert!(attempts.load(Ordering::SeqCst) >= 2, "run() was restarted");

        let mut voted = Vec::new();
        while let Ok(Some(action)) =
            tokio::time::timeout(Duration::from_millis(200), rpc_rx.recv()).await
        {
            if let RpcAction::VoteCheckpoint { checkpoint, .. } = action {
                voted.push(checkpoint);
            }
        }
        voted.sort_by_key(|checkpoint| checkpoint.height);
        assert_eq!(voted, expected);
    }

    #[tokio::test]
    async fn startup_retries_resubmission_after_a_storage_error() {
        /// Records that `run()` started, then exits Ok.
        struct ExitIndexer {
            attempts: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl ChainIndexer for ExitIndexer {
            const CHAIN: Chain = Chain::Ethereum;

            async fn run(
                &self,
                _events_tx: mpsc::Sender<ChainEvent>,
                _cancel: CancellationToken,
            ) -> anyhow::Result<()> {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let chain = Chain::Ethereum;
        let storage = CheckpointStorage::in_memory();
        let backlog = Backlog::persisted(storage.clone());
        let checkpoint = backlog.set_processed_block(chain, 100).await.unwrap();
        let expected = CheckpointDigest {
            chain,
            height: 100,
            digest: checkpoint.digest(),
        };
        storage.fail_next_load_pending(1);

        let attempts = Arc::new(AtomicUsize::new(0));
        let indexer = ExitIndexer {
            attempts: attempts.clone(),
        };
        let (sign_tx, _sign_rx) = mpsc::channel(8);
        let (ctx, _cp_tx, _mesh_tx, mut rpc_rx) = test_ctx(backlog, sign_tx);

        tokio::time::timeout(
            Duration::from_secs(5),
            run_supervised_with_watchdog(indexer, ctx, NoopChainTelemetry, Duration::from_secs(60)),
        )
        .await
        .expect("supervisor should shut down after run() exits");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "run() starts only once startup recovery, including resubmission, succeeds"
        );

        let mut voted = Vec::new();
        while let Ok(Some(action)) =
            tokio::time::timeout(Duration::from_millis(200), rpc_rx.recv()).await
        {
            if let RpcAction::VoteCheckpoint { checkpoint, .. } = action {
                voted.push(checkpoint);
            }
        }
        assert_eq!(voted, vec![expected]);
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
        // Startup also resubmits the seeded pending checkpoint's vote, which may
        // be delivered on either side of the abort.
        let abort = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match rpc_rx.recv().await {
                    Some(RpcAction::VoteCheckpoint { .. }) => continue,
                    other => break other,
                }
            }
        })
        .await
        .expect("regression should abort RPC work immediately");
        assert!(matches!(
            abort,
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

    /// A `select!` precondition gates arming a branch, so once the cap is full the
    /// events branch stays disabled until some other branch resolves. Confirming a
    /// checkpoint frees the slot, and the digest change that confirmed it is what
    /// resolves the regression branch, so dispatch resumes without the watchdog.
    #[tokio::test]
    async fn freed_checkpoint_slot_resumes_dispatch() {
        /// Emits one event on demand, then exits Ok on demand, closing the event
        /// channel. The supervisor can only observe that through the events branch.
        struct StagedIndexer {
            started: Arc<Notify>,
            emit: Arc<Notify>,
            exit: Arc<Notify>,
        }

        #[async_trait::async_trait]
        impl ChainIndexer for StagedIndexer {
            const CHAIN: Chain = Chain::Ethereum;

            async fn run(
                &self,
                events_tx: mpsc::Sender<ChainEvent>,
                _cancel: CancellationToken,
            ) -> anyhow::Result<()> {
                self.started.notify_one();
                self.emit.notified().await;
                events_tx.send(ChainEvent::Block(1)).await.unwrap();
                self.exit.notified().await;
                Ok(())
            }
        }

        let chain = Chain::Ethereum;
        let backlog = Backlog::new();
        let (sign_tx, _sign_rx) = mpsc::channel(8);
        let (ctx, cp_tx, _mesh_tx, _rpc_rx) = test_ctx(backlog.clone(), sign_tx);

        let started = Arc::new(Notify::new());
        let emit = Arc::new(Notify::new());
        let exit = Arc::new(Notify::new());
        // Long enough that only the digest change can resolve anything.
        let task = tokio::spawn(run_supervised_with_watchdog(
            StagedIndexer {
                started: started.clone(),
                emit: emit.clone(),
                exit: exit.clone(),
            },
            ctx,
            NoopChainTelemetry,
            Duration::from_secs(3600),
        ));

        // Recovery is done and the loop is running before the cap is filled.
        started.notified().await;
        let newest = fill_checkpoint_cap(&backlog, chain).await;

        // The event resolves the events branch if it is armed, and the next
        // `select!` then re-reads `has_slot`, which is now false. Either way the
        // close that follows is not observable while the cap is full.
        emit.notify_one();
        exit.notify_one();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !task.is_finished(),
            "run()'s exit must not be observable while the cap is full"
        );

        // Confirming this digest promotes the pending checkpoint, freeing a slot,
        // and resolves the regression branch as aligned.
        cp_tx
            .send(Some(digest_of(chain, newest.block_height, newest.digest())))
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("a freed slot must resume dispatch without the watchdog")
            .expect("supervisor task should not panic");
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
        fill_checkpoint_cap(&backlog, chain).await;

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
