use crate::client::EthereumClient;
#[cfg(test)]
use crate::config::IndexerConfig;
use crate::EthConfig;
use alloy::eips::BlockNumberOrTag;
use alloy::rpc::types::BlockId;
use mpc_primitives::{Chain, ChainConfig as _};
use mpc_utils::task::CancellationTokenExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Tracks finalized-head advancement for stall detection, emitting the
/// advance / backwards / stalled warnings.
struct FinalizedHeadStall {
    last_final: Option<u64>,
    last_advanced_at: Instant,
    last_stall_warn_at: Instant,
    warn_after_secs: u64,
    rewarn_every_secs: u64,
}

impl FinalizedHeadStall {
    fn new(warn_after_secs: u64, rewarn_every_secs: u64) -> Self {
        let now = Instant::now();
        Self {
            last_final: None,
            last_advanced_at: now,
            last_stall_warn_at: now,
            warn_after_secs,
            rewarn_every_secs,
        }
    }

    /// Record a finalized-head sample, emitting advance/stall warnings as needed.
    fn observe(&mut self, new_final: u64) {
        if self.last_final.is_none_or(|n| new_final > n) {
            self.last_advanced_at = Instant::now();
            tracing::debug!(new_final, prev = self.last_final, "finalized head advanced");
        }

        match self.last_final.replace(new_final) {
            Some(prev) if new_final < prev => {
                tracing::warn!(new_final, prev, "finalized block number went backwards");
            }
            Some(prev) if prev == new_final => self.warn_if_stalled(new_final),
            _ => {}
        }
    }

    fn warn_if_stalled(&mut self, new_final: u64) {
        let now = Instant::now();
        let stalled_for = now.duration_since(self.last_advanced_at).as_secs();
        if stalled_for < self.warn_after_secs {
            return;
        }
        if now.duration_since(self.last_stall_warn_at).as_secs() < self.rewarn_every_secs {
            return;
        }
        tracing::warn!(
            new_final,
            stalled_for,
            warn_after_secs = self.warn_after_secs,
            "ethereum finalized head has not advanced; \
             blocks above it will not be emitted until finality catches up. \
             If this persists the stream watchdog will restart the pipeline"
        );
        self.last_stall_warn_at = now;
    }
}

/// Owns the cached finalized-head `watch` channel plus the watcher config.
/// Cloning shares the underlying channel (cheap), so tests can advance the head
/// from a spawned task.
#[derive(Clone)]
pub struct FinalizedHeadTracker {
    head: watch::Sender<Option<u64>>,
    optimistic: bool,
    refresh_interval: Duration,
    max_failures: u32,
    stall_rewarn_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherExit {
    Cancelled,
    UnexpectedExit,
    Panicked,
    JoinCancelled,
}

/// Owns the watcher task. Waiting through this guard observes task exit as
/// well as head updates; retaining the watch sender alone cannot do that.
/// A resolved task is terminal: waits return an error and production callers
/// immediately stop the indexer, so this handle is never polled again.
pub struct FinalizedHeadWatcher {
    tracker: FinalizedHeadTracker,
    task: JoinHandle<Result<(), WatcherExit>>,
}

impl Drop for FinalizedHeadWatcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FinalizedHeadWatcher {
    fn map_join(result: Result<Result<(), WatcherExit>, tokio::task::JoinError>) -> WatcherExit {
        match result {
            Ok(Ok(())) => WatcherExit::UnexpectedExit,
            Ok(Err(exit)) => exit,
            Err(err) if err.is_cancelled() => WatcherExit::JoinCancelled,
            Err(_) => WatcherExit::Panicked,
        }
    }

    pub async fn wait_initialized(&mut self) -> Result<u64, WatcherExit> {
        let mut head_rx = self.tracker.head.subscribe();
        loop {
            if let Some(head) = *head_rx.borrow_and_update() {
                return Ok(head);
            }
            tokio::select! {
                changed = head_rx.changed() => if changed.is_err() { return Err(WatcherExit::UnexpectedExit); },
                result = &mut self.task => return Err(Self::map_join(result)),
            }
        }
    }

    pub async fn wait_for(&mut self, block_number: u64) -> Result<u64, WatcherExit> {
        let mut head_rx = self.tracker.head.subscribe();
        loop {
            if let Some(head) = *head_rx.borrow_and_update() {
                if head >= block_number {
                    return Ok(head);
                }
            }
            tokio::select! {
                changed = head_rx.changed() => if changed.is_err() { return Err(WatcherExit::UnexpectedExit); },
                result = &mut self.task => return Err(Self::map_join(result)),
            }
        }
    }
}

impl FinalizedHeadTracker {
    pub fn new(eth: &EthConfig) -> Self {
        Self {
            head: watch::channel(None).0,
            optimistic: eth.optimistic_requests,
            refresh_interval: Duration::from_millis(eth.refresh_finalized_interval),
            max_failures: eth.indexer.max_finalized_failures,
            stall_rewarn_secs: eth.indexer.stall_rewarn_secs,
        }
    }

    /// Construct a finalized-head tracker for unit tests, with a short refresh interval and no optimistic mode.
    #[cfg(test)]
    fn new_for_test() -> Self {
        let indexer = IndexerConfig::default();
        Self {
            head: watch::channel(None).0,
            optimistic: false, // existing unit tests assume finalized mode
            refresh_interval: Duration::from_millis(100),
            max_failures: indexer.max_finalized_failures,
            stall_rewarn_secs: indexer.stall_rewarn_secs,
        }
    }

    /// Cached finalized block number.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn current(&self) -> Option<u64> {
        *self.head.borrow()
    }

    /// Force the cached head to `n` (used by tests to bypass the watcher).
    #[cfg(test)]
    pub fn set_head(&self, n: u64) {
        self.head.send_replace(Some(n));
    }

    #[cfg(test)]
    async fn wait_initialized(&self) -> anyhow::Result<u64> {
        let mut rx = self.head.subscribe();
        loop {
            if let Some(head) = *rx.borrow_and_update() {
                return Ok(head);
            }
            rx.changed()
                .await
                .map_err(|_| anyhow::anyhow!("head channel closed"))?;
        }
    }

    #[cfg(test)]
    async fn wait_for(&self, block_number: u64) -> anyhow::Result<()> {
        if self.current().is_some_and(|head| head >= block_number) {
            return Ok(());
        }
        let mut rx = self.head.subscribe();
        loop {
            if rx
                .borrow_and_update()
                .is_some_and(|head| head >= block_number)
            {
                return Ok(());
            }
            rx.changed()
                .await
                .map_err(|_| anyhow::anyhow!("head channel closed"))?;
        }
    }

    /// Spawn the background watcher that maintains the cached head.
    pub fn spawn_watcher(
        &self,
        client: Arc<EthereumClient>,
        cancel: CancellationToken,
    ) -> FinalizedHeadWatcher {
        let task = tokio::spawn(Self::watch_head(
            client,
            self.head.clone(),
            self.refresh_interval,
            self.max_failures,
            self.stall_rewarn_secs,
            self.optimistic,
            cancel,
        ));
        FinalizedHeadWatcher {
            tracker: self.clone(),
            task,
        }
    }

    #[cfg(test)]
    fn spawn_panicking_watcher(&self) -> FinalizedHeadWatcher {
        fn panic_result() -> Result<(), WatcherExit> {
            panic!("test watcher panic");
        }

        let task = tokio::spawn(async { panic_result() });
        FinalizedHeadWatcher {
            tracker: self.clone(),
            task,
        }
    }

    // TODO: Currently if this dies silently we have to wait 35 min for the stream supervisor to restart it. Implement faster failure detection and restart.
    /// Background task maintaining the cached head.
    ///
    /// Polls `eth_getBlockByNumber(Finalized)` (production) or `(Latest)`
    /// (optimistic dev mode) on the configured interval and publishes advances
    /// over the `watch` channel. Retries forever; the stream supervisor
    /// watchdog remains the escape hatch.
    async fn watch_head(
        client: Arc<EthereumClient>,
        head: watch::Sender<Option<u64>>,
        refresh_interval: Duration,
        max_failures: u32,
        stall_rewarn_secs: u64,
        optimistic: bool,
        cancel: CancellationToken,
    ) -> Result<(), WatcherExit> {
        let mut stall = FinalizedHeadStall::new(
            Chain::Ethereum.expected_finality_time_secs(),
            stall_rewarn_secs,
        );
        let mut failures = 0u32;

        tracing::info!(optimistic, "ethereum head watcher started");

        loop {
            let block_id = BlockId::Number(if optimistic {
                BlockNumberOrTag::Latest
            } else {
                BlockNumberOrTag::Finalized
            });
            match client.get_block(block_id).await {
                Ok(Some(block)) => {
                    failures = 0;
                    let new_final = block.header.number;
                    stall.observe(new_final);
                    head.send_if_modified(|cur| {
                        if cur.is_none_or(|current| new_final > current) {
                            *cur = Some(new_final);
                            true
                        } else {
                            false
                        }
                    });
                }
                Ok(None) => {
                    tracing::warn!(
                        "ethereum get_block(head) returned no block; watcher keeps retrying"
                    );
                }
                Err(err) => {
                    failures = failures.saturating_add(1);
                    tracing::warn!(
                        ?err,
                        failures,
                        max_failures,
                        "ethereum get_block(head) failed; watcher keeps retrying"
                    );
                }
            }

            if cancel.cancelled_within(refresh_interval).await {
                return Err(WatcherExit::Cancelled);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FinalizedHeadTracker, WatcherExit};
    use crate::test_utils;
    use mockito::{Matcher, Server};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn wait_for_returns_when_head_covers_block() {
        // wait_for only reads the cached head; a covering head returns without
        // any RPC (no client is involved).
        let tracker = FinalizedHeadTracker::new_for_test();
        tracker.set_head(100);

        tracker
            .wait_for(42)
            .await
            .expect("head covers block; should return without blocking");
    }

    #[tokio::test]
    async fn wait_for_resolves_when_head_advances() {
        let tracker = FinalizedHeadTracker::new_for_test();

        // Head starts at 0; the wait must block until the head advances past 50.
        let head = tracker.clone();
        let advancer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            head.set_head(100);
        });

        tracker
            .wait_for(50)
            .await
            .expect("should resolve once the head advances past the block");

        advancer.await.unwrap();
    }

    #[tokio::test]
    async fn wait_initialized_never_returns_cached_zero() {
        let tracker = FinalizedHeadTracker::new_for_test();
        let publisher = tracker.clone();
        let task = tokio::spawn(async move { tracker.wait_initialized().await.unwrap() });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished());
        publisher.set_head(42);
        assert_eq!(task.await.unwrap(), 42);
    }

    #[tokio::test]
    async fn sequential_waits_reuse_one_watcher_task() {
        let tracker = FinalizedHeadTracker::new_for_test();
        let client = Arc::new(test_utils::create_test_ethereum_client("http://127.0.0.1:1").await);
        let cancel = CancellationToken::new();
        let mut watcher = tracker.spawn_watcher(client, cancel.clone());

        tracker.set_head(10);
        let head = watcher.wait_initialized().await.unwrap();
        assert_eq!(head, 10);
        let head = watcher.wait_for(5).await.unwrap();
        assert_eq!(head, 10);
        tracker.set_head(20);
        let head = watcher.wait_for(15).await.unwrap();
        assert_eq!(head, 20);

        cancel.cancel();
    }

    #[tokio::test]
    async fn watcher_panic_before_initialization_is_an_error() {
        let tracker = FinalizedHeadTracker::new_for_test();
        let mut watcher = tracker.spawn_panicking_watcher();
        assert!(matches!(
            watcher.wait_initialized().await,
            Err(WatcherExit::Panicked)
        ));
    }

    #[tokio::test]
    async fn watcher_cancellation_during_wait_is_an_error() {
        let tracker = FinalizedHeadTracker::new_for_test();
        let client = Arc::new(test_utils::create_test_ethereum_client("http://127.0.0.1:1").await);
        let cancel = CancellationToken::new();
        let mut watcher = tracker.spawn_watcher(client, cancel.clone());
        cancel.cancel();
        assert!(matches!(
            watcher.wait_for(100).await,
            Err(WatcherExit::Cancelled)
        ));
    }

    #[tokio::test]
    async fn spawn_watcher_advances_head_and_unblocks_waiter() {
        let mut server = Server::new_async().await;

        // The watcher polls eth_getBlockByNumber(finalized); serve a head past 50.
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getBlockByNumber",
                "params": ["finalized", false]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(test_utils::block_response(1, 100).to_string())
            .create_async()
            .await;

        let client = Arc::new(test_utils::create_test_ethereum_client(&server.url()).await);
        let tracker = FinalizedHeadTracker::new_for_test();

        let cancel = CancellationToken::new();
        let mut watcher = tracker.spawn_watcher(client, cancel.clone());

        assert_eq!(
            watcher
                .wait_initialized()
                .await
                .expect("watcher should publish its first finalized sample"),
            100
        );
        watcher
            .wait_for(50)
            .await
            .expect("watcher should advance the head past 50 and unblock the wait");

        cancel.cancel();
    }
}
