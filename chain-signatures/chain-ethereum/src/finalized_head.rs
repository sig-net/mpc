use crate::client::EthereumClient;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherExit {
    Cancelled,
    Panicked,
    /// Watch channel closed while waiting for a head update
    Terminated,
}

/// Owns the watcher task maintaining the cached finalized head. Waiting
/// through this guard observes task exit as well as head updates; retaining
/// the watch sender alone cannot do that. A resolved task is terminal: waits
/// return an error and production callers immediately stop the indexer, so
/// this handle is never polled again.
///
/// The `head` channel is shared with the indexer, which retains a clone so
/// tests can force-publish a head without a running task.
pub struct FinalizedHeadWatcher {
    head: watch::Sender<Option<u64>>,
    task: JoinHandle<()>,
}

impl Drop for FinalizedHeadWatcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FinalizedHeadWatcher {
    /// Spawn the background watcher (`Finalized` in production, `Latest` in
    /// optimistic dev mode). Dropping the returned guard aborts the task.
    pub fn spawn(
        head: watch::Sender<Option<u64>>,
        eth: &EthConfig,
        client: Arc<EthereumClient>,
        cancel: CancellationToken,
    ) -> Self {
        let task = tokio::spawn(watch_head(
            client,
            head.clone(),
            Duration::from_millis(eth.refresh_finalized_interval),
            eth.indexer.max_finalized_failures,
            eth.indexer.stall_rewarn_secs,
            eth.optimistic_requests,
            cancel,
        ));
        Self { head, task }
    }

    fn map_join(result: Result<(), tokio::task::JoinError>) -> WatcherExit {
        match result {
            Ok(()) => WatcherExit::Cancelled,
            Err(err) if err.is_cancelled() => WatcherExit::Cancelled,
            Err(_) => WatcherExit::Panicked,
        }
    }

    pub async fn wait_initialized(&mut self) -> Result<u64, WatcherExit> {
        let mut head_rx = self.head.subscribe();
        loop {
            if let Some(head) = *head_rx.borrow_and_update() {
                return Ok(head);
            }
            tokio::select! {
                changed = head_rx.changed() => if changed.is_err() { return Err(WatcherExit::Terminated); },
                result = &mut self.task => return Err(Self::map_join(result)),
            }
        }
    }

    pub async fn wait_for(&mut self, block_number: u64) -> Result<u64, WatcherExit> {
        let mut head_rx = self.head.subscribe();
        loop {
            if let Some(head) = *head_rx.borrow_and_update() {
                if head >= block_number {
                    return Ok(head);
                }
            }
            tokio::select! {
                changed = head_rx.changed() => if changed.is_err() { return Err(WatcherExit::Terminated); },
                result = &mut self.task => return Err(Self::map_join(result)),
            }
        }
    }
}

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
    // TODO: max_failures is logged but never enforced — the watcher retries
    // forever and relies on the stream watchdog for recovery. Either exit
    // with WatcherExit::Panicked once failures exceed it, or drop the field
    // and its config entirely.
    max_failures: u32,
    stall_rewarn_secs: u64,
    optimistic: bool,
    cancel: CancellationToken,
) {
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
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FinalizedHeadWatcher, WatcherExit};
    use crate::test_utils;
    use mockito::{Matcher, Server};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::watch;
    use tokio::time::Duration;
    use tokio_util::sync::CancellationToken;

    async fn spawn_watcher(
        url: &str,
        cancel: &CancellationToken,
    ) -> (watch::Sender<Option<u64>>, FinalizedHeadWatcher) {
        let head = watch::channel(None).0;
        let client = Arc::new(test_utils::create_test_ethereum_client(url).await);
        let watcher = FinalizedHeadWatcher::spawn(
            head.clone(),
            &test_utils::test_eth_config(url),
            client,
            cancel.clone(),
        );
        (head, watcher)
    }

    #[tokio::test]
    async fn wait_initialized_blocks_until_first_publish() {
        // Watcher against an unroutable endpoint: only the explicit publish
        // unblocks, so the wait must block until then.
        let cancel = CancellationToken::new();
        let (head, mut watcher) = spawn_watcher("http://127.0.0.1:1", &cancel).await;

        let task = tokio::spawn(async move { watcher.wait_initialized().await.unwrap() });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished());
        head.send_replace(Some(42));
        assert_eq!(task.await.unwrap(), 42);

        cancel.cancel();
    }

    #[tokio::test]
    async fn sequential_waits_reuse_one_watcher_task() {
        let cancel = CancellationToken::new();
        let (head, mut watcher) = spawn_watcher("http://127.0.0.1:1", &cancel).await;

        head.send_replace(Some(10));
        assert_eq!(watcher.wait_initialized().await.unwrap(), 10);
        assert_eq!(watcher.wait_for(5).await.unwrap(), 10);
        head.send_replace(Some(20));
        assert_eq!(watcher.wait_for(15).await.unwrap(), 20);

        cancel.cancel();
    }

    #[tokio::test]
    async fn watcher_panic_before_initialization_is_an_error() {
        let head = watch::channel(None).0;
        let mut watcher = FinalizedHeadWatcher {
            head,
            task: tokio::spawn(async {
                panic!("test watcher panic");
            }),
        };
        assert!(matches!(
            watcher.wait_initialized().await,
            Err(WatcherExit::Panicked)
        ));
    }

    #[tokio::test]
    async fn watcher_cancellation_during_wait_is_an_error() {
        let cancel = CancellationToken::new();
        let (_head, mut watcher) = spawn_watcher("http://127.0.0.1:1", &cancel).await;
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

        let cancel = CancellationToken::new();
        let (_head, mut watcher) = spawn_watcher(&server.url(), &cancel).await;

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
