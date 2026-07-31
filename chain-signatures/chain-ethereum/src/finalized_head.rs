use crate::client::EthereumClient;
#[cfg(test)]
use crate::config::IndexerConfig;
use crate::EthConfig;
use alloy::eips::BlockNumberOrTag;
use alloy::rpc::types::BlockId;
use mpc_chain_integration_core::utils::task::{AbortOnDrop, CancellationTokenExt};
use mpc_primitives::{Chain, ChainConfig as _};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
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
    head: watch::Sender<u64>,
    optimistic: bool,
    refresh_interval: Duration,
    max_failures: u32,
    stall_rewarn_secs: u64,
}

impl FinalizedHeadTracker {
    pub fn new(eth: &EthConfig) -> Self {
        Self {
            head: watch::channel(0).0,
            optimistic: eth.optimistic_requests,
            refresh_interval: Duration::from_millis(eth.refresh_finalized_interval),
            max_failures: eth.indexer.max_finalized_failures,
            stall_rewarn_secs: eth.indexer.stall_rewarn_secs,
        }
    }

    /// Construct a finalized-head tracker for unit tests, with a short refresh interval and no optimistic mode.
    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        let indexer = IndexerConfig::default();
        Self {
            head: watch::channel(0).0,
            optimistic: false,
            refresh_interval: Duration::from_millis(100),
            max_failures: indexer.max_finalized_failures,
            stall_rewarn_secs: indexer.stall_rewarn_secs,
        }
    }

    /// Cached finalized block number.
    pub fn current(&self) -> u64 {
        *self.head.borrow()
    }

    /// Force the cached head to `n` (used by tests to bypass the watcher).
    #[cfg(test)]
    pub fn set_head(&self, n: u64) {
        self.head.send_replace(n);
    }

    /// Blocks until the cached finalized head covers `block_number`. Returns
    /// immediately in optimistic mode (dev chains never report finality).
    pub async fn wait_for(&self, block_number: u64) -> anyhow::Result<()> {
        if self.optimistic || *self.head.borrow() >= block_number {
            return Ok(());
        }

        // Slow path: wait for the watcher to publish an advance.
        let mut rx = self.head.subscribe();
        loop {
            if *rx.borrow_and_update() >= block_number {
                return Ok(());
            }
            if rx.changed().await.is_err() {
                anyhow::bail!(
                    "finalized-head watcher terminated before block {block_number} finalized"
                );
            }
        }
    }

    /// Spawn the background finalized-head watcher that maintains the cached
    /// head. Returns a guard whose drop aborts the task, or `None` in
    /// optimistic mode (dev chains never report a finalized head).
    pub fn spawn_watcher(
        &self,
        client: Arc<EthereumClient>,
        cancel: CancellationToken,
    ) -> Option<AbortOnDrop> {
        if self.optimistic {
            return None;
        }
        Some(AbortOnDrop(tokio::spawn(Self::watch_finalized_head(
            client,
            self.head.clone(),
            self.refresh_interval,
            self.max_failures,
            self.stall_rewarn_secs,
            cancel,
        ))))
    }

    // TODO: Currently if this dies silently we have to wait 35 min for the stream supervisor to restart it. Implement faster failure detection and restart.
    /// Background task maintaining the cached finalized head.
    ///
    /// Polls `eth_getBlockByNumber(Finalized)` on the configured interval and
    /// publishes advances over the `watch` channel. Retries forever; the stream
    /// supervisor watchdog remains the escape hatch.
    async fn watch_finalized_head(
        client: Arc<EthereumClient>,
        head: watch::Sender<u64>,
        refresh_interval: Duration,
        max_failures: u32,
        stall_rewarn_secs: u64,
        cancel: CancellationToken,
    ) {
        let mut stall = FinalizedHeadStall::new(
            Chain::Ethereum.expected_finality_time_secs(),
            stall_rewarn_secs,
        );
        let mut failures = 0u32;

        tracing::info!("ethereum finalized-head watcher started");

        loop {
            match client
                .get_block(BlockId::Number(BlockNumberOrTag::Finalized))
                .await
            {
                Ok(Some(block)) => {
                    failures = 0;
                    let new_final = block.header.number;
                    stall.observe(new_final);
                    head.send_if_modified(|cur| {
                        if new_final > *cur {
                            *cur = new_final;
                            true
                        } else {
                            false
                        }
                    });
                }
                Ok(None) => {
                    tracing::warn!(
                        "ethereum get_block(Finalized) returned no block; watcher keeps retrying"
                    );
                }
                Err(err) => {
                    failures = failures.saturating_add(1);
                    tracing::warn!(
                        ?err,
                        failures,
                        max_failures,
                        "ethereum get_block(Finalized) failed; watcher keeps retrying"
                    );
                }
            }

            if cancel.cancelled_within(refresh_interval).await {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FinalizedHeadTracker;
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
        let _watcher = tracker.spawn_watcher(client, cancel.clone());

        tracker
            .wait_for(50)
            .await
            .expect("watcher should advance the head past 50 and unblock the wait");

        cancel.cancel();
    }
}
