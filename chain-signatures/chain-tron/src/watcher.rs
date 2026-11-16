//! Watches Tron-targeted transactions by polling solidified receipts by
//! txID, and resolves M6 expiry over the `Executing` backlog.
//! Target-only, so [`ChainIndexer`](mpc_chain_integration_core::ChainIndexer)
//! is the supervision vehicle alone: no block scanning, no catchup — restart
//! rebuilds the map from the backlog.
use std::sync::Arc;

use alloy::primitives::B256;
use anyhow::Context;
use futures_util::stream::{iter, Stream, StreamExt};
use mpc_chain_integration_core::{
    ChainIndexer, ChainTelemetry, ExtractionFailure, StateManager, WatchedExecution,
};
use mpc_primitives::{BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::client::TronHttp;
use crate::config::TronConfig;
use crate::expiry::{
    closed_groups, expired_event, ExpiryVerdict, Group, SolidityCache, SolidityView,
    MAX_CONCURRENT_PROVIDER_REQUESTS,
};
use crate::types::{SolidifiedBlock, TronReceipt};

pub struct TronWatcher<S: StateManager, T: ChainTelemetry> {
    client: TronHttp,
    cache: SolidityCache,
    config: TronConfig,
    state_manager: S,
    telemetry: T,
}

impl<S: StateManager, T: ChainTelemetry> TronWatcher<S, T> {
    pub fn new(config: TronConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        Ok(Self {
            client: TronHttp::new(&config)?,
            cache: SolidityCache::default(),
            config,
            state_manager,
            telemetry,
        })
    }

    /// Forwards one pass's events as they resolve; `true` ends the run
    /// (cancelled or the channel closed), `false` when the pass drained.
    async fn forward_pass<St: futures_util::Stream<Item = ChainEvent> + Unpin>(
        &self,
        mut events: St,
        events_tx: &mpsc::Sender<ChainEvent>,
        cancel: &CancellationToken,
    ) -> bool {
        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => return true,
                event = events.next() => match event {
                    Some(event) => event,
                    None => return false,
                },
            };
            if events_tx.send(event).await.is_err() {
                return true;
            }
        }
    }

    /// Yields per resolved receipt, in resolution order; pending, failed
    /// fetch, and unclassifiable receipts yield nothing and retry next
    /// tick. Resolution order is load-bearing: immediate sends keep a
    /// pass that outlasts the stall timeout from losing confirmations.
    /// One fetch per flat id, one classification per member.
    async fn poll_watchers(&self) -> impl Stream<Item = ChainEvent> + Unpin + '_ {
        let watchers = self.state_manager.get_execution_watchers(Chain::Tron).await;
        tracing::debug!(flat_ids = watchers.len(), "polling tron execution watchers");

        iter(watchers)
            .map(|(tx_id, members)| self.resolve_watched_id(tx_id, members))
            .buffer_unordered(MAX_CONCURRENT_PROVIDER_REQUESTS)
            .map(iter)
            .flatten()
    }

    /// An empty vec defers the id to the next tick.
    async fn resolve_watched_id(
        &self,
        tx_id: BidirectionalTxId,
        members: Vec<WatchedExecution>,
    ) -> Vec<ChainEvent> {
        let member_count = members.len();
        let receipt = match self
            .client
            .get_transaction_info_solidity(&B256::from(tx_id.0))
            .await
        {
            Ok(receipt) => receipt,
            Err(err) => {
                let failure = ExtractionFailure::from(err);
                self.telemetry
                    .bidirectional_extraction_failed(failure.kind());
                tracing::warn!(
                    ?tx_id,
                    members = member_count,
                    "receipt poll failed: {failure:#}"
                );
                return Vec::new();
            }
        };
        let Some(receipt) = receipt else {
            return Vec::new();
        };

        members
            .into_iter()
            .filter_map(|member| self.member_event(member, &receipt))
            .collect()
    }

    /// `None` — unclassifiable under this member's schema; retries next
    /// tick.
    fn member_event(&self, member: WatchedExecution, receipt: &TronReceipt) -> Option<ChainEvent> {
        let WatchedExecution { sign_id, tx } = member;
        let tx_id = tx.id;
        let result = match receipt.execution_outcome(&tx) {
            Ok(result) => result,
            Err(failure) => {
                self.telemetry
                    .bidirectional_extraction_failed(failure.kind());
                match failure {
                    ExtractionFailure::Retryable(err) => {
                        tracing::warn!(?tx_id, ?sign_id, "{err:#}");
                        return None;
                    }
                    ExtractionFailure::Terminal(err) => {
                        tracing::error!(
                            ?tx_id,
                            ?sign_id,
                            "output extraction failed; parking: {err:#}"
                        );
                        ExecutionOutcome::ExtractionFailed
                    }
                }
            }
        };

        Some(ChainEvent::ExecutionConfirmed {
            tx_id,
            sign_id,
            source_chain: tx.source_chain,
            block_height: receipt.block_number,
            result,
        })
    }

    /// M6 attestations per flat id, each at the boundary every node
    /// derives identically. A pass outlasting the stall budget loses
    /// only the unsent tail.
    async fn expiry_scan(&self) -> futures_util::stream::BoxStream<'_, ChainEvent> {
        let Some((head, groups)) = self.closed_window_groups().await else {
            return futures_util::stream::empty().boxed();
        };
        let ids: Vec<_> = groups.iter().map(|group| group[0].1.id).collect();
        self.cache.prune(head.number, &ids).await;
        let view = SolidityView::new(&self.client, head.number, self.cache.clone());
        iter(groups)
            .map(move |group| self.resolve_group(group, view.clone()))
            .buffer_unordered(MAX_CONCURRENT_PROVIDER_REQUESTS)
            .map(futures_util::stream::iter)
            .flatten()
            .boxed()
    }

    /// The head and its window-closed groups; `None` defers the
    /// pass: empty backlog (head unread), head failure, nothing
    /// closed yet.
    async fn closed_window_groups(&self) -> Option<(SolidifiedBlock, Vec<Group>)> {
        let pending = self.state_manager.get_pending_executions(Chain::Tron).await;
        if pending.is_empty() {
            return None;
        }
        let head = self.solidified_head().await?;
        let groups = closed_groups(pending, &head);
        (!groups.is_empty()).then_some((head, groups))
    }

    /// The scan head — a gate only, never part of an attestation.
    /// Failure defers, counted through `expiry_scan_deferred`.
    async fn solidified_head(&self) -> Option<SolidifiedBlock> {
        self.client
            .get_now_block_solidity()
            .await
            .map_err(|err| {
                tracing::warn!(?err, "solidity head fetch failed; expiry scan deferred");
                self.telemetry.expiry_scan_deferred();
            })
            .ok()
    }

    async fn resolve_group(&self, group: Group, view: SolidityView<'_>) -> Vec<ChainEvent> {
        let (sign_id, tx, window) = &group[0];
        match view.verdict(tx.id, window).await {
            Ok(ExpiryVerdict::Included) => {
                for (sign_id, tx, _) in &group {
                    tracing::info!(?sign_id, ?tx.id,
                        "expired window with inclusion; re-registered for the receipt arm");
                    self.state_manager
                        .watch_execution(Chain::Tron, Arc::clone(tx))
                        .await;
                }
                Vec::new()
            }
            Ok(ExpiryVerdict::Absent { boundary }) => group
                .into_iter()
                .map(|(sign_id, tx, _)| {
                    tracing::info!(?sign_id, ?tx.id, source = ?tx.source_chain,
                        boundary,
                        "validity window closed without inclusion; attesting unexecutable");
                    expired_event(sign_id, &tx, boundary)
                })
                .collect(),
            Err(err) => {
                tracing::warn!(?tx.id, ?sign_id, "expiry walk failed; deferring: {err:#}");
                Vec::new()
            }
        }
    }
}

#[async_trait::async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for TronWatcher<S, T> {
    const CHAIN: Chain = Chain::Tron;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        tracing::info!("tron execution watcher started");
        // No catchup — txID lookups need none; recovery rebuilds the map.
        // The respond leg gates on the source chain's flag, so this event
        // only satisfies the indexer contract.
        if events_tx.send(ChainEvent::CatchupCompleted).await.is_err() {
            return Ok(());
        }
        loop {
            let head = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                head = self.client.get_now_block() => {
                    head.context("fetching the tron head block")?.number
                }
            };
            // Block last: it certifies the tick; a pass outlasting the
            // stall timeout (`run_supervised_with_watchdog`) restarts
            // with the map already shrunk. Polls drain first so a
            // receipt found by either arm wins over the closed window.
            let polls = self.poll_watchers().await;
            if self.forward_pass(polls, &events_tx, &cancel).await {
                return Ok(());
            }

            let scans = self.expiry_scan().await;
            if self.forward_pass(scans, &events_tx, &cancel).await {
                return Ok(());
            }

            // Provider head as a liveness gauge; Tron indexes no blocks.
            self.telemetry.block_indexed(head);
            if events_tx.send(ChainEvent::Block(head)).await.is_err() {
                return Ok(());
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep(self.config.poll_interval) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use mockito::Matcher;
    use mpc_chain_integration_core::utils::retry::RetryConfig;
    use mpc_chain_integration_core::{
        ExtractionFailureKind, MockStateManager, NoopChainTelemetry, StateManager,
    };
    use mpc_primitives::{
        BidirectionalTx, BidirectionalTxId, ExecutionOutcome, RequestKind, SignId,
    };

    use super::*;
    use crate::test_utils::*;

    /// Counts `bidirectional_extraction_failed`, as the Ethereum watcher
    /// tests do.
    #[derive(Clone, Default)]
    struct CountingTelemetry {
        retryable: Arc<AtomicUsize>,
        terminal: Arc<AtomicUsize>,
        deferred_expiry_scans: Arc<AtomicUsize>,
    }

    impl CountingTelemetry {
        fn retryable_failures(&self) -> usize {
            self.retryable.load(Ordering::Relaxed)
        }
        fn terminal_failures(&self) -> usize {
            self.terminal.load(Ordering::Relaxed)
        }
        fn deferred_expiry_scans(&self) -> usize {
            self.deferred_expiry_scans.load(Ordering::Relaxed)
        }
    }

    impl ChainTelemetry for CountingTelemetry {
        fn block_indexed(&self, _: u64) {}
        fn block_finalized(&self, _: u64) {}
        fn checkpoint_created(&self, _: u64) {}
        fn request_indexed_at(&self, _: u64, _: RequestKind) {}
        fn request_indexed(&self, _: RequestKind) {}
        fn bidirectional_extraction_failed(&self, kind: ExtractionFailureKind) {
            match kind {
                ExtractionFailureKind::Retryable => &self.retryable,
                ExtractionFailureKind::Terminal => &self.terminal,
            }
            .fetch_add(1, Ordering::Relaxed);
        }
        fn expiry_scan_deferred(&self) {
            self.deferred_expiry_scans.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct WatcherRun {
        cancel: CancellationToken,
        events: mpsc::Receiver<ChainEvent>,
        done: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    impl WatcherRun {
        async fn stop(self) {
            self.cancel.cancel();
            self.done.await.unwrap().unwrap();
        }
    }

    fn spawn_watcher(
        config: TronConfig,
        state: MockStateManager,
        telemetry: impl ChainTelemetry + 'static,
    ) -> WatcherRun {
        let (events_tx, events_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let run_cancel = cancel.clone();
        let done = tokio::spawn(async move {
            let watcher = TronWatcher::new(config, state, telemetry)?;
            watcher.run(events_tx, run_cancel).await
        });
        WatcherRun {
            cancel,
            events: events_rx,
            done,
        }
    }

    /// Waits for `seed`'s `ExecutionConfirmed`, returning it with the
    /// events seen first.
    async fn until_confirmed(
        run: &mut WatcherRun,
        seed: u8,
    ) -> (Vec<ChainEvent>, ExecutionOutcome) {
        let deadline = Duration::from_secs(5);
        tokio::time::timeout(deadline, async {
            let mut seen = Vec::new();
            loop {
                let event = run.events.recv().await.expect("watcher channel open");
                match event {
                    ChainEvent::ExecutionConfirmed { tx_id, result, .. } if tx_id.0[0] == seed => {
                        return (seen, result)
                    }
                    other => seen.push(other),
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no ExecutionConfirmed for seed {seed} within {deadline:?}"))
    }

    async fn first_is_catchup_completed(run: &mut WatcherRun) {
        let event = tokio::time::timeout(Duration::from_secs(5), run.events.recv())
            .await
            .expect("first event within deadline");
        assert!(
            matches!(event, Some(ChainEvent::CatchupCompleted)),
            "first event must be CatchupCompleted, got {event:?}"
        );
    }

    #[tokio::test]
    async fn success_receipt_resolves_execution_confirmed() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, success_body(1))
            .expect(1)
            .create();
        receipt_stub(&mut server, 2, success_body(2))
            .expect(1)
            .create();

        let state = MockStateManager::new();
        state.watch_execution(Chain::Tron, watcher_tx(1).2).await;
        state.watch_execution(Chain::Tron, watcher_tx(2).2).await;

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;

        let (seen1, result1) = until_confirmed(&mut run, 1).await;
        let (seen2, result2) = until_confirmed(&mut run, 2).await;
        assert!(
            matches!(result1, ExecutionOutcome::Success { output } if output.is_empty()),
            "seen before seed 1: {seen1:?}"
        );
        assert!(
            matches!(result2, ExecutionOutcome::Success { output } if output.is_empty()),
            "seen before seed 2: {seen2:?}"
        );

        run.stop().await;
    }

    #[tokio::test]
    async fn revert_receipt_resolves_failed() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, failure_body(1, "REVERT"))
            .expect(1)
            .create();

        let state = MockStateManager::new();
        state.watch_execution(Chain::Tron, watcher_tx(1).2).await;

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (_, result) = until_confirmed(&mut run, 1).await;
        assert!(matches!(result, ExecutionOutcome::Failed));

        run.stop().await;
    }

    #[tokio::test]
    async fn pending_receipt_polls_again() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        // Mockito answers the first stub whose expectation is still unmet:
        // the pending `{}` stub hands the first poll, the receipt the next.
        receipt_stub(&mut server, 1, "{}".to_string())
            .expect(1)
            .create();
        receipt_stub(&mut server, 1, success_body(1)).create();

        let state = MockStateManager::new();
        state.watch_execution(Chain::Tron, watcher_tx(1).2).await;

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (_, result) = until_confirmed(&mut run, 1).await;
        assert!(matches!(result, ExecutionOutcome::Success { output } if output.is_empty()));

        run.stop().await;
    }

    /// Immutable receipts: an unclassifiable result can never change, so
    /// attesting a guess is forbidden — poll on, counting one retryable
    /// extraction failure per watcher per tick.
    #[tokio::test]
    async fn unclassifiable_receipt_resolves_nothing() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, unclassifiable_body(1)).create();
        let resultless = format!(
            r#"{{ "id": "{}", "blockNumber": 1 }}"#,
            hex::encode(watcher_tx(2).0 .0)
        );
        receipt_stub(&mut server, 2, resultless).create();

        let state = MockStateManager::new();
        state.watch_execution(Chain::Tron, watcher_tx(1).2).await;
        state.watch_execution(Chain::Tron, watcher_tx(2).2).await;

        let telemetry = CountingTelemetry::default();
        let mut run = spawn_watcher(config, state, telemetry.clone());
        first_is_catchup_completed(&mut run).await;
        // Several ticks' worth of Block events without any confirmation.
        for _ in 0..10 {
            match run.events.recv().await.expect("watcher channel open") {
                ChainEvent::Block(_) => {}
                other => panic!("unexpected event: {other:?}"),
            }
        }
        // Two unresolved watchers per tick, and each received Block
        // certifies a completed tick — so ten blocks guarantee twenty
        // counted failures (the next tick may add more while we assert).
        assert!(
            telemetry.retryable_failures() >= 20,
            "each unclassifiable receipt must count per tick"
        );
        run.stop().await;
    }

    /// A successful receipt yields the request's output:
    /// `contractResult[0]` decoded and re-serialized (Fab `bool` →
    /// one byte).
    #[tokio::test]
    async fn schema_carrying_success_extracts() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, success_body_with_return(1, ABI_FALSE_WORD))
            .expect(1)
            .create();

        let state = MockStateManager::new();
        state
            .watch_execution(Chain::Tron, schema_carrying_tx(1).2)
            .await;

        let telemetry = CountingTelemetry::default();
        let mut run = spawn_watcher(config, state, telemetry.clone());
        first_is_catchup_completed(&mut run).await;
        let (_, result) = until_confirmed(&mut run, 1).await;
        assert!(matches!(&result,
            ExecutionOutcome::Success { output } if *output == vec![0]));
        assert_eq!(telemetry.terminal_failures(), 0);
        assert_eq!(telemetry.retryable_failures(), 0);

        run.stop().await;
    }

    /// Receipt and entry are immutable, so a table refusal is
    /// deterministic — park with terminal telemetry, never retry.
    #[tokio::test]
    async fn undecodable_return_data_parks() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, success_body_with_return(1, "00"))
            .expect(1)
            .create();

        let state = MockStateManager::new();
        state
            .watch_execution(Chain::Tron, schema_carrying_tx(1).2)
            .await;

        let telemetry = CountingTelemetry::default();
        let mut run = spawn_watcher(config, state, telemetry.clone());
        first_is_catchup_completed(&mut run).await;
        let (_, result) = until_confirmed(&mut run, 1).await;
        assert!(matches!(result, ExecutionOutcome::ExtractionFailed));
        assert!(telemetry.terminal_failures() >= 1);
        assert_eq!(telemetry.retryable_failures(), 0);

        run.stop().await;
    }

    /// A schema-carrying call whose receipt carries no return data
    /// parks — same arm, different table row.
    #[tokio::test]
    async fn schema_without_return_data_parks() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, success_body(1))
            .expect(1)
            .create();

        let state = MockStateManager::new();
        state
            .watch_execution(Chain::Tron, schema_carrying_tx(1).2)
            .await;

        let telemetry = CountingTelemetry::default();
        let mut run = spawn_watcher(config, state, telemetry.clone());
        first_is_catchup_completed(&mut run).await;
        let (_, result) = until_confirmed(&mut run, 1).await;
        assert!(matches!(result, ExecutionOutcome::ExtractionFailed));
        assert!(telemetry.terminal_failures() >= 1);

        run.stop().await;
    }

    /// Return data with an empty output schema parks under EVM parity
    /// — the recorded USDT shape the placeholder used to attest empty.
    #[tokio::test]
    async fn return_data_with_empty_schema_parks() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, success_body_with_return(1, ABI_FALSE_WORD))
            .expect(1)
            .create();

        let state = MockStateManager::new();
        state.watch_execution(Chain::Tron, calling_tx(1).2).await;

        let telemetry = CountingTelemetry::default();
        let mut run = spawn_watcher(config, state, telemetry.clone());
        first_is_catchup_completed(&mut run).await;
        let (_, result) = until_confirmed(&mut run, 1).await;
        assert!(matches!(result, ExecutionOutcome::ExtractionFailed));
        assert!(telemetry.terminal_failures() >= 1);

        run.stop().await;
    }

    /// Counted per tick, never resolved — no verdict off an unreadable body.
    #[tokio::test]
    async fn malformed_receipt_counts_retryable_and_resolves_nothing() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        let malformed = format!(
            r#"{{ "id": "{}", "blockNumber": 1, "contractResult": ["zz"],
                 "receipt": {{ "result": "SUCCESS" }} }}"#,
            hex::encode(watcher_tx(3).0 .0)
        );
        receipt_stub(&mut server, 3, malformed).create();

        let state = MockStateManager::new();
        state.watch_execution(Chain::Tron, watcher_tx(3).2).await;

        let telemetry = CountingTelemetry::default();
        let mut run = spawn_watcher(config, state, telemetry.clone());
        first_is_catchup_completed(&mut run).await;
        for _ in 0..5 {
            match run.events.recv().await.expect("watcher channel open") {
                ChainEvent::Block(_) => {}
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert!(
            telemetry.retryable_failures() >= 5,
            "one malformed-receipt count per tick"
        );
        assert_eq!(telemetry.terminal_failures(), 0);

        run.stop().await;
    }

    /// A receipt must confirm while a slower poll is in flight: a batched
    /// pass outlasting the stall timeout would discard it on restart.
    #[tokio::test]
    async fn confirms_stream_while_a_slow_poll_is_in_flight() {
        let server = mockito::Server::new_async().await;
        // Seed 2 retries a 429 on a 300ms cadence — in flight well past
        // the assert window below.
        let config = TronConfig {
            retry: RetryConfig {
                min_delay: Duration::from_millis(300),
                max_delay: Duration::from_millis(300),
                max_times: 5,
                jitter: false,
            },
            ..test_config(server.url().parse().unwrap())
        };
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, success_body(1))
            .expect(1)
            .create();
        let tx2 = watcher_tx(2).0;
        server
            .mock("POST", "/walletsolidity/gettransactioninfobyid")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "value": hex::encode(tx2.0)
            })))
            .with_status(429)
            .expect_at_least(1)
            .create();

        let state = MockStateManager::new();
        state.watch_execution(Chain::Tron, watcher_tx(1).2).await;
        state.watch_execution(Chain::Tron, watcher_tx(2).2).await;

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;

        let (seen, result) =
            tokio::time::timeout(Duration::from_millis(600), until_confirmed(&mut run, 1))
                .await
                .expect("seed 1 must confirm while seed 2's poll is still in flight");
        assert!(
            matches!(result, ExecutionOutcome::Success { output } if output.is_empty()),
            "seen before seed 1: {seen:?}"
        );
        // Block certifies a completed pass — seed 2 is still retrying.
        assert!(
            !seen
                .iter()
                .any(|event| matches!(event, ChainEvent::Block(_))),
            "Block must not precede the pass's end: {seen:?}"
        );

        run.stop().await;
    }

    #[tokio::test]
    async fn receipt_poll_failure_spares_other_watchers() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, "{}".to_string())
            .with_status(500)
            .create();
        receipt_stub(&mut server, 2, success_body(2)).create();

        let state = MockStateManager::new();
        state.watch_execution(Chain::Tron, watcher_tx(1).2).await;
        state.watch_execution(Chain::Tron, watcher_tx(2).2).await;

        let telemetry = CountingTelemetry::default();
        let mut run = spawn_watcher(config, state, telemetry.clone());
        first_is_catchup_completed(&mut run).await;
        let (seen, result) = until_confirmed(&mut run, 2).await;
        assert!(matches!(result, ExecutionOutcome::Success { output } if output.is_empty()));
        assert!(
            !seen.iter().any(|e| matches!(
                e,
                ChainEvent::ExecutionConfirmed { tx_id, .. } if tx_id.0[0] == 1
            )),
            "the failing watcher must not resolve: {seen:?}"
        );
        // A Block certifies the completed pass — seed 1's retries drain
        // within it.
        loop {
            if let ChainEvent::Block(_) = run.events.recv().await.expect("watcher channel open") {
                break;
            }
        }
        // Counted, as on Ethereum's post-retry fetch failures.
        assert!(telemetry.retryable_failures() >= 1);
        assert_eq!(telemetry.terminal_failures(), 0);

        run.stop().await;
    }

    /// A dead endpoint fails `run` itself — the supervisor's restart
    /// contract, not a warn-and-spin.
    #[tokio::test]
    async fn head_fetch_failure_fails_the_run() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        server
            .mock("POST", "/wallet/getnowblock")
            .with_status(500)
            .create();

        let run = spawn_watcher(config, MockStateManager::new(), NoopChainTelemetry);
        let result = run.done.await.unwrap().unwrap_err();
        let rendered = format!("{result:#}");
        assert!(
            rendered.contains("getnowblock"),
            "unexpected error: {rendered}"
        );
    }

    /// Solidity-only outage: no resolution, no shutdown, one deferral
    /// per tick.
    #[tokio::test]
    async fn solidity_head_failure_defers_the_scan_and_keeps_the_run_alive() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        server
            .mock("POST", "/walletsolidity/getnowblock")
            .with_status(500)
            .create();

        let state = MockStateManager::new();
        pending_expiry_entry(&state, 7, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        let telemetry = CountingTelemetry::default();
        let counting = telemetry.clone();

        let mut run = spawn_watcher(config, state, telemetry);
        first_is_catchup_completed(&mut run).await;
        let events = until_blocks(&mut run, 2).await;
        assert_eq!(counting.deferred_expiry_scans(), 2, "events: {events:?}");
        assert!(
            events
                .iter()
                .all(|event| matches!(event, ChainEvent::Block(_))),
            "a deferred scan resolves nothing: {events:?}"
        );

        run.stop().await;
    }

    /// Waits for `id`'s confirmation, returning its height, source, outcome.
    async fn until_tx_confirmed(
        run: &mut WatcherRun,
        id: &BidirectionalTxId,
    ) -> (u64, Chain, ExecutionOutcome) {
        let deadline = Duration::from_secs(5);
        tokio::time::timeout(deadline, async {
            loop {
                let event = run.events.recv().await.expect("watcher channel open");
                if let ChainEvent::ExecutionConfirmed {
                    tx_id,
                    source_chain,
                    block_height,
                    result,
                    ..
                } = event
                {
                    if tx_id == *id {
                        return (block_height, source_chain, result);
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no ExecutionConfirmed for {id:?} within {deadline:?}"))
    }

    /// Collects until `n` `Block` events pass, returning every event seen.
    async fn until_blocks(run: &mut WatcherRun, n: usize) -> Vec<ChainEvent> {
        let deadline = Duration::from_secs(5);
        tokio::time::timeout(deadline, async {
            let mut seen = Vec::new();
            let mut blocks = 0;
            while blocks < n {
                let event = run.events.recv().await.expect("watcher channel open");
                if matches!(event, ChainEvent::Block(_)) {
                    blocks += 1;
                }
                seen.push(event);
            }
            seen
        })
        .await
        .unwrap_or_else(|_| panic!("fewer than {n} blocks within {deadline:?}"))
    }

    /// M6 with the watch displaced by a duplicate id and the window
    /// closed.
    #[tokio::test]
    async fn expired_displaced_entry_attests_unviable() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        solid_block_ladder(&mut server, &[]);
        let (id, _, _) =
            pending_expiry_entry(&state, 1, Chain::Midnight, SOLIDITY_TS - 40_000).await;

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (height, source, result) = until_tx_confirmed(&mut run, &id).await;
        assert_eq!(height, 32);
        assert_eq!(source, Chain::Midnight);
        assert!(matches!(result, ExecutionOutcome::Unviable));

        run.stop().await;
    }

    /// A watched entry expires too: the receipt poll finds nothing, and the
    /// scan answers at the solidified head.
    #[tokio::test]
    async fn expired_watched_entry_resolves_through_the_scan() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        solid_block_ladder(&mut server, &[]);
        let (id, _, _) =
            watched_expiry_entry(&state, 3, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        receipt_for(&mut server, &id, "{}".to_string());

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (height, _, result) = until_tx_confirmed(&mut run, &id).await;
        assert_eq!(height, 32);
        assert!(matches!(result, ExecutionOutcome::Unviable));

        run.stop().await;
    }

    /// M6's premise fails — a solidified receipt exists — so the arm
    /// re-registers rather than attests.
    #[tokio::test]
    async fn expired_but_executed_re_registers_for_receipt_resolution() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        let (id, _, _) =
            pending_expiry_entry(&state, 4, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        solid_block_ladder(&mut server, &[(20, id.0)]);
        receipt_for(&mut server, &id, success_receipt(&id));

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (height, _, result) = until_tx_confirmed(&mut run, &id).await;
        assert_eq!(height, 71896097);
        assert!(matches!(result, ExecutionOutcome::Success { .. }));

        run.stop().await;
    }

    /// Watched, window closed, receipt present: both arms see the
    /// entry, and the receipt arm must win with no Unviable. The tick
    /// drains fully before retirement so the scan pass is observable.
    #[tokio::test]
    async fn expired_and_included_watched_entry_resolves_once_through_the_receipt() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        let (id, sign_id, _) =
            watched_expiry_entry(&state, 6, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        receipt_for(&mut server, &id, success_receipt(&id));
        solid_block_ladder(&mut server, &[(20, id.0)]);

        let mut run = spawn_watcher(config, state.clone(), NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let tick = until_blocks(&mut run, 1).await;
        let confirmed = tick
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    ChainEvent::ExecutionConfirmed { tx_id, .. } if *tx_id == id
                )
            })
            .count();
        assert_eq!(confirmed, 1, "events: {tick:?}");
        assert!(
            tick.iter().any(|event| matches!(
                event,
                ChainEvent::ExecutionConfirmed {
                    tx_id, block_height, result: ExecutionOutcome::Success { output },
                    ..
                } if *tx_id == id && *block_height == 71896097 && output.is_empty()
            )),
            "events: {tick:?}"
        );
        assert!(
            !tick.iter().any(|event| matches!(
                event,
                ChainEvent::ExecutionConfirmed {
                    result: ExecutionOutcome::Unviable | ExecutionOutcome::Failed,
                    ..
                }
            )),
            "the closed window must not attest: {tick:?}"
        );

        state
            .remove_pending_execution(Chain::Midnight, sign_id)
            .await;
        state
            .remove_execution_watch(Chain::Tron, &id, Chain::Midnight, sign_id)
            .await;
        let next_tick = until_blocks(&mut run, 1).await;
        assert!(
            next_tick
                .iter()
                .all(|event| matches!(event, ChainEvent::Block(_))),
            "retired entry re-fired: {next_tick:?}"
        );

        run.stop().await;
    }

    /// Two requests share the flat txID; both must resolve through the
    /// one receipt — fetched once per id, not once per entry.
    #[tokio::test]
    async fn duplicate_flat_id_entries_both_resolve_through_the_receipt_arm() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        let (id, displacing, tx) =
            pending_expiry_entry(&state, 5, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        // Both entries hold their own watch under the flat id; the walk
        // ladder stays for members the poll arm has not reached yet.
        solid_block_ladder(&mut server, &[(20, id.0)]);
        let mut displaced_tx = (*tx).clone();
        displaced_tx.request_id = [0x7f; 32];
        let displaced = displaced_tx.sign_id();
        let displaced_tx: Arc<BidirectionalTx> = displaced_tx.into();
        state.add_pending_execution(Arc::clone(&displaced_tx)).await;
        state.watch_execution(Chain::Tron, tx).await;
        state.watch_execution(Chain::Tron, displaced_tx).await;
        receipt_for(&mut server, &id, success_receipt(&id));

        let confirmed_state = state.clone();
        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let confirmations = tokio::time::timeout(Duration::from_secs(5), async {
            let mut seen: Vec<(SignId, u64, ExecutionOutcome)> = Vec::new();
            loop {
                let event = run.events.recv().await.expect("watcher channel open");
                if let ChainEvent::ExecutionConfirmed {
                    tx_id,
                    sign_id,
                    source_chain,
                    block_height,
                    result,
                    ..
                } = event
                {
                    if tx_id == id {
                        confirmed_state
                            .remove_pending_execution(source_chain, sign_id)
                            .await;
                        if !seen.iter().any(|(sign, ..)| *sign == sign_id) {
                            seen.push((sign_id, block_height, result));
                            if seen.len() == 2 {
                                return seen;
                            }
                        }
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("both flat-id entries must confirm"));

        for (sign, height, result) in confirmations {
            assert!(sign == displacing || sign == displaced, "unknown sign id");
            assert_eq!(height, 71896097);
            assert!(matches!(result, ExecutionOutcome::Success { .. }));
        }

        run.stop().await;
    }

    /// One receipt fetch per flat id: a single request confirms every
    /// entry registered under the id in the same pass.
    #[tokio::test]
    async fn one_receipt_fetch_confirms_every_flat_id_entry() {
        let (mut server, config, state) = expiry_stack().await;
        let (id, first, tx) =
            watched_expiry_entry(&state, 5, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        let mut twin = (*tx).clone();
        twin.request_id = [0x7f; 32];
        let second = twin.sign_id();
        state.watch_execution(Chain::Tron, Arc::new(twin)).await;
        let receipt = receipt_for_once(&mut server, &id, success_receipt(&id));

        let watcher = TronWatcher::new(config, state, NoopChainTelemetry).unwrap();
        let confirmed: Vec<SignId> = watcher
            .poll_watchers()
            .await
            .map(|event| match event {
                ChainEvent::ExecutionConfirmed { sign_id, .. } => sign_id,
                _ => unreachable!("the poll arm emits confirmations only"),
            })
            .collect()
            .await;

        assert_eq!(confirmed.len(), 2, "both members confirm in one pass");
        assert!(confirmed.contains(&first) && confirmed.contains(&second));
        receipt.assert_async().await;
    }

    /// Schemas are not in the rid, so twins may differ: one receipt
    /// settles each member under its own schema.
    #[tokio::test]
    async fn divergent_twin_schemas_settle_independently_from_one_fetch() {
        let (mut server, config, state) = expiry_stack().await;
        let (id, plain, tx) =
            watched_expiry_entry(&state, 5, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        let mut twin = (*tx).clone();
        twin.request_id = [0x7f; 32];
        let parked = twin.sign_id();
        twin.output_deserialization_schema =
            br#"[{\"name\":\"output\",\"type\":\"bool\"}]"#.to_vec();
        state.watch_execution(Chain::Tron, twin.into()).await;
        let receipt = receipt_for_once(&mut server, &id, success_receipt(&id));

        let telemetry = CountingTelemetry::default();
        let watcher = TronWatcher::new(config, state, telemetry.clone()).unwrap();
        let outcomes: Vec<(SignId, ExecutionOutcome)> = watcher
            .poll_watchers()
            .await
            .map(|event| match event {
                ChainEvent::ExecutionConfirmed {
                    sign_id, result, ..
                } => (sign_id, result),
                _ => unreachable!("the poll arm emits confirmations only"),
            })
            .collect()
            .await;

        assert_eq!(outcomes.len(), 2, "both members settle in one pass");
        let outcome_of = |sign_id: &SignId| {
            outcomes
                .iter()
                .find(|(id, _)| id == sign_id)
                .map(|(_, result)| result)
                .expect("each member settles exactly once")
        };
        assert!(matches!(
            outcome_of(&plain),
            ExecutionOutcome::Success { .. }
        ));
        assert!(matches!(
            outcome_of(&parked),
            ExecutionOutcome::ExtractionFailed
        ));
        assert_eq!(telemetry.terminal_failures(), 1);
        assert_eq!(telemetry.retryable_failures(), 0);
        receipt.assert_async().await;
    }

    /// Two nodes at different solidified heads attest the same height:
    /// the boundary — the digest binds the height, so a head a poll
    /// interval apart must not diverge the message.
    #[tokio::test]
    async fn expiry_attests_the_same_boundary_whatever_the_head() {
        let mut heights = Vec::new();
        for head in [41u64, LADDER_TOP] {
            let (mut server, config, state) = expiry_stack().await;
            solidity_head_at(&mut server, head);
            solid_block_ladder(&mut server, &[]);
            let (id, _, _) =
                pending_expiry_entry(&state, 1, Chain::Midnight, SOLIDITY_TS - 40_000).await;

            let mut run = spawn_watcher(config, state, NoopChainTelemetry);
            first_is_catchup_completed(&mut run).await;
            let (height, _, result) = until_tx_confirmed(&mut run, &id).await;
            heights.push(height);
            assert!(matches!(result, ExecutionOutcome::Unviable));
            run.stop().await;
        }
        assert_eq!(heights, [32, 32]);
    }

    /// No `Executing` entries: the solidified head is never fetched.
    #[tokio::test]
    async fn empty_backlog_skips_the_solidity_head() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        let solidity = server
            .mock("POST", "/walletsolidity/getnowblock")
            .expect(0)
            .create();

        let mut run = spawn_watcher(config, MockStateManager::new(), NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        until_blocks(&mut run, 3).await;
        solidity.assert_async().await;

        run.stop().await;
    }

    /// A probe below the head reading absent must defer, not attest at a
    /// boundary it cannot prove is the first past the window — the
    /// pruned-history shape. The head serves by number; mockito answers
    /// the first matching stub, so the exact stub precedes the catch-all.
    #[tokio::test]
    async fn absent_probe_below_the_head_defers_rather_than_attesting() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_head_at(&mut server, 41);
        solid_block_mock(&mut server, 41, &[]);
        solid_block_absent(&mut server);
        pending_expiry_entry(&state, 1, Chain::Midnight, SOLIDITY_TS - 40_000).await;

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let events = until_blocks(&mut run, 2).await;
        assert!(
            events
                .iter()
                .all(|event| matches!(event, ChainEvent::Block(_))),
            "an absent probe must defer, not attest: {events:?}"
        );

        run.stop().await;
    }

    /// One retry cycle of read failures during the walk defers the
    /// pass; the entry attests once reads recover.
    #[tokio::test]
    async fn walk_read_failure_defers_then_attests_on_recovery() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        let failures = server
            .mock("POST", "/walletsolidity/getblockbynum")
            .with_status(500)
            .expect(3)
            .create();
        solid_block_ladder(&mut server, &[]);
        let (id, _, _) =
            pending_expiry_entry(&state, 1, Chain::Midnight, SOLIDITY_TS - 40_000).await;

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (height, _, result) = until_tx_confirmed(&mut run, &id).await;
        assert_eq!(height, 32);
        assert!(matches!(result, ExecutionOutcome::Unviable));

        failures.assert_async().await;
        run.stop().await;
    }

    /// The pass order is load-bearing: polls drain before the scan, so
    /// a receipt the walk cannot see still resolves first.
    #[tokio::test]
    async fn polls_drain_before_the_expiry_scan() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        let (id, _, tx) =
            expiry_tx_assembled_at(1_728_000_050_000, 9, Chain::Midnight, SOLIDITY_TS - 40_000);
        state.add_pending_execution(Arc::clone(&tx)).await;
        state.watch_execution(Chain::Tron, Arc::clone(&tx)).await;
        receipt_for(&mut server, &id, success_receipt(&id));
        solid_block_ladder(&mut server, &[(1, id.0)]);

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let tick = until_blocks(&mut run, 1).await;
        let receipt_at = tick.iter().position(|event| {
            matches!(
                event,
                ChainEvent::ExecutionConfirmed {
                    tx_id,
                    result: ExecutionOutcome::Success { .. },
                    ..
                } if *tx_id == id
            )
        });
        let scan_at = tick.iter().position(|event| {
            matches!(
                event,
                ChainEvent::ExecutionConfirmed {
                    tx_id,
                    result: ExecutionOutcome::Unviable,
                    ..
                } if *tx_id == id
            )
        });
        assert!(
            receipt_at.is_some(),
            "the receipt must resolve in the same tick: {tick:?}"
        );
        assert!(
            scan_at.is_some(),
            "the closed window still attests: {tick:?}"
        );
        assert!(
            receipt_at < scan_at,
            "polls must drain before the scan: {tick:?}"
        );

        run.stop().await;
    }

    /// TaPoS bounds the walk below: an inclusion between the reference
    /// block and a lying assembly time still vetoes Unviable.
    #[tokio::test]
    async fn inclusion_below_a_lying_timestamp_still_wins() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        let (id, _, tx) =
            expiry_tx_assembled_at(1_728_000_050_000, 9, Chain::Midnight, SOLIDITY_TS - 40_000);
        state.add_pending_execution(Arc::clone(&tx)).await;
        receipt_for(&mut server, &id, success_receipt(&id));
        solid_block_ladder(&mut server, &[(10, id.0)]);

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (height, _, result) = until_tx_confirmed(&mut run, &id).await;
        assert_eq!(height, 71896097);
        assert!(matches!(result, ExecutionOutcome::Success { .. }));

        run.stop().await;
    }

    /// A span block answering `{}` must defer — reading it as empty
    /// would attest over a block the walk never saw. The absent stub
    /// for block 10 precedes the ladder's, so mockito serves it first.
    #[tokio::test]
    async fn absent_span_block_defers_instead_of_reading_empty() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        let (id, _, _) =
            pending_expiry_entry(&state, 1, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        server
            .mock("POST", "/walletsolidity/getblockbynum")
            .match_body(Matcher::PartialJson(serde_json::json!({ "num": 10 })))
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();
        solid_block_ladder(&mut server, &[(10, id.0)]);

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let events = until_blocks(&mut run, 2).await;
        assert!(
            events
                .iter()
                .all(|event| matches!(event, ChainEvent::Block(_))),
            "an absent span block must defer, not attest: {events:?}"
        );

        run.stop().await;
    }

    /// Memoization spans passes: a block one pass fetched is never
    /// re-fetched by the next.
    #[tokio::test]
    async fn walk_progress_survives_across_passes() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        let boundary_once = server
            .mock("POST", "/walletsolidity/getblockbynum")
            .match_body(Matcher::PartialJson(serde_json::json!({ "num": 32 })))
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{ "blockID": "{:0>64}",
                     "block_header": {{ "raw_data": {{ "number": 32, "timestamp": {} }} }},
                     "transactions": [] }}"#,
                format!("{:x}", 32),
                ladder_ts(32)
            ))
            .expect(2)
            .create();
        // The header and membership fetches each read block 32 once
        // in the first pass; the second pass must hit only the cache.
        solid_block_ladder(&mut server, &[]);
        pending_expiry_entry(&state, 1, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        let watcher = TronWatcher::new(config, state, NoopChainTelemetry).unwrap();

        for pass in 0..2 {
            let events: Vec<ChainEvent> = watcher.expiry_scan().await.collect().await;
            let [event] = events.as_slice() else {
                panic!("pass {pass} must attest once: {events:?}")
            };
            assert!(
                matches!(
                    event,
                    ChainEvent::ExecutionConfirmed {
                        block_height: 32,
                        result: ExecutionOutcome::Unviable,
                        ..
                    }
                ),
                "pass {pass}: {event:?}"
            );
        }
        boundary_once.assert_async().await;
    }
}
