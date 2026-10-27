//! Execution watcher for Tron targets: polls solidified receipts by txID.
//! Tron is a target-only chain, so [`ChainIndexer`](mpc_chain_integration_core::ChainIndexer)
//! is implemented purely as the supervision vehicle — no block scanning,
//! no catchup; the watcher map is rebuilt from backlog checkpoints on
//! restart.

use std::sync::Arc;

use alloy::primitives::B256;
use anyhow::Context;
use futures_util::stream::{iter, StreamExt};
use mpc_chain_integration_core::{
    ChainIndexer, ChainTelemetry, ExtractionFailureKind, StateManager,
};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome, SignId,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::client::TronHttp;
use crate::config::TronConfig;

pub struct TronWatcher<S: StateManager, T: ChainTelemetry> {
    client: Arc<TronHttp>,
    config: TronConfig,
    state_manager: S,
    telemetry: T,
}

impl<S: StateManager, T: ChainTelemetry> TronWatcher<S, T> {
    /// Bounded so a slow provider delays the tick, not the watchdog;
    /// mirrors the Ethereum watcher's default.
    const MAX_CONCURRENT_RECEIPT_POLLS: usize = 8;

    pub fn new(config: TronConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        Ok(Self {
            client: Arc::new(TronHttp::new(&config)?),
            config,
            state_manager,
            telemetry,
        })
    }

    /// One poll tick: resolve each pending watcher's solidified receipt
    /// into an event. Unresolved watchers — pending, fetch failure,
    /// unclassifiable result — produce nothing and retry on the next tick.
    async fn poll_watchers(&self) -> Vec<ChainEvent> {
        let watchers = self.state_manager.get_execution_watchers(Chain::Tron).await;
        if watchers.is_empty() {
            return Vec::new();
        }
        tracing::debug!(watchers = watchers.len(), "polling tron execution watchers");

        iter(watchers)
            .map(|(tx_id, (sign_id, tx))| self.resolve(tx_id, sign_id, tx))
            .buffer_unordered(Self::MAX_CONCURRENT_RECEIPT_POLLS)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect()
    }

    /// Resolve one watcher from its solidified receipt: `None` = pending,
    /// fetch failure, or unclassifiable result — all retried on the next tick.
    async fn resolve(
        &self,
        tx_id: BidirectionalTxId,
        sign_id: SignId,
        tx: Arc<BidirectionalTx>,
    ) -> Option<ChainEvent> {
        let receipt = self
            .client
            .get_transaction_info_solidity(&B256::from(tx_id.0))
            .await
            .inspect_err(|err| tracing::warn!(?tx_id, ?sign_id, ?err, "receipt poll failed"))
            .ok()??;

        let result = receipt
            .execution_outcome()
            .inspect_err(|err| {
                tracing::warn!(?tx_id, ?sign_id, "{err:#}");
                self.telemetry
                    .bidirectional_extraction_failed(ExtractionFailureKind::Retryable);
            })
            .ok()?;

        let result = match result {
            ExecutionOutcome::Failed => ExecutionOutcome::Failed,
            ExecutionOutcome::Success { .. } if tx.output_deserialization_schema.is_empty() => {
                result
            }
            // Any other case with a non-empty schema is considered terminal: we cannot extract the output.
            _ => {
                self.telemetry
                    .bidirectional_extraction_failed(ExtractionFailureKind::Terminal);
                tracing::error!(
                    ?tx_id,
                    ?sign_id,
                    "schema-carrying request, but Tron output extraction is undefined; parking"
                );
                ExecutionOutcome::ExtractionFailed
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
        // No catchup: receipts are direct txID lookups and the supervisor's
        // recovery rebuilds the watcher map. Without this event the respond
        // leg stays gated on `caught_up`.
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
            // Polls first, Block last: a Block event certifies a completed tick.
            for event in self.poll_watchers().await {
                if events_tx.send(event).await.is_err() {
                    return Ok(());
                }
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
    use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
    use mpc_primitives::{
        BidirectionalTx, BidirectionalTxId, ExecutionOutcome, RequestKind, SignId,
    };
    use url::Url;

    use super::*;

    const RETRY: RetryConfig = RetryConfig {
        min_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(1),
        max_times: 2,
        jitter: false,
    };

    fn test_config(endpoint: Url) -> TronConfig {
        TronConfig {
            endpoint,
            poll_interval: Duration::from_millis(10),
            request_timeout: Duration::from_secs(2),
            retry: RETRY,
            ..TronConfig::default()
        }
    }

    /// A Tron-target watcher entry whose txID is the first 32 bytes of the
    /// seed; the request id mirrors it, as `to_bidirectional_tx` builds it.
    fn watcher_tx(seed: u8) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
        let mut id = [0u8; 32];
        *id.first_mut().unwrap() = seed;
        let tx = Arc::new(BidirectionalTx {
            id: BidirectionalTxId(id),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: mpc_primitives::Chain::Midnight,
            target_chain: mpc_primitives::Chain::Tron,
            caip2_id: "tron:mainnet".to_string(),
            key_version: 0,
            deposit: 0,
            path: String::new(),
            algo: "secp256k1".to_string(),
            dest: "tron:mainnet".to_string(),
            params: String::new(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            request_id: id,
            from_address: [0u8; 20],
            nonce: 0,
        });
        (BidirectionalTxId(id), SignId::new(id), tx)
    }

    /// The same entry carrying a non-empty output schema — what admission
    /// refuses for Tron targets today; the watcher must still handle it.
    fn schema_carrying_tx(seed: u8) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
        let (tx_id, sign_id, tx) = watcher_tx(seed);
        let mut with_schema = (*tx).clone();
        with_schema.output_deserialization_schema =
            br#"[{"name":"output","type":"bool"}]"#.to_vec();
        (tx_id, sign_id, with_schema.into())
    }

    /// Counts `bidirectional_extraction_failed` calls, the way the Ethereum
    /// watcher tests assert on extraction-failure telemetry.
    #[derive(Clone, Default)]
    struct CountingTelemetry {
        retryable: Arc<AtomicUsize>,
        terminal: Arc<AtomicUsize>,
    }

    impl CountingTelemetry {
        fn retryable_failures(&self) -> usize {
            self.retryable.load(Ordering::Relaxed)
        }
        fn terminal_failures(&self) -> usize {
            self.terminal.load(Ordering::Relaxed)
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
    }

    struct WatcherRun {
        cancel: CancellationToken,
        events: mpsc::Receiver<ChainEvent>,
        done: tokio::task::JoinHandle<anyhow::Result<()>>,
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

    fn nowblock_mock(server: &mut mockito::ServerGuard) {
        server
            .mock("POST", "/wallet/getnowblock")
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{ "blockID": "{}",
                     "block_header": {{ "raw_data": {{ "number": 42, "timestamp": 1730000000000 }} }} }}"#,
                hex::encode([0xau8; 32])
            ))
            .create();
    }

    fn receipt_stub(server: &mut mockito::ServerGuard, seed: u8, body: String) -> mockito::Mock {
        let tx_id = watcher_tx(seed).0;
        server
            .mock("POST", "/walletsolidity/gettransactioninfobyid")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "value": hex::encode(tx_id.0)
            })))
            .with_header("content-type", "application/json")
            .with_body(body)
    }

    fn receipt_body(seed: u8, result_field: &str) -> String {
        let tx_id = watcher_tx(seed).0;
        match result_field {
            "contractRet" => format!(
                r#"{{ "id": "{}", "blockNumber": 71896097, "fee": 472800, "contractRet": "SUCCESS" }}"#,
                hex::encode(tx_id.0)
            ),
            other => format!(
                r#"{{ "id": "{}", "blockNumber": 71896097, "fee": 472800, "receipt": {{ "result": "{}" }} }}"#,
                hex::encode(tx_id.0),
                other
            ),
        }
    }

    /// Collects events until an `ExecutionConfirmed` for `seed` arrives
    /// (or the deadline passes), returning it with everything seen before.
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
        // One watcher per provider form: TronGrid's nested receipt and
        // java-tron's contractRet.
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, receipt_body(1, "SUCCESS"))
            .expect(1)
            .create();
        receipt_stub(&mut server, 2, receipt_body(2, "contractRet"))
            .expect(1)
            .create();

        let state = MockStateManager::new();
        state
            .watch_execution(Chain::Tron, watcher_tx(1).1, watcher_tx(1).2)
            .await;
        state
            .watch_execution(Chain::Tron, watcher_tx(2).1, watcher_tx(2).2)
            .await;

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

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn revert_receipt_resolves_failed() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, receipt_body(1, "REVERT"))
            .expect(1)
            .create();

        let state = MockStateManager::new();
        state
            .watch_execution(Chain::Tron, watcher_tx(1).1, watcher_tx(1).2)
            .await;

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (_, result) = until_confirmed(&mut run, 1).await;
        assert!(matches!(result, ExecutionOutcome::Failed));

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
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
        receipt_stub(&mut server, 1, receipt_body(1, "SUCCESS")).create();

        let state = MockStateManager::new();
        state
            .watch_execution(Chain::Tron, watcher_tx(1).1, watcher_tx(1).2)
            .await;

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (_, result) = until_confirmed(&mut run, 1).await;
        assert!(matches!(result, ExecutionOutcome::Success { output } if output.is_empty()));

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
    }

    /// Unclassifiable or result-less receipts are solidified and immutable:
    /// resolving them would attest a guess, so they must keep polling
    /// without emitting anything — and count as retryable extraction
    /// failures, once per watcher per tick.
    #[tokio::test]
    async fn unclassifiable_receipt_resolves_nothing() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, receipt_body(1, "WEIRD")).create();
        let resultless = format!(
            r#"{{ "id": "{}", "blockNumber": 1 }}"#,
            hex::encode(watcher_tx(2).0 .0)
        );
        receipt_stub(&mut server, 2, resultless).create();

        let state = MockStateManager::new();
        state
            .watch_execution(Chain::Tron, watcher_tx(1).1, watcher_tx(1).2)
            .await;
        state
            .watch_execution(Chain::Tron, watcher_tx(2).1, watcher_tx(2).2)
            .await;

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
        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
    }

    /// A schema-carrying request cannot have its output extracted from a
    /// Tron receipt, so a successful execution parks rather than attests an
    /// empty output.
    #[tokio::test]
    async fn schema_carrying_success_parks() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, receipt_body(1, "SUCCESS"))
            .expect(1)
            .create();

        let state = MockStateManager::new();
        state
            .watch_execution(
                Chain::Tron,
                schema_carrying_tx(1).1,
                schema_carrying_tx(1).2,
            )
            .await;

        let telemetry = CountingTelemetry::default();
        let mut run = spawn_watcher(config, state, telemetry.clone());
        first_is_catchup_completed(&mut run).await;
        let (_, result) = until_confirmed(&mut run, 1).await;
        assert!(matches!(result, ExecutionOutcome::ExtractionFailed));
        assert_eq!(telemetry.terminal_failures(), 1);
        assert_eq!(telemetry.retryable_failures(), 0);

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
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
        receipt_stub(&mut server, 2, receipt_body(2, "SUCCESS")).create();

        let state = MockStateManager::new();
        state
            .watch_execution(Chain::Tron, watcher_tx(1).1, watcher_tx(1).2)
            .await;
        state
            .watch_execution(Chain::Tron, watcher_tx(2).1, watcher_tx(2).2)
            .await;

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
        // Transport failures only warn, as on Ethereum.
        assert_eq!(telemetry.retryable_failures(), 0);
        assert_eq!(telemetry.terminal_failures(), 0);

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
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
}
