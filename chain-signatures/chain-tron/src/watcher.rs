//! Watches Tron-targeted transactions by polling solidified receipts by
//! txID, and resolves M6 expiry over the `Executing` backlog.
//! Target-only, so [`ChainIndexer`](mpc_chain_integration_core::ChainIndexer)
//! is the supervision vehicle alone: no block scanning, no catchup — restart
//! rebuilds the map from the backlog.

use std::sync::Arc;

use alloy::primitives::B256;
use anyhow::Context;
use futures_util::stream::{empty, iter, once, Stream, StreamExt};
use mpc_chain_integration_core::{
    unexecutable_outcome, ChainIndexer, ChainTelemetry, ExtractionFailureKind, StateManager,
};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome, SignId,
};
use mpc_tron_wire::pb::RawTransaction;
use mpc_tron_wire::NowBlock;
use std::future::ready;
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

/// Solidified head strictly past `expiration`: java-tron rejects packaging
/// at `expiration <= headBlockTime`, validated against the *parent* head
/// (`Manager.validateCommon`, java-tron b33eed89a6a4) — strict, because a
/// block one 3 s slot past the expiration can still carry the transaction.
fn is_window_closed(head: &NowBlock, tx: &BidirectionalTx) -> bool {
    RawTransaction::parse(&tx.serialized_transaction)
        .map(|raw| {
            u64::try_from(raw.expiration).is_ok_and(|expiration| head.timestamp > expiration)
        })
        .unwrap_or_else(|err| {
            tracing::warn!(
                sign_id = ?tx.sign_id(),
                ?tx.id,
                ?err,
                "cannot parse serialized_transaction; admission validated these bytes"
            );
            false
        })
}

/// The M6 attestation for one expired, unexecuted entry: the unexecutable
/// outcome at the solidified head's height.
fn expired_event(sign_id: SignId, tx: &BidirectionalTx, head: &NowBlock) -> ChainEvent {
    ChainEvent::ExecutionConfirmed {
        tx_id: tx.id,
        sign_id,
        source_chain: tx.source_chain,
        block_height: head.number,
        result: unexecutable_outcome(tx.source_chain),
    }
}

impl<S: StateManager, T: ChainTelemetry> TronWatcher<S, T> {
    /// Bounds in-flight receipt requests to the provider; Ethereum's
    /// default.
    const MAX_CONCURRENT_RECEIPT_POLLS: usize = 8;

    pub fn new(config: TronConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        Ok(Self {
            client: Arc::new(TronHttp::new(&config)?),
            config,
            state_manager,
            telemetry,
        })
    }

    /// Yields per resolved receipt, in resolution order; pending, failed
    /// fetch, and unclassifiable receipts yield nothing and retry next
    /// tick. Resolution order is load-bearing: immediate sends keep a
    /// pass that outlasts the stall timeout from losing confirmations.
    async fn poll_watchers(&self) -> impl futures_util::Stream<Item = ChainEvent> + Unpin + '_ {
        let watchers = self.state_manager.get_execution_watchers(Chain::Tron).await;
        tracing::debug!(watchers = watchers.len(), "polling tron execution watchers");

        iter(watchers)
            .map(|(tx_id, (sign_id, tx))| self.resolve_watcher_from_receipt(tx_id, sign_id, tx))
            .buffer_unordered(Self::MAX_CONCURRENT_RECEIPT_POLLS)
            .filter_map(std::future::ready)
    }

    /// `None` — pending;
    /// Failed fetch or unclassifiable — retries next tick.
    async fn resolve_watcher_from_receipt(
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
            .execution_outcome(&tx.output_deserialization_schema)
            .inspect_err(|err| {
                tracing::warn!(?tx_id, ?sign_id, "{err:#}");
                self.telemetry
                    .bidirectional_extraction_failed(ExtractionFailureKind::Retryable);
            })
            .ok()?;

        // The park arm reports terminal telemetry.
        if matches!(result, ExecutionOutcome::ExtractionFailed) {
            self.telemetry
                .bidirectional_extraction_failed(ExtractionFailureKind::Terminal);
            tracing::error!(
                ?tx_id,
                ?sign_id,
                "schema-carrying request, but Tron output extraction is undefined; parking"
            );
        }

        Some(ChainEvent::ExecutionConfirmed {
            tx_id,
            sign_id,
            source_chain: tx.source_chain,
            block_height: receipt.block_number,
            result,
        })
    }

    /// M6 resolutions for `Executing` entries whose validity window
    /// closed. Backlog-keyed: an entry whose watch a duplicate flat id
    /// displaced has no other resolution path. Failures defer to the
    /// next tick.
    fn expired_resolutions(&self) -> impl Stream<Item = ChainEvent> + Unpin + '_ {
        once(async move {
            let pending = self.state_manager.get_pending_executions(Chain::Tron).await;
            if pending.is_empty() {
                return empty().boxed();
            }
            let head = match self.client.get_now_block_solidity().await {
                Ok(head) => head,
                Err(err) => {
                    tracing::warn!(?err, "solidity head fetch failed; expiry scan deferred");
                    return empty().boxed();
                }
            };
            iter(pending)
                .filter(move |(_, tx)| ready(is_window_closed(&head, tx)))
                .then(move |(sign_id, tx)| async move {
                    match self
                        .client
                        .get_transaction_info_solidity(&B256::from(tx.id.0))
                        .await
                    {
                        Ok(Some(_)) => {
                            tracing::debug!(?sign_id, ?tx.id,
                                "expired window but executed; M6 premise fails, receipt-keyed resolution deferred");
                            None
                        }
                        Ok(None) => {
                            tracing::info!(?sign_id, ?tx.id, source = ?tx.source_chain,
                                height = head.number,
                                "validity window closed without inclusion; attesting unexecutable");
                            Some(expired_event(sign_id, &tx, &head))
                        }
                        Err(err) => {
                            tracing::warn!(?sign_id, ?tx.id, ?err, "expiry receipt lookup failed");
                            None
                        }
                    }
                })
                .filter_map(ready)
                .boxed()
        })
        .flatten()
        .boxed()
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
            // Block last: it certifies the tick. Per-resolution sends mean
            // a pass outlasting the stall timeout restarts with the map
            // already shrunk.
            let mut pass = self.poll_watchers().await.chain(self.expired_resolutions());

            loop {
                let event = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    event = pass.next() => match event {
                        Some(event) => event,
                        None => break,
                    },
                };
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
        BidirectionalTx, BidirectionalTxId, ExecutionOutcome, RequestKind, SignId, TronTxParams,
    };
    use mpc_tron_wire::{to_unsigned_tron_tx, TronAddress};
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

    /// Watcher entry keyed by the seed (txID's first byte); the request id
    /// mirrors it, as `to_bidirectional_tx` builds it.
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

    /// The same entry carrying a non-empty output schema — admission
    /// refuses these today; the watcher must still handle it.
    fn schema_carrying_tx(seed: u8) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
        let (tx_id, sign_id, tx) = watcher_tx(seed);
        let mut with_schema = (*tx).clone();
        with_schema.output_deserialization_schema =
            br#"[{"name":"output","type":"bool"}]"#.to_vec();
        (tx_id, sign_id, with_schema.into())
    }

    /// Counts `bidirectional_extraction_failed`, as the Ethereum watcher
    /// tests do.
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

    /// Proto3 omits the zero `SUCESS`, so success prints only the nested
    /// verdict.
    fn success_body(seed: u8) -> String {
        receipt_body(seed, "", "SUCCESS")
    }

    /// Failure prints `FAILED` above the specific member.
    fn failure_body(seed: u8, member: &str) -> String {
        receipt_body(seed, r#", "result": "FAILED""#, member)
    }

    /// Synthetic: a real failure always carries the top-level `FAILED`,
    /// which would classify; the unknown member must stand alone.
    fn unclassifiable_body(seed: u8) -> String {
        receipt_body(seed, "", "WEIRD")
    }

    fn receipt_body(seed: u8, top_level: &str, nested: &str) -> String {
        let tx_id = watcher_tx(seed).0;
        format!(
            r#"{{ "id": "{}", "blockNumber": 71896097, "fee": 472800{top_level}, "receipt": {{ "result": "{nested}" }} }}"#,
            hex::encode(tx_id.0)
        )
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
        receipt_stub(&mut server, 1, failure_body(1, "REVERT"))
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
        receipt_stub(&mut server, 1, success_body(1)).create();

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

    /// A successful receipt can't yield a schema-carrying request's
    /// output: park rather than attest an empty one.
    #[tokio::test]
    async fn schema_carrying_success_parks() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        receipt_stub(&mut server, 1, success_body(1))
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
        assert!(telemetry.terminal_failures() >= 1);
        assert_eq!(telemetry.retryable_failures(), 0);

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
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
        state
            .watch_execution(Chain::Tron, watcher_tx(1).1, watcher_tx(1).2)
            .await;
        state
            .watch_execution(Chain::Tron, watcher_tx(2).1, watcher_tx(2).2)
            .await;

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
        receipt_stub(&mut server, 2, success_body(2)).create();

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

    /// Solidified-head timestamp the expiry tests pin against; its block
    /// number (41) sits behind the live head's 42, so an attestation at 41
    /// proves the scan reads solidified state.
    const SOLIDITY_TS: u64 = 1_728_000_100_000;

    fn solidity_nowblock_mock(server: &mut mockito::ServerGuard) {
        server
            .mock("POST", "/walletsolidity/getnowblock")
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{ "blockID": "{}",
                     "block_header": {{ "raw_data": {{ "number": 41, "timestamp": {} }} }} }}"#,
                hex::encode([0x9u8; 32]),
                SOLIDITY_TS
            ))
            .create();
    }

    fn receipt_for(server: &mut mockito::ServerGuard, id: &BidirectionalTxId, body: String) {
        server
            .mock("POST", "/walletsolidity/gettransactioninfobyid")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "value": hex::encode(id.0)
            })))
            .with_header("content-type", "application/json")
            .with_body(body)
            .create();
    }

    /// An entry whose serialized bytes carry `expiration`; the id is
    /// those bytes' txID, as admission derives it.
    fn expiry_tx(
        seed: u8,
        source: Chain,
        expiration: u64,
    ) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
        let params = TronTxParams {
            ref_block_bytes: [0x27, 0x10],
            ref_block_hash: [0x42; 8],
            timestamp: 1_728_000_000_000 + seed as u64,
            expiration,
            contract_address: {
                let mut address = [0xcd; 21];
                address[0] = 0x41;
                address
            },
            ..TronTxParams::default()
        };
        let owner = TronAddress::from_evm(alloy::primitives::Address::from_slice(&[0xab; 20]));
        let raw = to_unsigned_tron_tx(&params, owner).unwrap();
        let (_, sign_id, base) = watcher_tx(seed);
        let mut tx = (*base).clone();
        tx.id = BidirectionalTxId(RawTransaction::parse(&raw).unwrap().txid());
        tx.serialized_transaction = raw;
        tx.source_chain = source;
        (tx.id, sign_id, Arc::new(tx))
    }

    /// Registers an `expiry_tx` as an `Executing` backlog entry.
    async fn pending_expiry_entry(
        state: &MockStateManager,
        seed: u8,
        source: Chain,
        expiration: u64,
    ) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
        let entry = expiry_tx(seed, source, expiration);
        state.add_pending_execution(Arc::clone(&entry.2)).await;
        entry
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
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        solidity_nowblock_mock(&mut server);
        let state = MockStateManager::new();
        let (id, _, _) =
            pending_expiry_entry(&state, 1, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        receipt_for(&mut server, &id, "{}".to_string());

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (height, source, result) = until_tx_confirmed(&mut run, &id).await;
        assert_eq!(height, 41);
        assert_eq!(source, Chain::Midnight);
        assert!(matches!(result, ExecutionOutcome::Unviable));

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
    }

    /// A watched entry expires too: the receipt poll finds nothing, and the
    /// scan answers at the solidified head.
    #[tokio::test]
    async fn expired_watched_entry_resolves_through_the_scan() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        solidity_nowblock_mock(&mut server);
        let state = MockStateManager::new();
        let (id, sign_id, tx) =
            pending_expiry_entry(&state, 3, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        state.watch_execution(Chain::Tron, sign_id, tx).await;
        receipt_for(&mut server, &id, "{}".to_string());

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let (height, _, result) = until_tx_confirmed(&mut run, &id).await;
        assert_eq!(height, 41);
        assert!(matches!(result, ExecutionOutcome::Unviable));

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
    }

    /// M6's premise fails — the id has a solidified receipt (a displaced
    /// duplicate of an executed transaction) — so the expiry arm attests
    /// nothing; receipt-keyed resolution is deferred with output schemas.
    #[tokio::test]
    async fn expired_but_executed_is_left_for_receipt_keyed_resolution() {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        solidity_nowblock_mock(&mut server);
        let state = MockStateManager::new();
        let (id, _, _) =
            pending_expiry_entry(&state, 4, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        receipt_for(
            &mut server,
            &id,
            format!(
                r#"{{ "id": "{}", "blockNumber": 71896097, "fee": 472800, "receipt": {{ "result": "SUCCESS" }} }}"#,
                hex::encode(id.0)
            ),
        );

        let mut run = spawn_watcher(config, state, NoopChainTelemetry);
        first_is_catchup_completed(&mut run).await;
        let seen = until_blocks(&mut run, 3).await;
        assert!(
            !seen.iter().any(|event| matches!(
                event,
                ChainEvent::ExecutionConfirmed { tx_id, .. } if *tx_id == id
            )),
            "expiry arm must not attest an included transaction"
        );

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
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

        run.cancel.cancel();
        run.done.await.unwrap().unwrap();
    }

    #[test]
    fn window_closes_strictly_past_the_expiration() {
        let head = |timestamp| NowBlock {
            block_id: B256::from([0x9u8; 32]),
            number: 41,
            timestamp,
        };
        let tx = |expiration| expiry_tx(1, Chain::Midnight, expiration).2;
        assert!(!is_window_closed(&head(1_000), &tx(1_000)));
        assert!(is_window_closed(&head(1_001), &tx(1_000)));
        let mut unparsable = (*tx(1_000)).clone();
        unparsable.serialized_transaction = vec![0xff];
        assert!(!is_window_closed(&head(2_000), &unparsable));
    }

    #[test]
    fn expired_event_attests_by_source_policy() {
        let head = NowBlock {
            block_id: B256::from([0x9u8; 32]),
            number: 41,
            timestamp: 1_000,
        };
        let midnight = expiry_tx(1, Chain::Midnight, 900).2;
        let canton = expiry_tx(2, Chain::Canton, 900).2;
        let assert_event = |tx: &BidirectionalTx, unviable: bool| {
            let ChainEvent::ExecutionConfirmed {
                tx_id,
                sign_id,
                source_chain,
                block_height,
                result,
            } = expired_event(tx.sign_id(), tx, &head)
            else {
                panic!("expected an ExecutionConfirmed")
            };
            assert_eq!(tx_id, tx.id);
            assert_eq!(sign_id, tx.sign_id());
            assert_eq!(source_chain, tx.source_chain);
            assert_eq!(block_height, 41);
            assert_eq!(
                matches!(result, ExecutionOutcome::Unviable),
                unviable,
                "midnight attests unviable, legacy sources refund failed"
            );
        };
        assert_event(&midnight, true);
        assert_event(&canton, false);
    }
}
