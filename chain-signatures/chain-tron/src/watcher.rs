//! Watches Tron-targeted transactions by polling solidified receipts by
//! txID, and resolves M6 expiry over the `Executing` backlog.
//! Target-only, so [`ChainIndexer`](mpc_chain_integration_core::ChainIndexer)
//! is the supervision vehicle alone: no block scanning, no catchup — restart
//! rebuilds the map from the backlog.
use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::B256;
use anyhow::Context;
use futures_util::stream::{iter, StreamExt};
use mpc_chain_integration_core::{
    unexecutable_outcome, ChainIndexer, ChainTelemetry, ExtractionFailureKind, StateManager,
};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome, SignId,
};
use mpc_tron_wire::pb::RawTransaction;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::client::TronHttp;
use crate::config::TronConfig;
use crate::types::SolidifiedBlock;

pub struct TronWatcher<S: StateManager, T: ChainTelemetry> {
    client: TronHttp,
    config: TronConfig,
    state_manager: S,
    telemetry: T,
}

struct TxWindow {
    timestamp: i64,
    expiration: i64,
}

/// One flat id's entries; the txID is the hash of their (identical)
/// bytes, so they share a window and one verdict settles them.
type Group = Vec<(SignId, Arc<BidirectionalTx>, TxWindow)>;

fn tx_window(tx: &BidirectionalTx) -> Option<TxWindow> {
    RawTransaction::parse(&tx.serialized_transaction)
        .map(|raw| TxWindow {
            timestamp: raw.timestamp,
            expiration: raw.expiration,
        })
        .map_err(|err| {
            tracing::warn!(
                sign_id = ?tx.sign_id(),
                ?tx.id,
                ?err,
                "cannot parse serialized_transaction; admission validated these bytes"
            );
        })
        .ok()
}

/// The M6 attestation for one expired, unexecuted entry.
fn expired_event(sign_id: SignId, tx: &BidirectionalTx, boundary: u64) -> ChainEvent {
    ChainEvent::ExecutionConfirmed {
        tx_id: tx.id,
        sign_id,
        source_chain: tx.source_chain,
        block_height: boundary,
        result: unexecutable_outcome(tx.source_chain),
    }
}

fn closed_groups(
    pending: Vec<(SignId, Arc<BidirectionalTx>)>,
    head: &SolidifiedBlock,
) -> Vec<Group> {
    let mut groups: HashMap<BidirectionalTxId, Vec<_>> = HashMap::new();
    for (sign_id, tx) in pending {
        if let Some(window) = tx_window(&tx).filter(|w| head.timestamp >= w.expiration) {
            groups.entry(tx.id).or_default().push((sign_id, tx, window));
        }
    }
    groups.into_values().collect()
}

/// One walk's answer for a flat id's bytes.
#[derive(Debug)]
enum ExpiryVerdict {
    Included,
    Absent { boundary: u64 },
}

/// Bounds the linear absence walk at one 24 h window of 3 s slots.
/// tron-wire caps windows at admission (`MAX_WINDOW_MS`), so a breach
/// means a pre-cap backlog entry or a lying provider.
const MAX_WALK_SPAN: u64 = 28_800;

/// Solidified blocks by number, memoized for the scan pass — final
/// blocks never change, so re-fetches are pure cost and a racing
/// double fetch is benign.
#[derive(Clone)]
struct SolidityView<'a> {
    client: &'a TronHttp,
    head: u64,
    span_cap: u64,
    blocks: Arc<Mutex<HashMap<u64, Option<Arc<SolidifiedBlock>>>>>,
}

impl<'a> SolidityView<'a> {
    fn new(client: &'a TronHttp, head: u64) -> Self {
        Self {
            client,
            head,
            span_cap: MAX_WALK_SPAN,
            blocks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn block(&self, number: u64) -> anyhow::Result<Option<Arc<SolidifiedBlock>>> {
        if let Some(hit) = self.blocks.lock().await.get(&number) {
            return Ok(hit.clone());
        }
        let fetched = self.client.get_block_solidity(number).await?.map(Arc::new);
        self.blocks.lock().await.insert(number, fetched.clone());
        Ok(fetched)
    }

    /// A search mid's timestamp; absent below the head is pruned
    /// history or a lagging instance — deferring, not reading it as
    /// ancient, keeps the boundary one every node shares.
    async fn require_timestamp(&self, number: u64) -> anyhow::Result<i64> {
        self.block(number)
            .await?
            .map(|block| block.timestamp)
            .with_context(|| {
                format!(
                    "solidified block {number} below the scan head {} is absent: \
                     pruned history or a lagging instance",
                    self.head
                )
            })
    }

    /// The first block number at or past `ts`, deferring when nothing
    /// that new is solidified. Timestamps strictly increase with
    /// height, so a lower-bound binary search.
    async fn first_at_or_after(&self, ts: i64) -> anyhow::Result<u64> {
        let (mut lo, mut hi) = (0, self.head);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.require_timestamp(mid).await? >= ts {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        // The converged probe may be the head itself; absent there only
        // means nothing that new is solidified yet.
        self.block(lo)
            .await?
            .filter(|block| block.timestamp >= ts)
            .with_context(|| format!("nothing solidified at or past {ts}"))
            .map(|_| lo)
    }

    /// Inclusion over the packable span — blocks before the tx's
    /// timestamp cannot hold it (it did not exist yet) and blocks
    /// past the window's end cannot pack it — the whole M6 proof.
    async fn verdict(
        &self,
        tx: &BidirectionalTx,
        window: &TxWindow,
    ) -> anyhow::Result<ExpiryVerdict> {
        let start = self.first_at_or_after(window.timestamp).await?;
        let boundary = self.first_at_or_after(window.expiration).await?;
        anyhow::ensure!(
            boundary - start <= self.span_cap,
            "packable span {start}..={boundary} exceeds the {}-block walk cap",
            self.span_cap
        );
        for number in start..=boundary {
            if self
                .block(number)
                .await?
                .is_some_and(|block| block.txids.contains(&tx.id.0))
            {
                return Ok(ExpiryVerdict::Included);
            }
        }
        Ok(ExpiryVerdict::Absent { boundary })
    }
}

impl<S: StateManager, T: ChainTelemetry> TronWatcher<S, T> {
    /// Bounds in-flight provider requests across both arms; Ethereum's
    /// receipt-poll default.
    const MAX_CONCURRENT_PROVIDER_REQUESTS: usize = 8;

    pub fn new(config: TronConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        Ok(Self {
            client: TronHttp::new(&config)?,
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
    async fn poll_watchers(&self) -> impl futures_util::Stream<Item = ChainEvent> + Unpin + '_ {
        let watchers = self.state_manager.get_execution_watchers(Chain::Tron).await;
        tracing::debug!(watchers = watchers.len(), "polling tron execution watchers");

        iter(watchers)
            .map(|(tx_id, (sign_id, tx))| self.resolve_watcher_from_receipt(tx_id, sign_id, tx))
            .buffer_unordered(Self::MAX_CONCURRENT_PROVIDER_REQUESTS)
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

    /// M6 attestations per flat id, each at the boundary every node
    /// derives identically. A pass outlasting the stall budget loses
    /// only the unsent tail.
    async fn expiry_scan(&self) -> futures_util::stream::BoxStream<'_, ChainEvent> {
        let Some((head, groups)) = self.closed_window_groups().await else {
            return futures_util::stream::empty().boxed();
        };
        let view = SolidityView::new(&self.client, head.number);
        iter(groups)
            .map(move |group| self.resolve_group(group, view.clone()))
            .buffer_unordered(Self::MAX_CONCURRENT_PROVIDER_REQUESTS)
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
        match view.verdict(tx, window).await {
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
        BidirectionalTx, BidirectionalTxId, Calldata, CompactMaybe, ExecutionOutcome, RequestKind,
        SignId, TronTxParams,
    };
    use mpc_tron_wire::pb::RawTransaction;
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

    /// The expiry tests' shared fixture: a server answering both heads
    /// plus a fresh state.
    async fn expiry_stack() -> (mockito::ServerGuard, TronConfig, MockStateManager) {
        let server = mockito::Server::new_async().await;
        let config = test_config(server.url().parse().unwrap());
        let mut server = server;
        nowblock_mock(&mut server);
        (server, config, MockStateManager::new())
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
        // Transport failures only warn, as on Ethereum.
        assert_eq!(telemetry.retryable_failures(), 0);
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

    /// Solidified-head timestamp the expiry tests pin against; its block
    /// number (41) sits behind the live head's 42, so an attestation at 41
    /// proves the scan reads solidified state.
    const SOLIDITY_TS: u64 = 1_728_000_100_000;
    /// The fixtures' assembly anchor: 2024-10-03T00:00:00Z, 100 s
    /// before [`SOLIDITY_TS`].
    const ASSEMBLED_AT: u64 = 1_728_000_000_000;

    fn solidity_nowblock_mock(server: &mut mockito::ServerGuard) {
        solidity_head_at(server, 41);
    }

    /// The tests' solidified chain: `ts(n) = SOLIDITY_TS − (45 − n)·3 s`,
    /// empty blocks. Resident txids stub their number ahead of the
    /// ladder — mockito answers the first matching stub.
    const LADDER_TOP: u64 = 45;

    fn ladder_ts(number: u64) -> i64 {
        SOLIDITY_TS as i64 - (LADDER_TOP - number) as i64 * 3_000
    }

    fn solid_block_mock(server: &mut mockito::ServerGuard, number: u64, txids: &[[u8; 32]]) {
        let transactions: Vec<String> = txids
            .iter()
            .map(|id| format!(r#"{{ "txID": "{}" }}"#, hex::encode(id)))
            .collect();
        server
            .mock("POST", "/walletsolidity/getblockbynum")
            .match_body(Matcher::PartialJson(serde_json::json!({ "num": number })))
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{ "blockID": "{}",
                 "block_header": {{ "raw_data": {{ "number": {number}, "timestamp": {} }} }},
                 "transactions": [{}] }}"#,
                hex::encode([number as u8; 32]),
                ladder_ts(number),
                transactions.join(",")
            ))
            .create();
    }

    fn solid_block_ladder(server: &mut mockito::ServerGuard, resident: &[(u64, [u8; 32])]) {
        for number in 0..=LADDER_TOP {
            let txids: Vec<_> = resident
                .iter()
                .filter(|(at, _)| *at == number)
                .map(|(_, id)| *id)
                .collect();
            solid_block_mock(server, number, &txids);
        }
    }

    /// Every `getblockbynum` reads absent.
    fn solid_block_absent(server: &mut mockito::ServerGuard) {
        server
            .mock("POST", "/walletsolidity/getblockbynum")
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();
    }

    fn solidity_head_at(server: &mut mockito::ServerGuard, number: u64) {
        server
            .mock("POST", "/walletsolidity/getnowblock")
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{ "blockID": "{}",
                 "block_header": {{ "raw_data": {{ "number": {number}, "timestamp": {} }} }} }}"#,
                hex::encode([0x9u8; 32]),
                ladder_ts(number)
            ))
            .create();
    }

    fn success_receipt(id: &BidirectionalTxId) -> String {
        format!(
            r#"{{ "id": "{}", "blockNumber": 71896097, "fee": 472800, "receipt": {{ "result": "SUCCESS" }} }}"#,
            hex::encode(id.0)
        )
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
        expiry_tx_assembled_at(ASSEMBLED_AT + seed as u64, seed, source, expiration)
    }

    /// [`expiry_tx`] with an explicit assembly time — a lying one puts
    /// the tx's real inclusion below the walkable span.
    fn expiry_tx_assembled_at(
        timestamp: u64,
        seed: u8,
        source: Chain,
        expiration: u64,
    ) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
        let params = TronTxParams {
            ref_block_bytes: [0x27, 0x10],
            ref_block_hash: [0x42; 8],
            timestamp,
            expiration,
            contract_address: {
                let mut address = [0xcd; 21];
                address[0] = 0x41;
                address
            },
            fee_limit: 0,
            call_value: 0,
            calldata: CompactMaybe {
                is_some: false,
                value: Calldata {
                    selector: [0; 4],
                    no_words: 0,
                    words: Vec::new(),
                },
            },
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

    /// A pending entry that also carries a watch.
    async fn watched_expiry_entry(
        state: &MockStateManager,
        seed: u8,
        source: Chain,
        expiration: u64,
    ) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
        let entry = pending_expiry_entry(state, seed, source, expiration).await;
        state
            .watch_execution(Chain::Tron, Arc::clone(&entry.2))
            .await;
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

        state.remove_pending_execution(sign_id).await;
        state.remove_execution_watch(Chain::Tron, &id).await;
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
    /// one receipt.
    #[tokio::test]
    async fn duplicate_flat_id_entries_both_resolve_through_the_receipt_arm() {
        let (mut server, config, state) = expiry_stack().await;
        solidity_nowblock_mock(&mut server);
        let (id, displacing, tx) =
            pending_expiry_entry(&state, 5, Chain::Midnight, SOLIDITY_TS - 40_000).await;
        // The twins' bytes live in a walked block: whichever twin the
        // receipt arm retires first, the scan re-registers the other.
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
                    block_height,
                    result,
                    ..
                } = event
                {
                    if tx_id == id {
                        confirmed_state.remove_pending_execution(sign_id).await;
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
        solid_block_ladder(&mut server, &[(3, id.0)]);

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

    /// A span past the cap defers; below it, the same walk resolves the
    /// boundary.
    #[tokio::test]
    async fn verdict_refuses_spans_past_the_cap() {
        let (mut server, config, _) = expiry_stack().await;
        solid_block_ladder(&mut server, &[]);
        let client = TronHttp::new(&config).unwrap();
        let (_, _, tx) = expiry_tx(1, Chain::Midnight, SOLIDITY_TS - 40_000);
        let window = tx_window(&tx).unwrap();

        let mut view = SolidityView::new(&client, LADDER_TOP);
        view.span_cap = 8;
        let err = format!("{:#}", view.verdict(&tx, &window).await.unwrap_err());
        assert!(err.contains("walk cap"), "{err}");

        view.span_cap = 32;
        match view.verdict(&tx, &window).await.unwrap() {
            ExpiryVerdict::Absent { boundary } => assert_eq!(boundary, 32),
            other => panic!("absence expected, got {other:?}"),
        }
    }

    /// Eligibility over a live window; assembly refuses dead ones.
    #[test]
    fn the_scan_eligibility_ends_at_or_past_the_expiration() {
        const EXPIRATION: i64 = 1_728_000_060_000;
        let head = |timestamp| SolidifiedBlock {
            number: 41,
            timestamp,
            txids: Vec::new(),
        };
        let tx = || expiry_tx(1, Chain::Midnight, EXPIRATION as u64).2;
        let eligible = |head_ts: i64| {
            let pending = vec![(SignId::new([1; 32]), tx())];
            let groups = closed_groups(pending, &head(head_ts));
            groups.len() == 1 && groups[0].len() == 1
        };
        assert!(!eligible(EXPIRATION - 1));
        assert!(eligible(EXPIRATION), "the end block is past the window");
        assert!(eligible(i64::MAX));
        let mut unparsable = (*tx()).clone();
        unparsable.serialized_transaction = vec![0xff];
        let groups = closed_groups(
            vec![(SignId::new([1; 32]), unparsable.into())],
            &head(i64::MAX),
        );
        assert!(groups.is_empty(), "unparsable bytes never scan");
    }

    #[test]
    fn expired_event_attests_by_source_policy() {
        const EXPIRATION: u64 = 1_728_000_060_000;
        let midnight = expiry_tx(1, Chain::Midnight, EXPIRATION).2;
        let canton = expiry_tx(2, Chain::Canton, EXPIRATION).2;
        let assert_event = |tx: &BidirectionalTx, unviable: bool| {
            let ChainEvent::ExecutionConfirmed {
                tx_id,
                sign_id,
                source_chain,
                block_height,
                result,
            } = expired_event(tx.sign_id(), tx, 41)
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
