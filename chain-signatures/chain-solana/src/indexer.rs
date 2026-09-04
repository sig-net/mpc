use std::collections::BTreeSet;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;
use futures_util::stream::{self, StreamExt};
use futures_util::Stream;
use mpc_chain_integration_core::{
    ChainIndexer, ChainTelemetry, NoopPublisherTelemetry, StateManager,
};
use mpc_primitives::{Chain, ChainEvent};
use mpc_utils::task::retry_until_ok;
use solana_sdk::{pubkey::Pubkey, signature::Signature};
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{EncodedTransactionWithStatusMeta, UiConfirmedBlock};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::client::{SolanaCatchupBlock, CATCHUP_PAGE_SIZE};
use crate::config::SolIndexerConfig;
use crate::events::{emit_events, extract_tx_signature};
use crate::{SolConfig, SolanaClient};

/// Per-run state for the indexer poll loop.
/// Seeded once from persisted state (resume point), then advanced by drained ticks.
#[derive(Clone, Copy)]
struct PollState {
    /// Slot the next tick starts draining from
    // TODO: https://github.com/sig-net/mpc/issues/777
    next_start: u64,
    /// Highest anchor slot observed this run; `None` until the first tick.
    last_observed_slot: Option<u64>,
    /// When `last_observed_slot` last advanced.
    slot_last_advanced_at: Instant,
    /// Whether [`ChainEvent::CatchupCompleted`] has been emitted
    caught_up: bool,
}

impl PollState {
    /// Initialize from persisted state (resume point) or the current anchor slot if none exists.
    async fn resumed<S: StateManager>(state_manager: &S, seed_anchor: u64) -> Self {
        // The persisted watermark is the last fully drained slot, so the next tick starts at the next slot.
        let next_start = state_manager
            .get_processed_block(Chain::Solana)
            .await
            .map(|n| n.saturating_add(1))
            .unwrap_or(seed_anchor);

        Self {
            next_start,
            last_observed_slot: None,
            slot_last_advanced_at: Instant::now(),
            caught_up: false,
        }
    }

    /// Slot-stall watchdog: only a strictly greater anchor counts as progress
    /// Warns at half the budget, bails at the full budget so the supervisor
    /// restarts and surfaces the frozen node (dense markers cover only
    /// drained slots, so a frozen anchor stops `Block` flow; this trips
    /// sooner than the supervisor's block-event timeout)
    fn observe_anchor(self, anchor: u64, timeout: Duration) -> anyhow::Result<Self> {
        // Only a strictly greater anchor counts as progress
        match self.last_observed_slot {
            Some(prev) if anchor > prev => Ok(Self {
                last_observed_slot: Some(anchor),
                slot_last_advanced_at: Instant::now(),
                ..self
            }),
            // If the anchor has not advanced, check how long it has been stalled for
            Some(prev) => {
                let stalled_for = self.slot_last_advanced_at.elapsed();
                if stalled_for >= timeout {
                    anyhow::bail!(
                        "solana observed slot frozen at {prev} for {stalled_for:?}; \
                         bailing so the supervisor restarts and surfaces it"
                    );
                }
                if stalled_for >= timeout / 2 {
                    tracing::warn!(
                        last_slot = prev,
                        ?stalled_for,
                        "solana observed slot has not advanced; RPC node may be frozen"
                    );
                }
                Ok(self)
            }
            // If this is the first tick, seed the last observed slot so the watchdog has a baseline
            None => Ok(Self {
                last_observed_slot: Some(anchor),
                slot_last_advanced_at: Instant::now(),
                ..self
            }),
        }
    }

    /// Advance past a drained tick. The next tick starts at the anchor, and `CatchupCompleted` is emitted.
    fn drained(self, anchor: u64) -> Self {
        Self {
            next_start: self.next_start.max(anchor),
            caught_up: true,
            ..self
        }
    }
}

pub struct SolanaIndexer<S: StateManager, T: ChainTelemetry> {
    program_id: Pubkey,
    client: SolanaClient,
    config: SolIndexerConfig,
    state_manager: S,
    telemetry: T,
}

type CatchupBlockItem = (u64, SolanaCatchupBlock);

impl<S: StateManager, T: ChainTelemetry> SolanaIndexer<S, T> {
    /// Delay between retries of transient RPC failures
    const RETRY_DELAY: Duration = Duration::from_millis(500);

    /// Current finalized anchor slot, or `None` on cancellation.
    async fn next_anchor(&self, cancel: &CancellationToken) -> Option<anyhow::Result<u64>> {
        tokio::select! {
            _ = cancel.cancelled() => None,
            slot = self.client.get_slot_finalized() => Some(
                slot.context("solana failed to fetch anchor slot")
            ),
        }
    }

    pub fn new(config: SolConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        let program_id = Pubkey::from_str(&config.program_address).with_context(|| {
            format!(
                "failed to parse solana program address: {}",
                config.program_address
            )
        })?;

        let client = SolanaClient::for_indexer(
            config.rpc_http_url.clone(),
            program_id,
            Arc::new(NoopPublisherTelemetry), // Indexer does not publish
        );

        Ok(Self {
            program_id,
            client,
            config: config.indexer,
            state_manager,
            telemetry,
        })
    }

    /// Catchup items in `[start_slot, anchor)` fetched in chunks.
    /// `fetch_slots` failures are propagated so the supervisor can restart.
    async fn catchup_blocks(
        &self,
        anchor_height: u64,
        start_slot: u64,
    ) -> anyhow::Result<
        Pin<Box<dyn Stream<Item = anyhow::Result<CatchupBlockItem>> + Send + 'static>>,
    > {
        let end_slot = anchor_height.saturating_sub(1);
        if start_slot > end_slot {
            tracing::info!(anchor_slot = anchor_height, "solana catchup not required");
            return Ok(Box::pin(stream::empty()));
        }

        tracing::info!(
            anchor_slot = anchor_height,
            start_slot,
            end_slot,
            "solana catchup started"
        );

        let newest_first_pages =
            Self::paginate_slots(self.client.clone(), self.program_id, start_slot, end_slot);
        let ordered_pages = Self::order_and_chunk_pages(
            newest_first_pages,
            start_slot,
            end_slot,
            CATCHUP_PAGE_SIZE,
        );

        Ok(Self::fetch_blocks_for_pages(
            self.client.clone(),
            ordered_pages,
        ))
    }

    /// Collect newest-first signature pages and emit globally ascending,
    /// deduplicated slot chunks. Keeping this as a lazy stream lets the caller
    /// cancel catchup while signature pagination is still in progress.
    fn order_and_chunk_pages(
        pages: impl Stream<Item = anyhow::Result<BTreeSet<u64>>> + Send + 'static,
        start_slot: u64,
        end_slot: u64,
        chunk_size: usize,
    ) -> impl Stream<Item = anyhow::Result<BTreeSet<u64>>> + Send + 'static {
        stream::once(async move {
            futures_util::pin_mut!(pages);

            let started_at = Instant::now();
            let mut signature_pages = 0usize;
            let mut ordered_slots = BTreeSet::new();
            while let Some(page) = pages.next().await {
                signature_pages += 1;
                ordered_slots.extend(page?);
            }

            tracing::info!(
                start_slot,
                end_slot,
                signature_pages,
                unique_slots = ordered_slots.len(),
                elapsed = ?started_at.elapsed(),
                "solana catchup signature pagination complete"
            );

            Ok::<_, anyhow::Error>(Self::chunk_slots(ordered_slots, chunk_size))
        })
        .flat_map(|result| {
            let chunks: Vec<anyhow::Result<BTreeSet<u64>>> = match result {
                Ok(chunks) => chunks.into_iter().map(Ok).collect(),
                Err(err) => vec![Err(err)],
            };
            stream::iter(chunks)
        })
    }

    /// Split globally ordered slots into bounded, ascending chunks. Collecting
    /// all slot numbers first is necessary because Solana signature pages are
    /// returned newest-to-oldest, while request lifecycle events must be
    /// replayed oldest-to-newest.
    fn chunk_slots(slots: BTreeSet<u64>, chunk_size: usize) -> Vec<BTreeSet<u64>> {
        debug_assert!(chunk_size > 0, "catchup slot chunk size must be positive");

        slots.into_iter().fold(Vec::new(), |mut chunks, slot| {
            match chunks.last_mut() {
                Some(chunk) if chunk.len() < chunk_size => {
                    chunk.insert(slot);
                }
                _ => chunks.push(BTreeSet::from([slot])),
            }
            chunks
        })
    }

    /// Paginate `getSignaturesForAddress` backwards from the anchor, yielding
    /// pages of slots within `[start_slot, end_slot]`. Stops once the cursor
    /// walks past `start_slot` or the RPC runs dry.
    fn paginate_slots(
        client: SolanaClient,
        program_id: Pubkey,
        start_slot: u64,
        end_slot: u64,
    ) -> impl Stream<Item = anyhow::Result<BTreeSet<u64>>> {
        struct PageState {
            client: SolanaClient,
            program_id: Pubkey,
            start_slot: u64,
            end_slot: u64,
            cursor: Option<Signature>,
            finished: bool,
        }

        stream::unfold(
            PageState {
                client,
                program_id,
                start_slot,
                end_slot,
                cursor: None,
                finished: false,
            },
            |mut state| async move {
                if state.finished {
                    return None;
                }

                let batch = match state
                    .client
                    .fetch_signatures_from_latest(&state.program_id, state.cursor)
                    .await
                {
                    Ok(b) if b.is_empty() => return None,
                    Ok(b) => b,
                    Err(e) => {
                        state.finished = true;
                        return Some((Err(e), state));
                    }
                };

                state.cursor = batch
                    .last()
                    .and_then(|s| Signature::from_str(&s.signature).ok());
                if state.cursor.is_none() {
                    state.finished = true;
                }

                let mut slots = BTreeSet::new();
                for sig in batch {
                    if sig.slot < state.start_slot {
                        state.finished = true;
                    } else if sig.slot <= state.end_slot {
                        slots.insert(sig.slot);
                    }
                }

                Some((Ok(slots), state))
            },
        )
    }

    /// Fetch blocks for each page of slots and flatten into a stream of `(slot, block)` items.
    fn fetch_blocks_for_pages(
        client: SolanaClient,
        pages: impl Stream<Item = anyhow::Result<BTreeSet<u64>>> + Send + 'static,
    ) -> Pin<Box<dyn Stream<Item = anyhow::Result<CatchupBlockItem>> + Send + 'static>> {
        let stream = pages
            .filter_map(|res| async move {
                match res {
                    Ok(slots) if slots.is_empty() => None,
                    Ok(slots) => Some(Ok(slots)),
                    Err(e) => Some(Err(e)),
                }
            })
            // This must remain sequential and order-preserving: lifecycle
            // events in older slots must reach the backlog before newer ones.
            // Using buffer_unordered here would undo global slot ordering.
            .then(move |res| {
                let client = client.clone();
                async move {
                    let slots = res?;
                    let mut blocks = client.fetch_blocks_for_slots(slots.clone()).await;
                    let items: Vec<CatchupBlockItem> = slots
                        .into_iter()
                        .map(|s| {
                            let block = blocks.remove(&s).unwrap_or(SolanaCatchupBlock::Missing);
                            (s, block)
                        })
                        .collect();
                    Ok::<_, anyhow::Error>(items)
                }
            })
            .map(|res| match res {
                Ok(items) => {
                    let stream_items: Vec<anyhow::Result<CatchupBlockItem>> =
                        items.into_iter().map(Ok).collect();
                    stream::iter(stream_items)
                }
                Err(e) => stream::iter(vec![Err(e)]),
            })
            .flatten();

        Box::pin(stream)
    }

    async fn process_catchup_item(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        slot: u64,
        block: &SolanaCatchupBlock,
    ) -> anyhow::Result<()> {
        match block {
            SolanaCatchupBlock::Block(block) => self.process_block(events_tx, slot, block).await,
            SolanaCatchupBlock::Missing => {
                let block = self.client.get_block(slot).await?;
                self.process_block(events_tx, slot, &block).await
            }
        }
    }

    /// Retries `process_catchup_item` with `RETRY_DELAY` backoff until it
    /// succeeds or `cancel` fires.
    async fn process_catchup_retrying(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        slot: u64,
        block: &SolanaCatchupBlock,
        cancel: &CancellationToken,
    ) {
        retry_until_ok(
            cancel,
            Self::RETRY_DELAY,
            &format!("solana catchup block processing (slot {slot})"),
            || async { self.process_catchup_item(events_tx, slot, block).await },
        )
        .await;
    }

    /// Drain `[start_slot, anchor)`: process active slots in order and emit a
    /// `Block` marker for every inactive slot, so each drained slot produces
    /// exactly one marker, in order.
    //
    // TODO: the anchor (`getSlot`) and the signature walk
    // (`getSignaturesForAddress`) may be served by different RPC backends
    // behind a load balancer. A lagging signatures backend reports the top
    // of the range empty, so markers advance the watermark past slots the
    // walk never actually verified — silent loss. Consider discounting the
    // anchor by a requery margin before draining, so both the drain range
    // and the emitted markers stay behind the verified head.
    async fn drain_range(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        anchor: u64,
        start_slot: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        let mut catchup_iter = self.catchup_blocks(anchor, start_slot).await?;
        let mut next_marker = start_slot;
        loop {
            let item = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                item = catchup_iter.next() => item,
            };
            // Stream end is a landmark at the anchor: it flushes the
            // trailing inactive slots, then exits the drain.
            let (landmark, block) = match item {
                Some(res) => {
                    // Propagate RPC page errors so supervisor restarts cleanly
                    let (slot, block) = res?;
                    (slot, Some(block))
                }
                None => (anchor, None),
            };
            self.emit_block_markers_for_drained_inactive_slots(
                events_tx,
                next_marker..landmark,
                cancel,
            )
            .await?;
            let Some(block) = block else { break };
            self.process_catchup_retrying(events_tx, landmark, &block, cancel)
                .await;
            next_marker = landmark + 1;
        }
        Ok(())
    }

    /// Emit a `Block` marker for each drained slot that had no
    /// program activity (active slots emit their own marker via
    /// `process_block`).
    async fn emit_block_markers_for_drained_inactive_slots(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        slots: std::ops::Range<u64>,
        cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        for slot in slots {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                res = events_tx.send(ChainEvent::Block(slot)) => {
                    res.context("failed to send solana block marker event")?;
                    self.telemetry.block_indexed(slot);
                }
            }
        }
        Ok(())
    }

    async fn process_block(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        height: u64,
        block: &UiConfirmedBlock,
    ) -> anyhow::Result<()> {
        // Update indexed block metrics
        self.telemetry.block_indexed(height);

        let Some(transactions) = &block.transactions else {
            events_tx.send(ChainEvent::Block(height)).await?;
            return Ok(());
        };

        for tx in transactions {
            process_transaction(events_tx, &self.program_id, tx).await?;
        }

        events_tx.send(ChainEvent::Block(height)).await?;
        Ok(())
    }
}

/// Process a single transaction from a fetched block: skip failed
/// transactions, then emit their CPI events. Failed transactions never
/// produce durable state on chain, so their events must not be indexed.
async fn process_transaction(
    events_tx: &mpsc::Sender<ChainEvent>,
    program_id: &Pubkey,
    tx: &EncodedTransactionWithStatusMeta,
) -> anyhow::Result<()> {
    let Some(meta) = tx.meta.as_ref() else {
        return Ok(());
    };
    if meta.err.is_some() {
        return Ok(());
    }
    let OptionSerializer::Some(logs) = meta.log_messages.as_ref() else {
        return Ok(());
    };

    let signature = extract_tx_signature(&tx.transaction)?;
    emit_events(events_tx, program_id, signature, tx, logs).await
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for SolanaIndexer<S, T> {
    const CHAIN: Chain = Chain::Solana;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Seed the resume point before entering the loop
        let Some(seed) = self.next_anchor(&cancel).await else {
            return Ok(());
        };
        let mut state = PollState::resumed(&self.state_manager, seed?).await;

        loop {
            let Some(res) = self.next_anchor(&cancel).await else {
                return Ok(());
            };
            let anchor = res?;
            state = state.observe_anchor(anchor, self.config.slot_stall_timeout)?;

            let tick_started_at = Instant::now();
            self.drain_range(&events_tx, anchor, state.next_start, &cancel)
                .await?;

            let was_caught_up = state.caught_up;
            state = state.drained(anchor);

            if !was_caught_up {
                tracing::info!(
                    anchor_slot = anchor,
                    elapsed = ?tick_started_at.elapsed(),
                    "solana catchup complete"
                );
                events_tx
                    .send(ChainEvent::CatchupCompleted)
                    .await
                    .context("failed to send catchup completed event")?;
            } else {
                tracing::debug!(
                    anchor_slot = anchor,
                    elapsed = ?tick_started_at.elapsed(),
                    "solana poll iteration complete"
                );
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
    use std::collections::{BTreeMap, VecDeque};

    use super::*;
    use crate::events::SolanaSignEvent;
    use anchor_lang::{AnchorSerialize, Discriminator};
    use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
    use mpc_primitives::SignId;
    use signet_program::{SignatureRequestedEvent, SignatureRespondedEvent};
    use solana_sdk::commitment_config::CommitmentLevel;
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status::{
        TransactionDetails, UiTransactionEncoding, UiTransactionStatusMeta,
    };

    /// Create a test indexer with a mock state manager and a given RPC URL.
    fn test_indexer(
        url: &str,
        state_manager: MockStateManager,
    ) -> SolanaIndexer<MockStateManager, NoopChainTelemetry> {
        let program_id = Pubkey::new_unique();
        let client = SolanaClient::for_indexer(
            url.to_string(),
            program_id,
            Arc::new(NoopPublisherTelemetry),
        )
        .with_fast_retry();
        SolanaIndexer {
            program_id,
            client,
            config: SolIndexerConfig::default(),
            state_manager,
            telemetry: NoopChainTelemetry,
        }
    }

    /// Create a mock signature entry for testing, with a given slot.
    fn signature_entry(slot: u64) -> serde_json::Value {
        serde_json::json!({
            "signature": Signature::new_unique().to_string(),
            "slot": slot,
            "err": null,
            "memo": null,
            "blockTime": null,
            "confirmationStatus": "confirmed"
        })
    }

    /// Create a mock JSON-RPC response for a list of signature entries.
    fn signatures_response(entries: &[serde_json::Value]) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": entries
        })
        .to_string()
    }

    /// Create a mock JSON-RPC response for a block at a given slot.
    fn block_response(id: usize, slot: u64) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "result": {
                "blockHeight": slot,
                "blockTime": null,
                "blockhash": "11111111111111111111111111111111",
                "parentSlot": slot.saturating_sub(1),
                "previousBlockhash": "11111111111111111111111111111111",
                "transactions": [],
                "rewards": []
            }
        })
    }

    fn cpi_event_instruction<T: AnchorSerialize + Discriminator>(event: &T) -> String {
        let mut data = anchor_lang::event::EVENT_IX_TAG_LE.to_vec();
        data.extend_from_slice(T::DISCRIMINATOR);
        event.serialize(&mut data).unwrap();
        solana_sdk::bs58::encode(data).into_string()
    }

    fn event_transaction(
        program_id: Pubkey,
        signature: Signature,
        instruction: &str,
        event_data: String,
    ) -> serde_json::Value {
        serde_json::json!({
            "meta": {
                "err": null,
                "status": { "Ok": null },
                "fee": 5_000,
                "preBalances": [],
                "postBalances": [],
                "innerInstructions": [{
                    "index": 0,
                    "instructions": [{
                        "accounts": [],
                        "data": event_data,
                        "programId": program_id.to_string(),
                        "stackHeight": 2
                    }]
                }],
                "logMessages": [
                    format!("Program {program_id} invoke [1]"),
                    format!("Program log: Instruction: {instruction}"),
                    format!("Program {program_id} success")
                ],
                "preTokenBalances": [],
                "postTokenBalances": [],
                "rewards": null,
                "loadedAddresses": { "readonly": [], "writable": [] },
                "computeUnitsConsumed": 0
            },
            "transaction": {
                "message": {
                    "accountKeys": [{
                        "pubkey": program_id.to_string(),
                        "signer": false,
                        "source": "transaction",
                        "writable": false
                    }],
                    "instructions": [],
                    "recentBlockhash": "11111111111111111111111111111111"
                },
                "signatures": [signature.to_string()]
            },
            "version": "legacy"
        })
    }

    fn event_block_response(
        id: usize,
        slot: u64,
        transaction: serde_json::Value,
    ) -> serde_json::Value {
        let mut response = block_response(id, slot);
        response["result"]["transactions"] = serde_json::json!([transaction]);
        response
    }

    /// Match a JSON-RPC block batch whose first `getBlock` request is for `slot`.
    fn block_batch_starting_at(slot: u64) -> mockito::Matcher {
        mockito::Matcher::Regex(format!(r#""params"\s*:\s*\[\s*{slot}\s*,"#))
    }

    /// Fixture for driving `run()` against a mockito RPC server. Owns the
    /// mock server, indexer, event channel and run task; tests only script
    /// RPC responses and assert on the event sequence.
    struct RunFixture {
        _server: mockito::ServerGuard,
        cancel: CancellationToken,
        run: tokio::task::JoinHandle<anyhow::Result<()>>,
        events_rx: mpsc::Receiver<ChainEvent>,
    }

    /// JSON-RPC reply body for `getSlot` returning `slot`.
    fn getslot_body(slot: u64) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{slot}}}"#)
    }

    impl RunFixture {
        /// Spawn `run()` with a getSlot mock serving `slots` in order (the
        /// last repeats forever), an optional persisted watermark, and an
        /// optional `SolIndexerConfig` (defaults: fast poll, slow stall timeout).
        async fn spawn(
            slots: &[u64],
            processed: Option<u64>,
            config: impl Into<Option<SolIndexerConfig>>,
        ) -> Self {
            let server = mockito::Server::new_async().await;
            Self::spawn_with_server(server, slots, processed, config).await
        }

        /// Variant taking a pre-built mockito server
        async fn spawn_with_server(
            mut server: mockito::ServerGuard,
            slots: &[u64],
            processed: Option<u64>,
            config: impl Into<Option<SolIndexerConfig>>,
        ) -> Self {
            // Serve the slots in order, repeating the last one forever
            let bodies = Arc::new(std::sync::Mutex::new(
                slots
                    .iter()
                    .map(|s| getslot_body(*s))
                    .collect::<VecDeque<_>>(),
            ));
            server
                .mock("POST", "/")
                .match_body(mockito::Matcher::Regex("getSlot".to_string()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body_from_request({
                    let bodies = bodies.clone();
                    move |_req| {
                        let mut script = bodies.lock().expect("script lock");
                        let body = if script.len() > 1 {
                            script.pop_front().expect("script body")
                        } else {
                            script.front().cloned().expect("script body")
                        };
                        body.into_bytes()
                    }
                })
                .create_async()
                .await;

            let state_manager = MockStateManager::new();
            if let Some(height) = processed {
                state_manager
                    .set_processed_block(Chain::Solana, height)
                    .await;
            }
            let mut indexer = test_indexer(&server.url(), state_manager);
            indexer.config = config.into().unwrap_or(SolIndexerConfig {
                poll_interval: Duration::from_millis(5),
                slot_stall_timeout: Duration::from_secs(30),
            });

            let (events_tx, events_rx) = mpsc::channel(64);
            let cancel = CancellationToken::new();
            let run = {
                let cancel = cancel.clone();
                tokio::spawn(async move { indexer.run(events_tx, cancel).await })
            };

            Self {
                _server: server,
                cancel,
                run,
                events_rx,
            }
        }

        async fn next_event(&mut self) -> Option<ChainEvent> {
            tokio::time::timeout(Duration::from_secs(5), self.events_rx.recv())
                .await
                .expect("timed out waiting for chain event")
        }

        async fn cancel_and_join(&mut self) {
            self.cancel.cancel();
            tokio::time::timeout(Duration::from_secs(5), &mut self.run)
                .await
                .expect("run should stop promptly on cancel")
                .expect("run task should not panic")
                .expect("run should return Ok on cancel");
        }

        /// Await the run task to completion without cancelling it.
        async fn await_result(self) -> anyhow::Result<()> {
            tokio::time::timeout(Duration::from_secs(5), self.run)
                .await
                .expect("run should finish within timeout")
                .expect("run task should not panic")
        }
    }

    #[test]
    fn block_fetch_config_sets_max_supported_transaction_version() {
        let config = SolanaClient::block_fetch_config();

        assert_eq!(config.max_supported_transaction_version, Some(u8::MAX));
        assert_eq!(config.transaction_details, Some(TransactionDetails::Full));
        assert_eq!(config.encoding, Some(UiTransactionEncoding::JsonParsed));
        assert_eq!(config.rewards, Some(false));
        assert_eq!(
            config.commitment.map(|commitment| commitment.commitment),
            Some(CommitmentLevel::Finalized)
        );
    }

    #[test]
    fn btree_extend_preserves_slot_order_for_catchup() {
        let mut from_signatures = BTreeMap::new();
        from_signatures.insert(10_u64, SolanaCatchupBlock::Missing);
        from_signatures.insert(12_u64, SolanaCatchupBlock::Missing);

        let mut from_sparse = BTreeMap::new();
        from_sparse.insert(8_u64, SolanaCatchupBlock::Missing);
        from_sparse.insert(9_u64, SolanaCatchupBlock::Missing);

        from_signatures.extend(from_sparse);

        let slots: Vec<_> = from_signatures.into_keys().collect();
        assert_eq!(slots, vec![8, 9, 10, 12]);
    }

    #[test]
    fn globally_ordered_slots_are_split_into_bounded_chunks() {
        let chunks = SolanaIndexer::<MockStateManager, NoopChainTelemetry>::chunk_slots(
            BTreeSet::from([5, 1, 4, 2, 3]),
            2,
        );

        assert_eq!(
            chunks,
            vec![
                BTreeSet::from([1, 2]),
                BTreeSet::from([3, 4]),
                BTreeSet::from([5]),
            ]
        );
    }

    /// Check we can still parse the old format for failed transactions.
    ///
    /// Note that there are some SDK versions that can parse the new format but
    /// not the new, and other versions that have the opposite problem.
    /// See: https://github.com/anza-xyz/solana-sdk/pull/410
    /// and https://github.com/anza-xyz/solana-sdk/issues/394
    ///
    /// We want a version that can parse both.
    #[test]
    fn transaction_error_borsh_io_error_object_deserialization() {
        // Exact error shape returned _before_ Solana 4.0 RPC for a failed transaction.
        let json = r#"{"InstructionError": [0, { "BorshIoError": "Reason for the error" }]}"#;
        let result: std::result::Result<solana_sdk::transaction::TransactionError, _> =
            serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "BorshIoError unit-variant deserialization failed: {:?}",
            result.err()
        );
    }

    /// Check we can parse the new format for failed transactions.
    ///
    /// Note that there are some SDK versions that can parse the new format but
    /// not the new, and other versions that have the opposite problem.
    /// See: https://github.com/anza-xyz/solana-sdk/pull/410
    /// and https://github.com/anza-xyz/solana-sdk/issues/394
    ///
    /// We want a version that can parse both.
    #[test]
    fn transaction_error_borsh_io_error_unit_variant_deserialization() {
        // Exact error shape returned by Solana 4.0 RPC for a failed transaction.
        let json = r#"{"InstructionError": [0, "BorshIoError"]}"#;
        let result: std::result::Result<solana_sdk::transaction::TransactionError, _> =
            serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "BorshIoError unit-variant deserialization failed: {:?}",
            result.err()
        );
    }

    /// Regression test for being able to deserialize devnet slot 466737912 (TX
    /// index 32).
    ///
    /// This is the exact UiTransactionStatusMeta captured from the devnet slot.
    /// It got the SOL indexer stuck as reported in
    /// https://github.com/sig-net/mpc/issues/844.
    #[test]
    fn ui_transaction_meta_with_borsh_io_error_deserializes() {
        let meta_json = r#"{
            "err": {"InstructionError": [0, "BorshIoError"]},
            "status": {"Err": {"InstructionError": [0, "BorshIoError"]}},
            "fee": 5000,
            "preBalances":  [1130764920,0,0,1,1461600,1003361680,1141440,0,1009200,12051573357],
            "postBalances": [1130759920,0,0,1,1461600,1003361680,1141440,0,1009200,12051573357],
            "innerInstructions": [],
            "logMessages": [
                "Program 3kjK4HA6A4K86NgNB93gGhSt257wtN4QAqXMNPQ4fVTm invoke [1]",
                "Program log: Instruction 12: WithdrawFromFeeAccount",
                "Program 3kjK4HA6A4K86NgNB93gGhSt257wtN4QAqXMNPQ4fVTm consumed 5299 of 200000 compute units",
                "Program 3kjK4HA6A4K86NgNB93gGhSt257wtN4QAqXMNPQ4fVTm failed: Failed to serialize or deserialize account data"
            ],
            "preTokenBalances": [],
            "postTokenBalances": [],
            "rewards": null,
            "loadedAddresses": {"readonly": [], "writable": []},
            "computeUnitsConsumed": 5299
        }"#;

        let result: std::result::Result<UiTransactionStatusMeta, _> =
            serde_json::from_str(meta_json);
        assert!(
            result.is_ok(),
            "UiTransactionStatusMeta with BorshIoError failed to deserialize: {:?}",
            result.err()
        );
        let meta = result.unwrap();
        assert!(meta.err.is_some(), "expected err to be set");
    }

    #[tokio::test]
    async fn catchup_blocks_empty_when_up_to_date() {
        let server = mockito::Server::new_async().await;
        let indexer = test_indexer(&server.url(), MockStateManager::new());
        const ANCHOR_SLOT: u64 = 10;

        // No processed block persisted: start == anchor, so no catchup and no RPC calls.
        let mut stream = indexer
            .catchup_blocks(ANCHOR_SLOT, ANCHOR_SLOT)
            .await
            .unwrap();
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn catchup_blocks_propagates_fetch_slots_error() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .expect(3) // 1 attempt + 2 retries (fast retry config)
            .create_async()
            .await;

        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 5).await;
        let indexer = test_indexer(&server.url(), state_manager);
        const ANCHOR_SLOT: u64 = 10;

        let mut stream = indexer.catchup_blocks(ANCHOR_SLOT, 6).await.unwrap();
        let first = stream.next().await;
        assert!(first.is_some() && first.unwrap().is_err());
    }

    #[tokio::test]
    async fn single_page_catchup_processes_slots_in_order() {
        let mut server = mockito::Server::new_async().await;

        // Signatures walk back from the anchor: slots 9..=6 are in range,
        // slot 5 (< start_slot 6) terminates the walk.
        let entries: Vec<_> = [9, 8, 7, 6, 5].into_iter().map(signature_entry).collect();
        let _signatures = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                "getSignaturesForAddress".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&entries))
            .create_async()
            .await;

        let blocks = serde_json::json!([
            block_response(0, 6),
            block_response(1, 7),
            block_response(2, 8),
            block_response(3, 9),
        ])
        .to_string();
        let _blocks = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("getBlock".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(blocks)
            .create_async()
            .await;

        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 5).await;
        let indexer = test_indexer(&server.url(), state_manager);

        let (events_tx, mut events_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();
        const ANCHOR_SLOT: u64 = 10;

        let mut stream = indexer.catchup_blocks(ANCHOR_SLOT, 6).await.unwrap();

        while let Some(res) = stream.next().await {
            let (slot, block) = res.unwrap();
            indexer
                .process_catchup_retrying(&events_tx, slot, &block, &cancel)
                .await;
        }

        // Verify that the events were emitted in order
        for expected in 6..=9 {
            let event = events_rx.recv().await.unwrap();
            assert!(
                matches!(event, ChainEvent::Block(slot) if slot == expected),
                "expected Block({expected}), got {event:?}"
            );
        }
    }

    #[tokio::test]
    async fn catchup_parses_request_and_response_cpi_events() {
        let mut server = mockito::Server::new_async().await;
        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 5).await;
        let indexer = test_indexer(&server.url(), state_manager);

        let request = SignatureRequestedEvent {
            sender: Pubkey::new_unique(),
            payload: [1; 32],
            key_version: 0,
            deposit: 1,
            chain_id: "solana".to_string(),
            path: "test".to_string(),
            algo: "secp256k1".to_string(),
            dest: "test".to_string(),
            params: String::new(),
            fee_payer: None,
        };
        let request_id = SolanaSignEvent::SignatureRequested(request.clone()).generate_request_id();
        let response = SignatureRespondedEvent {
            request_id,
            responder: Pubkey::new_unique(),
            signature: signet_program::Signature {
                big_r: signet_program::AffinePoint {
                    x: hex::decode(
                        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    )
                    .unwrap()
                    .try_into()
                    .unwrap(),
                    y: hex::decode(
                        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
                    )
                    .unwrap()
                    .try_into()
                    .unwrap(),
                },
                s: [1; 32],
                recovery_id: 0,
            },
        };

        let entries: Vec<_> = [8, 7, 5].into_iter().map(signature_entry).collect();
        let _signatures = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                "getSignaturesForAddress".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&entries))
            .expect(1)
            .create_async()
            .await;

        let blocks = serde_json::json!([
            event_block_response(
                0,
                7,
                event_transaction(
                    indexer.program_id,
                    Signature::new_unique(),
                    "Sign",
                    cpi_event_instruction(&request),
                ),
            ),
            event_block_response(
                1,
                8,
                event_transaction(
                    indexer.program_id,
                    Signature::new_unique(),
                    "Respond",
                    cpi_event_instruction(&response),
                ),
            ),
        ]);
        let _blocks = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                r#""method":"getBlock".*"encoding":"jsonParsed""#.to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(blocks.to_string())
            .expect(1)
            .create_async()
            .await;

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let mut catchup = indexer.catchup_blocks(9, 6).await.unwrap();
        while let Some(item) = catchup.next().await {
            let (slot, block) = item.unwrap();
            indexer
                .process_catchup_item(&events_tx, slot, &block)
                .await
                .unwrap();
        }

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::SignRequest { request, .. }) if request.id == SignId::new(request_id)
        ));
        assert!(matches!(events_rx.recv().await, Some(ChainEvent::Block(7))));
        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::Respond(event)) if event.request_id == request_id
        ));
        assert!(matches!(events_rx.recv().await, Some(ChainEvent::Block(8))));
    }

    #[tokio::test]
    async fn catchup_skips_failed_transactions_like_live() {
        let indexer = test_indexer("http://localhost:1", MockStateManager::new());
        let request = SignatureRequestedEvent {
            sender: Pubkey::new_unique(),
            payload: [1; 32],
            key_version: 0,
            deposit: 1,
            chain_id: "solana".to_string(),
            path: "test".to_string(),
            algo: "secp256k1".to_string(),
            dest: "test".to_string(),
            params: String::new(),
            fee_payer: None,
        };
        let mut transaction = event_transaction(
            indexer.program_id,
            Signature::new_unique(),
            "Sign",
            cpi_event_instruction(&request),
        );
        let error = serde_json::json!({ "InstructionError": [0, { "Custom": 1 }] });
        transaction["meta"]["err"] = error.clone();
        transaction["meta"]["status"] = serde_json::json!({ "Err": error });

        let response = event_block_response(0, 7, transaction);
        let block: UiConfirmedBlock = serde_json::from_value(response["result"].clone()).unwrap();
        let (events_tx, mut events_rx) = mpsc::channel(8);

        indexer.process_block(&events_tx, 7, &block).await.unwrap();

        assert!(matches!(events_rx.recv().await, Some(ChainEvent::Block(7))));
        assert!(events_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn multi_transaction_slot_emits_single_block_after_all_events() {
        let mut server = mockito::Server::new_async().await;
        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 5).await;
        let indexer = test_indexer(&server.url(), state_manager);

        // Two requests in the same slot, with different payloads. The
        // indexer must emit both of them, then exactly one Block(7).
        let req_a = SignatureRequestedEvent {
            sender: Pubkey::new_unique(),
            payload: [1; 32],
            key_version: 0,
            deposit: 1,
            chain_id: "solana".to_string(),
            path: "test".to_string(),
            algo: "secp256k1".to_string(),
            dest: "test".to_string(),
            params: String::new(),
            fee_payer: None,
        };
        let req_b = SignatureRequestedEvent {
            payload: [2; 32],
            ..req_a.clone()
        };

        let entries: Vec<_> = [7, 5].into_iter().map(signature_entry).collect();
        let _signatures = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                "getSignaturesForAddress".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&entries))
            .expect(1)
            .create_async()
            .await;

        // Construct the block containing both transactions.
        let mut block = event_block_response(
            0,
            7,
            event_transaction(
                indexer.program_id,
                Signature::new_unique(),
                "Sign",
                cpi_event_instruction(&req_a),
            ),
        );

        block["result"]["transactions"]
            .as_array_mut()
            .unwrap()
            .push(event_transaction(
                indexer.program_id,
                Signature::new_unique(),
                "Sign",
                cpi_event_instruction(&req_b),
            ));

        let _blocks = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                r#""method":"getBlock".*"encoding":"jsonParsed""#.to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::json!([block]).to_string())
            .expect(1)
            .create_async()
            .await;

        // Verify that the indexer emits both requests, then exactly one Block(7).
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let mut catchup = indexer.catchup_blocks(8, 6).await.unwrap();
        while let Some(item) = catchup.next().await {
            let (slot, block_item) = item.unwrap();
            indexer
                .process_catchup_item(&events_tx, slot, &block_item)
                .await
                .unwrap();
        }

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::SignRequest { .. })
        ));

        assert!(matches!(
            events_rx.recv().await,
            Some(ChainEvent::SignRequest { .. })
        ));

        assert!(matches!(events_rx.recv().await, Some(ChainEvent::Block(7))));
        assert!(
            events_rx.try_recv().is_err(),
            "Block(7) must be emitted exactly once for the multi-transaction slot"
        );
    }

    #[tokio::test]
    async fn block_fetch_pages_preserve_slot_order() {
        let mut server = mockito::Server::new_async().await;

        // Delay the older page. Sequential fetching must still emit it before
        // the immediately available newer page.
        let _older_blocks = server
            .mock("POST", "/")
            .match_body(block_batch_starting_at(1))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_chunked_body(|writer| {
                std::thread::sleep(Duration::from_millis(100));
                writer.write_all(b"[]")
            })
            .expect(1)
            .create_async()
            .await;
        let _newer_blocks = server
            .mock("POST", "/")
            .match_body(block_batch_starting_at(3))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .expect(1)
            .create_async()
            .await;

        let indexer = test_indexer(&server.url(), MockStateManager::new());
        let pages = stream::iter([Ok(BTreeSet::from([1, 2])), Ok(BTreeSet::from([3, 4]))]);
        let mut blocks =
            SolanaIndexer::<MockStateManager, NoopChainTelemetry>::fetch_blocks_for_pages(
                indexer.client,
                pages,
            );

        let mut slots = Vec::new();
        while let Some(item) = blocks.next().await {
            slots.push(item.unwrap().0);
        }

        assert_eq!(slots, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn multipage_catchup_does_not_lose_response_before_older_request() {
        let mut server = mockito::Server::new_async().await;
        let state_manager = MockStateManager::new();
        state_manager.set_processed_block(Chain::Solana, 5).await;
        let indexer = test_indexer(&server.url(), state_manager);

        // getSignaturesForAddress paginates newest-to-oldest. The response is
        // in the first (newer) page, while its request is in the second (older)
        // page. Slot 5 is below the catchup start and terminates pagination.
        let newest_page: Vec<_> = [9, 8].into_iter().map(signature_entry).collect();
        // Slot 8 appears on both pages to verify global deduplication at a page
        // boundary. Fetching its block once still discovers every transaction
        // in that slot.
        let older_page: Vec<_> = [8, 7, 6, 5].into_iter().map(signature_entry).collect();
        let before_cursor = newest_page
            .last()
            .and_then(|entry| entry["signature"].as_str())
            .expect("newest page should have a cursor signature");

        let _newest_page = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "method": "getSignaturesForAddress",
                "params": [indexer.program_id.to_string(), { "before": null }],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&newest_page))
            .expect(1)
            .create_async()
            .await;
        let _older_page = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "method": "getSignaturesForAddress",
                "params": [indexer.program_id.to_string(), { "before": before_cursor }],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&older_page))
            .expect(1)
            .create_async()
            .await;

        let ordered_blocks = serde_json::json!([
            block_response(0, 6),
            block_response(1, 7),
            block_response(2, 8),
            block_response(3, 9),
        ])
        .to_string();

        let _ordered_blocks = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("getBlock".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ordered_blocks)
            .expect(1)
            .create_async()
            .await;

        let mut catchup = indexer.catchup_blocks(10, 6).await.unwrap();

        let mut replayed_slots = Vec::new();
        let mut request_pending = false;
        let mut response_applied = false;

        while let Some(item) = catchup.next().await {
            let (slot, _block) = item.unwrap();
            replayed_slots.push(slot);
            match slot {
                // The request is created in the older block.
                7 => request_pending = true,
                // This mirrors process_respond_event: if the request is not
                // in the backlog yet, the response is skipped permanently.
                8 if request_pending => {
                    request_pending = false;
                    response_applied = true;
                }
                _ => {}
            }
        }

        assert_eq!(replayed_slots, vec![6, 7, 8, 9]);
        assert!(
            response_applied && !request_pending,
            "catchup replayed slots as {replayed_slots:?}; the response was processed before its request and lost"
        );
    }

    #[tokio::test]
    async fn poll_state_resumes_after_persisted_watermark_or_seeds_from_anchor() {
        // Persisted watermark: resume from the slot after it.
        let sm = MockStateManager::new();
        sm.set_processed_block(Chain::Solana, 41).await;
        let state = PollState::resumed(&sm, 100).await;
        assert_eq!(state.next_start, 42);
        assert_eq!(state.last_observed_slot, None);
        assert!(!state.caught_up);

        // Fresh deployment: nothing persisted, start live from the seed anchor.
        let fresh = PollState::resumed(&MockStateManager::new(), 100).await;
        assert_eq!(fresh.next_start, 100);
    }

    #[tokio::test]
    async fn poll_state_advance_requires_strictly_greater_anchor() {
        let timeout = Duration::from_secs(60);
        let sm = MockStateManager::new();
        let state = PollState::resumed(&sm, 10).await;

        // First observation initializes the high-water slot.
        let state = state
            .observe_anchor(10, timeout)
            .expect("first observation should succeed");
        assert_eq!(state.last_observed_slot, Some(10));

        // A lower anchor (lagging replica behind an LB) is not progress: the
        // high-water slot must not regress.
        let state = state
            .observe_anchor(7, timeout)
            .expect("regressed anchor is tolerated (no bail this fast)");
        assert_eq!(state.last_observed_slot, Some(10));

        // A strictly greater anchor advances and resets the stall timer.
        let state = state
            .observe_anchor(20, timeout)
            .expect("advancing anchor should succeed");
        assert_eq!(state.last_observed_slot, Some(20));
    }

    #[tokio::test]
    async fn poll_state_drained_advances_next_start_monotonically() {
        let sm = MockStateManager::new();
        let state = PollState::resumed(&sm, 10).await;

        // anchor 10 drains `[next_start, 10)`: the next tick starts at 10
        // and the catchup gate flips.
        let state = state.drained(10);
        assert_eq!(state.next_start, 10);
        assert!(state.caught_up);

        let state = state.drained(30);
        assert_eq!(state.next_start, 30);

        // A regressing anchor (lagging replica behind an LB) cannot rewind
        // the next drain range.
        let state = state.drained(5);
        assert_eq!(state.next_start, 30);
    }

    #[tokio::test]
    async fn run_emits_single_catchup_completed_when_anchor_frozen() {
        // Frozen anchor: the range [10, 10) covers no new slots, so the only
        // event is exactly one CatchupCompleted — no Block markers.
        let mut f = RunFixture::spawn(&[10], Some(9), None).await;

        assert!(matches!(
            f.next_event().await,
            Some(ChainEvent::CatchupCompleted)
        ));
        assert!(
            f.events_rx.try_recv().is_err(),
            "a frozen anchor covers no new slots, so no Block markers may be emitted"
        );

        f.cancel_and_join().await;
    }

    #[tokio::test]
    async fn run_bails_when_observed_slot_frozen() {
        // A frozen RPC node: getSlot keeps returning the same slot forever.
        // Dense markers cover only drained slots, so a frozen anchor stops
        // Block flow; the indexer-side stall watchdog trips first.
        let f = RunFixture::spawn(
            &[10],
            Some(9),
            SolIndexerConfig {
                poll_interval: Duration::from_millis(5),
                slot_stall_timeout: Duration::from_millis(100),
            },
        )
        .await;

        let err = f
            .await_result()
            .await
            .expect_err("run should bail on a frozen observed slot");
        assert!(err.to_string().contains("frozen"));
    }

    #[tokio::test]
    async fn run_drains_new_range_once_when_anchor_advances() {
        let mut server = mockito::Server::new_async().await;

        // One signature page: slots 11, 10 in range; slot 9 (< start 10)
        // terminates pagination. Exactly one pagination pass covers the whole
        // advance — a regression to a stale watermark would re-fetch and fail
        // the `.expect(1)` on drop.
        let entries: Vec<_> = [11, 10, 9].into_iter().map(signature_entry).collect();
        let _signatures = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                "getSignaturesForAddress".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&entries))
            .expect(1)
            .create_async()
            .await;

        let blocks = serde_json::json!([block_response(0, 10), block_response(1, 11),]).to_string();
        let _blocks = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("getBlock".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(blocks)
            .expect(1)
            .create_async()
            .await;

        // getSlot script: seed 10, tick 1 at 10 (empty range), tick 2 at 12
        // (drains [10, 12)), tick 3 at 12 again (empty, proves no re-drain).
        let mut f = RunFixture::spawn_with_server(server, &[10, 10, 12], Some(9), None).await;

        // Tick 1: empty range — caught up at once, no markers.
        assert!(matches!(
            f.next_event().await,
            Some(ChainEvent::CatchupCompleted)
        ));

        // Tick 2: drain [10, 12) — exactly one Block event per slot, and no
        // duplicate marker at the tip.
        assert!(matches!(f.next_event().await, Some(ChainEvent::Block(10))));
        assert!(matches!(f.next_event().await, Some(ChainEvent::Block(11))));

        // Tick 3: anchor unchanged — no re-drain, no markers.
        assert!(
            f.events_rx.try_recv().is_err(),
            "an unchanged anchor covers no new slots, so no events may be emitted"
        );

        f.cancel_and_join().await;
    }

    #[tokio::test]
    async fn drain_range_emits_gapless_markers_for_inactive_slots() {
        let mut server = mockito::Server::new_async().await;

        // Program activity only at slots 11 and 13; slot 9 (< start 10)
        // terminates pagination.
        let entries: Vec<_> = [13, 11, 9].into_iter().map(signature_entry).collect();
        let _signatures = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex(
                "getSignaturesForAddress".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(signatures_response(&entries))
            .expect(1)
            .create_async()
            .await;

        let blocks = serde_json::json!([block_response(0, 11), block_response(1, 13)]).to_string();
        let _blocks = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("getBlock".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(blocks)
            .expect(1)
            .create_async()
            .await;

        let indexer = test_indexer(&server.url(), MockStateManager::new());
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        indexer
            .drain_range(&events_tx, 15, 10, &cancel)
            .await
            .unwrap();

        // Every slot in [10, 15) produces exactly one Block marker, in order:
        // active slots (11, 13) via process_block, inactive slots via markers.
        for expected in 10..15 {
            let event = events_rx.recv().await.unwrap();
            assert!(
                matches!(event, ChainEvent::Block(slot) if slot == expected),
                "expected Block({expected}), got {event:?}"
            );
        }
        assert!(events_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn run_block_sequence_is_poll_phase_invariant() {
        // Identical chain content drained under different tick phases must
        // emit identical Block heights. Activity at 10 and 12 leaves an
        // inactive slot between them, so the markers (11) are covered too.
        async fn block_heights(slots: &[u64]) -> Vec<u64> {
            let mut server = mockito::Server::new_async().await;
            let entries: Vec<_> = [12, 10, 9].into_iter().map(signature_entry).collect();
            let _signatures = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::Regex(
                    "getSignaturesForAddress".to_string(),
                ))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(signatures_response(&entries))
                .create_async()
                .await;
            let _blocks = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::Regex("getBlock".to_string()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    serde_json::json!([block_response(0, 10), block_response(1, 12)]).to_string(),
                )
                .create_async()
                .await;

            let mut f = RunFixture::spawn_with_server(server, slots, Some(9), None).await;
            let mut heights = Vec::new();
            while heights.len() < 3 {
                if let Some(ChainEvent::Block(height)) = f.next_event().await {
                    heights.push(height);
                }
            }
            f.cancel_and_join().await;
            heights
        }

        assert_eq!(block_heights(&[13, 13]).await, [10, 11, 12]);
        assert_eq!(block_heights(&[10, 10, 13]).await, [10, 11, 12]);
    }

    #[tokio::test]
    async fn process_catchup_retrying_stops_on_cancel() {
        // No mock: any RPC attempt fails after fast retries; cancel must
        // interrupt the retry loop without waiting for it.
        let indexer = test_indexer("http://localhost:1", MockStateManager::new());
        let (events_tx, _events_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();
        cancel.cancel();

        tokio::time::timeout(
            Duration::from_secs(5),
            indexer.process_catchup_retrying(&events_tx, 7, &SolanaCatchupBlock::Missing, &cancel),
        )
        .await
        .expect("process_catchup_retrying should stop promptly on cancel");
    }

    // Very expensive test in terms of RPC usage.
    #[tokio::test]
    #[ignore]
    async fn test_solana_pipeline_devnet() {
        let _ = tracing_subscriber::fmt::try_init();

        let api_key = match std::env::var("MPC_TEST_API_KEY") {
            Ok(key) if !key.is_empty() => key,
            _ => {
                tracing::debug!("Skipping devnet test: MPC_TEST_API_KEY not set");
                return;
            }
        };

        let sol_addr = std::env::var("MPC_TEST_SOL_ADDR")
            .unwrap_or_else(|_| "SigDHT99hPznk4d9SAxWLoBnKWT8jcob5pV8X7ti8SM".to_string());

        let http_url = format!("https://solana-devnet.g.alchemy.com/v2/{api_key}");

        let state_manager = MockStateManager::new();
        let (events_tx, mut events_rx) = mpsc::channel(1_000_000);

        let client = SolanaClient::for_indexer(
            http_url.clone(),
            Pubkey::from_str(&sol_addr).unwrap(),
            Arc::new(NoopPublisherTelemetry),
        );

        let indexer = SolanaIndexer {
            program_id: Pubkey::from_str(&sol_addr).unwrap(),
            client,
            config: SolIndexerConfig::default(),
            state_manager,
            telemetry: NoopChainTelemetry,
        };

        // Resolve anchor slot
        let anchor_height = indexer
            .client
            .get_slot_finalized()
            .await
            .expect("Failed to fetch current slot");

        tracing::debug!("Resolved anchor slot: {anchor_height}");

        // Start from a checkpoint ~1 week behind (assuming ~2.5 slots per second => 1,512,000 slots per week)
        let start_slot = anchor_height.saturating_sub(1_512_000);
        tracing::debug!("Starting catchup from slot: {start_slot} (~1 week behind)");

        indexer
            .state_manager
            .set_processed_block(Chain::Solana, start_slot.saturating_sub(1))
            .await;

        // Start the indexer in a separate task
        let cancel = CancellationToken::new();
        let run_handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { indexer.run(events_tx, cancel).await }
        });

        // Drain events until catchup completes
        loop {
            match events_rx.recv().await {
                Some(ChainEvent::CatchupCompleted) => {
                    tracing::debug!("Solana catchup complete");
                    break;
                }
                Some(event) => tracing::debug!("Received event: {:?}", event),
                None => break,
            }
        }

        cancel.cancel();
        run_handle.abort();
    }
}
