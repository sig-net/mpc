use std::collections::{BTreeSet, HashMap};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;
use futures_util::stream::{self, StreamExt};
use futures_util::Stream;
use mpc_chain_integration_core::{
    utils::stream::chain_event_channel, ChainIndexer, ChainTelemetry, NoopPublisherTelemetry,
    StateManager,
};
use mpc_primitives::{Chain, ChainEvent};
use mpc_utils::task::{retry_until_ok, AbortOnDrop};
use solana_client::{
    nonblocking::pubsub_client::PubsubClient,
    rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter},
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{EncodedTransactionWithStatusMeta, UiConfirmedBlock};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::client::{SolanaCatchupBlock, CATCHUP_PAGE_SIZE};
use crate::{emit_events, extract_tx_signature, SolConfig, SolanaClient};

pub struct SolanaIndexer<S: StateManager, T: ChainTelemetry> {
    program_id: Pubkey,
    client: SolanaClient,
    state_manager: S,
    telemetry: T,
}

type CatchupBlockItem = (u64, SolanaCatchupBlock);

impl<S: StateManager, T: ChainTelemetry> SolanaIndexer<S, T> {
    /// Delay between retries of transient RPC failures
    const RETRY_DELAY: Duration = Duration::from_millis(500);

    pub fn new(sol: SolConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        let program_id = Pubkey::from_str(&sol.program_address).with_context(|| {
            format!(
                "failed to parse solana program address: {}",
                sol.program_address
            )
        })?;

        let client = SolanaClient::for_indexer(
            sol.rpc_http_url.clone(),
            sol.rpc_ws_url.clone(),
            program_id,
            Arc::new(NoopPublisherTelemetry), // Indexer does not publish
        );

        Ok(Self {
            program_id,
            client,
            state_manager,
            telemetry,
        })
    }

    /// Catchup items in `[processed + 1, anchor)` fetched in chunks.
    /// `fetch_slots` failures are propagated so the supervisor can restart.
    async fn catchup_blocks(
        &self,
        anchor_height: u64,
    ) -> anyhow::Result<
        Pin<Box<dyn Stream<Item = anyhow::Result<CatchupBlockItem>> + Send + 'static>>,
    > {
        let Some((start_slot, end_slot)) = self.catchup_range(anchor_height).await else {
            tracing::info!(anchor_slot = anchor_height, "solana catchup not required");
            return Ok(Box::pin(stream::empty()));
        };

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

    /// Range of slots that still need to be caught up, inclusive on both ends.
    /// `None` means we're already caught up.
    // TODO: https://github.com/sig-net/mpc/issues/777
    async fn catchup_range(&self, anchor_height: u64) -> Option<(u64, u64)> {
        let start_slot = self
            .state_manager
            .get_processed_block(Chain::Solana)
            .await
            .map(|n| n.saturating_add(1))
            .unwrap_or(anchor_height);

        let end_slot = anchor_height.saturating_sub(1);
        (start_slot <= end_slot).then_some((start_slot, end_slot))
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

    /// Live phase: forward events produced by the live subscription until
    /// `cancel` fires or the producer terminates.
    async fn forward_live_events(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        live_rx: &mut mpsc::Receiver<ChainEvent>,
        cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                event = live_rx.recv() => event,
            };
            let Some(event) = event else {
                anyhow::bail!("solana live event producer terminated");
            };
            events_tx
                .send(event)
                .await
                .context("failed to forward live solana event")?;
        }
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
            process_transaction(events_tx, &self.program_id, None, tx).await?;
        }

        events_tx.send(ChainEvent::Block(height)).await?;
        Ok(())
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for SolanaIndexer<S, T> {
    const CHAIN: Chain = Chain::Solana;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Start the live subscription first: it buffers events while catchup
        // runs, and resolves the anchor slot once the WS is live so catchup
        // covers `[persisted_block, anchor)` with no gaps. The abort-on-drop
        // guard ties the task's lifetime to this `run()`.

        // TODO: live channel is bounded, if catchup takes too long live
        // channel will fill up and block subscription task, websocket connection will be closed.
        // Consider better solution.
        let (live_tx, mut live_rx) = chain_event_channel();
        let (anchor_tx, anchor_rx) = oneshot::channel::<u64>();
        let _live_task = AbortOnDrop(tokio::spawn(subscribe_and_buffer_live_events(
            self.program_id,
            self.client.clone(),
            live_tx,
            anchor_tx,
            self.telemetry.clone(),
        )));

        let anchor = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            anchor = anchor_rx => anchor.context("solana live subscription ended before resolving anchor slot")?,
        };

        let catchup_started_at = Instant::now();
        let mut catchup_iter = self.catchup_blocks(anchor).await?;
        loop {
            let item = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                item = catchup_iter.next() => item,
            };
            let Some(res) = item else { break };
            // Propagate RPC page errors so supervisor restarts cleanly
            let (slot, block) = res?;
            self.process_catchup_retrying(&events_tx, slot, &block, &cancel)
                .await;
        }

        tracing::info!(
            anchor_slot = anchor,
            elapsed = ?catchup_started_at.elapsed(),
            "solana catchup complete"
        );

        events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send catchup completed event")?;

        self.forward_live_events(&events_tx, &mut live_rx, &cancel)
            .await
    }
}

/// Subscribe to the live WS feed, preprocess events into `ChainEvent`s, and buffer them
/// in `live_tx`. The anchor slot (current confirmed slot at subscription time) is sent
/// via `anchor_tx` so that `run()` can bound catchup with it.
///
/// The anchor is resolved inside `subscribe_to_program_events` immediately after the WS
/// subscription is established — ensuring the subscription is live before we anchor, so
/// catchup covers `[persisted_block, anchor)` with no gaps.
async fn subscribe_and_buffer_live_events<T: ChainTelemetry>(
    program_id: Pubkey,
    client: SolanaClient,
    live_tx: mpsc::Sender<ChainEvent>,
    anchor_tx: oneshot::Sender<u64>,
    telemetry: T,
) {
    let mut anchor_tx = Some(anchor_tx);
    // Deliberately does not resubscribe in-place: blocks produced while the
    // websocket was down would be silently skipped. Returning drops `live_tx`,
    // which ends `forward_live_events` and fails `run()`, so the supervisor
    // restarts the indexer — resolving a fresh anchor and catching up
    // `[persisted_block, anchor)` before live events resume.
    if let Err(err) =
        subscribe_to_program_events(program_id, &client, live_tx, &mut anchor_tx, telemetry).await
    {
        tracing::warn!("Live solana subscription failed: {:?}", err);
    }
}

async fn subscribe_to_program_events<T: ChainTelemetry>(
    program_id: Pubkey,
    client: &SolanaClient,
    events_tx: mpsc::Sender<ChainEvent>,
    anchor_tx: &mut Option<oneshot::Sender<u64>>,
    telemetry: T,
) -> anyhow::Result<()> {
    let pubsub_client = PubsubClient::new(&client.rpc_ws_url).await?;

    let filter = RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]);
    let config = RpcTransactionLogsConfig {
        commitment: Some(CommitmentConfig::confirmed()),
    };

    let (mut stream, _unsubscriber) = pubsub_client.logs_subscribe(filter, config).await?;

    // The WS subscription is now live. Fetch the current confirmed slot via RPC as the
    // anchor: this is the correct boundary because the subscription is already buffering
    // all new events, so catchup can safely cover [persisted_block, anchor) via RPC history
    // with no gaps. We do not wait for the first WS event because that could deadlock if
    // no program-mentioning transactions arrive (e.g. in tests after a single sign call).
    if let Some(anchor_tx) = anchor_tx.take() {
        // TODO: this should probably use client.get_slot with retry strategy,
        // otherwise if RPC fails the anchor will not be sent and catchup will not run
        match client
            .rpc_client
            .get_slot_with_commitment(CommitmentConfig::confirmed())
            .await
        {
            Ok(slot) => {
                let _ = anchor_tx.send(slot);
            }
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to fetch anchor slot after WS subscribe; retry on reconnect"
                );
                // Drop anchor_tx — livestream() will receive a RecvError and propagate the failure.
            }
        }
    }

    // stall watchdog
    let stall_timeout = Duration::from_secs(60);
    let mut last_ws_msg = Instant::now();
    let mut watchdog = tokio::time::interval(Duration::from_secs(5));

    // Mirrors `wait_for_finalized_block`'s staleness warn in the Ethereum indexer
    const SLOT_STALL_WARN_SECS: u64 = 60;
    let mut last_slot: Option<u64> = None;
    let mut last_slot_advanced_at = Instant::now();
    let mut last_slot_stall_warn_at = Instant::now();

    // Simple TTL cache to avoid multiple getTransaction calls for the same signature
    let mut seen: HashMap<Signature, Instant> = HashMap::new();
    let ttl = Duration::from_secs(30);

    let program_invoke_log = format!("Program {program_id} invoke [");

    loop {
        // TODO: this might introduce CPU overhead if the WS is busy, consider a more efficient alternative
        cleanup_seen_cache(&mut seen, ttl);
        tokio::select! {
            // Receive WS logs
            maybe = stream.next() => {
                match maybe {
                    Some(response) => {
                        last_ws_msg = Instant::now();

                        let slot = response.context.slot;

                        // Update last observed slot and reset the stall timer if it advanced
                        if last_slot.is_none_or(|s| slot > s) {
                            last_slot = Some(slot);
                            last_slot_advanced_at = Instant::now();
                        }

                        // Update indexed block metrics
                        telemetry.block_indexed(slot);

                        let logs = &response.value.logs;
                        if response.value.err.is_some() || !has_log_starts_with(logs, &program_invoke_log) {
                            // block is not relevant to our program, skip but still
                            // emit block event for progress tracking
                            if let Err(err) = events_tx.send(ChainEvent::Block(slot)).await {
                                tracing::warn!(?err, "failed to send block event");
                            }
                            continue;
                        }

                        let Ok(signature) = Signature::from_str(&response.value.signature) else {
                            tracing::warn!("Invalid signature format");
                            continue;
                        };

                        if seen.contains_key(&signature) {
                            continue;
                        }

                        let tx_res = match client.get_tx(&signature).await {
                            Ok(tx) => tx,
                            Err(e) => {
                                tracing::warn!("Failed to fetch transaction {}: {}", signature, e);
                                continue;
                            }
                        };

                        let now = Instant::now();
                        seen.insert(signature, now);

                        if let Err(err) = process_transaction(
                            &events_tx,
                            &program_id,
                            Some(signature),
                            &tx_res.transaction,
                        ).await {
                            tracing::warn!(?err, sig = %signature, "failed to parse solana tx events");
                            continue;
                        }

                        // Emit block event for every observed slot
                        if let Err(err) = events_tx.send(ChainEvent::Block(slot)).await {
                            tracing::warn!(?err, "failed to send block event");
                        }
                    }
                    None => {
                        // stream ended => force reconnect
                        anyhow::bail!("solana logs stream ended (None), reconnecting");
                    }
                }
            }

            // Watchdog tick
            _ = watchdog.tick() => {
                if last_ws_msg.elapsed() > stall_timeout {
                    anyhow::bail!(
                        "solana logs subscription stalled: no ws message for {:?}",
                        stall_timeout
                    );
                }

                // Warn if the last observed slot has not advanced for a while
                let now = Instant::now();
                let secs_since_advance = now.duration_since(last_slot_advanced_at).as_secs();
                if secs_since_advance >= SLOT_STALL_WARN_SECS
                    && now.duration_since(last_slot_stall_warn_at).as_secs() >= SLOT_STALL_WARN_SECS
                {
                    tracing::warn!(
                        last_slot,
                        secs_since_advance,
                        "solana observed slot has not advanced; \
                         live feed may be stuck delivering stale slots. \
                         If this persists the stream watchdog will restart the pipeline"
                    );
                    last_slot_stall_warn_at = now;
                }
            }
        }
    }
}

fn has_log_starts_with(logs: &[String], start_with: &str) -> bool {
    logs.iter().any(|l| l.starts_with(start_with))
}

async fn process_transaction(
    events_tx: &mpsc::Sender<ChainEvent>,
    program_id: &Pubkey,
    known_signature: Option<Signature>,
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

    let signature = match known_signature {
        Some(signature) => signature,
        None => extract_tx_signature(&tx.transaction)?,
    };
    emit_events(events_tx, program_id, signature, tx, logs).await
}

// Clean up seen cache based on TTL
fn cleanup_seen_cache(seen: &mut HashMap<Signature, Instant>, ttl: Duration) {
    let now = Instant::now();
    seen.retain(|_, &mut t| now.duration_since(t) < ttl);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::events::SolanaSignEvent;

    use super::*;
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
            url.replace("http", "ws"),
            program_id,
            Arc::new(NoopPublisherTelemetry),
        )
        .with_fast_retry();
        SolanaIndexer {
            program_id,
            client,
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

    #[test]
    fn block_fetch_config_sets_max_supported_transaction_version() {
        let config = SolanaClient::block_fetch_config();

        assert_eq!(config.max_supported_transaction_version, Some(0));
        assert_eq!(config.transaction_details, Some(TransactionDetails::Full));
        assert_eq!(config.encoding, Some(UiTransactionEncoding::JsonParsed));
        assert_eq!(config.rewards, Some(false));
        assert_eq!(
            config.commitment.map(|commitment| commitment.commitment),
            Some(CommitmentLevel::Confirmed)
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
        let mut stream = indexer.catchup_blocks(ANCHOR_SLOT).await.unwrap();
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

        let mut stream = indexer.catchup_blocks(ANCHOR_SLOT).await.unwrap();
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

        let mut stream = indexer.catchup_blocks(ANCHOR_SLOT).await.unwrap();

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
        let mut catchup = indexer.catchup_blocks(9).await.unwrap();
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

        let mut catchup = indexer.catchup_blocks(10).await.unwrap();

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
    async fn forward_live_events_forwards_until_cancel() {
        let indexer = test_indexer("http://localhost:1", MockStateManager::new());
        let (events_tx, mut events_rx) = mpsc::channel(16);
        let (live_tx, mut live_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();

        live_tx.send(ChainEvent::Block(42)).await.unwrap();

        let mut forward = Box::pin(indexer.forward_live_events(&events_tx, &mut live_rx, &cancel));
        tokio::select! {
            result = &mut forward => panic!("forwarding ended early: {result:?}"),
            event = events_rx.recv() => {
                assert!(matches!(event, Some(ChainEvent::Block(42))));
            }
        }

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), &mut forward)
            .await
            .expect("forwarding should stop promptly on cancel")
            .unwrap();
    }

    #[tokio::test]
    async fn forward_live_events_bails_when_producer_drops() {
        let indexer = test_indexer("http://localhost:1", MockStateManager::new());
        let (events_tx, _events_rx) = mpsc::channel(16);
        let (live_tx, mut live_rx) = mpsc::channel::<ChainEvent>(16);
        drop(live_tx);

        let result = indexer
            .forward_live_events(&events_tx, &mut live_rx, &CancellationToken::new())
            .await;
        assert!(result.is_err());
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
            .unwrap_or_else(|_| "SigDuEPNeDjh3oJv7MUraPN7zaTFomS6ZWfpXwjUg4B".to_string());

        let http_url = format!("https://solana-devnet.g.alchemy.com/v2/{api_key}");
        let ws_url = format!("wss://solana-devnet.g.alchemy.com/v2/{api_key}");

        let state_manager = MockStateManager::new();
        let (events_tx, mut events_rx) = mpsc::channel(1_000_000);

        let client = SolanaClient::for_indexer(
            http_url.clone(),
            ws_url.clone(),
            Pubkey::from_str(&sol_addr).unwrap(),
            Arc::new(NoopPublisherTelemetry),
        );

        let indexer = SolanaIndexer {
            program_id: Pubkey::from_str(&sol_addr).unwrap(),
            client,
            state_manager,
            telemetry: NoopChainTelemetry,
        };

        // Resolve anchor slot
        let anchor_height = indexer
            .client
            .get_slot()
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
