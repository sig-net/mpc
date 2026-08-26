//! Catch up from the persisted checkpoint, then follow the live finalized chain. For
//! each block, discovery reads the ordered body and decodes the singleton's transcript
//! emissions. The source also returns the V1 proof-ready seed for the block, but the
//! indexer currently discards it; persistence and independent verification come later.

use crate::config::MidnightConfig;
use crate::convert::generate_sign_request;
use crate::emissions::{EmissionKind, SingletonCallEmissions};
use crate::reader::{
    decode_notification, decode_response_payload, resolve_verified_record,
    signet_field_node_by_path, unpack_notification_v1, Resolved,
};
use crate::records::SignBidirectionalEventNotification;
use crate::rpc::{is_oversized_contract_state, BlockRef};
use crate::source::{BlockEmissions, ChainSource, ContractState, LiveSource};

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, RespondBidirectionalEvent, SignatureRespondedEvent,
};
use mpc_utils::{
    task::{retry_until_some, CancellationTokenExt as _},
    time::current_unix_timestamp,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const RETRY_DELAY: Duration = Duration::from_millis(500);

#[derive(Debug)]
pub(crate) struct BlockHold {
    pub reason: &'static str,
    pub height: u64,
    pub cause: anyhow::Error,
}

impl BlockHold {
    pub(crate) fn new(reason: &'static str, height: u64, cause: impl Into<anyhow::Error>) -> Self {
        Self {
            reason,
            height,
            cause: cause.into(),
        }
    }
}

impl std::fmt::Display for BlockHold {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} at block {}: {:#}",
            self.reason, self.height, self.cause
        )
    }
}

impl std::error::Error for BlockHold {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

/// Midnight indexer: `run()` owns the whole read path.
pub struct MidnightIndexer<S: StateManager, T: ChainTelemetry> {
    config: MidnightConfig,
    state_manager: S,
    telemetry: T,
}

impl<S: StateManager, T: ChainTelemetry> MidnightIndexer<S, T> {
    pub async fn new(
        config: MidnightConfig,
        state_manager: S,
        telemetry: T,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            state_manager,
            telemetry,
        })
    }
}

/// One drop, one WARN, one distinct reason label.
fn drop_entry<T>(
    reason: &'static str,
    height: u64,
    request_id: Option<[u8; 32]>,
    detail: &str,
) -> Option<T> {
    tracing::warn!(
        reason,
        height,
        request_id = request_id.map(hex::encode),
        "midnight entry dropped: {detail}"
    );
    None
}

/// The outcome of fully indexing one block: processed and emitted, or `cancel` fired
/// mid-flight, which every caller answers by returning `Ok(())`.
enum Indexed {
    Done,
    Cancelled,
}

impl<S: StateManager, T: ChainTelemetry> MidnightIndexer<S, T> {
    /// Per-block processing, shared by catchup and live: discover the singleton's
    /// transcript emissions from the finalized block body and translate them.
    async fn process_block<C: ChainSource>(
        &self,
        source: &C,
        block: &BlockRef,
    ) -> anyhow::Result<Vec<ChainEvent>> {
        let Some(BlockEmissions {
            proof_seed,
            candidates,
        }) = source
            .block_emissions(block, self.config.central_address.as_bytes())
            .await?
        else {
            return Ok(Vec::new());
        };
        // V1 carries the raw proof seed across the source boundary but has no verifier
        // or persistence policy yet. A later verifier consumes this exact object.
        drop(proof_seed);
        let mut events = Vec::new();
        let mut indexed_ts = None;
        for candidate in candidates {
            for SingletonCallEmissions {
                call_index,
                emissions,
            } in candidate.calls
            {
                if emissions.is_empty() {
                    tracing::warn!(
                        reason = "singleton-call-silent",
                        height = block.number,
                        extrinsic_index = candidate.extrinsic_index,
                        call_index,
                        "midnight singleton call emitted no decoded events"
                    );
                }
                for emission in emissions {
                    match emission.kind {
                        EmissionKind::SignBidirectional => {
                            let notification = decode_notification(&emission.payload);
                            let indexed_ts = *indexed_ts.get_or_insert_with(current_unix_timestamp);
                            if let Some(request) = self
                                .process_entry(
                                    source,
                                    notification,
                                    &block.hash,
                                    block.number,
                                    indexed_ts,
                                )
                                .await?
                            {
                                events.push(ChainEvent::SignRequest {
                                    request: Arc::new(request),
                                    block_timestamp: None,
                                });
                            }
                        }
                        EmissionKind::SignatureResponded => {
                            let decoded = decode_response_payload(&emission.payload);
                            match decoded.signature {
                                Ok(signature) => {
                                    events.push(ChainEvent::Respond(SignatureRespondedEvent {
                                        request_id: decoded.request_id,
                                        signature,
                                        chain: Chain::Midnight,
                                    }));
                                }
                                Err(err) => {
                                    drop_entry::<()>(
                                        "response-signature-invalid",
                                        block.number,
                                        Some(decoded.request_id),
                                        &format!("respond: {err:#}"),
                                    );
                                }
                            }
                        }
                        EmissionKind::RespondBidirectional => {
                            let decoded = decode_response_payload(&emission.payload);
                            match decoded.signature {
                                Ok(signature) => events.push(ChainEvent::RespondBidirectional(
                                    RespondBidirectionalEvent {
                                        request_id: decoded.request_id,
                                        signature,
                                        chain: Chain::Midnight,
                                    },
                                )),
                                Err(err) => {
                                    drop_entry::<()>(
                                        "response-signature-invalid",
                                        block.number,
                                        Some(decoded.request_id),
                                        &format!("respondBidirectional: {err:#}"),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(events)
    }

    /// One decoded notification: unpack it, read the caller's ledger at
    /// `at_hash`, gate through `resolve_verified_record`, convert.
    ///
    async fn process_entry<C: ChainSource>(
        &self,
        source: &C,
        notification: SignBidirectionalEventNotification,
        at_hash: &str,
        height: u64,
        indexed_ts: u64,
    ) -> anyhow::Result<Option<IndexedSignRequest>> {
        let rid = notification.request_id;
        if notification.version != 1 {
            return Ok(drop_entry(
                "notification-version",
                height,
                Some(rid),
                &format!("unsupported version {}", notification.version),
            ));
        }
        let unpacked = match unpack_notification_v1(&notification) {
            Ok(unpacked) => unpacked,
            // Depth and path are caller-supplied payload bytes, not circuit-enforced.
            Err(err) => {
                return Ok(drop_entry(
                    "notification-payload",
                    height,
                    Some(rid),
                    &format!("{err:#}"),
                ));
            }
        };
        let caller_hex = hex::encode(unpacked.caller_address);

        // TODO: decide whether `caller_address` must be checked against the
        // cross-contract-call initiator of the transaction that filed this notification.
        // It is producer-supplied, so any contract can notify naming another, which
        // triggers a signature over a record that contract filed. What that record says
        // is already authenticated below: `resolve_verified_record` recomputes the
        // request id and `generate_sign_request` requires `sender` to equal the address the
        // record was read from. The exposure is therefore third-party triggering, not
        // forgery, and the open question is whether that is worth gating. Gating it
        // means joining each notification to the central call it came from through the
        // claimed communication commitment, which the ledger validates for uniqueness
        // and for corresponding to a real call.

        // Authority: the caller's own ledger at the SAME finalized hash the
        // notification was read at.
        let caller_tree = match source.contract_state_tree(&caller_hex, at_hash).await {
            Ok(ContractState::Tree(tree)) => tree,
            Ok(ContractState::Absent) => {
                return Ok(drop_entry(
                    "caller-contract-absent",
                    height,
                    Some(rid),
                    &caller_hex,
                ));
            }
            Ok(ContractState::Undecodable(err)) => {
                return Ok(drop_entry(
                    "caller-state-undecodable",
                    height,
                    Some(rid),
                    &format!("{caller_hex}: {err:#}"),
                ));
            }
            Err(err) if is_oversized_contract_state(&err) => {
                return Ok(drop_entry(
                    "caller-state-too-large",
                    height,
                    Some(rid),
                    &format!("{caller_hex}: {err:#}"),
                ));
            }
            Err(err) => {
                return Err(err.context(format!("failed to read caller state {caller_hex}")));
            }
        };
        let field = match signet_field_node_by_path(&caller_tree, &unpacked.requests_path) {
            Ok(field) => field,
            Err(err) => {
                // Producer-supplied data, so an out-of-range walk is a per-entry
                // drop rather than an abort.
                return Ok(drop_entry(
                    "requests-field-walk",
                    height,
                    Some(rid),
                    &format!("{err:#}"),
                ));
            }
        };
        // The resolver reports nothing and hands back the reason, so this is the only
        // place a resolution is logged.
        let record = match resolve_verified_record(field, rid) {
            Resolved::Found(record) => *record,
            Resolved::Absent => {
                // Not a fault: the id is absent from the caller's own index.
                tracing::debug!(
                    reason = "request-absent",
                    height,
                    request_id = %hex::encode(rid),
                    "midnight entry produced no request: the id is not in the caller's index"
                );
                return Ok(None);
            }
            Resolved::Dropped { reason, detail } => {
                return Ok(drop_entry(reason, height, Some(rid), &detail));
            }
        };
        match generate_sign_request(&record, &unpacked.caller_address, rid, indexed_ts) {
            Ok(request) => Ok(Some(request)),
            Err(err) => {
                // Every conversion failure is a per-record data property, so drop with
                // the id and reason and continue.
                Ok(drop_entry(
                    "convert-rejected",
                    height,
                    Some(rid),
                    &format!("{err:#}"),
                ))
            }
        }
    }

    /// [`process_block`](Self::process_block) under the per-block retry policy.
    /// Permanent scanner failures escape immediately; transport failures retry here.
    async fn process_block_retrying<C: ChainSource>(
        &self,
        source: &C,
        block: &BlockRef,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<Vec<ChainEvent>>> {
        loop {
            let result = tokio::select! {
                _ = cancel.cancelled() => return Ok(None),
                result = self.process_block(source, block) => result,
            };
            match result {
                Ok(requests) => return Ok(Some(requests)),
                Err(err) => {
                    if let Some(block_hold) = err.downcast_ref::<BlockHold>() {
                        tracing::error!(
                            reason = block_hold.reason,
                            height = block_hold.height,
                            error = %format_args!("{:#}", block_hold.cause),
                            "midnight block processing held"
                        );
                        return Err(err);
                    }
                    tracing::warn!(
                        reason = "retrying",
                        height = block.number,
                        "midnight block processing failed: {err:#}; retrying"
                    );
                }
            }
            if cancel.cancelled_within(RETRY_DELAY).await {
                return Ok(None);
            }
        }
    }

    /// One catchup or gap height: resolve the number to its finalized block, then
    /// [`index_block`](Self::index_block).
    async fn index_height<C: ChainSource>(
        &self,
        source: &C,
        events_tx: &mpsc::Sender<ChainEvent>,
        number: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Indexed> {
        let Some(block) =
            retry_until_some(cancel, RETRY_DELAY, "midnight block lookup", || async {
                source.block_at(number).await.map(Some)
            })
            .await
        else {
            return Ok(Indexed::Cancelled);
        };
        self.index_block(source, events_tx, &block, cancel).await
    }

    /// Processes and emits one block under the retry policy, surfacing the pruning
    /// signature or a halt as the error that restarts the run.
    async fn index_block<C: ChainSource>(
        &self,
        source: &C,
        events_tx: &mpsc::Sender<ChainEvent>,
        block: &BlockRef,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Indexed> {
        let Some(events) = self.process_block_retrying(source, block, cancel).await? else {
            return Ok(Indexed::Cancelled);
        };
        self.emit_block(events_tx, block, events).await?;
        Ok(Indexed::Done)
    }

    /// Emits a block's lifecycle events, then its Block event, then records telemetry.
    ///
    /// The Block event is the whole progress report: the node advances the persisted
    /// height only after CONSUMING it, which is what makes a supervised restart
    /// self-healing. Delivery is therefore at-least-once (blocks past the last
    /// consumed checkpoint re-emit on restart); dedup is by SignId downstream, never
    /// here.
    async fn emit_block(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        block: &BlockRef,
        events: Vec<ChainEvent>,
    ) -> anyhow::Result<()> {
        for event in events {
            events_tx
                .send(event)
                .await
                .context("failed to send a midnight lifecycle event")?;
        }
        events_tx
            .send(ChainEvent::Block(block.number))
            .await
            .context("failed to send a midnight block event")?;
        self.telemetry.block_indexed(block.number);
        Ok(())
    }

    /// `run()` over an explicit [`ChainSource`], the fixture seam.
    pub(crate) async fn run_with_source<C: ChainSource>(
        &self,
        source: &C,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let checkpoint = self
            .state_manager
            .get_processed_block(Chain::Midnight)
            .await
            .unwrap_or(0);
        let Some(anchor) =
            retry_until_some(&cancel, RETRY_DELAY, "midnight anchor sampling", || async {
                source.finalized_head().await.map(Some)
            })
            .await
        else {
            return Ok(());
        };

        let mut last_processed = checkpoint;
        if checkpoint == 0 {
            // A fresh node has no gap to close, and walking from genesis would
            // reprocess the whole chain, so catchup anchors at the finalized head.
            tracing::info!(
                anchor = anchor.number,
                "midnight fresh start: no checkpoint, anchoring at the finalized head"
            );
            last_processed = anchor.number;
        } else {
            for number in checkpoint.saturating_add(1)..anchor.number {
                match self
                    .index_height(source, &events_tx, number, &cancel)
                    .await?
                {
                    Indexed::Done => last_processed = number,
                    Indexed::Cancelled => return Ok(()),
                }
            }
            if anchor.number > checkpoint {
                match self
                    .index_block(source, &events_tx, &anchor, &cancel)
                    .await?
                {
                    Indexed::Done => last_processed = anchor.number,
                    Indexed::Cancelled => return Ok(()),
                }
            }
        }
        events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send midnight catchup completed event")?;

        let mut last_progress = tokio::time::Instant::now();
        loop {
            if cancel
                .cancelled_within(self.config.indexer.poll_interval)
                .await
            {
                return Ok(());
            }

            let block = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = source.finalized_head() => result
                    .context("failed to poll the midnight finalized head")?,
            };

            if block.number <= last_processed {
                if last_progress.elapsed() >= self.config.indexer.stall_timeout {
                    anyhow::bail!(
                        "midnight finalized head made no progress for {:?}",
                        self.config.indexer.stall_timeout
                    );
                }
                continue;
            }
            for number in last_processed.saturating_add(1)..block.number {
                match self
                    .index_height(source, &events_tx, number, &cancel)
                    .await?
                {
                    Indexed::Done => {}
                    Indexed::Cancelled => return Ok(()),
                }
            }
            match self
                .index_block(source, &events_tx, &block, &cancel)
                .await?
            {
                Indexed::Done => {
                    last_processed = block.number;
                    last_progress = tokio::time::Instant::now();
                }
                Indexed::Cancelled => return Ok(()),
            }
        }
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for MidnightIndexer<S, T> {
    const CHAIN: Chain = Chain::Midnight;

    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let source = LiveSource::connect(&self.config).await?;
        self.run_with_source(&source, events_tx, cancel).await
    }
}

#[cfg(test)]
#[path = "indexer_tests.rs"]
mod tests;
