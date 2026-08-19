//! Catchup from the persisted checkpoint, then the live finalized loop.

use crate::config::MidnightConfig;
use crate::convert::generate_sign_request;
use crate::reader::{
    decode_notification, decode_response_entry, resolve_verified_record, signet_field_node_by_path,
    signet_map_key_rid, unpack_notification_v1, DecodedResponseEntry, Node, Resolved,
    CENTRAL_LEDGER_FIELDS, NOTIFICATION_MAP_FIELD, RESPOND_BIDIRECTIONAL_MAP_FIELD,
    RESPOND_MAP_FIELD,
};
use crate::rpc::{BlockRef, ReadFailure};
use crate::source::{ChainSource, ContractState, LiveSource};

use midnight_base_crypto::fab::AlignedValue;
use midnight_onchain_state::state::StateValue;

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use async_trait::async_trait;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, RespondBidirectionalEvent, SignatureRespondedEvent,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const RETRY_DELAY: Duration = Duration::from_millis(500);

/// Marker context on a central state the ledger deserializer refused: this build can
/// no longer read the chain, so the block-level retry must halt on it, not spin.
const CENTRAL_STATE_UNDECODABLE: &str = "the central contract's own state did not decode";

/// A typed permanent failure so the retry boundary can halt without parsing prose.
#[derive(Debug)]
struct ResponseSchemaDrift {
    response_map: &'static str,
    request_id: Option<[u8; 32]>,
    cause: anyhow::Error,
}

impl std::fmt::Display for ResponseSchemaDrift {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "central {} entry violates the deployed contract schema",
            self.response_map
        )?;
        if let Some(request_id) = self.request_id {
            write!(formatter, " for request {}", hex::encode(request_id))?;
        }
        write!(formatter, ": {:#}", self.cause)
    }
}

impl std::error::Error for ResponseSchemaDrift {
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
        // `MidnightConfig` is publicly constructible with `String` fields, so a non-CLI
        // caller reaches here without passing the CLI's own check.
        config.validate()?;
        // Network-free beyond that.
        Ok(Self {
            config,
            state_manager,
            telemetry,
        })
    }
}

pub(crate) fn unix_now() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before the unix epoch")?
        .as_secs())
}

/// One entry of a central map, keyed by the composite `SignetMapKey`.
#[derive(Clone, PartialEq)]
pub(crate) struct MapEntry {
    pub key: AlignedValue,
    pub value: Node,
}

#[derive(Clone, Default)]
struct CentralEntries {
    notifications: Vec<MapEntry>,
    responses: Vec<MapEntry>,
    bidirectional_responses: Vec<MapEntry>,
}

type CentralCache = Option<(String, CentralEntries)>;

fn new_entries<'a>(entries: &'a [MapEntry], parent: &[MapEntry]) -> Vec<&'a MapEntry> {
    let parent_keys: HashSet<&AlignedValue> = parent.iter().map(|entry| &entry.key).collect();
    entries
        .iter()
        .filter(|entry| !parent_keys.contains(&entry.key))
        .collect()
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

/// [`drop_entry`] at ERROR: the failure may be node-local, not the caller's.
fn drop_entry_unattributed<T>(
    reason: &'static str,
    height: u64,
    request_id: Option<[u8; 32]>,
    detail: &str,
) -> Option<T> {
    tracing::error!(
        reason,
        height,
        request_id = request_id.map(hex::encode),
        "midnight entry dropped: {detail}"
    );
    None
}

fn response_event(
    entry: &MapEntry,
    response_map: &'static str,
    height: u64,
    make_event: impl FnOnce([u8; 32], mpc_primitives::Signature) -> ChainEvent,
) -> anyhow::Result<Option<ChainEvent>> {
    let request_id = signet_map_key_rid(&entry.key);
    let DecodedResponseEntry {
        request_id: decoded_request_id,
        signature,
    } = match decode_response_entry(&entry.key, &entry.value) {
        Ok(decoded) => decoded,
        Err(cause) => {
            let drift = ResponseSchemaDrift {
                response_map,
                request_id,
                cause,
            };
            tracing::error!(
                reason = "response-entry-structural-hold",
                height,
                response_map,
                request_id = request_id.map(hex::encode),
                error = %format_args!("{drift:#}"),
                "midnight central response entry violates the deployed contract schema; holding block"
            );
            return Err(drift.into());
        }
    };

    match signature {
        Ok(signature) => Ok(Some(make_event(decoded_request_id, signature))),
        Err(err) => Ok(drop_entry(
            "response-signature-invalid",
            height,
            Some(decoded_request_id),
            &format!("{response_map}: {err:#}"),
        )),
    }
}

/// Names the one failure a retry never clears. The supervised restart resumes from
/// the retained watermark and arrives back here, so the node holds at this height
/// until its rpc node can serve the state.
fn note_unservable(err: anyhow::Error, height: u64) -> anyhow::Error {
    tracing::error!(
        reason = "state-unservable-hold",
        height,
        "midnight node cannot serve state at this height; holding until it can. If \
         this persists, switch to an archive node"
    );
    err
}

/// The outcome of fully indexing one block: processed and emitted, or `cancel` fired
/// mid-flight, which every caller answers by returning `Ok(())`.
enum Indexed {
    Done,
    Cancelled,
}

/// The outcome of an operation run under [`retry_until_cancelled`].
enum Retried<T> {
    /// Succeeded, after however many retries.
    Done(T),
    /// `cancel` fired mid-flight; every caller answers this by returning `Ok(())`.
    Cancelled,
    /// The node cannot serve state at this height: the one failure a retry never
    /// clears. Each caller applies its own policy, which is why it is handed back
    /// rather than resolved here.
    Unservable(anyhow::Error),
    /// The client's connection is gone and every further call fails until `run()`
    /// is rebuilt: ends the run so the supervisor's restart reconnects.
    ClientClosed(anyhow::Error),
    /// Permanent at this height and never the caller's; the ERROR is logged where
    /// it is classified, so consumers just end the run and the restart holds.
    Halted(anyhow::Error),
}

/// Retries `attempt` every [`RETRY_DELAY`] until it succeeds or `cancel` fires.
///
/// The per-item retry the other chains' indexers apply around their own block
/// processing: a node hiccup costs one retry here, not a supervised
/// restart that re-runs backlog recovery, re-anchors and
/// re-queues the pending backlog. Only the pruning signature escapes, as
/// [`Retried::Unservable`]: no number of retries makes a pruned node serve state,
/// so retrying it would spin until the watchdog fires.
async fn retry_until_cancelled<T, F, Fut>(
    what: &'static str,
    height: u64,
    cancel: &CancellationToken,
    mut attempt: F,
) -> Retried<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => return Retried::Cancelled,
            result = attempt() => result,
        };
        match result {
            Ok(value) => return Retried::Done(value),
            Err(err) => match ReadFailure::of(&err) {
                Some(ReadFailure::Unservable) => return Retried::Unservable(err),
                Some(ReadFailure::ClientClosed) => return Retried::ClientClosed(err),
                _ => tracing::warn!(
                    reason = "retrying",
                    height,
                    "midnight {what} failed: {err:#}; retrying"
                ),
            },
        }
        tokio::select! {
            _ = cancel.cancelled() => return Retried::Cancelled,
            _ = tokio::time::sleep(RETRY_DELAY) => {}
        }
    }
}

/// Retries a startup step every [`RETRY_DELAY`] until it succeeds or `cancel` fires
/// (`Ok(None)`). No unservable escape, unlike [`retry_until_cancelled`]: at startup a
/// restart would only re-run backlog recovery to arrive back at the same step. The
/// dead-client class does escape (`Err`), since no in-place retry can revive a
/// closed client and only the supervised restart rebuilds the connection.
async fn retry_startup<T, F, Fut>(
    what: &'static str,
    cancel: &CancellationToken,
    mut attempt: F,
) -> anyhow::Result<Option<T>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => return Ok(None),
            result = attempt() => result,
        };
        match result {
            Ok(value) => return Ok(Some(value)),
            Err(err) if ReadFailure::of(&err) == Some(ReadFailure::ClientClosed) => {
                return Err(err);
            }
            Err(err) => tracing::warn!("midnight {what} failed: {err:#}; retrying"),
        }
        tokio::select! {
            _ = cancel.cancelled() => return Ok(None),
            _ = tokio::time::sleep(RETRY_DELAY) => {}
        }
    }
}

impl<S: StateManager, T: ChainTelemetry> MidnightIndexer<S, T> {
    /// The central singleton's tree at `at_hash`, or `None` when the contract is not
    /// present there, which is ordinary during catchup from before deployment.
    async fn central_tree<C: ChainSource>(
        &self,
        source: &C,
        at_hash: &str,
    ) -> anyhow::Result<Option<Node>> {
        match source
            .contract_state_tree(&self.config.central_address, at_hash)
            .await?
        {
            ContractState::Tree(tree) => Ok(Some(tree)),
            ContractState::Absent => Ok(None),
            ContractState::Undecodable(err) => Err(err.context(CENTRAL_STATE_UNDECODABLE)),
        }
    }

    fn map_entries(
        tree: &Node,
        field: u8,
        field_name: &'static str,
    ) -> anyhow::Result<Vec<MapEntry>> {
        let node = signet_field_node_by_path(tree, &[field])
            .with_context(|| format!("central {field_name} field"))?;
        let StateValue::Map(entries) = node else {
            anyhow::bail!("central field {field} ({field_name}) is not a map");
        };
        Ok(entries
            .iter()
            .map(|entry| {
                let (key, value) = &*entry;
                MapEntry {
                    key: (**key).clone(),
                    value: (**value).clone(),
                }
            })
            .collect())
    }

    /// The three append logs consumed by the node, all from one finalized central tree.
    /// Their positions and map shapes are fixed by the deployed singleton, so drift
    /// halts before the block checkpoint can advance.
    fn central_entries(tree: &Node) -> anyhow::Result<CentralEntries> {
        let StateValue::Array(fields) = tree else {
            anyhow::bail!("central singleton state root is not an array");
        };
        anyhow::ensure!(
            fields.len() == CENTRAL_LEDGER_FIELDS,
            "central singleton state has {} ledger fields, expected {CENTRAL_LEDGER_FIELDS}",
            fields.len()
        );
        Ok(CentralEntries {
            notifications: Self::map_entries(
                tree,
                NOTIFICATION_MAP_FIELD,
                "signBidirectionalEventNotificationMap",
            )?,
            responses: Self::map_entries(tree, RESPOND_MAP_FIELD, "respondMap")?,
            bidirectional_responses: Self::map_entries(
                tree,
                RESPOND_BIDIRECTIONAL_MAP_FIELD,
                "respondBidirectionalMap",
            )?,
        })
    }

    /// Per-block processing, shared by catchup and live: diff all three central event
    /// maps against the parent block and translate their new entries.
    async fn process_block<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut CentralCache,
        block: &BlockRef,
    ) -> anyhow::Result<Vec<ChainEvent>> {
        // An absent central is ordinary during catchup from before deployment.
        let entries = match self.central_tree(source, &block.hash).await? {
            Some(tree) => Self::central_entries(&tree)?,
            None => CentralEntries::default(),
        };
        let fetched_parent;
        let parent_entries = match cache.as_ref() {
            Some((hash, entries)) if hash == &block.parent_hash => entries,
            _ => {
                fetched_parent = match self.central_tree(source, &block.parent_hash).await? {
                    Some(tree) => Self::central_entries(&tree)?,
                    None => CentralEntries::default(),
                };
                &fetched_parent
            }
        };

        let mut events = Vec::new();
        let notification_entries =
            new_entries(&entries.notifications, &parent_entries.notifications);
        if !notification_entries.is_empty() {
            let indexed_ts = unix_now().unwrap_or(0);
            for entry in notification_entries {
                if let Some(request) = self
                    .process_entry(source, entry, &block.hash, block.number, indexed_ts)
                    .await?
                {
                    events.push(ChainEvent::SignRequest {
                        request,
                        block_timestamp: None,
                    });
                }
            }
        }

        for entry in new_entries(&entries.responses, &parent_entries.responses) {
            if let Some(event) = response_event(
                entry,
                "respondMap",
                block.number,
                |request_id, signature| {
                    ChainEvent::Respond(SignatureRespondedEvent {
                        request_id,
                        signature,
                        chain: Chain::Midnight,
                    })
                },
            )? {
                events.push(event);
            }
        }

        for entry in new_entries(
            &entries.bidirectional_responses,
            &parent_entries.bidirectional_responses,
        ) {
            if let Some(event) = response_event(
                entry,
                "respondBidirectionalMap",
                block.number,
                |request_id, signature| {
                    ChainEvent::RespondBidirectional(RespondBidirectionalEvent {
                        request_id,
                        signature,
                        chain: Chain::Midnight,
                    })
                },
            )? {
                events.push(event);
            }
        }

        *cache = Some((block.hash.clone(), entries));
        Ok(events)
    }

    /// One notification entry: decode and unpack it, read the caller's ledger at
    /// `at_hash`, gate through `resolve_verified_record`, convert.
    ///
    /// `Err` is reserved for our own schema drift: the singleton's circuits fix the
    /// map-key shape and the notification's shape and version, so callers cannot
    /// produce those failures, and dropping them would silently lose every request
    /// while the checkpoint advances. Everything caller-attributable is a counted drop,
    /// classified purely by which stage failed: `decode_notification` covers the
    /// circuit-enforced half, `unpack_notification_v1` the caller-supplied payload.
    async fn process_entry<C: ChainSource>(
        &self,
        source: &C,
        entry: &MapEntry,
        at_hash: &str,
        height: u64,
        indexed_ts: u64,
    ) -> anyhow::Result<Option<IndexedSignRequest>> {
        let Some(rid) = signet_map_key_rid(&entry.key) else {
            anyhow::bail!(
                "central map key with {} atoms is not a SignetMapKey",
                entry.key.value.0.len()
            );
        };
        let notification =
            decode_notification(&entry.value).context("central notification value")?;
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
            Err(err) => match ReadFailure::of(&err) {
                // Ours to fix, not this entry's: a closed client fails every read
                // until the supervisor's restart rebuilds the connection.
                Some(ReadFailure::ClientClosed) => return Err(err),
                // An oversized state is the contract's own property (retrying
                // cannot shrink it), and pruning the request index is the
                // integrator's job.
                Some(ReadFailure::TooLarge) => {
                    return Ok(drop_entry(
                        "caller-state-too-large",
                        height,
                        Some(rid),
                        &format!("{caller_hex}: {err:#}"),
                    ));
                }
                // The transport already spent its retry budget, and block-level
                // retries cannot be bounded per entry, so escalating would let one
                // caller whose state cannot be served (`caller_address` is
                // producer-supplied) halt the chain. Charged to the entry instead,
                // the unservable answer included, but only once a head probe
                // proves the node healthy: the node collapses transient faults
                // into the same answer, and an ambient fault must hold, not drop.
                Some(ReadFailure::Unservable) | None => {
                    if let Err(probe_err) = source.finalized_head().await {
                        return Err(err.context(format!(
                            "caller state read failed and the head probe failed too \
                             ({probe_err:#}): the fault is ambient, holding the block"
                        )));
                    }
                    return Ok(drop_entry_unattributed(
                        "caller-state-unreadable",
                        height,
                        Some(rid),
                        &format!("{caller_hex}: {err:#}"),
                    ));
                }
            },
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
                // Not a fault: the caller notified an id its own index does not hold,
                // having notified before its write landed or computed the id wrong.
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

    /// [`process_block`](Self::process_block) under [`retry_until_cancelled`]'s policy.
    /// Spelled out because holding `&mut cache` across attempts needs an `async ||`,
    /// whose lending future defeats `Send` inference at the node's spawn boundary on
    /// stable Rust.
    async fn process_block_retrying<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut CentralCache,
        block: &BlockRef,
        cancel: &CancellationToken,
    ) -> Retried<Vec<ChainEvent>> {
        loop {
            let result = tokio::select! {
                _ = cancel.cancelled() => return Retried::Cancelled,
                result = self.process_block(source, cache, block) => result,
            };
            match result {
                Ok(requests) => return Retried::Done(requests),
                Err(err) => match ReadFailure::of(&err) {
                    Some(ReadFailure::Unservable) => return Retried::Unservable(err),
                    Some(ReadFailure::ClientClosed) => return Retried::ClientClosed(err),
                    None if err.downcast_ref::<ResponseSchemaDrift>().is_some() => {
                        return Retried::Halted(err);
                    }
                    None if err.to_string().contains(CENTRAL_STATE_UNDECODABLE) => {
                        tracing::error!(
                            reason = "central-state-undecodable-hold",
                            height = block.number,
                            "midnight central contract state does not decode with this \
                             build's ledger crates; holding. If the chain upgraded, \
                             upgrade mpc-node"
                        );
                        return Retried::Halted(err);
                    }
                    _ => tracing::warn!(
                        reason = "retrying",
                        height = block.number,
                        "midnight block processing failed: {err:#}; retrying"
                    ),
                },
            }
            tokio::select! {
                _ = cancel.cancelled() => return Retried::Cancelled,
                _ = tokio::time::sleep(RETRY_DELAY) => {}
            }
        }
    }

    /// One catchup or gap height: resolve the number to its finalized block, then
    /// [`index_block`](Self::index_block).
    async fn index_height<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut CentralCache,
        events_tx: &mpsc::Sender<ChainEvent>,
        number: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Indexed> {
        let block =
            match retry_until_cancelled("block lookup", number, cancel, || source.block_at(number))
                .await
            {
                Retried::Done(block) => block,
                Retried::Cancelled => return Ok(Indexed::Cancelled),
                Retried::Unservable(err) => return Err(note_unservable(err, number)),
                Retried::ClientClosed(err) | Retried::Halted(err) => return Err(err),
            };
        self.index_block(source, cache, events_tx, &block, cancel)
            .await
    }

    /// Processes and emits one block under the retry policy, surfacing the pruning
    /// signature as the error that restarts the run.
    async fn index_block<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut CentralCache,
        events_tx: &mpsc::Sender<ChainEvent>,
        block: &BlockRef,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Indexed> {
        match self
            .process_block_retrying(source, cache, block, cancel)
            .await
        {
            Retried::Done(events) => {
                self.emit_block(events_tx, block, events).await?;
                Ok(Indexed::Done)
            }
            Retried::Cancelled => Ok(Indexed::Cancelled),
            Retried::Unservable(err) => Err(note_unservable(err, block.number)),
            Retried::ClientClosed(err) | Retried::Halted(err) => Err(err),
        }
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
            retry_startup("anchor sampling", &cancel, || source.finalized_head()).await?
        else {
            return Ok(());
        };

        let mut cache: CentralCache = None;
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
            for number in (checkpoint + 1)..=anchor.number {
                match self
                    .index_height(source, &mut cache, &events_tx, number, &cancel)
                    .await?
                {
                    Indexed::Done => last_processed = number,
                    Indexed::Cancelled => return Ok(()),
                }
            }
        }
        events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send midnight catchup completed event")?;

        let (blocks_tx, mut blocks_rx) = mpsc::channel(self.config.indexer.live_block_buffer);
        let _producer = source.spawn_block_producer(blocks_tx).await?;
        loop {
            let block = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                block = blocks_rx.recv() => match block {
                    Some(block) => block,
                    // To run_supervised, Ok(()) is permanent shutdown and Err is a
                    // restart, so an ended producer must be Err and let the restart
                    // re-anchor.
                    None => anyhow::bail!("midnight finalized block producer terminated"),
                },
            };
            if block.number <= last_processed {
                continue;
            }
            // Close any finality gap so a lagging subscription cannot skip
            // notifications; each height processes exactly like catchup.
            // `last_processed` stays put mid-walk: every continuation overwrites it
            // below before any read, so a per-height assignment is a dead store.
            for number in (last_processed + 1)..block.number {
                match self
                    .index_height(source, &mut cache, &events_tx, number, &cancel)
                    .await?
                {
                    Indexed::Done => {}
                    Indexed::Cancelled => return Ok(()),
                }
            }
            match self
                .index_block(source, &mut cache, &events_tx, &block, &cancel)
                .await?
            {
                Indexed::Done => last_processed = block.number,
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
        // A failed dial is the same transient class as a failed anchor read.
        let Some(source) = retry_startup("node connect", &cancel, || {
            LiveSource::connect(&self.config)
        })
        .await?
        else {
            return Ok(());
        };
        self.run_with_source(&source, events_tx, cancel).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::decode_contract_state;
    use mpc_chain_integration_core::utils::stream::chain_event_channel;
    use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
    use std::time::Duration;

    type TestIndexer = MidnightIndexer<MockStateManager, NoopChainTelemetry>;

    // run() over an injected ChainSource.

    use crate::test_utils::{
        array_of, ascii_padded, cell_from_atoms, cell_from_record, key_of, map_of, sample_record,
        trim,
    };
    use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom};
    use mpc_primitives::SignId;
    use mpc_utils::task::AbortOnDrop;
    use std::collections::HashMap;

    /// A record with a distinguishing nonce, and the id it files itself under.
    fn named_record_and_rid(nonce: u64) -> (crate::records::SignBidirectionalRecord, [u8; 32]) {
        let mut record = sample_record();
        record.request_nonce = nonce;
        let rid = crate::request_id::compute_request_id(&record);
        (record, rid)
    }

    fn caller_record_and_rid() -> (crate::records::SignBidirectionalRecord, [u8; 32]) {
        named_record_and_rid(7)
    }

    /// The caller contract whose ledger the fixture serves: minimal-1word's sender,
    /// with its request map at flat field 4 (the 5-field layout).
    const CALLER: [u8; 32] = [0xab; 32];
    const REQUESTS_FIELD: u8 = 4;

    fn central_address() -> String {
        "12".repeat(32)
    }

    /// The config every fixture indexer runs on: a never-dialed URL and the fixture central.
    fn test_config() -> MidnightConfig {
        MidnightConfig {
            node_ws_url: "ws://127.0.0.1:1".to_string(),
            central_address: central_address(),
            publisher: None,
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    fn hash_of(number: u64) -> String {
        format!("0x{number:064x}")
    }

    fn block_ref(number: u64) -> BlockRef {
        BlockRef {
            number,
            hash: hash_of(number),
            parent_hash: hash_of(number.saturating_sub(1)),
        }
    }

    /// The composite `SignetMapKey { count: Uint<64>, requestId: Bytes<32> }`.
    fn signet_map_key(count: u8, rid: &[u8; 32]) -> AlignedValue {
        AlignedValue {
            value: Value(vec![ValueAtom(trim(&[count])), ValueAtom(trim(rid))]),
            alignment: Alignment(vec![
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 8 }),
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            ]),
        }
    }

    /// One notification-map entry: V1 payload naming CALLER and the depth-1 path
    /// `[REQUESTS_FIELD]` (this caller is flat).
    fn notification_entry(count: u8, rid: &[u8; 32]) -> (AlignedValue, Node) {
        let mut payload = CALLER.to_vec();
        payload.push(1); // requests_path_depth
        payload.push(REQUESTS_FIELD); // path[0]
        (
            signet_map_key(count, rid),
            cell_from_atoms(&[vec![1u8], payload], &[1, 128]),
        )
    }

    fn response_entry(
        count: u8,
        rid: &[u8; 32],
        signature: &mpc_primitives::Signature,
    ) -> (AlignedValue, Node) {
        use k256::elliptic_curve::sec1::ToEncodedPoint as _;

        let encoded = signature.big_r.to_encoded_point(false);
        (
            signet_map_key(count, rid),
            cell_from_atoms(
                &[
                    trim(encoded.x().expect("affine x")),
                    trim(encoded.y().expect("affine y")),
                    trim(signature.s.to_bytes().as_slice()),
                    trim(&[signature.recovery_id]),
                ],
                &[32, 32, 32, 1],
            ),
        )
    }

    fn raw_response_entry(
        count: u8,
        rid: &[u8; 32],
        x: [u8; 32],
        y: [u8; 32],
        s: [u8; 32],
        recovery_id: u8,
    ) -> (AlignedValue, Node) {
        (
            signet_map_key(count, rid),
            cell_from_atoms(
                &[trim(&x), trim(&y), trim(&s), trim(&[recovery_id])],
                &[32, 32, 32, 1],
            ),
        )
    }

    /// The central singleton: six flat fields, notification map at ordinal 1.
    fn central_state(entries: Vec<(AlignedValue, Node)>) -> Node {
        central_state_with_responses(entries, vec![], vec![])
    }

    fn central_state_with_responses(
        notifications: Vec<(AlignedValue, Node)>,
        responses: Vec<(AlignedValue, Node)>,
        bidirectional_responses: Vec<(AlignedValue, Node)>,
    ) -> Node {
        array_of(vec![
            map_of(vec![]),
            map_of(notifications),
            map_of(vec![]),
            map_of(responses),
            map_of(vec![]),
            map_of(bidirectional_responses),
        ])
    }

    /// The caller's five-field ledger with the record filed under its rid at field 4.
    fn caller_state(record: &crate::records::SignBidirectionalRecord, rid: &[u8; 32]) -> Node {
        array_of(vec![
            StateValue::Null,
            StateValue::Null,
            StateValue::Null,
            StateValue::Null,
            map_of(vec![(key_of(*rid), cell_from_record(record))]),
        ])
    }

    #[derive(Default)]
    struct FixtureSource {
        head: u64,
        /// (address, at_hash) -> tree; absent means Ok(None), contract not present at
        /// that block.
        states: HashMap<(String, String), Node>,
        /// (address, at_hash) -> error message; checked BEFORE `states`, so a read can
        /// fail with e.g.
        state_errors: HashMap<(String, String), String>,
        /// (address, at_hash) -> (error message, failures still owed). Counts down per
        /// read and then lets the read succeed, which is how a test distinguishes a
        /// retry from a restart: a restarting indexer never reaches the success.
        transient_state_errors: std::sync::Mutex<HashMap<(String, String), (String, usize)>>,
        /// (address, at_hash) -> decode rejection; the node served the bytes
        /// and the DECODER refused them.
        undecodable_states: HashMap<(String, String), String>,
        /// `finalized_head` failures still owed before the read succeeds, the
        /// startup twin of `transient_state_errors`.
        transient_head_errors: std::sync::Mutex<usize>,
        /// A permanent `finalized_head` failure (e.g. the dead-client marker),
        /// checked before the transient debt.
        sticky_head_error: Option<String>,
        live: tokio::sync::Mutex<Option<mpsc::Receiver<BlockRef>>>,
        /// Deterministic suspension: the read named here announces itself on `reached`
        /// and then never resolves, so a test can cancel while a walk is PROVABLY
        /// mid-flight instead of racing a sleep against it.
        park_at: Option<u64>,
        /// Parks `contract_state_tree` for this address, which suspends a walk INSIDE
        /// `process_entry` rather than between blocks.
        park_state_read: Option<String>,
        reached: Option<mpsc::Sender<String>>,
    }

    impl FixtureSource {
        /// Announce arrival at a park point, then never resolve.
        async fn park(&self, label: String) -> ! {
            if let Some(reached) = &self.reached {
                reached.send(label).await.expect("park signal receiver");
            }
            std::future::pending().await
        }

        fn set_state(&mut self, address: &str, at: u64, tree: Node) {
            self.states.insert((address.to_string(), hash_of(at)), tree);
        }

        /// Injects a read failure that clears itself after `times` reads.
        fn set_transient_error(&mut self, address: &str, at: u64, times: usize, message: &str) {
            self.transient_state_errors
                .lock()
                .expect("fixture transient errors")
                .insert(
                    (address.to_string(), hash_of(at)),
                    (message.to_string(), times),
                );
        }

        /// Consumes one failure still owed for `key`, or `None` once the debt is paid.
        fn take_transient_error(&self, key: &(String, String)) -> Option<String> {
            let mut pending = self
                .transient_state_errors
                .lock()
                .expect("fixture transient errors");
            let (message, remaining) = pending.get_mut(key)?;
            if *remaining == 0 {
                return None;
            }
            *remaining -= 1;
            Some(message.clone())
        }

        /// Injects the pruning signature for one (address, height) read.
        fn set_unservable(&mut self, address: &str, at: u64) {
            self.state_errors.insert(
                (address.to_string(), hash_of(at)),
                ReadFailure::Unservable.marker().to_string(),
            );
        }

        /// Injects a real decode failure for one (address, height): the ledger's own
        /// deserializer refuses bytes whose tag is not the contract state this build
        /// speaks, which is how a chain that moved ahead of us surfaces.
        fn set_undecodable(&mut self, address: &str, at: u64) {
            self.undecodable_states.insert(
                (address.to_string(), hash_of(at)),
                "contract state did not deserialize: unexpected tag".to_string(),
            );
        }
    }

    #[async_trait]
    impl ChainSource for FixtureSource {
        async fn finalized_head(&self) -> anyhow::Result<BlockRef> {
            if let Some(message) = &self.sticky_head_error {
                anyhow::bail!("{message}");
            }
            {
                let mut owed = self
                    .transient_head_errors
                    .lock()
                    .expect("fixture head errors");
                if *owed > 0 {
                    *owed -= 1;
                    anyhow::bail!("finalized head fetch failed: connection reset by peer");
                }
            }
            Ok(block_ref(self.head))
        }

        async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef> {
            if self.park_at == Some(number) {
                self.park(format!("block_at:{number}")).await;
            }
            Ok(block_ref(number))
        }

        async fn contract_state_tree(
            &self,
            address_64hex: &str,
            at_hash: &str,
        ) -> anyhow::Result<ContractState> {
            if self.park_state_read.as_deref() == Some(address_64hex) {
                self.park(format!("state:{address_64hex}")).await;
            }
            let key = (address_64hex.to_string(), at_hash.to_string());
            if let Some(message) = self.take_transient_error(&key) {
                anyhow::bail!("{message}");
            }
            if let Some(message) = self.state_errors.get(&key) {
                anyhow::bail!("{message}");
            }
            if let Some(message) = self.undecodable_states.get(&key) {
                return Ok(ContractState::Undecodable(anyhow::anyhow!("{message}")));
            }
            Ok(self
                .states
                .get(&key)
                .cloned()
                .map_or(ContractState::Absent, ContractState::Tree))
        }

        async fn spawn_block_producer(
            &self,
            tx: mpsc::Sender<BlockRef>,
        ) -> anyhow::Result<AbortOnDrop> {
            let mut rx = self.live.lock().await.take().expect("one producer per run");
            Ok(AbortOnDrop(tokio::spawn(async move {
                while let Some(block) = rx.recv().await {
                    if tx.send(block).await.is_err() {
                        return;
                    }
                }
            })))
        }
    }

    struct RunFixture {
        events_rx: mpsc::Receiver<ChainEvent>,
        cancel: CancellationToken,
        handle: tokio::task::JoinHandle<anyhow::Result<()>>,
        state: MockStateManager,
    }

    impl RunFixture {
        async fn spawn(source: FixtureSource, checkpoint: u64) -> Self {
            let state = MockStateManager::new();
            if checkpoint > 0 {
                state.set_processed_block(Chain::Midnight, checkpoint).await;
            }
            Self::spawn_with_state(source, state).await
        }

        /// Spawns over an EXISTING state manager: the restart tests' seam, so a second
        /// run provably resumes from what the first persisted.
        async fn spawn_with_state(source: FixtureSource, state: MockStateManager) -> Self {
            let indexer = MidnightIndexer::new(test_config(), state.clone(), NoopChainTelemetry)
                .await
                .expect("indexer constructs");

            let (events_tx, events_rx) = chain_event_channel();
            let cancel = CancellationToken::new();
            let handle = tokio::spawn({
                let cancel = cancel.clone();
                async move { indexer.run_with_source(&source, events_tx, cancel).await }
            });
            Self {
                events_rx,
                cancel,
                handle,
                state,
            }
        }

        async fn next_event(&mut self) -> ChainEvent {
            tokio::time::timeout(Duration::from_secs(5), self.events_rx.recv())
                .await
                .expect("timed out waiting for a chain event")
                .expect("events channel closed")
        }

        async fn cancel_and_join(self) {
            self.cancel.cancel();
            tokio::time::timeout(Duration::from_secs(5), self.handle)
                .await
                .expect("run() should stop promptly after cancel")
                .expect("run task panicked")
                .expect("run() should exit Ok on cancel");
        }
    }

    fn assert_block(event: &ChainEvent, number: u64) {
        assert!(
            matches!(event, ChainEvent::Block(n) if *n == number),
            "expected Block({number}), got {event:?}"
        );
    }

    /// Asserts the emitted request end to end: the id and the absent block timestamp.
    fn assert_sign_request(event: &ChainEvent, rid: [u8; 32]) {
        match event {
            ChainEvent::SignRequest {
                request,
                block_timestamp,
            } => {
                assert_eq!(request.id, SignId::new(rid), "request id");
                assert_eq!(
                    *block_timestamp, None,
                    "midnight carries no block timestamp"
                );
            }
            other => panic!("expected SignRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_emits_catchup_before_completed_and_live_blocks() {
        let (record, rid) = caller_record_and_rid();
        let central = central_address();
        let mut source = FixtureSource {
            head: 8,
            ..Default::default()
        };
        // Parent-of-first-catchup-block state exists and is empty.
        source.set_state(&central, 5, central_state(vec![]));
        source.set_state(&central, 6, central_state(vec![]));
        // Block 7 files the notification; block 8 carries it unchanged.
        source.set_state(
            &central,
            7,
            central_state(vec![notification_entry(1, &rid)]),
        );
        source.set_state(
            &central,
            8,
            central_state(vec![notification_entry(1, &rid)]),
        );
        source.set_state(&hex::encode(CALLER), 7, caller_state(&record, &rid));

        // A live block is already queued BEFORE run() starts; its events must still
        // come after CatchupCompleted.
        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));
        source.set_state(
            &central,
            9,
            central_state(vec![notification_entry(1, &rid)]),
        );
        live_tx.send(block_ref(9)).await.expect("queue live block");

        let mut harness = RunFixture::spawn(source, 5).await;

        assert_block(&harness.next_event().await, 6);
        assert_sign_request(&harness.next_event().await, rid);
        assert_block(&harness.next_event().await, 7);
        assert_block(&harness.next_event().await, 8);
        assert!(
            matches!(harness.next_event().await, ChainEvent::CatchupCompleted),
            "catchup events and only catchup events precede CatchupCompleted"
        );
        // The pre-queued live block adds nothing new (same entry) and emits its Block
        // only now.
        assert_block(&harness.next_event().await, 9);
        harness.cancel_and_join().await;
    }

    #[tokio::test]
    async fn process_block_emits_one_request_per_new_entry() {
        let (record, rid) = caller_record_and_rid();
        let central = central_address();
        let mut source = FixtureSource {
            head: 8,
            ..Default::default()
        };
        // The pre-existing entry files the SAME rid under count 1 (a re-notification
        // scenario), so it is fully resolvable: a diff mutant that treats every entry
        // as new re-emits it and fails the exactly-one assertion below, rather than
        // hiding behind an unresolvable decoy rid.
        source.set_state(
            &central,
            8,
            central_state(vec![notification_entry(1, &rid)]),
        );
        source.set_state(
            &central,
            9,
            central_state(vec![
                notification_entry(1, &rid),
                notification_entry(2, &rid),
            ]),
        );
        source.set_state(&hex::encode(CALLER), 9, caller_state(&record, &rid));
        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));

        let mut harness = RunFixture::spawn(source, 8).await;
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));

        live_tx.send(block_ref(9)).await.expect("send live block");
        // Exactly ONE request: the pre-existing entry is not re-emitted (a diff mutant
        // that treats every entry as new emits two).
        assert_sign_request(&harness.next_event().await, rid);
        assert_block(&harness.next_event().await, 9);
        harness.cancel_and_join().await;
    }

    #[tokio::test]
    async fn response_maps_emit_both_lifecycle_events_before_the_block() {
        let respond_rid = [0x31; 32];
        let bidirectional_rid = [0x32; 32];
        let respond_signature = mpc_primitives::Signature::new(
            k256::AffinePoint::GENERATOR,
            k256::Scalar::from(9u64),
            0,
        );
        let bidirectional_signature = mpc_primitives::Signature::new(
            k256::AffinePoint::GENERATOR,
            k256::Scalar::from(10u64),
            1,
        );
        let central = central_address();
        let mut source = FixtureSource {
            head: 8,
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        let response_state = central_state_with_responses(
            vec![],
            vec![
                raw_response_entry(
                    1,
                    &respond_rid,
                    [0xff; 32],
                    [0xff; 32],
                    k256::Scalar::from(8u64).to_bytes().into(),
                    0,
                ),
                response_entry(2, &respond_rid, &respond_signature),
            ],
            vec![
                raw_response_entry(
                    1,
                    &bidirectional_rid,
                    [0xff; 32],
                    [0xff; 32],
                    k256::Scalar::from(8u64).to_bytes().into(),
                    0,
                ),
                response_entry(2, &bidirectional_rid, &bidirectional_signature),
            ],
        );
        source.set_state(&central, 9, response_state);
        let repeated_response_state = central_state_with_responses(
            vec![],
            vec![
                raw_response_entry(
                    1,
                    &respond_rid,
                    [0xff; 32],
                    [0xff; 32],
                    k256::Scalar::from(8u64).to_bytes().into(),
                    0,
                ),
                response_entry(2, &respond_rid, &respond_signature),
                response_entry(3, &respond_rid, &respond_signature),
            ],
            vec![
                raw_response_entry(
                    1,
                    &bidirectional_rid,
                    [0xff; 32],
                    [0xff; 32],
                    k256::Scalar::from(8u64).to_bytes().into(),
                    0,
                ),
                response_entry(2, &bidirectional_rid, &bidirectional_signature),
            ],
        );
        source.set_state(&central, 10, repeated_response_state.clone());
        source.set_state(&central, 11, repeated_response_state);
        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));

        let mut harness = RunFixture::spawn(source, 8).await;
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));

        live_tx.send(block_ref(9)).await.expect("send live block");
        match harness.next_event().await {
            ChainEvent::Respond(event) => {
                assert_eq!(event.request_id, respond_rid);
                assert_eq!(event.signature, respond_signature);
                assert_eq!(event.chain, Chain::Midnight);
            }
            other => panic!("expected Respond, got {other:?}"),
        }
        match harness.next_event().await {
            ChainEvent::RespondBidirectional(event) => {
                assert_eq!(event.request_id, bidirectional_rid);
                assert_eq!(event.signature, bidirectional_signature);
                assert_eq!(event.chain, Chain::Midnight);
            }
            other => panic!("expected RespondBidirectional, got {other:?}"),
        }
        assert_block(&harness.next_event().await, 9);
        live_tx
            .send(block_ref(10))
            .await
            .expect("send repeat block");
        match harness.next_event().await {
            ChainEvent::Respond(event) => {
                assert_eq!(event.request_id, respond_rid);
                assert_eq!(event.signature, respond_signature);
            }
            other => panic!("expected repeated Respond, got {other:?}"),
        }
        assert_block(&harness.next_event().await, 10);
        live_tx
            .send(block_ref(11))
            .await
            .expect("send unchanged block");
        assert_block(&harness.next_event().await, 11);
        harness.cancel_and_join().await;
    }

    #[tokio::test]
    async fn response_schema_drift_halts_without_events_or_cache_commit() {
        let valid_rid = [0x40; 32];
        let drift_rid = [0x41; 32];
        let valid_signature = mpc_primitives::Signature::new(
            k256::AffinePoint::GENERATOR,
            k256::Scalar::from(9u64),
            0,
        );

        for (map_name, drift_in_bidirectional_map) in
            [("respondMap", false), ("respondBidirectionalMap", true)]
        {
            let central = central_address();
            let mut source = FixtureSource::default();
            source.set_state(&central, 7, central_state(vec![]));
            source.set_state(&central, 8, central_state(vec![]));

            // The invalid point must not hide the extra atom: contract structure is
            // exhausted before caller-controlled cryptographic values are checked.
            let structurally_invalid = (
                signet_map_key(2, &drift_rid),
                cell_from_atoms(
                    &[vec![0xff; 32], vec![0xff; 32], vec![9], vec![], vec![1]],
                    &[32, 32, 32, 1, 1],
                ),
            );
            let entries = vec![
                response_entry(1, &valid_rid, &valid_signature),
                structurally_invalid,
            ];
            let (responses, bidirectional_responses) = if drift_in_bidirectional_map {
                (vec![], entries)
            } else {
                (entries, vec![])
            };
            source.set_state(
                &central,
                9,
                central_state_with_responses(vec![], responses, bidirectional_responses),
            );

            let indexer = direct_indexer().await;
            let mut cache = None;
            indexer
                .process_block(&source, &mut cache, &block_ref(8))
                .await
                .expect("the parent primes the cache");
            let parent_hash = hash_of(8);
            assert_eq!(
                cache.as_ref().map(|(hash, _)| hash.as_str()),
                Some(parent_hash.as_str())
            );

            let (events_tx, mut events_rx) = chain_event_channel();
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                indexer.index_block(
                    &source,
                    &mut cache,
                    &events_tx,
                    &block_ref(9),
                    &CancellationToken::new(),
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("{map_name} schema drift must halt, not retry"));
            let err = match result {
                Err(err) => err,
                Ok(_) => panic!("{map_name} schema drift must fail the block"),
            };
            assert!(
                format!("{err:#}").contains(map_name),
                "the error must name its response map: {err:#}"
            );
            assert!(
                events_rx.try_recv().is_err(),
                "no lifecycle or Block event may escape a failed block"
            );
            assert_eq!(
                cache.as_ref().map(|(hash, _)| hash.as_str()),
                Some(parent_hash.as_str()),
                "a failed block must preserve the parent cache"
            );
        }
    }

    #[tokio::test]
    async fn process_entry_drops_undecodable_caller_state() {
        let (_record, rid) = caller_record_and_rid();
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(
            &central,
            9,
            central_state(vec![notification_entry(1, &rid)]),
        );
        // The caller contract IS present; its state does not deserialize.
        source.set_undecodable(&hex::encode(CALLER), 9);

        let mut harness = RunFixture::spawn(source, 8).await;
        // The block still reports progress past the poisoned entry, or the restart
        // re-walks it forever.
        assert_block(&harness.next_event().await, 9);
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    /// An indexer plus a `cache` slot for driving `process_block`/`process_entry`
    /// directly: the drift classification is about return values, not event flows.
    async fn direct_indexer() -> TestIndexer {
        MidnightIndexer::new(test_config(), MockStateManager::new(), NoopChainTelemetry)
            .await
            .expect("indexer constructs")
    }

    // ---- The committed capture (fixtures/README.md) ----------------------------

    /// Raw `midnight_contractState` bytes from the capture chain at its notify block.
    const CAPTURED_SINGLETON_POST: &[u8] = include_bytes!("../fixtures/singleton-post-state-64.mn");
    const CAPTURED_CALLER_POST: &[u8] = include_bytes!("../fixtures/caller-post-state-64.mn");
    const CAPTURED_HEIGHT: u64 = 64;

    fn hex32(hex64: &str) -> [u8; 32] {
        <[u8; 32]>::try_from(hex::decode(hex64).expect("hex")).expect("32 bytes")
    }

    /// The capture chain's deployed test caller.
    fn captured_caller() -> [u8; 32] {
        hex32("34f8406321f607763d3176d07f486db807d05d7c5103f2550850119d353a2987")
    }

    /// The request id the capture's submit filed.
    fn captured_rid() -> [u8; 32] {
        hex32("aadca83b95a932a675a6298ac3b4fa2ac092ecc19e4aef8001a496cf2ace84d7")
    }

    /// The record the capture's `submitSignatureRequest(evmNonce: 0, keyVersion: 1)`
    /// files, rebuilt from the caller contract's own constants
    /// (test-caller-contract.compact), never from anything this crate decoded.
    fn captured_record() -> crate::records::SignBidirectionalRecord {
        use crate::records::{
            CompactMaybe, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord,
        };
        SignBidirectionalRecord {
            sender: captured_caller(),
            request_nonce: 0,
            key_version: 1,
            path: ascii_padded(b"caller-path"),
            algo: 0,
            dest: 0,
            params: [0u8; 64],
            tx_param_type: 0,
            tx_params: EvmType2TxParams {
                chain_id: 31337,
                nonce: 0,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 30_000_000_000,
                gas_limit: 100_000,
                to: ascii_padded(b"signet-caller-e2e-to"),
                value: 0,
                calldata: CompactMaybe {
                    is_some: true,
                    value: EvmCalldata {
                        selector: [0xca, 0x11, 0xab, 0x1e],
                        no_words: 1,
                        words: vec![ascii_padded(b"signet-caller:fixed-word")],
                    },
                },
                access_list_entry_count: 0,
                access_list: Vec::new(),
            },
            caip2_id: ascii_padded(b"eip155:31337"),
            output_deserialization_schema: br#"[{"name":"success","type":"bool"}]"#.to_vec(),
            respond_serialization_schema: br#"[{"name":"success","type":"bool"}]"#.to_vec(),
        }
    }

    /// The other tests in this module build their cells with the same width tables the
    /// decoder checks, so they cannot catch both sides being wrong about the actual
    /// contract. This one runs the entry pipeline over bytes the contract toolchain
    /// produced, and every expectation is fixed outside this crate: the deployed
    /// caller's address, the ledger path its source pins ([4] at depth 1), and the
    /// record fields its submit circuit hardcodes.
    #[tokio::test]
    async fn captured_entry_decodes_resolves_and_converts() {
        let central = crate::state::decode_contract_state(CAPTURED_SINGLETON_POST)
            .expect("the captured singleton state decodes");
        let entries =
            TestIndexer::central_entries(&central).expect("the captured central event maps decode");
        assert_eq!(
            entries.notifications.len(),
            1,
            "the capture holds exactly one notify"
        );
        let entry = &entries.notifications[0];
        assert_eq!(
            signet_map_key_rid(&entry.key),
            Some(captured_rid()),
            "the registry keys the notification by the filed request id"
        );

        let notification =
            decode_notification(&entry.value).expect("the stored notification cell decodes");
        let unpacked = unpack_notification_v1(&notification).expect("the V1 payload unpacks");
        assert_eq!(unpacked.caller_address, captured_caller());
        assert_eq!(
            unpacked.requests_path,
            vec![REQUESTS_FIELD],
            "the payload carries the caller's contract-info path"
        );

        let caller_tree = crate::state::decode_contract_state(CAPTURED_CALLER_POST)
            .expect("the captured caller state decodes");
        let field = signet_field_node_by_path(&caller_tree, &unpacked.requests_path)
            .expect("the carried path walks the captured ledger");
        let Resolved::Found(record) = resolve_verified_record(field, captured_rid()) else {
            panic!("the captured record must resolve, request-id recompute included");
        };
        assert_eq!(*record, captured_record());

        // The production entry pipeline over the same bytes, conversion included.
        let indexer = direct_indexer().await;
        let mut source = FixtureSource::default();
        source.set_state(
            &hex::encode(captured_caller()),
            CAPTURED_HEIGHT,
            caller_tree,
        );
        let request = indexer
            .process_entry(
                &source,
                entry,
                &hash_of(CAPTURED_HEIGHT),
                CAPTURED_HEIGHT,
                0,
            )
            .await
            .expect("nothing in the capture is drift")
            .expect("the captured entry must produce a request");
        assert_eq!(request.id, SignId::new(captured_rid()));
        assert_eq!(request.args.key_version, 1);
        assert_eq!(
            request.args.path, "63616c6c65722d70617468000000000000000000000000000000000000000000",
            "the full 32 path bytes as lowercase hex"
        );
    }

    #[tokio::test]
    async fn process_block_errors_on_central_schema_drift() {
        // None of the three event-map fields can change shape through a caller: a
        // non-map is contract drift or a wrong central address and must halt loudly.
        let central = central_address();
        let indexer = direct_indexer().await;
        for field in [
            usize::from(NOTIFICATION_MAP_FIELD),
            usize::from(RESPOND_MAP_FIELD),
            usize::from(RESPOND_BIDIRECTIONAL_MAP_FIELD),
        ] {
            let mut source = FixtureSource::default();
            source.set_state(&central, 8, central_state(vec![]));
            let mut fields: Vec<Node> =
                (0..CENTRAL_LEDGER_FIELDS).map(|_| map_of(vec![])).collect();
            fields[field] = StateValue::Null;
            source.set_state(&central, 9, array_of(fields));

            let mut cache = None;
            let err = indexer
                .process_block(&source, &mut cache, &block_ref(9))
                .await
                .expect_err("a non-map central field must error, never degrade")
                .to_string();
            assert!(err.contains("is not a map"), "field {field}, err: {err}");
        }
    }

    #[tokio::test]
    async fn process_entry_errors_on_singleton_shapes_and_drops_caller_data() {
        // The singleton's circuits fix the key shape, the value shape and version, so
        // those failures are drift (Err); the payload's depth byte is caller data (drop).
        let (_record, rid) = caller_record_and_rid();
        let source = FixtureSource::default();
        let indexer = direct_indexer().await;

        let one_atom_key = MapEntry {
            key: AlignedValue::from([0x11; 32]),
            value: notification_entry(1, &rid).1,
        };
        let err = indexer
            .process_entry(&source, &one_atom_key, &hash_of(9), 9, 0)
            .await
            .expect_err("a non-SignetMapKey key is drift")
            .to_string();
        assert!(err.contains("SignetMapKey"), "err: {err}");

        let three_atom_value = MapEntry {
            key: signet_map_key(1, &rid),
            value: cell_from_atoms(&[vec![1], vec![2], vec![3]], &[1, 1, 1]),
        };
        let err = indexer
            .process_entry(&source, &three_atom_value, &hash_of(9), 9, 0)
            .await
            .expect_err("a malformed notification cell is drift")
            .to_string();
        assert!(err.contains("notification"), "err: {err}");

        let mut payload = CALLER.to_vec();
        payload.extend([1u8, REQUESTS_FIELD]);
        let version_two = MapEntry {
            key: signet_map_key(1, &rid),
            value: cell_from_atoms(&[vec![2u8], payload], &[1, 128]),
        };
        let err = format!(
            "{:#}",
            indexer
                .process_entry(&source, &version_two, &hash_of(9), 9, 0)
                .await
                .expect_err("the singleton asserts version 1 in circuit, so 2 is drift")
        );
        assert!(err.contains("version 2"), "err: {err}");

        // Depth 0 is caller-writable payload: a drop, and never an abort.
        let mut zero_depth = CALLER.to_vec();
        zero_depth.push(0);
        let bad_depth = MapEntry {
            key: signet_map_key(1, &rid),
            value: cell_from_atoms(&[vec![1u8], zero_depth], &[1, 128]),
        };
        let dropped = indexer
            .process_entry(&source, &bad_depth, &hash_of(9), 9, 0)
            .await
            .expect("caller-supplied depth must not abort the block");
        assert!(dropped.is_none());
    }

    /// What `captured_entry_decodes_resolves_and_converts` does not cover: the
    /// parent-diff over the real pre/post states finds exactly the one new entry, and
    /// the emitted epsilon matches the derivation the TS reference pins for the
    /// deployed caller.
    #[tokio::test]
    async fn process_block_diffs_the_captured_states() {
        let pre = decode_contract_state(include_bytes!("../fixtures/singleton-pre-state-63.mn"))
            .expect("the pre-notify singleton capture decodes");
        let post = decode_contract_state(CAPTURED_SINGLETON_POST)
            .expect("the post-notify singleton capture decodes");
        let caller =
            decode_contract_state(CAPTURED_CALLER_POST).expect("the caller capture decodes");

        let central = central_address();
        let mut source = FixtureSource::default();
        source.set_state(&central, CAPTURED_HEIGHT - 1, pre);
        source.set_state(&central, CAPTURED_HEIGHT, post);
        source.set_state(&hex::encode(captured_caller()), CAPTURED_HEIGHT, caller);
        let indexer = direct_indexer().await;
        let mut cache = None;
        let events = indexer
            .process_block(&source, &mut cache, &block_ref(CAPTURED_HEIGHT))
            .await
            .expect("the captured block processes");
        let [ChainEvent::SignRequest { request, .. }] = events.as_slice() else {
            panic!("exactly one captured request, got {events:?}")
        };
        assert_eq!(request.id, SignId::new(captured_rid()));
        let path_hex = "63616c6c65722d70617468000000000000000000000000000000000000000000";
        assert_eq!(
            request.args.epsilon,
            mpc_crypto::kdf::derive_epsilon_midnight(1, &hex::encode(captured_caller()), path_hex),
            "epsilon derives from the deployed caller and the contract's own path"
        );
    }

    #[tokio::test]
    async fn process_entry_drops_a_caller_read_that_exhausts_retries() {
        // The transport budget is the only retry a caller read gets: `caller_address`
        // is producer-supplied, so escalating to block-level retries would let one
        // unservable caller halt the chain. Both persistent-error shapes drop.
        let (_record, rid) = caller_record_and_rid();
        let indexer = direct_indexer().await;
        let entry = MapEntry {
            key: signet_map_key(1, &rid),
            value: notification_entry(1, &rid).1,
        };

        let mut source = FixtureSource::default();
        source.state_errors.insert(
            (hex::encode(CALLER), hash_of(9)),
            "contract state read failed: connection reset by peer".to_string(),
        );
        let dropped = indexer
            .process_entry(&source, &entry, &hash_of(9), 9, 0)
            .await
            .expect("a dead caller read is charged to the entry");
        assert!(dropped.is_none());

        let mut source = FixtureSource::default();
        source.set_unservable(&hex::encode(CALLER), 9);
        let dropped = indexer
            .process_entry(&source, &entry, &hash_of(9), 9, 0)
            .await
            .expect("an unservable caller read drops rather than restarting the run");
        assert!(dropped.is_none());
    }

    #[tokio::test]
    async fn process_entry_drops_too_large_caller_state_but_propagates_a_dead_client() {
        // Only one of these is about the caller: an oversized state is the
        // contract's own property (drop), while a closed client is our
        // transport's death and must not be charged to the entry observing it.
        let (_record, rid) = caller_record_and_rid();
        let indexer = direct_indexer().await;
        let entry = MapEntry {
            key: signet_map_key(1, &rid),
            value: notification_entry(1, &rid).1,
        };

        let mut source = FixtureSource::default();
        source.state_errors.insert(
            (hex::encode(CALLER), hash_of(9)),
            ReadFailure::TooLarge.marker().to_string(),
        );
        let dropped = indexer
            .process_entry(&source, &entry, &hash_of(9), 9, 0)
            .await
            .expect("an oversized caller state is charged to the entry");
        assert!(dropped.is_none());

        let mut source = FixtureSource::default();
        source.state_errors.insert(
            (hex::encode(CALLER), hash_of(9)),
            ReadFailure::ClientClosed.marker().to_string(),
        );
        let err = indexer
            .process_entry(&source, &entry, &hash_of(9), 9, 0)
            .await
            .expect_err("a dead client is never the caller's fault: propagate for the reconnect");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "err: {err:#}"
        );
    }

    #[tokio::test]
    async fn process_entry_holds_when_caller_read_and_node_probe_both_fail() {
        // Charging `caller-state-unreadable` to an entry is only sound while the
        // node is provably healthy: when even the head probe fails, the fault is
        // ambient (node or transport), so the entry must abort the block into the
        // lossless retry path rather than be destroyed.
        let (_record, rid) = caller_record_and_rid();
        let indexer = direct_indexer().await;
        let entry = MapEntry {
            key: signet_map_key(1, &rid),
            value: notification_entry(1, &rid).1,
        };

        // Both persistent caller-read shapes that drop when the node is healthy:
        // a generic fault and the unservable answer.
        for unservable in [false, true] {
            let mut source = FixtureSource::default();
            if unservable {
                source.set_unservable(&hex::encode(CALLER), 9);
            } else {
                source.state_errors.insert(
                    (hex::encode(CALLER), hash_of(9)),
                    "contract state read failed: connection reset by peer".to_string(),
                );
            }
            source.transient_head_errors = std::sync::Mutex::new(usize::MAX);
            let err = indexer
                .process_entry(&source, &entry, &hash_of(9), 9, 0)
                .await
                .expect_err("an ambient fault must hold the block, never destroy the entry");
            assert!(
                format!("{err:#}").contains("probe"),
                "the hold must name the failed probe: {err:#}"
            );
        }
    }

    #[tokio::test]
    async fn run_surfaces_a_dead_client_from_the_live_loop() {
        // A closed client fails every read until `run()` is rebuilt, so the
        // block-level retry must not spin on it: the error ends the run and the
        // supervisor's restart reconnects.
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(&central, 9, central_state(vec![]));
        source.state_errors.insert(
            (central.clone(), hash_of(10)),
            ReadFailure::ClientClosed.marker().to_string(),
        );

        let mut harness = RunFixture::spawn(source, 8).await;
        assert_block(&harness.next_event().await, 9);
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        live_tx.send(block_ref(10)).await.expect("send live block");

        let err = tokio::time::timeout(Duration::from_secs(5), harness.handle)
            .await
            .expect("run() returns promptly instead of retrying a dead client")
            .expect("run task panicked")
            .expect_err("a dead client must surface for the supervised reconnect");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "err: {err}"
        );
        drop(live_tx);
    }

    #[tokio::test]
    async fn catchup_retries_a_transient_central_read() {
        // A node hiccup costs a retry, not a supervised restart: block 8's OWN
        // emission proves the faulted read was re-attempted.
        let (record, rid) = caller_record_and_rid();
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(&central, 6, central_state(vec![]));
        source.set_state(&central, 7, central_state(vec![]));
        source.set_state(
            &central,
            8,
            central_state(vec![notification_entry(1, &rid)]),
        );
        source.set_state(
            &central,
            9,
            central_state(vec![notification_entry(1, &rid)]),
        );
        source.set_state(&hex::encode(CALLER), 8, caller_state(&record, &rid));
        // A transport fault on the central read, not the pruning signature.
        source.set_transient_error(
            &central,
            8,
            1,
            "contract state read failed: connection reset by peer",
        );

        let mut harness = RunFixture::spawn(source, 6).await;
        assert_block(&harness.next_event().await, 7);
        assert_sign_request(&harness.next_event().await, rid);
        assert_block(&harness.next_event().await, 8);
        assert_block(&harness.next_event().await, 9);
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn live_retries_a_transient_central_read() {
        // A hiccup in the live loop must cost a retry, not a supervised restart, and
        // the request the failing read was carrying still arrives.
        let (record, rid) = caller_record_and_rid();
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 8,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(
            &central,
            9,
            central_state(vec![notification_entry(1, &rid)]),
        );
        source.set_state(&hex::encode(CALLER), 9, caller_state(&record, &rid));
        source.set_transient_error(
            &central,
            9,
            1,
            "contract state read failed: connection reset by peer",
        );

        let mut harness = RunFixture::spawn(source, 8).await;
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        live_tx.send(block_ref(9)).await.expect("send live block");
        assert_sign_request(&harness.next_event().await, rid);
        assert_block(&harness.next_event().await, 9);
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_surfaces_a_dead_client_from_the_anchor_read() {
        // `retry_startup` must not spin against a client that can never answer
        // again: the dead-client class escapes so the supervised restart
        // reconnects instead of the watchdog rescuing it minutes later.
        let source = FixtureSource {
            sticky_head_error: Some(ReadFailure::ClientClosed.marker().to_string()),
            ..Default::default()
        };
        let harness = RunFixture::spawn(source, 8).await;
        let err = tokio::time::timeout(Duration::from_secs(5), harness.handle)
            .await
            .expect("run() returns promptly instead of retrying a dead client at startup")
            .expect("run task panicked")
            .expect_err("a dead client at the anchor read must surface for the reconnect");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "err: {err}"
        );
    }

    #[tokio::test]
    async fn run_retries_a_transient_anchor_read() {
        // A startup fault costs an in-place retry, never a supervised restart:
        // reaching CatchupCompleted proves the faulted sampling was re-attempted.
        // The connect step runs through the same `retry_startup`.
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 8,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            transient_head_errors: std::sync::Mutex::new(2),
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));

        let mut harness = RunFixture::spawn(source, 8).await;
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_surfaces_the_pruning_signature_from_the_live_loop() {
        // The one failure the retry must NOT swallow: no number of retries makes a
        // pruned node serve the state, so it ends `run()` and the restart re-anchors
        // and re-anchors.
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(&central, 9, central_state(vec![]));
        source.set_unservable(&central, 10);

        let mut harness = RunFixture::spawn(source, 8).await;
        assert_block(&harness.next_event().await, 9);
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        live_tx.send(block_ref(10)).await.expect("send live block");

        let err = tokio::time::timeout(Duration::from_secs(5), harness.handle)
            .await
            .expect("run() returns promptly")
            .expect("run task panicked")
            .expect_err("a pruned node must surface for the supervised restart");
        assert!(
            err.to_string().contains("cannot serve contract state"),
            "err: {err}"
        );
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_surfaces_central_undecodable_from_the_live_loop() {
        // Bytes the ledger deserializer refuses on the CENTRAL contract mean this
        // build can no longer read the chain (ledger drift): retrying cannot fix
        // it, so the run must end with one loud error instead of a retry storm.
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(&central, 9, central_state(vec![]));
        source.set_undecodable(&central, 10);

        let mut harness = RunFixture::spawn(source, 8).await;
        assert_block(&harness.next_event().await, 9);
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        live_tx.send(block_ref(10)).await.expect("send live block");

        let err = tokio::time::timeout(Duration::from_secs(5), harness.handle)
            .await
            .expect("run() returns promptly instead of retrying an undecodable state")
            .expect("run task panicked")
            .expect_err("an undecodable central state must surface for the supervised hold");
        assert!(
            err.to_string().contains("did not decode"),
            "the hold must name the decode failure: {err:#}"
        );
        drop(live_tx);
    }

    #[tokio::test]
    async fn emit_block_does_not_double_count_requests() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        #[derive(Clone, Default)]
        struct CountingTelemetry(Arc<AtomicUsize>);

        impl ChainTelemetry for CountingTelemetry {
            fn block_indexed(&self, _block_number: u64) {}
            fn block_finalized(&self, _block_number: u64) {}
            fn checkpoint_created(&self, _block_number: u64) {}
            fn request_indexed_at(&self, _block_timestamp: u64) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn request_indexed(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn bidirectional_extraction_failed(
                &self,
                _kind: mpc_chain_integration_core::ExtractionFailureKind,
            ) {
            }
        }

        let (record, rid) = caller_record_and_rid();
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(
            &central,
            9,
            central_state(vec![notification_entry(1, &rid)]),
        );
        source.set_state(&hex::encode(CALLER), 9, caller_state(&record, &rid));

        let counted = CountingTelemetry::default();
        let state = MockStateManager::new();
        state.set_processed_block(Chain::Midnight, 8).await;
        let indexer = MidnightIndexer::new(test_config(), state, counted.clone())
            .await
            .expect("indexer constructs");

        let (events_tx, mut events_rx) = chain_event_channel();
        let cancel = CancellationToken::new();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { indexer.run_with_source(&source, events_tx, cancel).await }
        });
        // Drain until the block that carries the request has been emitted.
        loop {
            let event = tokio::time::timeout(Duration::from_secs(5), events_rx.recv())
                .await
                .expect("timed out")
                .expect("channel closed");
            if matches!(event, ChainEvent::Block(9)) {
                break;
            }
        }
        assert_eq!(
            counted.0.load(Ordering::Relaxed),
            0,
            "the indexer must not count requests itself; the stream layer counts every one"
        );
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_returns_ok_on_cancel_mid_catchup() {
        // The range walk's own cancel arms.
        let (reached_tx, mut reached_rx) = mpsc::channel(1);
        let (live_tx, live_rx) = mpsc::channel(8);
        let source = FixtureSource {
            head: 600,
            park_at: Some(103),
            reached: Some(reached_tx),
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };

        let mut harness = RunFixture::spawn(source, 100).await;
        assert_block(&harness.next_event().await, 101);
        assert_block(&harness.next_event().await, 102);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), reached_rx.recv())
                .await
                .expect("the range walk must reach the parked height")
                .expect("park signal channel closed"),
            "block_at:103",
            "cancel must arrive while the walk is parked mid-range"
        );

        // A walk parked mid-range emits exactly the blocks it completed, no more: 103 is
        // suspended, so nothing beyond 102 can have reached the channel.
        assert!(
            harness.events_rx.try_recv().is_err(),
            "the walk emitted past the last block it actually completed"
        );
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_bails_when_block_producer_terminates() {
        // Ok(()) is shutdown to run_supervised, so an ended producer must surface as
        // Err; only cancel may return Ok.
        let central = central_address();
        let mut source = FixtureSource {
            head: 8,
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));

        let mut harness = RunFixture::spawn(source, 8).await;
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));

        drop(live_tx);
        let err = tokio::time::timeout(Duration::from_secs(5), harness.handle)
            .await
            .expect("run() should return promptly when the producer ends")
            .expect("run task panicked")
            .expect_err("an ended producer must be Err, never Ok: Ok is permanent shutdown");
        assert!(
            err.to_string().contains("producer terminated"),
            "err: {err}"
        );
    }

    #[tokio::test]
    async fn run_leaves_the_persisted_checkpoint_to_the_block_consumer() {
        // The height belongs to whoever CONSUMED the block's events, not to whoever
        // queued them: the node advances it in `process_block_event` after the block's
        // requests have been processed, and only once caught up. An indexer that
        // advanced it here would claim blocks whose events are still sitting in the
        // channel, and a supervised restart drops that channel.
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        for n in 5..=10 {
            source.set_state(&central, n, central_state(vec![]));
        }
        let mut harness = RunFixture::spawn(source, 5).await;
        for n in 6..=9 {
            assert_block(&harness.next_event().await, n);
        }
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        live_tx.send(block_ref(10)).await.expect("send live block");
        assert_block(&harness.next_event().await, 10);

        assert_eq!(
            harness.state.get_processed_block(Chain::Midnight).await,
            Some(5),
            "the indexer only READS the checkpoint at startup; emitting Block is how it \
         reports progress"
        );
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_recatches_from_checkpoint_on_restart() {
        // A restart resumes from the persisted checkpoint rather than re-walking from
        // zero or skipping the gap.
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        for n in 5..=9 {
            source.set_state(&central, n, central_state(vec![]));
        }
        let mut harness = RunFixture::spawn(source, 5).await;
        for n in 6..=9 {
            assert_block(&harness.next_event().await, n);
        }
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        let state = harness.state.clone();
        harness.cancel_and_join().await;
        drop(live_tx);
        // Stands in for the node's `process_block_event`, which is what advances the
        // height once it has consumed each `Block` event asserted above.
        state.set_processed_block(Chain::Midnight, 9).await;

        // The restart: same persisted state, head advanced to 12.
        let (live_tx2, live_rx2) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 12,
            live: tokio::sync::Mutex::new(Some(live_rx2)),
            ..Default::default()
        };
        for n in 9..=12 {
            source.set_state(&central, n, central_state(vec![]));
        }
        let mut second = RunFixture::spawn_with_state(source, state).await;
        for n in 10..=12 {
            assert_block(&second.next_event().await, n);
        }
        assert!(matches!(
            second.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        second.cancel_and_join().await;
        drop(live_tx2);
    }

    #[tokio::test]
    async fn run_anchors_at_head_without_catchup_when_fresh() {
        // Checkpoint 0: no gap to close and no genesis walk; live starts at the anchor.
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 8,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(&central, 9, central_state(vec![]));

        let mut harness = RunFixture::spawn(source, 0).await;
        assert!(
            matches!(harness.next_event().await, ChainEvent::CatchupCompleted),
            "a fresh node emits no catchup blocks"
        );
        live_tx.send(block_ref(9)).await.expect("send live block");
        assert_block(&harness.next_event().await, 9);
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn process_block_drops_only_failing_entry() {
        // One malformed record must never stop indexing for everyone.
        let (good_record, good_rid) = caller_record_and_rid();
        // Reserved algo: decodes off the wire, then fails conversion.
        let mut bad_record = sample_record();
        bad_record.algo = 1;
        let bad_rid = crate::request_id::compute_request_id(&bad_record);
        let central = central_address();
        let mut source = FixtureSource {
            head: 8,
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(
            &central,
            9,
            central_state(vec![
                notification_entry(1, &bad_rid),
                notification_entry(2, &good_rid),
            ]),
        );
        source.set_state(
            &hex::encode(CALLER),
            9,
            array_of(vec![
                StateValue::Null,
                StateValue::Null,
                StateValue::Null,
                StateValue::Null,
                map_of(vec![
                    (key_of(bad_rid), cell_from_record(&bad_record)),
                    (key_of(good_rid), cell_from_record(&good_record)),
                ]),
            ]),
        );

        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));

        let mut harness = RunFixture::spawn(source, 8).await;
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));

        live_tx.send(block_ref(9)).await.expect("send live block");
        assert_sign_request(&harness.next_event().await, good_rid);
        // The block completes and reports progress past the bad entry.
        assert_block(&harness.next_event().await, 9);
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_skips_replayed_live_block() {
        // The re-delivery guard.
        let central = central_address();
        let mut source = FixtureSource {
            head: 8,
            ..Default::default()
        };
        for n in 8..=10 {
            source.set_state(&central, n, central_state(vec![]));
        }
        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));

        let mut harness = RunFixture::spawn(source, 8).await;
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));

        live_tx.send(block_ref(9)).await.expect("send 9");
        assert_block(&harness.next_event().await, 9);

        live_tx.send(block_ref(9)).await.expect("replay 9");
        live_tx.send(block_ref(10)).await.expect("send 10");
        assert_block(&harness.next_event().await, 10);
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn midnight_indexer_new_rejects_unusable_config() {
        let config = MidnightConfig {
            node_ws_url: String::new(),
            central_address: "ab".repeat(32),
            publisher: None,
            rpc: Default::default(),
            indexer: Default::default(),
        };
        let Err(err) = TestIndexer::new(config, MockStateManager::new(), NoopChainTelemetry).await
        else {
            panic!("an empty node_ws_url must fail at construction, not forever at runtime")
        };
        let err = err.to_string();
        assert!(err.contains("node_ws_url"), "unexpected error: {err}");
    }
}
