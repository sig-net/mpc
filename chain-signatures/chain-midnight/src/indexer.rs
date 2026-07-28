//! Catchup from the persisted checkpoint, then the live finalized loop.

use crate::config::MidnightConfig;
use crate::convert::to_sign_request;
use crate::reader::{
    decode_notification, resolve_verified_record, signet_field_node, unpack_notification_v1, Node,
    Resolved,
};
use crate::rpc::{is_state_unservable, ArchiveState, BlockRef, MidnightRpc};
use crate::state::decode_contract_state;
use crate::tx_decode::{decode_transactions, DecodedTransactions};

use midnight_base_crypto::fab::AlignedValue;
use midnight_onchain_state::state::StateValue;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::StreamExt as _;
use mpc_chain_integration_core::utils::task::AbortOnDrop;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{Chain, ChainEvent, IndexedSignRequest};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const RETRY_DELAY: Duration = Duration::from_millis(500);

/// The central singleton's notification map ordinal, the only field the diff reads.
const NOTIFICATION_MAP_FIELD: u8 = 1;

/// What a contract-state read found.
pub(crate) enum ContractState {
    Tree(Node),
    /// Not present at that block.
    Absent,
    /// The node served bytes that did not deserialize.
    Undecodable(anyhow::Error),
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

/// Applies the startup policy to the archive probe's answer: degrade by default, refuse
/// when the operator set `require_archive_state`.
pub fn select_catchup_mode(
    state: ArchiveState,
    require_archive_state: bool,
) -> anyhow::Result<ArchiveState> {
    match state {
        ArchiveState::Archive => Ok(state),
        ArchiveState::Pruned { probed_height } => {
            anyhow::ensure!(
                !require_archive_state,
                "midnight node cannot serve contract state at height {probed_height} and \
                 require_archive_state is set: rerun the node with --state-pruning archive, \
                 or unset require_archive_state to accept watermark catchup"
            );
            tracing::warn!(
                probed_height,
                "midnight node is pruned within the archive probe window; catchup will \
                 degrade to the watermark path. Rerun the node with --state-pruning archive \
                 to restore exact-block reads"
            );
            Ok(state)
        }
    }
}

/// The node reads `run()` consumes, as a test seam.
#[async_trait]
pub(crate) trait ChainSource: Send + Sync {
    async fn probe_archive_state(&self, window: u64) -> anyhow::Result<ArchiveState>;
    async fn finalized_head(&self) -> anyhow::Result<BlockRef>;
    async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef>;
    /// The decoded state tree of `address_64hex` at `at_hash`.
    async fn contract_state_tree(
        &self,
        address_64hex: &str,
        at_hash: &str,
    ) -> anyhow::Result<ContractState>;
    /// The block's decoded `send_mn_transaction` calls, advisory only.
    async fn decoded_transactions(&self, block: &BlockRef) -> anyhow::Result<DecodedTransactions>;
    /// Pushes live finalized blocks into `tx` until the underlying stream ends; the
    /// returned guard aborts the producer on drop.
    async fn spawn_block_producer(&self, tx: mpsc::Sender<BlockRef>)
        -> anyhow::Result<AbortOnDrop>;
}

/// Bytes that do not deserialize are charged to the contract that owns them, never to
/// the read: the decode is in-process, so there is no transport that could have failed.
fn classify_decode(decoded: anyhow::Result<Node>) -> anyhow::Result<ContractState> {
    match decoded {
        Ok(tree) => Ok(ContractState::Tree(tree)),
        Err(err) => Ok(ContractState::Undecodable(err)),
    }
}

struct LiveSource {
    rpc: MidnightRpc,
}

impl LiveSource {
    async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        Ok(Self {
            rpc: MidnightRpc::connect(config).await?,
        })
    }
}

#[async_trait]
impl ChainSource for LiveSource {
    async fn probe_archive_state(&self, window: u64) -> anyhow::Result<ArchiveState> {
        self.rpc.probe_archive_state(window).await
    }

    async fn finalized_head(&self) -> anyhow::Result<BlockRef> {
        self.rpc.finalized_block_ref().await
    }

    async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef> {
        self.rpc.block_ref_at(number).await
    }

    async fn contract_state_tree(
        &self,
        address_64hex: &str,
        at_hash: &str,
    ) -> anyhow::Result<ContractState> {
        match self.rpc.contract_state(address_64hex, at_hash).await? {
            None => Ok(ContractState::Absent),
            // Decoded in-process by the ledger's own deserializer: the state path makes
            // no network call beyond the node read above.
            Some(state) => classify_decode(decode_contract_state(&state)),
        }
    }

    async fn decoded_transactions(&self, block: &BlockRef) -> anyhow::Result<DecodedTransactions> {
        let blobs = self.rpc.send_mn_transaction_bytes_at(&block.hash).await?;
        if blobs.is_empty() {
            return Ok(DecodedTransactions {
                transactions: Vec::new(),
                skipped: Vec::new(),
            });
        }
        let decoded = decode_transactions(&blobs);
        if !decoded.skipped.is_empty() {
            // Advisory, like the rest of provenance: an unreadable blob costs
            // attribution for this block, never a request.
            tracing::warn!(
                height = block.number,
                reason = "provenance-blob-skipped",
                "could not decode {} of {} transaction blobs: {:?}",
                decoded.skipped.len(),
                blobs.len(),
                decoded.skipped
            );
        }
        Ok(decoded)
    }

    async fn spawn_block_producer(
        &self,
        tx: mpsc::Sender<BlockRef>,
    ) -> anyhow::Result<AbortOnDrop> {
        let mut stream = self.rpc.subscribe_finalized().await?;
        Ok(AbortOnDrop(tokio::spawn(async move {
            while let Some(block) = stream.next().await {
                if tx.send(block.block_ref()).await.is_err() {
                    return;
                }
            }
        })))
    }
}

/// Advisory cross-contract-call provenance: the address of the call claiming the
/// central call's communication commitment in the same transaction.
fn attribute_caller(txs: &DecodedTransactions, central_address: &str) -> Option<String> {
    for tx in &txs.transactions {
        let Some(central_call) = tx.calls.iter().find(|call| call.address == central_address)
        else {
            continue;
        };
        for call in &tx.calls {
            if call.address == central_address {
                continue;
            }
            if call
                .claimed
                .iter()
                .any(|claim| claim.commitment == central_call.communication_commitment)
            {
                return Some(call.address.clone());
            }
        }
    }
    None
}

/// The composite `SignetMapKey { count: Uint<64>, requestId: Bytes<32> }` recovered
/// from its atom-preserving wire key: two trimmed atoms, the count folded little-endian
/// and the rid re-padded.
fn signet_map_key_rid(key: &AlignedValue) -> Option<(u64, [u8; 32])> {
    let [count, rid] = key.value.0.as_slice() else {
        return None;
    };
    Some((
        u64::try_from(count).ok()?,
        <[u8; 32]>::try_from(rid.clone()).ok()?,
    ))
}

/// The central singleton's `respondCounterMap` ordinal: the on-chain per-rid watermark
/// the degraded catchup reads.
const RESPOND_COUNTER_FIELD: u8 = 2;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One entry of a central map, keyed by the composite `SignetMapKey`.
#[derive(Clone, PartialEq)]
pub(crate) struct MapEntry {
    pub key: AlignedValue,
    pub value: Node,
}

/// The entries of a central-tree field that must be a map, or `None` when the field
/// could not be read at all.
fn central_map_entries(
    tree: &Node,
    field: u8,
    field_name: &'static str,
    height: u64,
) -> Option<Vec<MapEntry>> {
    match signet_field_node(tree, usize::from(field)) {
        Ok(StateValue::Map(entries)) => Some(
            entries
                .iter()
                .map(|entry| {
                    let (key, value) = &*entry;
                    MapEntry {
                        key: (**key).clone(),
                        value: (**value).clone(),
                    }
                })
                .collect(),
        ),
        Ok(_) => {
            degraded_read(
                "central-field-not-a-map",
                height,
                &format!(
                    "central field {field} ({field_name}) is not a map; wrong central address \
                     or schema drift"
                ),
            );
            None
        }
        Err(err) => {
            degraded_read(
                "central-field-walk",
                height,
                &format!("central field {field} ({field_name}): {err:#}"),
            );
            None
        }
    }
}

/// Per-rid response counts from the central tree's field 2.
fn response_counts(tree: &Node, height: u64) -> HashMap<[u8; 32], u64> {
    central_map_entries(tree, RESPOND_COUNTER_FIELD, "respondCounterMap", height)
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| {
            let rid = counter_map_rid(&entry.key)?;
            let StateValue::Cell(count) = &entry.value else {
                return Some((rid, 0));
            };
            let count = count
                .value
                .0
                .first()
                .and_then(|atom| u64::try_from(atom).ok())
                .unwrap_or(0);
            Some((rid, count))
        })
        .collect()
}

/// The counter maps' single-atom `Bytes<32>` key.
fn counter_map_rid(key: &AlignedValue) -> Option<[u8; 32]> {
    let [atom] = key.value.0.as_slice() else {
        return None;
    };
    <[u8; 32]>::try_from(atom.clone()).ok()
}

// The reporting contract.

/// One drop, one WARN, one distinct reason label.
fn drop_entry(
    reason: &'static str,
    height: u64,
    request_id: Option<[u8; 32]>,
    detail: &str,
) -> Option<IndexedSignRequest> {
    tracing::warn!(
        reason,
        height,
        request_id = request_id.map(hex::encode),
        "midnight entry dropped: {detail}"
    );
    None
}

/// A field or block read that degraded.
fn degraded_read(reason: &'static str, height: u64, detail: &str) {
    tracing::warn!(reason, height, "midnight read degraded: {detail}");
}

/// Labels the pruning signature at the three sites that cannot switch catchup modes in
/// place: the live loop, the finality-gap walk, and the per-entry caller read.
fn note_unservable(err: anyhow::Error, height: u64) -> anyhow::Error {
    if is_state_unservable(&err) {
        tracing::warn!(
            reason = "state-unservable-restart",
            height,
            "midnight node pruned under an in-flight read; restarting to re-anchor and recover \
             through the watermark walk"
        );
    }
    err
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
}

/// Retries `attempt` every [`RETRY_DELAY`] until it succeeds or `cancel` fires.
///
/// The per-item retry the other chains' indexers apply around their own block
/// processing: a node hiccup costs one retry here, not a supervised
/// restart that re-runs backlog recovery, re-probes state retention, re-anchors and
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
            Err(err) if is_state_unservable(&err) => return Retried::Unservable(err),
            Err(err) => tracing::warn!(
                reason = "retrying",
                height,
                "midnight {what} failed: {err:#}; retrying"
            ),
        }
        tokio::select! {
            _ = cancel.cancelled() => return Retried::Cancelled,
            _ = tokio::time::sleep(RETRY_DELAY) => {}
        }
    }
}

/// An observation from the advisory provenance join.
fn advisory_note(reason: &'static str, height: u64, request_id: Option<[u8; 32]>, detail: &str) {
    tracing::warn!(
        reason,
        height,
        request_id = request_id.map(hex::encode),
        "midnight provenance advisory, request still signed: {detail}"
    );
}

/// Whether advisory attribution ran for the entries being processed.
enum Attribution {
    Skipped,
    Ran(Option<String>),
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
            ContractState::Undecodable(err) => {
                Err(err.context("the central contract's own state did not decode"))
            }
        }
    }

    /// Field-1 entries of an already-fetched central tree, or `None` when the field
    /// could not be read.
    fn notification_entries(tree: &Node, height: u64) -> Option<Vec<MapEntry>> {
        central_map_entries(
            tree,
            NOTIFICATION_MAP_FIELD,
            "signBidirectionalEventNotificationMap",
            height,
        )
    }

    /// Per-block processing, shared by catchup and live.
    async fn process_block<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut Option<(String, Vec<MapEntry>)>,
        block: &BlockRef,
    ) -> anyhow::Result<Vec<IndexedSignRequest>> {
        // `None` means the map could not be read.
        let read_entries: Option<Vec<MapEntry>> =
            match self.central_tree(source, &block.hash).await? {
                Some(tree) => Self::notification_entries(&tree, block.number),
                // Central not yet deployed at this block: an ordinary empty block,
                // common during catchup from before deployment.
                None => Some(Vec::new()),
            };
        let entries = read_entries.clone().unwrap_or_default();

        // `None` is "could not read the parent", not "the parent had no entries", and
        // is the one state the diff below must refuse to subtract.
        let parent_entries: Option<Vec<MapEntry>> = match cache.take() {
            Some((hash, entries)) if hash == block.parent_hash => Some(entries),
            _ => match self.central_tree(source, &block.parent_hash).await? {
                Some(tree) => Self::notification_entries(&tree, block.number.saturating_sub(1)),
                None => Some(Vec::new()),
            },
        };
        let new_entries: Vec<&MapEntry> = match &parent_entries {
            Some(parent) => {
                let parent_keys: HashSet<&AlignedValue> =
                    parent.iter().map(|entry| &entry.key).collect();
                entries
                    .iter()
                    .filter(|entry| !parent_keys.contains(&entry.key))
                    .collect()
            }
            // No diff is possible, so this block emits nothing, giving up only the
            // entries filed at this exact height.
            None => {
                degraded_read(
                    "parent-notification-map-unreadable",
                    block.number,
                    &format!(
                        "cannot diff against the parent, so this block emits nothing and the {} \
                         entries visible here are not evaluated; any filed at exactly this \
                         height are given up. The next block diffs against this one",
                        entries.len()
                    ),
                );
                Vec::new()
            }
        };

        let mut requests = Vec::new();
        if !new_entries.is_empty() {
            // Advisory attribution, once per block.
            let attribution = match source.decoded_transactions(block).await {
                Ok(txs) => Attribution::Ran(attribute_caller(&txs, &self.config.central_address)),
                Err(err) => {
                    degraded_read(
                        "provenance-decode-failed",
                        block.number,
                        &format!("{err:#}"),
                    );
                    Attribution::Ran(None)
                }
            };
            let indexed_ts = unix_now();
            for entry in new_entries {
                if let Some(request) = self
                    .process_entry(
                        source,
                        entry,
                        &block.hash,
                        block.number,
                        &attribution,
                        indexed_ts,
                    )
                    .await?
                {
                    requests.push(request);
                }
            }
        }

        // Only a map that was actually read becomes the next block's parent.
        *cache = read_entries.map(|entries| (block.hash.clone(), entries));
        Ok(requests)
    }

    /// One notification entry: decode and unpack it, read the caller's ledger at
    /// `at_hash`, gate through `resolve_verified_record`, convert.
    async fn process_entry<C: ChainSource>(
        &self,
        source: &C,
        entry: &MapEntry,
        at_hash: &str,
        height: u64,
        attribution: &Attribution,
        indexed_ts: u64,
    ) -> anyhow::Result<Option<IndexedSignRequest>> {
        let Some((_, rid)) = signet_map_key_rid(&entry.key) else {
            return Ok(drop_entry(
                "malformed-map-key",
                height,
                None,
                &format!("{} atoms in a SignetMapKey", entry.key.value.0.len()),
            ));
        };
        let notification = match decode_notification(&entry.value) {
            Ok(notification) => notification,
            Err(err) => {
                return Ok(drop_entry(
                    "notification-undecodable",
                    height,
                    Some(rid),
                    &format!("{err:#}"),
                ));
            }
        };
        let unpacked = match unpack_notification_v1(&notification) {
            Ok(unpacked) => unpacked,
            Err(err) => {
                return Ok(drop_entry(
                    "notification-version",
                    height,
                    Some(rid),
                    &format!("{err:#}"),
                ));
            }
        };
        let caller_hex = hex::encode(unpacked.caller_address);

        // Advisory, never a gate: absence and disagreement are notes and the read below
        // proceeds regardless, which is why they go through `advisory_note`.
        match attribution {
            Attribution::Ran(Some(address)) if *address != caller_hex => {
                advisory_note(
                    "provenance-mismatch",
                    height,
                    Some(rid),
                    &format!("decoded caller {address} vs notification {caller_hex}"),
                );
            }
            Attribution::Ran(None) => {
                advisory_note(
                    "provenance-absent",
                    height,
                    Some(rid),
                    "no commitment pair in this block's decoded calls",
                );
            }
            _ => {}
        }

        // Authority: the caller's own ledger at the SAME finalized hash the
        // notification was read at.
        let caller_tree = match source
            .contract_state_tree(&caller_hex, at_hash)
            .await
            .map_err(|err| note_unservable(err, height))?
        {
            ContractState::Tree(tree) => tree,
            ContractState::Absent => {
                return Ok(drop_entry(
                    "caller-contract-absent",
                    height,
                    Some(rid),
                    &caller_hex,
                ));
            }
            // The caller's own bytes, refused by the decoder: a per-entry data property
            // like the rest.
            ContractState::Undecodable(err) => {
                return Ok(drop_entry(
                    "caller-state-undecodable",
                    height,
                    Some(rid),
                    &format!("{caller_hex}: {err:#}"),
                ));
            }
        };
        let field =
            match signet_field_node(&caller_tree, usize::from(unpacked.requests_index_field)) {
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
        match to_sign_request(
            &record,
            &unpacked.caller_address,
            &self.config.central_address,
            rid,
            indexed_ts,
        ) {
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
    /// Spelled out rather than handed to that helper because it holds `&mut cache`
    /// across attempts, which a closure returning a future cannot.
    async fn process_block_retrying<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut Option<(String, Vec<MapEntry>)>,
        block: &BlockRef,
        cancel: &CancellationToken,
    ) -> Retried<Vec<IndexedSignRequest>> {
        loop {
            let result = tokio::select! {
                _ = cancel.cancelled() => return Retried::Cancelled,
                result = self.process_block(source, cache, block) => result,
            };
            match result {
                Ok(requests) => return Retried::Done(requests),
                Err(err) if is_state_unservable(&err) => return Retried::Unservable(err),
                Err(err) => tracing::warn!(
                    reason = "retrying",
                    height = block.number,
                    "midnight block processing failed: {err:#}; retrying"
                ),
            }
            tokio::select! {
                _ = cancel.cancelled() => return Retried::Cancelled,
                _ = tokio::time::sleep(RETRY_DELAY) => {}
            }
        }
    }

    /// The degraded catchup: read the central contract's latest state once at the
    /// anchor and process every field-1 entry above the per-rid watermark.
    async fn catchup_from_latest_state<C: ChainSource>(
        &self,
        source: &C,
        events_tx: &mpsc::Sender<ChainEvent>,
        cancel: &CancellationToken,
        anchor: &BlockRef,
    ) -> anyhow::Result<()> {
        let Some(tree) = self.central_tree(source, &anchor.hash).await? else {
            // No central contract at the head: nothing to recover; the anchor emit
            // below still records progress.
            tracing::info!(
                anchor = anchor.number,
                "watermark catchup: central contract not present at the anchor"
            );
            return self.emit_block(events_tx, anchor, Vec::new()).await;
        };
        // This walk subtracts nothing, so an unreadable map is simply no work to do,
        // and `central_map_entries` has already named it.
        let entries = Self::notification_entries(&tree, anchor.number).unwrap_or_default();
        let responses = response_counts(&tree, anchor.number);

        let indexed_ts = unix_now();
        let mut requests = Vec::new();
        for entry in &entries {
            if cancel.is_cancelled() {
                // No progress is persisted on a cancelled walk; the next run re-covers
                // from the same checkpoint.
                return Ok(());
            }
            if let Some((count, rid)) = signet_map_key_rid(&entry.key) {
                if count < responses.get(&rid).copied().unwrap_or(0) {
                    // This instance predates the latest phase-1 response, so its answer
                    // already exists on-chain.
                    continue;
                }
            }
            let request =
                match retry_until_cancelled("watermark entry", anchor.number, cancel, || {
                    self.process_entry(
                        source,
                        entry,
                        &anchor.hash,
                        anchor.number,
                        &Attribution::Skipped,
                        indexed_ts,
                    )
                })
                .await
                {
                    Retried::Done(request) => request,
                    Retried::Cancelled => return Ok(()),
                    Retried::Unservable(err) => return Err(err),
                };
            if let Some(request) = request {
                requests.push(request);
            }
        }
        self.emit_block(events_tx, anchor, requests).await
    }

    /// Emits a block's requests, then its Block event, then records telemetry.
    ///
    /// The Block event is the whole progress report: the node advances the persisted
    /// height in `process_block_event` after CONSUMING it, and only once caught up.
    /// Writing the height here instead would claim blocks whose requests are still
    /// queued, and a supervised restart allocates a fresh event channel and drops
    /// whatever the old one still held, so those requests would be neither delivered
    /// nor re-walked. Leaving the height to the consumer is what makes a restart
    /// self-healing, and is what every other chain does.
    async fn emit_block(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        block: &BlockRef,
        requests: Vec<IndexedSignRequest>,
    ) -> anyhow::Result<()> {
        for request in requests {
            events_tx
                .send(ChainEvent::SignRequest {
                    request,
                    block_timestamp: None,
                })
                .await
                .context("failed to send a midnight sign request event")?;
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
        // Startup gate.
        let state = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            state = source.probe_archive_state(self.config.indexer.archive_probe_window) => state?,
        };
        let mode = select_catchup_mode(state, self.config.indexer.require_archive_state)?;
        self.telemetry
            .catchup_degraded(matches!(mode, ArchiveState::Pruned { .. }));

        let checkpoint = self
            .state_manager
            .get_processed_block(Chain::Midnight)
            .await
            .unwrap_or(0);
        let anchor = loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                head = source.finalized_head() => match head {
                    Ok(head) => break head,
                    Err(err) => {
                        tracing::warn!("midnight anchor sampling failed: {err:#}; retrying");
                        tokio::select! {
                            _ = cancel.cancelled() => return Ok(()),
                            _ = tokio::time::sleep(RETRY_DELAY) => {}
                        }
                    }
                }
            }
        };

        let mut cache: Option<(String, Vec<MapEntry>)> = None;
        let mut last_processed = checkpoint;
        // Pruned goes straight to the watermark walk: a degraded block walk could only
        // drop unservable blocks and lose their requests, where the watermark recovers
        // them from latest state.
        let mut need_watermark = matches!(mode, ArchiveState::Pruned { .. });
        if checkpoint == 0 {
            // A fresh node has no gap to close, and walking from genesis would
            // reprocess the whole chain, so catchup anchors at the finalized head in
            // either mode.
            tracing::info!(
                anchor = anchor.number,
                "midnight fresh start: no checkpoint, anchoring at the finalized head"
            );
            last_processed = anchor.number;
            need_watermark = false;
        } else if !need_watermark {
            'range: for number in (checkpoint + 1)..=anchor.number {
                let block = match retry_until_cancelled("block lookup", number, &cancel, || {
                    source.block_at(number)
                })
                .await
                {
                    Retried::Done(block) => block,
                    Retried::Cancelled => return Ok(()),
                    Retried::Unservable(err) => return Err(err),
                };
                match self
                    .process_block_retrying(source, &mut cache, &block, &cancel)
                    .await
                {
                    Retried::Done(requests) => {
                        self.emit_block(&events_tx, &block, requests).await?;
                        last_processed = number;
                    }
                    Retried::Cancelled => return Ok(()),
                    // The gap reaches deeper than the node's retention even though the
                    // probe said Archive.
                    Retried::Unservable(err) => {
                        tracing::warn!(
                            height = number,
                            reason = "catchup-switching-to-watermark",
                            "midnight catchup hit the pruning signature mid-range: {err:#}"
                        );
                        need_watermark = true;
                        break 'range;
                    }
                }
            }
        }
        if need_watermark {
            self.telemetry.catchup_degraded(true);
            self.catchup_from_latest_state(source, &events_tx, &cancel, &anchor)
                .await?;
            if cancel.is_cancelled() {
                return Ok(());
            }
            last_processed = anchor.number;
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
            for number in (last_processed + 1)..block.number {
                let gap = match retry_until_cancelled("block lookup", number, &cancel, || {
                    source.block_at(number)
                })
                .await
                {
                    Retried::Done(gap) => gap,
                    Retried::Cancelled => return Ok(()),
                    Retried::Unservable(err) => return Err(note_unservable(err, number)),
                };
                let requests = match self
                    .process_block_retrying(source, &mut cache, &gap, &cancel)
                    .await
                {
                    Retried::Done(requests) => requests,
                    Retried::Cancelled => return Ok(()),
                    Retried::Unservable(err) => return Err(note_unservable(err, number)),
                };
                self.emit_block(&events_tx, &gap, requests).await?;
            }
            let requests = match self
                .process_block_retrying(source, &mut cache, &block, &cancel)
                .await
            {
                Retried::Done(requests) => requests,
                Retried::Cancelled => return Ok(()),
                Retried::Unservable(err) => return Err(note_unservable(err, block.number)),
            };
            self.emit_block(&events_tx, &block, requests).await?;
            last_processed = block.number;
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
mod tests {
    use super::*;
    use mpc_chain_integration_core::utils::stream::chain_event_channel;
    use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
    use std::time::Duration;

    type TestIndexer = MidnightIndexer<MockStateManager, NoopChainTelemetry>;

    #[test]
    fn select_catchup_mode_degrades_pruned_by_default() {
        // Probe-and-degrade: pruned is a MODE, not an error, unless the operator opted
        // into strict refusal.
        assert_eq!(
            select_catchup_mode(ArchiveState::Archive, false).unwrap(),
            ArchiveState::Archive
        );
        assert_eq!(
            select_catchup_mode(ArchiveState::Archive, true).unwrap(),
            ArchiveState::Archive
        );
        assert_eq!(
            select_catchup_mode(ArchiveState::Pruned { probed_height: 924 }, false).unwrap(),
            ArchiveState::Pruned { probed_height: 924 }
        );
    }

    #[test]
    fn select_catchup_mode_refuses_pruned_when_archive_state_is_required() {
        // The strict error must hand the operator everything needed to act: the option
        // that made this fatal, the height that failed, and the node-side fix.
        let err = select_catchup_mode(ArchiveState::Pruned { probed_height: 924 }, true)
            .expect_err("require_archive_state turns pruned into a startup error")
            .to_string();
        for needle in ["require_archive_state", "924", "--state-pruning archive"] {
            assert!(
                err.contains(needle),
                "strict refusal must name {needle:?}, got: {err}"
            );
        }
    }

    // run() over an injected ChainSource.

    use crate::test_utils::{array_of, cell_from_record, cell_of, key_of, map_of, sample_record};
    use crate::tx_decode::{ClaimedCall, DecodedCall, DecodedTransaction};
    use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom};
    use mpc_chain_integration_core::utils::task::AbortOnDrop;
    use mpc_primitives::SignId;
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

    fn hash_of(number: u64) -> String {
        format!("0x{number:064x}")
    }

    fn block_ref(number: u64) -> BlockRef {
        BlockRef {
            number,
            hash: hash_of(number),
            parent_hash: hash_of(number - 1),
        }
    }

    fn trim(bytes: &[u8]) -> Vec<u8> {
        let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
        bytes[..end].to_vec()
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

    /// One notification-map entry: V1 payload naming CALLER and REQUESTS_FIELD.
    fn notification_entry(count: u8, rid: &[u8; 32]) -> (AlignedValue, Node) {
        let mut payload = CALLER.to_vec();
        payload.push(REQUESTS_FIELD);
        (
            signet_map_key(count, rid),
            cell_of(&[vec![1u8], payload], &[1, 128]),
        )
    }

    /// The central singleton: six flat fields, notification map at ordinal 1.
    fn central_state(entries: Vec<(AlignedValue, Node)>) -> Node {
        array_of(vec![
            StateValue::Null,
            map_of(entries),
            StateValue::Null,
            StateValue::Null,
            StateValue::Null,
            StateValue::Null,
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
        /// block hash -> decoded transactions; absent means empty.
        txs: HashMap<String, DecodedTransactions>,
        /// None means Archive (the common case for these tests).
        probe: Option<ArchiveState>,
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
                crate::rpc::STATE_UNSERVABLE_MSG.to_string(),
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
        async fn probe_archive_state(&self, _window: u64) -> anyhow::Result<ArchiveState> {
            Ok(self.probe.unwrap_or(ArchiveState::Archive))
        }

        async fn finalized_head(&self) -> anyhow::Result<BlockRef> {
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

        async fn decoded_transactions(
            &self,
            block: &BlockRef,
        ) -> anyhow::Result<DecodedTransactions> {
            Ok(self
                .txs
                .get(&block.hash)
                .cloned()
                .unwrap_or(DecodedTransactions {
                    transactions: Vec::new(),
                    skipped: Vec::new(),
                }))
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
            let indexer = MidnightIndexer::new(
                MidnightConfig {
                    node_ws_url: "ws://127.0.0.1:1".to_string(),
                    central_address: central_address(),
                    network_id: "undeployed".to_string(),
                    rpc: Default::default(),
                    indexer: Default::default(),
                },
                state.clone(),
                NoopChainTelemetry,
            )
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
        // Provenance PRESENT and matching for this one: a multi-call block whose
        // commitment join names the true caller.
        source.txs.insert(
            hash_of(9),
            DecodedTransactions {
                transactions: vec![DecodedTransaction {
                    index: 0,
                    calls: vec![
                        DecodedCall {
                            address: central.clone(),
                            communication_commitment: "cc01".to_string(),
                            claimed: Vec::new(),
                        },
                        DecodedCall {
                            address: hex::encode(CALLER),
                            communication_commitment: "cc02".to_string(),
                            claimed: vec![ClaimedCall {
                                address: central.clone(),
                                entry_point: "signBidirectional".to_string(),
                                commitment: "cc01".to_string(),
                            }],
                        },
                    ],
                }],
                skipped: Vec::new(),
            },
        );

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

    #[tokio::test]
    async fn process_block_emits_nothing_on_unreadable_parent_map() {
        let (record, rid) = caller_record_and_rid();
        let (other_record, other_rid) = named_record_and_rid(11);
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        // Block 8's central state is present but field 1 is not a map, so the
        // notification map there cannot be read: a shape TRANSITION, since block 9's is
        // readable.
        source.set_state(&central, 8, array_of(vec![StateValue::Null; 6]));
        source.set_state(
            &central,
            9,
            central_state(vec![notification_entry(1, &rid)]),
        );
        source.set_state(&hex::encode(CALLER), 9, caller_state(&record, &rid));
        // Block 10 adds a second notification on top of block 9's.
        source.set_state(
            &central,
            10,
            central_state(vec![
                notification_entry(1, &rid),
                notification_entry(1, &other_rid),
            ]),
        );
        source.set_state(
            &hex::encode(CALLER),
            10,
            array_of(vec![
                StateValue::Null,
                StateValue::Null,
                StateValue::Null,
                StateValue::Null,
                map_of(vec![
                    (key_of(rid), cell_from_record(&record)),
                    (key_of(other_rid), cell_from_record(&other_record)),
                ]),
            ]),
        );

        let mut harness = RunFixture::spawn(source, 8).await;
        // Block 9 emits its Block event and NO request: progress is still reported,
        // which is what keeps this out of a restart loop.
        assert_block(&harness.next_event().await, 9);
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));

        // Block 10 diffs against block 9, which WAS readable, so exactly the one
        // genuinely new entry emits.
        live_tx.send(block_ref(10)).await.expect("send live block");
        assert_sign_request(&harness.next_event().await, other_rid);
        assert_block(&harness.next_event().await, 10);
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn catchup_retries_a_transient_read_instead_of_degrading() {
        // A node hiccup costs a retry, not a switch to the watermark walk.
        // Block 8 is where the fault lands, so it is block 8's OWN emission that proves
        // the retry: degrading instead would abandon the range and emit only the
        // anchor, skipping 8 entirely.
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
        // A transport fault on the caller read, not the pruning signature: that one has
        // its own policy (switch to the watermark walk).
        source.set_transient_error(
            &hex::encode(CALLER),
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
    async fn live_retries_a_transient_read_instead_of_restarting() {
        // The live loop has no degraded fallback, so a failure there ends `run()` and
        // costs a supervised restart: backlog recovery, a fresh retention probe, a
        // re-anchor and a re-queue. A hiccup must cost a retry instead, and the request
        // the failing read was carrying still arrives.
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
            &hex::encode(CALLER),
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
    async fn run_surfaces_the_pruning_signature_from_the_live_loop() {
        // The one failure the retry must NOT swallow: no number of retries makes a
        // pruned node serve the state, so it ends `run()` and the restart re-anchors
        // and recovers through the watermark walk.
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
        let indexer = MidnightIndexer::new(
            MidnightConfig {
                node_ws_url: "ws://127.0.0.1:1".to_string(),
                central_address: central,
                network_id: "undeployed".to_string(),
                rpc: Default::default(),
                indexer: Default::default(),
            },
            state,
            counted.clone(),
        )
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
    async fn run_returns_ok_on_cancel_in_watermark_walk() {
        // The watermark walk's cancellation, which no other test reaches:
        // run_recovers_pruned_requests_via_watermark cancels only AFTER the walk has
        // finished.
        let (record, rid) = caller_record_and_rid();
        let central = central_address();
        let (reached_tx, mut reached_rx) = mpsc::channel(1);
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            probe: Some(ArchiveState::Pruned { probed_height: 3 }),
            park_state_read: Some(hex::encode(CALLER)),
            reached: Some(reached_tx),
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(
            &central,
            9,
            central_state_with_responses(vec![notification_entry(1, &rid)], &[]),
        );
        source.set_state(&hex::encode(CALLER), 9, caller_state(&record, &rid));

        let harness = RunFixture::spawn(source, 5).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), reached_rx.recv())
                .await
                .expect("the watermark walk must reach the parked caller read")
                .expect("park signal channel closed"),
            format!("state:{}", hex::encode(CALLER)),
            "cancel must arrive while the walk is parked inside an entry"
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

    #[test]
    fn attribute_caller_finds_committed_caller_and_rejects_decoys() {
        // Three shapes: multi-call, the matching claim NOT first, a decoy commitment
        // matching nothing, distinguishable values.
        let central = central_address();
        let txs = DecodedTransactions {
            transactions: vec![DecodedTransaction {
                index: 0,
                calls: vec![
                    DecodedCall {
                        address: "dd".repeat(32),
                        communication_commitment: "cc99".to_string(),
                        claimed: vec![ClaimedCall {
                            address: "dd".repeat(32),
                            entry_point: "unrelated".to_string(),
                            commitment: "feed".to_string(),
                        }],
                    },
                    DecodedCall {
                        address: central.clone(),
                        communication_commitment: "cc01".to_string(),
                        claimed: Vec::new(),
                    },
                    DecodedCall {
                        address: "ee".repeat(32),
                        communication_commitment: "cc02".to_string(),
                        claimed: vec![
                            ClaimedCall {
                                address: "aa".repeat(32),
                                entry_point: "other".to_string(),
                                commitment: "beef".to_string(),
                            },
                            ClaimedCall {
                                address: central.clone(),
                                entry_point: "signBidirectional".to_string(),
                                commitment: "cc01".to_string(),
                            },
                        ],
                    },
                ],
            }],
            skipped: Vec::new(),
        };
        assert_eq!(
            attribute_caller(&txs, &central),
            Some("ee".repeat(32)),
            "the caller is the call CLAIMING the central call's commitment"
        );

        // Absent: no claim matches the central call's commitment.
        let mut absent = txs.clone();
        absent.transactions[0].calls[2].claimed[1].commitment = "cc77".to_string();
        assert_eq!(attribute_caller(&absent, &central), None);

        // No central call in the block at all.
        assert_eq!(attribute_caller(&txs, &"99".repeat(32)), None);
    }

    /// The central singleton with responses recorded: field 1 entries plus field 2
    /// (respondCounterMap, the phase-1 signature responses) carrying a per-rid response
    /// COUNT, the on-chain per-rid watermark.
    fn central_state_with_responses(
        entries: Vec<(AlignedValue, Node)>,
        responses: &[([u8; 32], u64)],
    ) -> Node {
        array_of(vec![
            StateValue::Null,
            map_of(entries),
            map_of(
                responses
                    .iter()
                    .map(|(rid, count)| {
                        (key_of(*rid), cell_of(&[trim(&count.to_le_bytes())], &[8]))
                    })
                    .collect(),
            ),
            StateValue::Null,
            StateValue::Null,
            StateValue::Null,
        ])
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
    async fn run_recovers_pruned_requests_via_watermark() {
        // A Pruned node recovers the gap's requests from latest state instead of
        // dropping unservable blocks.
        let (record, rid) = caller_record_and_rid();
        let (responded_record, responded_rid) = named_record_and_rid(11);
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            probe: Some(ArchiveState::Pruned { probed_height: 3 }),
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        // No per-block states for 6..=8 AT ALL: the pruned walk never runs.
        source.set_state(
            &central,
            9,
            central_state_with_responses(
                vec![
                    // The circuit's first notification carries count 0; one response
                    // makes respondCount 1, so 0 < 1 skips it.
                    notification_entry(0, &responded_rid),
                    notification_entry(1, &rid),
                ],
                &[(responded_rid, 1)],
            ),
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
                    (key_of(responded_rid), cell_from_record(&responded_record)),
                    (key_of(rid), cell_from_record(&record)),
                ]),
            ]),
        );

        let mut harness = RunFixture::spawn(source, 5).await;
        assert_sign_request(&harness.next_event().await, rid);
        assert_block(&harness.next_event().await, 9);
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_switches_to_watermark_on_mid_catchup_pruning() {
        // Archive mode, but the gap reaches deeper than retention: block 7's central
        // read hits the pruning signature, and the walk SWITCHES to the watermark for
        // the remainder instead of restarting into the same wall or losing the gap's
        // requests.
        let (record, rid) = caller_record_and_rid();
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        source.set_state(&central, 5, central_state(vec![]));
        source.set_state(&central, 6, central_state(vec![]));
        source.set_unservable(&central, 7);
        source.set_state(
            &central,
            9,
            central_state_with_responses(vec![notification_entry(1, &rid)], &[]),
        );
        source.set_state(&hex::encode(CALLER), 9, caller_state(&record, &rid));

        let mut harness = RunFixture::spawn(source, 5).await;
        assert_block(&harness.next_event().await, 6);
        // The switch: block 7 is never emitted block-wise; the watermark walk recovers
        // the request and lands progress at the anchor.
        assert_sign_request(&harness.next_event().await, rid);
        assert_block(&harness.next_event().await, 9);
        assert!(matches!(
            harness.next_event().await,
            ChainEvent::CatchupCompleted
        ));
        harness.cancel_and_join().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_anchors_at_head_without_catchup_when_fresh() {
        // Checkpoint 0 in EITHER mode: no gap to close, no genesis walk, no watermark
        // walk; live starts at the anchor.
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 8,
            probe: Some(ArchiveState::Pruned { probed_height: 3 }),
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
            network_id: "undeployed".to_string(),
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
