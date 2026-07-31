//! Catchup from the persisted checkpoint, then the live finalized loop.

use crate::config::MidnightConfig;
use crate::convert::to_sign_request;
use crate::reader::{
    decode_notification, resolve_verified_record, signet_field_node_by_path,
    unpack_notification_v1, Node, Resolved,
};
use crate::rpc::{is_state_unservable, BlockRef, MidnightRpc};
use crate::state::decode_contract_state;

use midnight_base_crypto::fab::AlignedValue;
use midnight_onchain_state::state::StateValue;

use std::collections::HashSet;
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

/// The node reads `run()` consumes, as a test seam.
#[async_trait]
pub(crate) trait ChainSource: Send + Sync {
    async fn finalized_head(&self) -> anyhow::Result<BlockRef>;
    async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef>;
    /// The decoded state tree of `address_64hex` at `at_hash`.
    async fn contract_state_tree(
        &self,
        address_64hex: &str,
        at_hash: &str,
    ) -> anyhow::Result<ContractState>;
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

    async fn spawn_block_producer(
        &self,
        tx: mpsc::Sender<BlockRef>,
    ) -> anyhow::Result<AbortOnDrop> {
        let mut stream = self.rpc.subscribe_finalized().await?;
        Ok(AbortOnDrop(tokio::spawn(async move {
            while let Some(block) = stream.next().await {
                if tx.send(block).await.is_err() {
                    return;
                }
            }
        })))
    }
}

/// The request id of a composite `SignetMapKey { count: Uint<64>, requestId: Bytes<32> }`
/// wire key: two trimmed atoms, the count checked as a `Uint<64>` and the rid re-padded.
fn signet_map_key_rid(key: &AlignedValue) -> Option<[u8; 32]> {
    let [count, rid] = key.value.0.as_slice() else {
        return None;
    };
    u64::try_from(count).ok()?;
    <[u8; 32]>::try_from(rid.clone()).ok()
}

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

/// Names the one failure a retry never clears, so the restart it triggers is not
/// mistaken for a transport blip. The indexer requires a node that still holds the
/// state it is asking for; recovering from a node that does not is future work.
fn note_unservable(err: anyhow::Error, height: u64) -> anyhow::Error {
    if is_state_unservable(&err) {
        tracing::warn!(
            reason = "state-unservable-restart",
            height,
            "midnight node cannot serve state at this height; restarting to re-anchor at the \
             finalized head. Requests filed in the skipped range are given up"
        );
    }
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

    /// Field-1 entries of an already-fetched central tree. The field's position and
    /// its map shape are fixed by our own singleton, so a failure here is
    /// binary-vs-contract drift (or a wrong central address): it halts indexing loudly
    /// rather than dropping every request while the checkpoint advances.
    fn notification_entries(tree: &Node) -> anyhow::Result<Vec<MapEntry>> {
        let node = signet_field_node_by_path(tree, &[NOTIFICATION_MAP_FIELD])
            .context("central signBidirectionalEventNotificationMap field")?;
        let StateValue::Map(entries) = node else {
            anyhow::bail!(
                "central field {NOTIFICATION_MAP_FIELD} (signBidirectionalEventNotificationMap) \
                 is not a map"
            );
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

    /// Per-block processing, shared by catchup and live: diff the notification map
    /// against the parent block's, evaluate the new entries.
    async fn process_block<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut Option<(String, Vec<MapEntry>)>,
        block: &BlockRef,
    ) -> anyhow::Result<Vec<IndexedSignRequest>> {
        // An absent central is ordinary during catchup from before deployment.
        let entries: Vec<MapEntry> = match self.central_tree(source, &block.hash).await? {
            Some(tree) => Self::notification_entries(&tree)?,
            None => Vec::new(),
        };
        let parent_entries: Vec<MapEntry> = match cache.take() {
            Some((hash, entries)) if hash == block.parent_hash => entries,
            _ => match self.central_tree(source, &block.parent_hash).await? {
                Some(tree) => Self::notification_entries(&tree)?,
                None => Vec::new(),
            },
        };
        let parent_keys: HashSet<&AlignedValue> =
            parent_entries.iter().map(|entry| &entry.key).collect();
        let new_entries: Vec<&MapEntry> = entries
            .iter()
            .filter(|entry| !parent_keys.contains(&entry.key))
            .collect();

        let mut requests = Vec::new();
        if !new_entries.is_empty() {
            let indexed_ts = unix_now();
            for entry in new_entries {
                if let Some(request) = self
                    .process_entry(source, entry, &block.hash, block.number, indexed_ts)
                    .await?
                {
                    requests.push(request);
                }
            }
        }

        *cache = Some((block.hash.clone(), entries));
        Ok(requests)
    }

    /// One notification entry: decode and unpack it, read the caller's ledger at
    /// `at_hash`, gate through `resolve_verified_record`, convert.
    ///
    /// `Err` is reserved for our own schema drift: the singleton's circuits fix the
    /// map-key and value shapes and assert `version == 1`, so callers cannot produce
    /// those failures, and dropping them would silently lose every request while the
    /// checkpoint advances. Everything caller-attributable is a counted drop.
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
        anyhow::ensure!(
            notification.version == 1,
            "notification version {}: this binary understands only version 1",
            notification.version
        );
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
        // request id and `to_sign_request` requires `sender` to equal the address the
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
            // The transport already spent its retry budget, and block-level retries
            // cannot be bounded per entry, so escalating would let one caller whose
            // state cannot be served (`caller_address` is producer-supplied) halt the
            // chain. Charged to the entry instead, the unservable answer included.
            Err(err) => {
                return Ok(drop_entry(
                    "caller-state-unreadable",
                    height,
                    Some(rid),
                    &format!("{caller_hex}: {err:#}"),
                ));
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
        match to_sign_request(&record, &unpacked.caller_address, rid, indexed_ts) {
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

    /// One catchup or gap height: resolve the number to its finalized block, then
    /// [`index_block`](Self::index_block).
    async fn index_height<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut Option<(String, Vec<MapEntry>)>,
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
            };
        self.index_block(source, cache, events_tx, &block, cancel)
            .await
    }

    /// Processes and emits one block under the retry policy, surfacing the pruning
    /// signature as the error that restarts the run.
    async fn index_block<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut Option<(String, Vec<MapEntry>)>,
        events_tx: &mpsc::Sender<ChainEvent>,
        block: &BlockRef,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Indexed> {
        match self
            .process_block_retrying(source, cache, block, cancel)
            .await
        {
            Retried::Done(requests) => {
                self.emit_block(events_tx, block, requests).await?;
                Ok(Indexed::Done)
            }
            Retried::Cancelled => Ok(Indexed::Cancelled),
            Retried::Unservable(err) => Err(note_unservable(err, block.number)),
        }
    }

    /// Emits a block's requests, then its Block event, then records telemetry.
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

    // run() over an injected ChainSource.

    use crate::test_utils::{
        array_of, cell_from_atoms, cell_from_record, key_of, map_of, sample_record,
    };
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

    /// An indexer plus a `cache` slot for driving `process_block`/`process_entry`
    /// directly: the drift classification is about return values, not event flows.
    async fn direct_indexer() -> TestIndexer {
        MidnightIndexer::new(
            MidnightConfig {
                node_ws_url: "ws://127.0.0.1:1".to_string(),
                central_address: central_address(),
                rpc: Default::default(),
                indexer: Default::default(),
            },
            MockStateManager::new(),
            NoopChainTelemetry,
        )
        .await
        .expect("indexer constructs")
    }

    #[tokio::test]
    async fn process_block_errors_on_central_schema_drift() {
        // Field 1 not being a map cannot come from a caller: it is drift or a wrong
        // central address, and must halt loudly rather than drop requests forever.
        let central = central_address();
        let mut source = FixtureSource::default();
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(&central, 9, array_of(vec![StateValue::Null; 6]));

        let indexer = direct_indexer().await;
        let mut cache = None;
        let err = indexer
            .process_block(&source, &mut cache, &block_ref(9))
            .await
            .expect_err("a non-map central field must error, never degrade")
            .to_string();
        assert!(err.contains("is not a map"), "err: {err}");
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
        let err = indexer
            .process_entry(&source, &version_two, &hash_of(9), 9, 0)
            .await
            .expect_err("the singleton asserts version 1 in circuit, so 2 is drift")
            .to_string();
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
