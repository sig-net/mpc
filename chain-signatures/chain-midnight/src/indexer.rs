//! Catchup from the persisted checkpoint, then the live finalized loop.
//!
//! Per-block processing follows one authority split: the state diff triggers,
//! decoded transactions attribute advisorily, and the caller-ledger read plus
//! the request-id gate authorise.

use crate::config::MidnightConfig;
use crate::convert::to_sign_request;
use crate::reader::{
    decode_notification, repad_atom_32, resolve_verified_record, signet_field_node,
    unpack_notification_v1, Resolved,
};
use crate::rpc::{is_state_unservable, ArchiveState, BlockRef, MidnightRpc};
use crate::sidecar::{is_refused_bytes, DecodedTransactions, MapEntry, SidecarClient, StateNode};

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::stream::Empty;
use futures_util::StreamExt as _;
use mpc_chain_integration_core::utils::task::AbortOnDrop;
use mpc_chain_integration_core::{ChainIndexer, ChainTelemetry, StateManager};
use mpc_primitives::{Chain, ChainEvent, IndexedSignRequest};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const RETRY_DELAY: Duration = Duration::from_millis(500);

/// The central singleton's notification map ordinal, the only field the diff
/// reads.
const NOTIFICATION_MAP_FIELD: u8 = 1;

/// What a contract-state read found. The enclosing `Err` is reserved for "the
/// node could not answer", the only class where restarting the indexer helps.
pub(crate) enum ContractState {
    Tree(StateNode),
    /// Not present at that block. Ordinary during catchup from before
    /// deployment, and for a caller address that names nothing.
    Absent,
    /// The node served the bytes and the sidecar refused to decode them.
    ///
    /// Separate from `Err` because the bytes belong to whoever owns that
    /// contract, so for a caller address this is a per-entry data property and
    /// must be a drop. Reachable without an adversary: the sidecar's state walk
    /// fails closed on any `StateValue` outside null/cell/array/map, and a
    /// `MerkleTree` field is the ordinary way a contract holds commitments.
    /// Folded into `Err`, one such integrator restart-loops the indexer forever.
    Undecodable(anyhow::Error),
}

/// Midnight indexer: `run()` owns the whole read path.
///
/// Block emission is live because the checkpoint cannot advance without it, and
/// a stale checkpoint makes every restart re-walk catchup and re-emit.
///
/// Rollout hazard: `checkpoint_interval(Midnight)` is `Some(120)`, so emitting a
/// block starts checkpoint creation, a threshold signing request. That stalls
/// unless threshold-many nodes have Midnight enabled, and a node without it
/// still buffers peer posits it never retires. Network-wide enablement plus a
/// `posit_queues` bound are preconditions for turning this on.
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
        // `MidnightConfig` is publicly constructible with `String` fields, so a
        // non-CLI caller reaches here without passing the CLI's own check.
        // Ethereum needs no equivalent: `Url`/`Address`/`PrivateKeySigner` make
        // an invalid value unrepresentable.
        config.validate()?;
        // Network-free beyond that. The CLI gate calls new() once and logs the
        // error without retrying, so a dial here would turn a transient outage
        // at boot into a permanently disabled chain. The archive probe runs at
        // the start of each supervised run() instead.
        Ok(Self {
            config,
            state_manager,
            telemetry,
        })
    }
}

/// Applies the startup policy to the archive probe's answer: degrade by
/// default, refuse when the operator set `require_archive_state`.
///
/// Degrading means catchup takes the watermark path, resuming from latest state
/// instead of exact-block contract-state reads. `ChainTelemetry::catchup_degraded`
/// carries this to a dashboard; the warning below is the log-side signal.
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

/// The node-and-sidecar reads `run()` consumes, as a test seam. Ethereum mocks
/// its HTTP transport, but subxt's WebSocket cannot be stubbed because an
/// `OnlineClient` fetches runtime metadata at construction, so the fixture
/// boundary is this trait. `LiveSource` is the production composition.
#[async_trait]
pub(crate) trait ChainSource: Send + Sync {
    async fn assert_sidecar_compatible(&self) -> anyhow::Result<()>;
    async fn probe_archive_state(&self, window: u64) -> anyhow::Result<ArchiveState>;
    async fn finalized_head(&self) -> anyhow::Result<BlockRef>;
    async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef>;
    /// The decoded state tree of `address_64hex` at `at_hash`.
    ///
    /// Three-way for the third arm's sake: `Err` must mean only "the node could
    /// not answer", so propagating it, which restarts the indexer, is always
    /// right. See [`ContractState::Undecodable`].
    async fn contract_state_tree(
        &self,
        address_64hex: &str,
        at_hash: &str,
    ) -> anyhow::Result<ContractState>;
    /// The block's decoded `send_mn_transaction` calls, advisory only.
    async fn decoded_transactions(&self, block: &BlockRef) -> anyhow::Result<DecodedTransactions>;
    /// Pushes live finalized blocks into `tx` until the underlying stream
    /// ends; the returned guard aborts the producer on drop.
    async fn spawn_block_producer(&self, tx: mpsc::Sender<BlockRef>)
        -> anyhow::Result<AbortOnDrop>;
}

/// Splits a sidecar decode into the per-entry class and the restart class.
///
/// Only a sidecar that REFUSED the bytes is charged to the contract that owns
/// them. One that could not answer (transport fault, timeout, 5xx) belongs to
/// the same "could not answer" class as a node fault and must propagate:
/// dropped instead, a sidecar blip mid-block loses that request forever,
/// because the block still emits, the checkpoint still advances, and the
/// notification joins the parent set so no later diff sees it as new.
fn classify_decode(decoded: anyhow::Result<StateNode>) -> anyhow::Result<ContractState> {
    match decoded {
        Ok(tree) => Ok(ContractState::Tree(tree)),
        Err(err) if is_refused_bytes(&err) => Ok(ContractState::Undecodable(err)),
        Err(err) => Err(err.context("sidecar could not decode contract state")),
    }
}

/// The production [`ChainSource`]: subxt node reads plus sidecar codecs.
struct LiveSource {
    rpc: MidnightRpc,
    sidecar: SidecarClient,
}

impl LiveSource {
    async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        Ok(Self {
            rpc: MidnightRpc::connect(config).await?,
            sidecar: SidecarClient::new(config)?,
        })
    }
}

#[async_trait]
impl ChainSource for LiveSource {
    async fn assert_sidecar_compatible(&self) -> anyhow::Result<()> {
        self.sidecar.assert_compatible().await
    }

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
        // Only a sidecar that REFUSED the bytes is charged to the contract that
        // owns them. One that could not answer (transport fault, timeout, 5xx)
        // is the same "could not answer" class as a node fault and must
        // propagate: dropped instead, a sidecar blip mid-block loses that
        // request forever, because the block still emits, the checkpoint still
        // advances, and the notification joins the parent set so no later diff
        // sees it as new.
        match self.rpc.contract_state(address_64hex, at_hash).await? {
            None => Ok(ContractState::Absent),
            Some(state) => classify_decode(self.sidecar.decode_contract_state(&state).await),
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
        let decoded = self.sidecar.decode_transactions(&blobs).await?;
        if !decoded.skipped.is_empty() {
            // Advisory, like the rest of provenance: an unreadable blob costs
            // attribution for this block, never a request.
            tracing::warn!(
                height = block.number,
                reason = "provenance-blob-skipped",
                "sidecar could not decode {} of {} transaction blobs: {:?}",
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

/// Advisory cross-contract-call provenance: the address of the call claiming
/// the central call's communication commitment in the same transaction.
///
/// The callee side carries no entry-point field, so the commitment join is the
/// only link, and the central contract's own call is never the caller.
/// Advisory means the result only feeds a log comparison, never a gate: a
/// direct call to the notify entry point has no such frame at all, so requiring
/// one would drop legitimate requests.
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

/// The composite `SignetMapKey { count: Uint<64>, requestId: Bytes<32> }`
/// recovered from its atom-preserving wire key: two trimmed atoms, the count
/// folded little-endian and the rid re-padded.
///
/// The one place the key layout is assumed; downstream passes the pair around.
/// Any other atom count, or a non-hex or overlong atom, is a malformed key that
/// the caller drops with its own reason.
fn signet_map_key_rid(key_atoms: &[String]) -> Option<(u64, [u8; 32])> {
    let [count_hex, rid_hex] = key_atoms else {
        return None;
    };
    Some((fold_le_u64(count_hex)?, repad_atom_32(rid_hex)?))
}

/// The central singleton's `respondCounterMap` ordinal: the on-chain per-rid
/// watermark the degraded catchup reads.
///
/// Field 2 counts phase-1 signature responses. Deliberately not field 4,
/// `respondBidirectionalCounterMap`, which counts phase-2 execution outputs and
/// would re-emit the whole signed-but-not-yet-executed set on every degraded
/// catchup.
const RESPOND_COUNTER_FIELD: u8 = 2;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The entries of a central-tree field that must be a map, or `None` when the
/// field could not be read at all.
///
/// `None` rather than an empty slice: the block diff subtracts the parent's
/// entries from this block's, and an unread parent that reads as empty makes
/// every entry look new. Only a genuinely empty map is safe to diff against, so
/// each caller answers "could not read" for itself.
///
/// One helper rather than one per field, so both call sites report a failed
/// walk the same way and their drop counters stay comparable.
fn central_map_entries<'a>(
    tree: &'a StateNode,
    field: u8,
    field_name: &'static str,
    height: u64,
) -> Option<&'a [MapEntry]> {
    match signet_field_node(tree, usize::from(field)) {
        Ok(StateNode::Map { entries }) => Some(entries),
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
///
/// The count matters, not membership: entry `(count = C, rid)` is unanswered
/// iff `C >= respondCount(rid)`, an absent rid reading 0. So a caller
/// re-notifying after a response, including a failed one, is processed rather
/// than skipped forever.
///
/// Absent, empty, undecodable and unreadable all read as no counts, which is
/// safe because it only ever processes more and never skips. Unlike the block
/// diff, this caller's "could not read" and "empty" genuinely coincide.
fn response_counts(tree: &StateNode, height: u64) -> HashMap<[u8; 32], u64> {
    central_map_entries(tree, RESPOND_COUNTER_FIELD, "respondCounterMap", height)
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| {
            let rid = counter_map_rid(&entry.key)?;
            let StateNode::Cell { atoms } = &entry.value else {
                return Some((rid, 0));
            };
            let count = atoms
                .first()
                .and_then(|atom| fold_le_u64(atom))
                .unwrap_or(0);
            Some((rid, count))
        })
        .collect()
}

/// One trimmed `Bytes<32>` atom re-padded: the counter maps' single-atom
/// key form. Malformed keys are simply not members.
fn counter_map_rid(key_atoms: &[String]) -> Option<[u8; 32]> {
    let [rid_hex] = key_atoms else {
        return None;
    };
    repad_atom_32(rid_hex)
}

/// Little-endian fold of a trimmed uint atom (at most 8 bytes), the wire
/// rule every stored integer uses.
fn fold_le_u64(atom_hex: &str) -> Option<u64> {
    let bytes = hex::decode(atom_hex).ok()?;
    if bytes.len() > 8 {
        return None;
    }
    Some(
        bytes
            .iter()
            .rev()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)),
    )
}

// The reporting contract. `ChainTelemetry` has no counter hook, so the `reason`
// label is the metric and all three sinks feed one namespace. That only works
// if a label means one thing, hence three sinks:
//
//   drop_entry      this entry produces no sign request
//   degraded_read   a field or block read degraded; not about an entry
//   advisory_note   provenance observed something; the request still signs
//
// All are WARN or below: every one is manufacturable at will by a caller
// writing junk into its own state, and ERROR would hand an adversary a free
// alarm bell. Reporting happens here and nowhere below, so a resolution is
// logged once rather than by both callee and caller.

/// One drop, one WARN, one distinct reason label. The label is the countable
/// signal, the line is the diagnosis.
///
/// Returns the `None` that ends the entry, so call sites read
/// `return Ok(drop_entry(..))` and cannot report a drop and then sign anyway.
///
/// `request_id` is optional for one caller: `malformed-map-key` drops an entry
/// whose id could not be recovered.
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

/// A field or block read that degraded. No entry is being decided, so there is
/// no request id and the line must not claim a drop; the caller states the
/// consequence rather than letting the label imply one.
fn degraded_read(reason: &'static str, height: u64, detail: &str) {
    tracing::warn!(reason, height, "midnight read degraded: {detail}");
}

/// Labels the pruning signature at the three sites that cannot switch catchup
/// modes in place: the live loop, the finality-gap walk, and the per-entry
/// caller read. Only the catchup range walk owns a mode variable.
///
/// Propagating there is the recovery route rather than an unhandled case: the
/// supervised restart re-anchors, re-probes and re-enters catchup, which does
/// switch. Dropping would lose a request whose only fault is that the node's
/// retention moved; switching in place would jump the processed block to the
/// anchor and abandon block granularity for a condition the restart handles in
/// about a second.
///
/// Changes no control flow. It exists so an operator sees why a run restarted.
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

/// An observation from the advisory provenance join. The request proceeds, so
/// these labels must never be read as request loss.
fn advisory_note(reason: &'static str, height: u64, request_id: Option<[u8; 32]>, detail: &str) {
    tracing::warn!(
        reason,
        height,
        request_id = request_id.map(hex::encode),
        "midnight provenance advisory, request still signed: {detail}"
    );
}

/// Whether advisory attribution ran for the entries being processed. The
/// watermark path skips it by construction, having no per-tx context, and a
/// skipped attribution must not warn `provenance-absent`: that label means
/// attribution ran and found no pair, a different fact.
enum Attribution {
    Skipped,
    Ran(Option<String>),
}

impl<S: StateManager, T: ChainTelemetry> MidnightIndexer<S, T> {
    /// The central singleton's tree at `at_hash`, or `None` when the contract
    /// is not present there, which is ordinary during catchup from before
    /// deployment.
    ///
    /// Everything else propagates, the pruning signature included: the policy
    /// for that lives in the catchup loop, never down here where it could only
    /// lose requests. An undecodable central state also propagates, unlike the
    /// caller path, because there is no entry to drop: the notification map is
    /// the only source of work, so reading it as "no entries" would lose every
    /// request while the indexer reported itself healthy.
    ///
    /// Known exposure: the central state's size is caller-driven, one map entry
    /// per notify forever, and nothing bounds the sidecar's response, so a large
    /// enough map fails this read beyond the reach of any drop policy.
    async fn central_tree<C: ChainSource>(
        &self,
        source: &C,
        at_hash: &str,
    ) -> anyhow::Result<Option<StateNode>> {
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

    /// Field-1 entries of an already-fetched central tree, or `None` when
    /// the field could not be read.
    fn notification_entries(tree: &StateNode, height: u64) -> Option<Vec<MapEntry>> {
        central_map_entries(
            tree,
            NOTIFICATION_MAP_FIELD,
            "signBidirectionalEventNotificationMap",
            height,
        )
        .map(<[MapEntry]>::to_vec)
    }

    /// Per-block processing, shared by catchup and live. Every per-entry
    /// failure is a counted drop, never a block abort: a poisoned entry must
    /// not stall the chain, and its siblings must still convert.
    ///
    /// Retry budget: with the parent tree cached, the worst-case degraded cost
    /// is three `retry_rpc!` node reads (central state, caller state,
    /// block-by-hash for the advisory decode), each up to ~75s under `RpcConfig`
    /// defaults, so ~225s against the 315s `live_block_timeout(Midnight)`
    /// watchdog, before sidecar budgets. The cache below keeps the central read
    /// at one per block on both paths, being keyed on the parent hash rather
    /// than on success. Redo this arithmetic before adding a per-block call.
    async fn process_block<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut Option<(String, Vec<MapEntry>)>,
        block: &BlockRef,
    ) -> anyhow::Result<Vec<IndexedSignRequest>> {
        // `None` means the map could not be read. The cache at the end must not
        // record that as an empty parent, which would hand the next diff a
        // confident "the parent held nothing" it has no basis for.
        let read_entries: Option<Vec<MapEntry>> =
            match self.central_tree(source, &block.hash).await? {
                Some(tree) => Self::notification_entries(&tree, block.number),
                // Central not yet deployed at this block: an ordinary empty
                // block, common during catchup from before deployment.
                None => Some(Vec::new()),
            };
        let entries = read_entries.clone().unwrap_or_default();

        // `None` is "could not read the parent", not "the parent had no
        // entries", and is the one state the diff below must refuse to
        // subtract. A contract genuinely absent at the parent really did hold
        // no notifications, so that stays an empty list.
        let parent_entries: Option<Vec<MapEntry>> = match cache.take() {
            Some((hash, entries)) if hash == block.parent_hash => Some(entries),
            _ => match self.central_tree(source, &block.parent_hash).await? {
                Some(tree) => Self::notification_entries(&tree, block.number.saturating_sub(1)),
                None => Some(Vec::new()),
            },
        };
        let new_entries: Vec<&MapEntry> = match &parent_entries {
            Some(parent) => {
                let parent_keys: HashSet<&[String]> =
                    parent.iter().map(|entry| entry.key.as_slice()).collect();
                entries
                    .iter()
                    .filter(|entry| !parent_keys.contains(entry.key.as_slice()))
                    .collect()
            }
            // No diff is possible, so this block emits nothing, giving up only
            // the entries filed at this exact height. Both alternatives are
            // unbounded: treating the parent as empty re-emits the whole
            // insert-only map and restart-loops past the watchdog, and
            // propagating puts the same permanent fault into the same loop.
            // The block still emits and the checkpoint still advances, so the
            // next diff is correct rather than degraded.
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
            // Advisory attribution, once per block. Its own failure is also
            // advisory: a sidecar decode fault must not stop signing.
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

        // Only a map that was actually read becomes the next block's parent. An
        // unreadable one leaves the cache empty, so the next block re-reads and
        // reaches the same `None` rather than silently diffing against a list
        // this block never saw.
        *cache = read_entries.map(|entries| (block.hash.clone(), entries));
        Ok(requests)
    }

    /// One notification entry: decode and unpack it, read the caller's ledger
    /// at `at_hash`, gate through `resolve_verified_record`, convert. Shared
    /// verbatim by the per-block diff and the watermark walk, which differ only
    /// in how they select entries and whether attribution runs.
    ///
    /// `Ok(None)` is a counted drop. `Err` means only that the node could not
    /// answer, so propagating it and restarting is always right; no property of
    /// a caller's own data may reach it, which is why `contract_state_tree` is
    /// three-way.
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
                &format!("{} atoms in a SignetMapKey", entry.key.len()),
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

        // Advisory, never a gate: absence and disagreement are notes and the
        // read below proceeds regardless, which is why they go through
        // `advisory_note`. Reporting them as drops would put every signed
        // request from a direct notify call, the common case, into the drop
        // counter. A skipped attribution says nothing at all.
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
            // The caller's own bytes, refused by the sidecar: a per-entry data
            // property like the rest. Propagating it lets one integrator whose
            // ledger the sidecar cannot walk restart-loop the indexer on the
            // same block forever, since the checkpoint cannot advance past a
            // block that never emits.
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
                    // Producer-supplied data, so an out-of-range walk is a
                    // per-entry drop rather than an abort.
                    return Ok(drop_entry(
                        "requests-field-walk",
                        height,
                        Some(rid),
                        &format!("{err:#}"),
                    ));
                }
            };
        // The resolver reports nothing and hands back the reason, so this is
        // the only place a resolution is logged.
        let record = match resolve_verified_record(field, rid) {
            Resolved::Found(record) => *record,
            Resolved::Absent => {
                // Not a fault: the caller notified an id its own index does not
                // hold, having notified before its write landed or computed the
                // id wrong. DEBUG because it is manufacturable at will, not
                // silent because integrators hit it most and cannot otherwise
                // diagnose it.
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
                // Every conversion failure is a per-record data property, so
                // drop with the id and reason and continue.
                Ok(drop_entry(
                    "convert-rejected",
                    height,
                    Some(rid),
                    &format!("{err:#}"),
                ))
            }
        }
    }

    /// The degraded catchup: read the central contract's latest state once at
    /// the anchor and process every field-1 entry above the per-rid watermark.
    ///
    /// No per-tx provenance and no per-block granularity, which is the trade;
    /// the request-id gate never depended on the block.
    ///
    /// Safe only because the notification map is insert-only, so the anchor's
    /// latest state holds every notification ever filed and
    /// `set_processed_block(anchor)` loses nothing. Over-coverage lands as keyed
    /// backlog inserts. The per-rid watermark is `respondCounterMap` read as a
    /// count, so a re-notification after a response is still processed:
    /// re-emission is idempotent where a silent skip is not.
    async fn catchup_from_latest_state<C: ChainSource>(
        &self,
        source: &C,
        events_tx: &mpsc::Sender<ChainEvent>,
        cancel: &CancellationToken,
        anchor: &BlockRef,
    ) -> anyhow::Result<()> {
        let Some(tree) = self.central_tree(source, &anchor.hash).await? else {
            // No central contract at the head: nothing to recover; the
            // anchor emit below still records progress.
            tracing::info!(
                anchor = anchor.number,
                "watermark catchup: central contract not present at the anchor"
            );
            return self.emit_block(events_tx, anchor, Vec::new()).await;
        };
        // This walk subtracts nothing, so an unreadable map is simply no work
        // to do, and `central_map_entries` has already named it.
        let entries = Self::notification_entries(&tree, anchor.number).unwrap_or_default();
        let responses = response_counts(&tree, anchor.number);

        let indexed_ts = unix_now();
        let mut requests = Vec::new();
        for entry in &entries {
            if cancel.is_cancelled() {
                // No progress is persisted on a cancelled walk; the next
                // run re-covers from the same checkpoint.
                return Ok(());
            }
            if let Some((count, rid)) = signet_map_key_rid(&entry.key) {
                if count < responses.get(&rid).copied().unwrap_or(0) {
                    // This instance predates the latest phase-1 response, so
                    // its answer already exists on-chain. One at or above the
                    // count still processes, which is how this path agrees with
                    // the block path on post-response re-notifications.
                    // Ordinary, not a drop.
                    continue;
                }
            }
            let request = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                request = self.process_entry(
                    source,
                    entry,
                    &anchor.hash,
                    anchor.number,
                    &Attribution::Skipped,
                    indexed_ts,
                ) => request?,
            };
            if let Some(request) = request {
                requests.push(request);
            }
        }
        self.emit_block(events_tx, anchor, requests).await
    }

    /// Emits a block's requests, then its Block event, then records progress
    /// and telemetry.
    ///
    /// Does not count the requests: the shared stream layer already calls
    /// `request_indexed` for every `SignRequest` without a block timestamp,
    /// which is all of this chain's, so counting here reports each one twice.
    /// `block_indexed` is not the same case, since the shared layer records
    /// `block_finalized` for a `ChainEvent::Block`.
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
        self.state_manager
            .set_processed_block(Chain::Midnight, block.number)
            .await;
        self.telemetry.block_indexed(block.number);
        Ok(())
    }

    /// `run()` over an explicit [`ChainSource`], the fixture seam. `run()`
    /// itself only connects the production source and delegates here.
    pub(crate) async fn run_with_source<C: ChainSource>(
        &self,
        source: &C,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Startup gates. Err from either is a supervised retry rather than a
        // construction failure: the CLI gate constructs the indexer once and
        // never retries new(), so a transient outage here must not permanently
        // disable the chain.
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            compatible = source.assert_sidecar_compatible() => {
                compatible.context("midnight sidecar compatibility gate failed")?;
            }
        }
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
        // Pruned goes straight to the watermark walk: a degraded block walk
        // could only drop unservable blocks and lose their requests, where the
        // watermark recovers them from latest state.
        let mut need_watermark = matches!(mode, ArchiveState::Pruned { .. });
        if checkpoint == 0 {
            // A fresh node has no gap to close, and walking from genesis would
            // reprocess the whole chain, so catchup anchors at the finalized
            // head in either mode.
            tracing::info!(
                anchor = anchor.number,
                "midnight fresh start: no checkpoint, anchoring at the finalized head"
            );
            last_processed = anchor.number;
            need_watermark = false;
        } else if !need_watermark {
            'range: for number in (checkpoint + 1)..=anchor.number {
                let block = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    block = source.block_at(number) => block?,
                };
                let requests = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    requests = self.process_block(source, &mut cache, &block) => requests,
                };
                match requests {
                    Ok(requests) => {
                        self.emit_block(&events_tx, &block, requests).await?;
                        last_processed = number;
                    }
                    // The gap reaches deeper than the node's retention even
                    // though the probe said Archive. Switch to the watermark
                    // walk for the remainder rather than restarting into the
                    // same wall.
                    Err(err) if is_state_unservable(&err) => {
                        tracing::warn!(
                            height = number,
                            reason = "catchup-switching-to-watermark",
                            "midnight catchup hit the pruning signature mid-range: {err:#}"
                        );
                        need_watermark = true;
                        break 'range;
                    }
                    Err(err) => return Err(err),
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
                    // To run_supervised, Ok(()) is permanent shutdown and Err
                    // is a restart, so an ended producer must be Err and let
                    // the restart re-anchor. Only cancellation returns Ok.
                    None => anyhow::bail!("midnight finalized block producer terminated"),
                },
            };
            if block.number <= last_processed {
                continue;
            }
            // Close any finality gap so a lagging subscription cannot skip
            // notifications; each height processes exactly like catchup.
            for number in (last_processed + 1)..block.number {
                let gap = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    gap = source.block_at(number) => gap?,
                };
                let requests = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    requests = self.process_block(source, &mut cache, &gap) =>
                        requests.map_err(|err| note_unservable(err, number))?,
                };
                self.emit_block(&events_tx, &gap, requests).await?;
            }
            let requests = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                requests = self.process_block(source, &mut cache, &block) =>
                    requests.map_err(|err| note_unservable(err, block.number))?,
            };
            self.emit_block(&events_tx, &block, requests).await?;
            last_processed = block.number;
        }
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for MidnightIndexer<S, T> {
    const CHAIN: Chain = Chain::Midnight;

    // TODO: not used, required by trait, remove later
    type Block = ();
    type Iter = Empty<()>;

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

    /// A sidecar that could not answer must restart the run, not drop the
    /// entry: a drop is permanent, because the block still emits and the
    /// notification joins the parent set.
    #[test]
    fn classify_decode_propagates_a_sidecar_that_could_not_answer() {
        let refused = anyhow::anyhow!(
            "{}: /decode/contract-state 422",
            crate::sidecar::REFUSED_BYTES_MSG
        );
        assert!(
            matches!(
                classify_decode(Err(refused)),
                Ok(ContractState::Undecodable(_))
            ),
            "a refusal is the contract's own data property"
        );

        let unanswered = anyhow::anyhow!("sidecar could not answer: /decode/contract-state 502");
        assert!(
            classify_decode(Err(unanswered)).is_err(),
            "an unanswered decode must propagate and restart the run"
        );

        let transport =
            anyhow::anyhow!("sidecar /decode/contract-state request failed: connection reset");
        assert!(
            classify_decode(Err(transport)).is_err(),
            "a transport fault must propagate and restart the run"
        );
    }

    #[test]
    fn select_catchup_mode_degrades_pruned_by_default() {
        // Probe-and-degrade: pruned is a MODE, not an error, unless the
        // operator opted into strict refusal. Archive always passes.
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
        // The strict error must hand the operator everything needed to act:
        // the option that made this fatal, the height that failed, and the
        // node-side fix.
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

    // run() over an injected ChainSource. Ethereum mocks its HTTP transport;
    // subxt's WebSocket cannot be mocked, so the seam is a trait.

    use crate::sidecar::{
        ClaimedCall, DecodedCall, DecodedTransaction, DecodedTransactions, MapEntry, StateNode,
    };
    use crate::test_fixtures::{atoms_from_record, cell_of, RecordFixture};
    use mpc_chain_integration_core::utils::task::AbortOnDrop;
    use mpc_primitives::SignId;
    use serde::Deserialize;
    use std::collections::HashMap;

    const RID_VECTORS_JSON: &str = include_str!("../tests/rid_vectors.json");

    #[derive(Deserialize)]
    struct RidVectorFile {
        vectors: Vec<RidVector>,
    }

    #[derive(Deserialize)]
    struct RidVector {
        name: String,
        expected_request_id_hex: String,
        record: RecordFixture,
    }

    /// A named oracle record (every tier shares the 0xab * 32 sender) and
    /// its filed id.
    fn named_record_and_rid(name: &str) -> (crate::records::SignBidirectionalRecord, [u8; 32]) {
        let file: RidVectorFile =
            serde_json::from_str(RID_VECTORS_JSON).expect("rid_vectors.json parses");
        let vector = file
            .vectors
            .into_iter()
            .find(|vector| vector.name == name)
            .unwrap_or_else(|| panic!("no rid vector named {name}"));
        let rid: [u8; 32] = hex::decode(&vector.expected_request_id_hex)
            .expect("rid hex")
            .try_into()
            .expect("32 bytes");
        (vector.record.0, rid)
    }

    fn caller_record_and_rid() -> (crate::records::SignBidirectionalRecord, [u8; 32]) {
        named_record_and_rid("minimal-1word")
    }

    /// The caller contract whose ledger the fixture serves: minimal-1word's
    /// sender, with its request map at flat field 4 (the 5-field layout).
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

    fn trimmed_hex(bytes: &[u8]) -> String {
        let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
        hex::encode(&bytes[..end])
    }

    /// One notification-map entry: composite [count, rid] key atoms, V1
    /// payload naming CALLER and REQUESTS_FIELD.
    fn notification_entry(count: u8, rid: &[u8; 32]) -> MapEntry {
        let mut payload = CALLER.to_vec();
        payload.push(REQUESTS_FIELD);
        MapEntry {
            key: vec![hex::encode([count]), trimmed_hex(rid)],
            value: StateNode::Cell {
                atoms: vec!["01".to_string(), hex::encode(payload)],
            },
        }
    }

    /// The central singleton: six flat fields, notification map at ordinal 1.
    fn central_state(entries: Vec<MapEntry>) -> StateNode {
        StateNode::Array {
            children: vec![
                StateNode::Null,
                StateNode::Map { entries },
                StateNode::Null,
                StateNode::Null,
                StateNode::Null,
                StateNode::Null,
            ],
        }
    }

    /// The caller's five-field ledger with the record filed under its rid at
    /// field 4.
    fn caller_state(record: &crate::records::SignBidirectionalRecord, rid: &[u8; 32]) -> StateNode {
        StateNode::Array {
            children: vec![
                StateNode::Null,
                StateNode::Null,
                StateNode::Null,
                StateNode::Null,
                StateNode::Map {
                    entries: vec![MapEntry {
                        key: vec![trimmed_hex(rid)],
                        value: cell_of(&atoms_from_record(record)),
                    }],
                },
            ],
        }
    }

    #[derive(Default)]
    struct FixtureSource {
        head: u64,
        /// (address, at_hash) -> tree; absent means Ok(None), contract not
        /// present at that block.
        states: HashMap<(String, String), StateNode>,
        /// (address, at_hash) -> error message; checked BEFORE `states`, so
        /// a read can fail with e.g. the pruning signature. This is the
        /// NODE-could-not-answer class and propagates.
        state_errors: HashMap<(String, String), String>,
        /// (address, at_hash) -> sidecar decode rejection; the node served
        /// the bytes and the SIDECAR refused them. A different class from
        /// `state_errors` on purpose, because the fix under test is exactly
        /// that the two must not share a channel.
        undecodable_states: HashMap<(String, String), String>,
        /// block hash -> decoded transactions; absent means empty.
        txs: HashMap<String, DecodedTransactions>,
        /// None means Archive (the common case for these tests).
        probe: Option<ArchiveState>,
        live: tokio::sync::Mutex<Option<mpsc::Receiver<BlockRef>>>,
        /// Deterministic suspension: the read named here announces itself on
        /// `reached` and then never resolves, so a test can cancel while a walk
        /// is PROVABLY mid-flight instead of racing a sleep against it. All
        /// three default to `None`, leaving every other fixture unchanged.
        park_at: Option<u64>,
        /// Parks `contract_state_tree` for this address, which suspends a walk
        /// INSIDE `process_entry` rather than between blocks.
        park_state_read: Option<String>,
        reached: Option<mpsc::Sender<String>>,
    }

    impl FixtureSource {
        /// Announce arrival at a park point, then never resolve. The only way
        /// out is the caller's own cancel handling, which is precisely what
        /// makes the cancellation tests fail when it is removed.
        async fn park(&self, label: String) -> ! {
            if let Some(reached) = &self.reached {
                reached.send(label).await.expect("park signal receiver");
            }
            std::future::pending().await
        }

        fn set_state(&mut self, address: &str, at: u64, tree: StateNode) {
            self.states.insert((address.to_string(), hash_of(at)), tree);
        }

        /// Injects the pruning signature for one (address, height) read.
        fn set_unservable(&mut self, address: &str, at: u64) {
            self.state_errors.insert(
                (address.to_string(), hash_of(at)),
                crate::rpc::STATE_UNSERVABLE_MSG.to_string(),
            );
        }

        /// Injects the sidecar's real refusal for one (address, height): its
        /// state walk fails closed on any `StateValue` variant outside
        /// null/cell/array/map, which a `MerkleTree` ledger field is.
        fn set_undecodable(&mut self, address: &str, at: u64) {
            self.undecodable_states.insert(
                (address.to_string(), hash_of(at)),
                "sidecar /decode/contract-state failed: 422 Unprocessable Entity: \
                 code=decode_failed message=unsupported StateValue variant in signet \
                 contract state: boundedMerkleTree"
                    .to_string(),
            );
        }
    }

    #[async_trait]
    impl ChainSource for FixtureSource {
        async fn assert_sidecar_compatible(&self) -> anyhow::Result<()> {
            Ok(())
        }

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

    struct Harness {
        events_rx: mpsc::Receiver<ChainEvent>,
        cancel: CancellationToken,
        handle: tokio::task::JoinHandle<anyhow::Result<()>>,
        state: MockStateManager,
    }

    impl Harness {
        async fn spawn(source: FixtureSource, checkpoint: u64) -> Self {
            let state = MockStateManager::new();
            if checkpoint > 0 {
                state.set_processed_block(Chain::Midnight, checkpoint).await;
            }
            Self::spawn_with_state(source, state).await
        }

        /// Spawns over an EXISTING state manager: the restart tests' seam,
        /// so a second run provably resumes from what the first persisted.
        async fn spawn_with_state(source: FixtureSource, state: MockStateManager) -> Self {
            let indexer = MidnightIndexer::new(
                MidnightConfig {
                    sidecar_url: "http://127.0.0.1:1".to_string(),
                    node_ws_url: "ws://127.0.0.1:1".to_string(),
                    central_address: central_address(),
                    network_id: "undeployed".to_string(),
                    rpc: Default::default(),
                    sidecar: Default::default(),
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

        async fn next(&mut self) -> ChainEvent {
            tokio::time::timeout(Duration::from_secs(5), self.events_rx.recv())
                .await
                .expect("timed out waiting for a chain event")
                .expect("events channel closed")
        }

        async fn cancel_and_join_ok(self) {
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

    const TX_VECTORS_JSON: &str = include_str!("../tests/tx_vectors.json");

    /// The oracle payload scalar for a named tx vector: the thing that gets
    /// SIGNED, read from tx_vectors.json's expected_unsigned_hash_hex and
    /// never recomputed in-crate, because payload_scalar(serialized(...))
    /// would run the very code path under test and pass for any
    /// consistent-but-wrong implementation, including the wiring bug this
    /// assertion exists to catch.
    fn oracle_payload(name: &str) -> k256::Scalar {
        use mpc_primitives::ScalarExt as _;
        let file: serde_json::Value =
            serde_json::from_str(TX_VECTORS_JSON).expect("tx_vectors.json parses");
        let hash_hex = file["vectors"]
            .as_array()
            .expect("fixture has a vectors array")
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap_or_else(|| panic!("no tx vector named {name}"))["expected_unsigned_hash_hex"]
            .as_str()
            .expect("expected_unsigned_hash_hex is a string");
        let hash: [u8; 32] = hex::decode(hash_hex.trim_start_matches("0x"))
            .expect("oracle hash decodes")
            .try_into()
            .expect("oracle hash is 32 bytes");
        k256::Scalar::from_bytes(hash).expect("oracle hash is in range")
    }

    /// Asserts the emitted request end to end: the id, the absent block
    /// timestamp, and the PAYLOAD pinned to the named oracle vector's
    /// unsigned hash.
    fn assert_sign_request(event: &ChainEvent, rid: [u8; 32], oracle_vector: &str) {
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
                assert_eq!(
                    request.args.payload,
                    oracle_payload(oracle_vector),
                    "the emitted payload must be the oracle's unsigned hash for {oracle_vector}"
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

        // A live block is already queued BEFORE
        // run() starts; its events must still come after CatchupCompleted.
        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));
        source.set_state(
            &central,
            9,
            central_state(vec![notification_entry(1, &rid)]),
        );
        live_tx.send(block_ref(9)).await.expect("queue live block");

        let mut harness = Harness::spawn(source, 5).await;

        assert_block(&harness.next().await, 6);
        assert_sign_request(&harness.next().await, rid, "minimal-1word");
        assert_block(&harness.next().await, 7);
        assert_block(&harness.next().await, 8);
        assert!(
            matches!(harness.next().await, ChainEvent::CatchupCompleted),
            "catchup events and only catchup events precede CatchupCompleted"
        );
        // The pre-queued live block adds nothing new (same entry) and emits
        // its Block only now.
        assert_block(&harness.next().await, 9);
        assert_eq!(
            harness.state.get_processed_block(Chain::Midnight).await,
            Some(9),
            "the checkpoint advances with emitted blocks"
        );
        harness.cancel_and_join_ok().await;
    }

    #[tokio::test]
    async fn process_block_emits_one_request_per_new_entry() {
        let (record, rid) = caller_record_and_rid();
        let central = central_address();
        let mut source = FixtureSource {
            head: 8,
            ..Default::default()
        };
        // The pre-existing entry files the SAME rid under count 1 (a
        // re-notification scenario), so it is fully resolvable: a diff
        // mutant that treats every entry as new re-emits it and fails the
        // exactly-one assertion below, rather than hiding behind an
        // unresolvable decoy rid.
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
        // Provenance PRESENT and matching for this one: a multi-call block
        // whose commitment join names the true caller.
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

        let mut harness = Harness::spawn(source, 8).await;
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));

        live_tx.send(block_ref(9)).await.expect("send live block");
        // Exactly ONE request: the pre-existing entry is not re-emitted (a
        // diff mutant that treats every entry as new emits two).
        assert_sign_request(&harness.next().await, rid, "minimal-1word");
        assert_block(&harness.next().await, 9);
        harness.cancel_and_join_ok().await;
    }

    /// A caller contract whose state the sidecar refuses is that caller's data
    /// property and must be a per-entry drop.
    ///
    /// As an `Err` it propagates out of `run()`, and since the checkpoint
    /// cannot advance past a block that never emits, the supervisor re-walks
    /// the same block into the same error forever: one integrator whose ledger
    /// holds a `MerkleTree` takes the chain down for everyone. Hence the
    /// assertions below that the block still emits, the checkpoint still
    /// advances, and run() is still alive to be cancelled.
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
        // The caller contract IS present; the sidecar cannot walk its state.
        source.set_undecodable(&hex::encode(CALLER), 9);

        let mut harness = Harness::spawn(source, 8).await;
        assert_block(&harness.next().await, 9);
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));
        assert_eq!(
            harness.state.get_processed_block(Chain::Midnight).await,
            Some(9),
            "the checkpoint must advance past the poisoned entry, or the restart re-walks it"
        );
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    /// An unreadable parent notification map is not diffed against, and the
    /// block emits nothing rather than everything.
    ///
    /// The direction is the point: treating the parent as empty re-emits the
    /// whole insert-only map, which is O(history) rather than one duplicate and
    /// escalates into a watchdog restart loop. The second half is what makes
    /// "bounded" a test rather than a claim: block 10 diffs normally against
    /// block 9, so the loss stops at the one unreadable height.
    #[tokio::test]
    async fn process_block_emits_nothing_on_unreadable_parent_map() {
        let (record, rid) = caller_record_and_rid();
        let (other_record, other_rid) = named_record_and_rid("no-calldata");
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        // Block 8's central state is present but field 1 is not a map, so
        // the notification map there cannot be read: a shape TRANSITION,
        // since block 9's is readable.
        source.set_state(
            &central,
            8,
            StateNode::Array {
                children: vec![StateNode::Null; 6],
            },
        );
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
            StateNode::Array {
                children: vec![
                    StateNode::Null,
                    StateNode::Null,
                    StateNode::Null,
                    StateNode::Null,
                    StateNode::Map {
                        entries: vec![
                            MapEntry {
                                key: vec![trimmed_hex(&rid)],
                                value: cell_of(&atoms_from_record(&record)),
                            },
                            MapEntry {
                                key: vec![trimmed_hex(&other_rid)],
                                value: cell_of(&atoms_from_record(&other_record)),
                            },
                        ],
                    },
                ],
            },
        );

        let mut harness = Harness::spawn(source, 8).await;
        // Block 9 emits its Block event and NO request: the checkpoint still
        // advances, which is what keeps this out of a restart loop.
        assert_block(&harness.next().await, 9);
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));

        // Block 10 diffs against block 9, which WAS readable, so exactly the
        // one genuinely new entry emits. The entry visible at block 9 is not
        // re-emitted, and the entry added at 10 is not lost: the give-up is
        // confined to the single height whose parent was unreadable.
        live_tx.send(block_ref(10)).await.expect("send live block");
        assert_sign_request(&harness.next().await, other_rid, "no-calldata");
        assert_block(&harness.next().await, 10);
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    /// The other half of that classification, and why the fix is a three-way
    /// rather than swallowing the error: a node that cannot answer must still
    /// take the run down. Turning every caller-state failure into a drop would
    /// pass the test above and keep indexing against a broken node.
    #[tokio::test]
    async fn run_restarts_when_node_cannot_answer() {
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
        // A transport fault on the caller read, not the pruning signature:
        // that one has its own policy (switch to the watermark walk).
        source.state_errors.insert(
            (hex::encode(CALLER), hash_of(9)),
            "sidecar /decode/contract-state request failed: connection reset by peer".to_string(),
        );

        let harness = Harness::spawn(source, 8).await;
        let err = tokio::time::timeout(Duration::from_secs(5), harness.handle)
            .await
            .expect("run() returns promptly")
            .expect("run task panicked")
            .expect_err("a node that cannot answer must surface for the supervised restart");
        assert!(err.to_string().contains("connection reset"), "err: {err}");
        drop(live_tx);
    }

    /// Counting a request is the SHARED stream layer's job: it calls
    /// `request_indexed` for every `ChainEvent::SignRequest` without a block
    /// timestamp, which is every request this chain emits. The indexer used
    /// to call it as well, so each request was counted twice.
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
                sidecar_url: "http://127.0.0.1:1".to_string(),
                node_ws_url: "ws://127.0.0.1:1".to_string(),
                central_address: central,
                network_id: "undeployed".to_string(),
                rpc: Default::default(),
                sidecar: Default::default(),
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
        // The range walk's own cancel arms. No other test reaches them: every
        // other run test cancels from the LIVE loop, and a sleep cannot get
        // here at all, because an unpopulated FixtureSource walks 500 blocks
        // faster than any sleep elapses. `park_at` suspends `block_at` at 103
        // with the head at 600, so the walk is parked 497 blocks short of the
        // anchor when cancel arrives and only the range loop's own cancel arm
        // can end it.
        let (reached_tx, mut reached_rx) = mpsc::channel(1);
        let (live_tx, live_rx) = mpsc::channel(8);
        let source = FixtureSource {
            head: 600,
            park_at: Some(103),
            reached: Some(reached_tx),
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };

        let mut harness = Harness::spawn(source, 100).await;
        assert_block(&harness.next().await, 101);
        assert_block(&harness.next().await, 102);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), reached_rx.recv())
                .await
                .expect("the range walk must reach the parked height")
                .expect("park signal channel closed"),
            "block_at:103",
            "cancel must arrive while the walk is parked mid-range"
        );

        let state = harness.state.clone();
        harness.cancel_and_join_ok().await;
        // A cancelled walk persists exactly the blocks it emitted, no more.
        assert_eq!(
            state.get_processed_block(Chain::Midnight).await,
            Some(102),
            "the checkpoint advanced only as far as the walk actually emitted"
        );
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_returns_ok_on_cancel_in_watermark_walk() {
        // The watermark walk's cancellation, which no other test reaches:
        // run_recovers_pruned_requests_via_watermark cancels only AFTER the
        // walk has finished. Parking the CALLER-state read suspends the walk
        // inside process_entry, so cancel arrives mid-entry and only the walk's
        // own cancel handling can end run().
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

        let harness = Harness::spawn(source, 5).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), reached_rx.recv())
                .await
                .expect("the watermark walk must reach the parked caller read")
                .expect("park signal channel closed"),
            format!("state:{}", hex::encode(CALLER)),
            "cancel must arrive while the walk is parked inside an entry"
        );
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_bails_when_block_producer_terminates() {
        // Ok(()) is shutdown to run_supervised, so an ended
        // producer must surface as Err; only cancel may return Ok.
        let central = central_address();
        let mut source = FixtureSource {
            head: 8,
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));

        let mut harness = Harness::spawn(source, 8).await;
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));

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
        // Three shapes: multi-call, the matching claim NOT first, a
        // decoy commitment matching nothing, distinguishable values.
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

    /// The central singleton with responses recorded: field 1 entries plus
    /// field 2 (respondCounterMap, the phase-1 signature responses) carrying
    /// a per-rid response COUNT, the on-chain per-rid watermark.
    fn central_state_with_responses(
        entries: Vec<MapEntry>,
        responses: &[([u8; 32], u64)],
    ) -> StateNode {
        StateNode::Array {
            children: vec![
                StateNode::Null,
                StateNode::Map { entries },
                StateNode::Map {
                    entries: responses
                        .iter()
                        .map(|(rid, count)| MapEntry {
                            key: vec![trimmed_hex(rid)],
                            value: StateNode::Cell {
                                atoms: vec![trimmed_hex(&count.to_le_bytes())],
                            },
                        })
                        .collect(),
                },
                StateNode::Null,
                StateNode::Null,
                StateNode::Null,
            ],
        }
    }

    #[tokio::test]
    async fn run_recatches_from_checkpoint_on_restart() {
        // A restart resumes from the persisted checkpoint rather than re-walking
        // from zero or skipping the gap. Two runs over one MockStateManager.
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
        let mut harness = Harness::spawn(source, 5).await;
        for n in 6..=9 {
            assert_block(&harness.next().await, n);
        }
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));
        let state = harness.state.clone();
        harness.cancel_and_join_ok().await;
        drop(live_tx);
        assert_eq!(state.get_processed_block(Chain::Midnight).await, Some(9));

        // The restart: same persisted state, head advanced to 12. Exactly
        // (9 .. 12] processes; 6..=9 must NOT re-walk and 10 must not skip.
        let (live_tx2, live_rx2) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 12,
            live: tokio::sync::Mutex::new(Some(live_rx2)),
            ..Default::default()
        };
        for n in 9..=12 {
            source.set_state(&central, n, central_state(vec![]));
        }
        let mut second = Harness::spawn_with_state(source, state).await;
        for n in 10..=12 {
            assert_block(&second.next().await, n);
        }
        assert!(matches!(second.next().await, ChainEvent::CatchupCompleted));
        second.cancel_and_join_ok().await;
        drop(live_tx2);
    }

    #[tokio::test]
    async fn run_recovers_pruned_requests_via_watermark() {
        // A Pruned node recovers the gap's requests from latest state instead
        // of dropping unservable blocks. The responded rid sits below the
        // per-rid watermark in field 2 and is skipped; the unresponded one is
        // recovered. Both rids resolve fully on purpose: a watermark that reads
        // the wrong field or inverts the skip then emits the responded one and
        // fails the exactly-one shape below, rather than hiding behind an
        // unresolvable decoy.
        let (record, rid) = caller_record_and_rid();
        let (responded_record, responded_rid) = named_record_and_rid("no-calldata");
        let central = central_address();
        let (live_tx, live_rx) = mpsc::channel(8);
        let mut source = FixtureSource {
            head: 9,
            probe: Some(ArchiveState::Pruned { probed_height: 3 }),
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        // No per-block states for 6..=8 AT ALL: the pruned walk never runs.
        // Latest state at the anchor carries both notifications and the
        // response marker for the first.
        source.set_state(
            &central,
            9,
            central_state_with_responses(
                vec![
                    // The circuit's first notification carries count 0; one
                    // response makes respondCount 1, so 0 < 1 skips it. The
                    // recovered entry's 1 >= 0 (no response) processes.
                    notification_entry(0, &responded_rid),
                    notification_entry(1, &rid),
                ],
                &[(responded_rid, 1)],
            ),
        );
        source.set_state(
            &hex::encode(CALLER),
            9,
            StateNode::Array {
                children: vec![
                    StateNode::Null,
                    StateNode::Null,
                    StateNode::Null,
                    StateNode::Null,
                    StateNode::Map {
                        entries: vec![
                            MapEntry {
                                key: vec![trimmed_hex(&responded_rid)],
                                value: cell_of(&atoms_from_record(&responded_record)),
                            },
                            MapEntry {
                                key: vec![trimmed_hex(&rid)],
                                value: cell_of(&atoms_from_record(&record)),
                            },
                        ],
                    },
                ],
            },
        );

        let mut harness = Harness::spawn(source, 5).await;
        assert_sign_request(&harness.next().await, rid, "minimal-1word");
        assert_block(&harness.next().await, 9);
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));
        assert_eq!(
            harness.state.get_processed_block(Chain::Midnight).await,
            Some(9),
            "the watermark walk records progress at the anchor"
        );
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_switches_to_watermark_on_mid_catchup_pruning() {
        // Archive mode, but the gap reaches deeper than retention: block 7's
        // central read hits the pruning signature, and the walk SWITCHES to
        // the watermark for the remainder instead of restarting into the
        // same wall or losing the gap's requests.
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

        let mut harness = Harness::spawn(source, 5).await;
        assert_block(&harness.next().await, 6);
        // The switch: block 7 is never emitted block-wise; the watermark
        // walk recovers the request and lands progress at the anchor.
        assert_sign_request(&harness.next().await, rid, "minimal-1word");
        assert_block(&harness.next().await, 9);
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_anchors_at_head_without_catchup_when_fresh() {
        // Checkpoint 0 in EITHER mode: no gap to close, no genesis walk, no
        // watermark walk; live starts at the anchor.
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

        let mut harness = Harness::spawn(source, 0).await;
        assert!(
            matches!(harness.next().await, ChainEvent::CatchupCompleted),
            "a fresh node emits no catchup blocks"
        );
        live_tx.send(block_ref(9)).await.expect("send live block");
        assert_block(&harness.next().await, 9);
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn process_block_drops_only_failing_entry() {
        // One malformed record must never stop indexing for everyone.
        // `enum-algo-set` is an ORACLE record, so it decodes cleanly and passes
        // the recompute-and-drop gate on its own filed id, and its sender is
        // CALLER like every other tier; the reserved `algo = 1` is rejected
        // only later, inside to_sign_request. A caller can file exactly this
        // into its own ledger at will, which is what makes a propagated Err a
        // caller-triggerable outage rather than a bug it alone suffers.
        //
        // The bad record is filed FIRST so a propagated Err pre-empts its
        // sibling rather than merely following it.
        let (good_record, good_rid) = caller_record_and_rid();
        let (bad_record, bad_rid) = named_record_and_rid("enum-algo-set");
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
            StateNode::Array {
                children: vec![
                    StateNode::Null,
                    StateNode::Null,
                    StateNode::Null,
                    StateNode::Null,
                    StateNode::Map {
                        entries: vec![
                            MapEntry {
                                key: vec![trimmed_hex(&bad_rid)],
                                value: cell_of(&atoms_from_record(&bad_record)),
                            },
                            MapEntry {
                                key: vec![trimmed_hex(&good_rid)],
                                value: cell_of(&atoms_from_record(&good_record)),
                            },
                        ],
                    },
                ],
            },
        );

        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));

        let mut harness = Harness::spawn(source, 8).await;
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));

        live_tx.send(block_ref(9)).await.expect("send live block");
        assert_sign_request(&harness.next().await, good_rid, "minimal-1word");
        assert_block(&harness.next().await, 9);
        assert_eq!(
            harness.state.get_processed_block(Chain::Midnight).await,
            Some(9),
            "the block completes and the checkpoint advances past the bad entry"
        );
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_skips_replayed_live_block() {
        // The re-delivery guard. A supervised restart or a resubscribe after a
        // transient WS drop can re-deliver a finalized block the loop already
        // processed; re-emitting it produces DUPLICATE sign requests rather
        // than a visible failure. The replay must produce no event at all,
        // which is observable as 10 arriving next instead of 9 a second time.
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

        let mut harness = Harness::spawn(source, 8).await;
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));

        live_tx.send(block_ref(9)).await.expect("send 9");
        assert_block(&harness.next().await, 9);

        live_tx.send(block_ref(9)).await.expect("replay 9");
        live_tx.send(block_ref(10)).await.expect("send 10");
        assert_block(&harness.next().await, 10);
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn midnight_indexer_new_rejects_unusable_config() {
        let config = MidnightConfig {
            sidecar_url: "http://127.0.0.1:8790".to_string(),
            node_ws_url: String::new(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".to_string(),
            rpc: Default::default(),
            sidecar: Default::default(),
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
