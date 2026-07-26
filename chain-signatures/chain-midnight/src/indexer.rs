//! Midnight indexer implementation: catchup from the persisted checkpoint,
//! then the live finalized loop, with per-block processing ordered by the
//! D5 authority split (state diff triggers, decoded transactions attribute
//! advisorily, the caller-ledger read plus the rid gate authorise).

use crate::config::MidnightConfig;
use crate::reader::{resolve_verified_record, signet_field_node};
use crate::rpc::{is_state_unservable, ArchiveState, BlockRef, MidnightRpc};
use crate::sidecar::{DecodedTransactions, MapEntry, SidecarClient, StateNode};
use crate::{decode_notification, to_sign_request, unpack_notification_v1};

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

/// Delay between anchor-sampling retries, mirroring Canton's shape.
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// The central singleton's notification map ordinal (D6 field 1), the only
/// field the diff reads.
const NOTIFICATION_MAP_FIELD: u8 = 1;

/// Midnight indexer: `run()` owns the whole read path.
///
/// BLOCK EMISSION IS LIVE, for a correctness reason before an operational
/// one: without `ChainEvent::Block` and `set_processed_block`, the
/// checkpoint never advances, so every supervised restart re-walks catchup
/// from the same stale checkpoint and re-emits the same `SignRequest`s,
/// independent of any watchdog tuning. Secondarily, the 315s
/// `live_block_timeout(Midnight)` watchdog (15 + 300, `stream/pipeline.rs`)
/// restart-loops a silent indexer every 5m15s by design.
///
/// The scaffold era's hazard note is updated rather than removed:
/// `checkpoint_interval(Midnight)` is `Some(120)`, so
/// emitting `ChainEvent::Block` while recording progress starts checkpoint
/// creation (`stream/ops.rs::process_block_event`), a threshold signing
/// request. Checkpoint signing stalls unless threshold-many nodes have
/// Midnight enabled, and a node WITHOUT Midnight still buffers peer posits
/// for checkpoint ids it never sees locally, in `posit_queues` entries that
/// only `retire_task` removes. That binds the ROLLOUT, not this code: the
/// off-by-default config gate keeps Midnight out of production config, and
/// network-wide enablement plus a `posit_queues` bound remain preconditions
/// for enabling Midnight where real value lives.
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
        // Fail on an unusable config here, once, rather than forever at
        // runtime once the read path dials these endpoints.
        config.validate()?;
        // Deliberately network-free beyond that: the CLI gate calls new()
        // once and logs the error without retrying, so a dial here would
        // turn a transient outage at boot into a permanently disabled
        // chain. The archive-state probe and catchup-mode selection run at
        // the start of each supervised run() instead, via
        // MidnightRpc::probe_archive_state and select_catchup_mode: B6
        // wires that call when it writes run(), B7 implements the catchup
        // modes the result selects.
        Ok(Self {
            config,
            state_manager,
            telemetry,
        })
    }
}

/// Applies the startup policy to the archive probe's answer:
/// probe-and-degrade by default, strict refusal when the operator set
/// `require_archive_state`.
///
/// Degrading means catchup falls back to the WATERMARK path (resume from
/// the last processed block using only data the node still serves) instead
/// of exact-block contract-state reads. B6's `run()` consumes the returned
/// mode at its start, right after `MidnightRpc::connect`, and threads it
/// into the catchup step; B7 implements the two modes it selects; see
/// `probe_archive_state` for why the probe does not run at construction.
/// The degraded state is dashboardable via
/// `ChainTelemetry::catchup_degraded`, which `run()` reports each
/// supervised run; the warning below stays as the log-side signal.
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

/// The node-and-sidecar reads `run()` consumes, as a seam: Ethereum's run
/// tests mock its HTTP transport, but subxt's WebSocket cannot be stubbed
/// (an `OnlineClient` fetches runtime metadata at construction), so the
/// fixture boundary is this trait instead. `LiveSource` is the production
/// composition; the test fixture is the other implementor.
#[async_trait]
pub(crate) trait ChainSource: Send + Sync {
    async fn assert_sidecar_compatible(&self) -> anyhow::Result<()>;
    async fn probe_archive_state(&self, window: u64) -> anyhow::Result<ArchiveState>;
    async fn finalized_head(&self) -> anyhow::Result<BlockRef>;
    async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef>;
    /// The decoded state tree of `address_64hex` at `at_hash`, `None` when
    /// the contract is not present at that block.
    async fn contract_state_tree(
        &self,
        address_64hex: &str,
        at_hash: &str,
    ) -> anyhow::Result<Option<StateNode>>;
    /// The block's decoded `send_mn_transaction` calls, advisory only.
    async fn decoded_transactions(&self, block: &BlockRef) -> anyhow::Result<DecodedTransactions>;
    /// Pushes live finalized blocks into `tx` until the underlying stream
    /// ends; the returned guard aborts the producer on drop.
    async fn spawn_block_producer(&self, tx: mpsc::Sender<BlockRef>)
        -> anyhow::Result<AbortOnDrop>;
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
    ) -> anyhow::Result<Option<StateNode>> {
        match self.rpc.contract_state(address_64hex, at_hash).await? {
            None => Ok(None),
            Some(state) => Ok(Some(self.sidecar.decode_contract_state(&state).await?)),
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
        self.sidecar.decode_transactions(&blobs).await
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

/// Advisory CCC provenance (D5): the address of the call CLAIMING the
/// central call's communication commitment within the same transaction, if
/// any pair exists. There is no entry-point field on the callee side, so
/// the commitment join is the only link; the central contract's own call is
/// never the caller. Advisory means exactly that: the result feeds a
/// counter and a comparison against the notification's caller, never a
/// gate, because a direct call to the notify entry point has no CCC frame
/// at all and requiring one would drop legitimate requests.
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
/// recovered from its atom-preserving wire key (D9 option 1): exactly two
/// trailing-zero-trimmed atoms, `[count, requestId]`, the count folded
/// little-endian and the rid re-padded to 32 bytes. This is the ONE place
/// the key layout is assumed; everything downstream passes the recovered
/// pair around. Any other atom count or a non-hex or overlong atom is a
/// malformed key, dropped by the caller with its own reason.
fn signet_map_key_rid(key_atoms: &[String]) -> Option<(u64, [u8; 32])> {
    let [count_hex, rid_hex] = key_atoms else {
        return None;
    };
    let count = fold_le_u64(count_hex)?;
    let rid = hex::decode(rid_hex).ok()?;
    if rid.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[..rid.len()].copy_from_slice(&rid);
    Some((count, padded))
}

/// The central singleton's respondCounterMap ordinal (D6 field 2): the
/// on-chain per-rid watermark the degraded catchup reads. Field 2, the
/// PHASE-1 signature response counter (`respond` appends "a signature
/// response"), deliberately NOT field 4: `respondBidirectionalCounterMap`
/// counts phase-2 execution outputs, and reading it would re-emit the
/// whole in-flight signed-but-not-yet-executed set on every degraded
/// catchup.
const RESPOND_COUNTER_FIELD: u8 = 2;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Per-rid response COUNTS from the central tree's field 2. The `respond`
/// circuit insertDefault-then-increments that counter per rid, and the
/// count matters, not membership: a notification entry `(count = C, rid)`
/// is unanswered iff `C >= respondCount(rid)` (an absent rid reads 0), so
/// a caller re-notifying AFTER a response, including after a failed one
/// (the 0xdeadbeef encoding), is processed rather than skipped forever.
/// An absent or empty field is the ordinary nothing-responded-yet state,
/// never an error; an undecodable counter reads 0, which only ever
/// PROCESSES more, never skips.
fn response_counts(tree: &StateNode, height: u64) -> HashMap<[u8; 32], u64> {
    let entries = match signet_field_node(tree, usize::from(RESPOND_COUNTER_FIELD)) {
        Ok(StateNode::Map { entries }) => entries.clone(),
        Ok(_) => return HashMap::new(),
        Err(err) => {
            drop_entry(
                "respond-counter-field-walk",
                height,
                None,
                &format!("{err:#}"),
            );
            return HashMap::new();
        }
    };
    entries
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
    let rid = hex::decode(rid_hex).ok()?;
    if rid.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[..rid.len()].copy_from_slice(&rid);
    Some(padded)
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

/// One drop, one WARN, one distinct reason label (binding 10): the label is
/// the countable signal (log-pipeline counters key on it), the line is the
/// diagnosis. WARN rather than ERROR deliberately: every one of these is
/// manufacturable at will by a caller writing junk into its own contract
/// state, and ERROR would hand an adversary a free alarm bell.
fn drop_entry(reason: &'static str, height: u64, request_id: Option<[u8; 32]>, detail: &str) {
    tracing::warn!(
        reason,
        height,
        request_id = request_id.map(hex::encode),
        "midnight entry dropped: {detail}"
    );
}

/// Whether step 4 (advisory attribution) ran for the entries being
/// processed. The watermark path skips it BY CONSTRUCTION (there is no
/// per-tx context in a latest-state walk), and a skipped attribution must
/// not warn `provenance-absent`: that label means attribution RAN and found
/// no pair, which is a different fact.
enum Attribution {
    Skipped,
    Ran(Option<String>),
}

impl<S: StateManager, T: ChainTelemetry> MidnightIndexer<S, T> {
    /// The central singleton's tree at `at_hash`, or `None` when the
    /// contract is not present there (ordinary during catchup from before
    /// deployment). Every error propagates, INCLUDING the unservable
    /// pruning signature: policy for that lives in the catchup loop (switch
    /// to the watermark mode), never down here where it could only lose
    /// requests.
    async fn central_tree<C: ChainSource>(
        &self,
        source: &C,
        at_hash: &str,
    ) -> anyhow::Result<Option<StateNode>> {
        source
            .contract_state_tree(&self.config.central_address, at_hash)
            .await
    }

    /// Field-1 entries of an already-fetched central tree.
    fn notification_entries(&self, tree: &StateNode, height: u64) -> Vec<MapEntry> {
        match signet_field_node(tree, usize::from(NOTIFICATION_MAP_FIELD)) {
            Ok(StateNode::Map { entries }) => entries.clone(),
            Ok(_) => {
                drop_entry(
                    "central-field-not-a-map",
                    height,
                    None,
                    "central field 1 is not a map; wrong central address or schema drift",
                );
                Vec::new()
            }
            Err(err) => {
                drop_entry("central-field-walk", height, None, &format!("{err:#}"));
                Vec::new()
            }
        }
    }

    /// Per-block processing, shared by catchup and live, ordered by the D5
    /// authority split: the state diff triggers, decoded transactions
    /// attribute advisorily, the caller-ledger read plus the rid gate
    /// authorise, B5 converts. Every per-entry failure is a counted drop,
    /// never a block abort: a poisoned entry must not stall the chain, and
    /// a sibling entry's conversion must still run.
    ///
    /// Retry-budget arithmetic (binding 3): with the parent tree cached,
    /// the worst-case degraded cost per block is three node reads wrapped
    /// in `retry_rpc!` (central state, caller state, block-by-hash for the
    /// advisory decode), each up to ~75s under `RpcConfig` defaults (6
    /// attempts x 10s per-attempt timeouts plus ~15s backoff), so ~225s
    /// against the 315s `live_block_timeout(Midnight)` watchdog, BEFORE
    /// sidecar budgets. The cache below keeps the central read at one per
    /// block on both the happy and the degraded path (it is keyed on the
    /// parent hash, not on success); anyone changing the shared retry
    /// budget or adding a per-block call must redo this arithmetic.
    async fn process_block<C: ChainSource>(
        &self,
        source: &C,
        cache: &mut Option<(String, Vec<MapEntry>)>,
        block: &BlockRef,
    ) -> anyhow::Result<Vec<IndexedSignRequest>> {
        let entries = match self.central_tree(source, &block.hash).await? {
            Some(tree) => self.notification_entries(&tree, block.number),
            // Central not yet deployed at this block: an ordinary empty
            // block, common during catchup from before deployment.
            None => Vec::new(),
        };

        let parent_entries = match cache.take() {
            Some((hash, entries)) if hash == block.parent_hash => entries,
            _ => match self.central_tree(source, &block.parent_hash).await? {
                Some(tree) => self.notification_entries(&tree, block.number.saturating_sub(1)),
                None => Vec::new(),
            },
        };
        let parent_keys: HashSet<&[String]> = parent_entries
            .iter()
            .map(|entry| entry.key.as_slice())
            .collect();
        let new_entries: Vec<&MapEntry> = entries
            .iter()
            .filter(|entry| !parent_keys.contains(entry.key.as_slice()))
            .collect();

        let mut requests = Vec::new();
        if !new_entries.is_empty() {
            // Advisory attribution, once per block. Its own failure is also
            // advisory: a sidecar decode fault must not stop signing.
            let attribution = match source.decoded_transactions(block).await {
                Ok(txs) => Attribution::Ran(attribute_caller(&txs, &self.config.central_address)),
                Err(err) => {
                    drop_entry(
                        "provenance-decode-failed",
                        block.number,
                        None,
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

        cache.replace((block.hash.clone(), entries));
        Ok(requests)
    }

    /// Steps 3, 5 and 6 for one notification entry: decode and unpack the
    /// notification, read the caller's ledger at `at_hash`, gate through
    /// `resolve_verified_record`, convert. Shared verbatim by the per-block
    /// diff and the watermark walk; only step 1 (the diff) and step 4
    /// (attribution) differ between the two, which is exactly the
    /// documented trade of the watermark mode. `Ok(None)` is a counted
    /// drop; `Err` is transport, propagated for the supervised restart.
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
            drop_entry(
                "malformed-map-key",
                height,
                None,
                &format!("{} atoms in a SignetMapKey", entry.key.len()),
            );
            return Ok(None);
        };
        let notification = match decode_notification(&entry.value) {
            Ok(notification) => notification,
            Err(err) => {
                drop_entry(
                    "notification-undecodable",
                    height,
                    Some(rid),
                    &format!("{err:#}"),
                );
                return Ok(None);
            }
        };
        let unpacked = match unpack_notification_v1(&notification) {
            Ok(unpacked) => unpacked,
            Err(err) => {
                drop_entry(
                    "notification-version",
                    height,
                    Some(rid),
                    &format!("{err:#}"),
                );
                return Ok(None);
            }
        };
        let caller_hex = hex::encode(unpacked.caller_address);

        // Advisory comparison, never a gate (D5): absence and disagreement
        // are counters, and the read below proceeds regardless. A SKIPPED
        // attribution (the watermark walk) warns nothing: provenance-absent
        // means attribution ran and found no pair, which is a different
        // fact from it never running.
        match attribution {
            Attribution::Ran(Some(address)) if *address != caller_hex => {
                drop_entry(
                    "provenance-mismatch",
                    height,
                    Some(rid),
                    &format!("decoded caller {address} vs notification {caller_hex}"),
                );
            }
            Attribution::Ran(None) => {
                drop_entry(
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
        let caller_tree = match source.contract_state_tree(&caller_hex, at_hash).await {
            Ok(Some(tree)) => tree,
            Ok(None) => {
                drop_entry("caller-contract-absent", height, Some(rid), &caller_hex);
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let field =
            match signet_field_node(&caller_tree, usize::from(unpacked.requests_index_field)) {
                Ok(field) => field,
                Err(err) => {
                    // The field position is producer-supplied data, so an
                    // out-of-range walk is a per-entry drop, never an abort.
                    drop_entry(
                        "requests-field-walk",
                        height,
                        Some(rid),
                        &format!("{err:#}"),
                    );
                    return Ok(None);
                }
            };
        let Some(record) = resolve_verified_record(field, rid) else {
            // resolve_verified_record warned with its own reason.
            drop_entry(
                "rid-gate",
                height,
                Some(rid),
                "recompute-and-drop rejected the record",
            );
            return Ok(None);
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
                // Binding 9/10: every conversion failure is a per-record
                // data property; drop with the id and reason together, WARN
                // not ERROR, and continue.
                drop_entry("convert-rejected", height, Some(rid), &format!("{err:#}"));
                Ok(None)
            }
        }
    }

    /// The watermark catchup (D10's degraded mode, B7): read the central
    /// contract's LATEST state once, at the anchor, and process every
    /// field-1 entry whose rid is above the persisted per-rid watermark
    /// through steps 3, 5 and 6. Steps 1 and 4 are skipped by construction,
    /// so this path has no per-tx provenance and no per-block granularity;
    /// that is the documented trade, and the rid gate holds because it
    /// never depended on the block.
    ///
    /// THE WATERMARK IS THE LEDGER'S OWN, twice over, because StateManager
    /// persists exactly one u64 per chain and no per-rid store exists
    /// locally. Coarse: the notification map is insert-only in the contract
    /// (`signBidirectional` reads-then-increments a per-rid counter and
    /// only ever inserts), so the anchor's latest state contains every
    /// notification ever filed and `set_processed_block(anchor)` afterwards
    /// loses nothing; the modes interleave safely because both resume from
    /// that one slot, and over-coverage lands as keyed backlog inserts
    /// (signing is gated on caught_up). Per-rid: the on-chain
    /// respondCounterMap (D6 field 2, the PHASE-1 signature responses,
    /// deliberately not field 4's phase-2 execution outputs), read from the
    /// SAME anchored tree as a COUNT: entry `(count = C, rid)` is
    /// unanswered iff `C >= respondCount(rid)`, absent reading 0. The count
    /// comparison rather than membership keeps re-notifications after a
    /// response, including after a failed one, processable: re-emission is
    /// idempotent, a silent skip is not, and the watermark path therefore
    /// agrees with the block path on post-response re-notifications.
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
        let entries = self.notification_entries(&tree, anchor.number);
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
                    // Below the per-rid watermark: this notification
                    // instance predates the latest phase-1 response, so its
                    // answer already exists on-chain. A re-notification AT
                    // or ABOVE the response count processes, so the
                    // watermark path AGREES with the block path on
                    // post-response re-notifications, including after a
                    // failed (0xdeadbeef) answer. Ordinary, not a drop.
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

    /// Emits a processed block's requests, then its Block event, then
    /// records progress and telemetry.
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
            self.telemetry.request_indexed();
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

    /// `run()` over an explicit [`ChainSource`]; `run()` itself only
    /// connects the production source and delegates here, which is the
    /// fixture seam.
    pub(crate) async fn run_with_source<C: ChainSource>(
        &self,
        source: &C,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Startup gates. Err from either is a supervised retry with light
        // backoff, deliberately NOT a construction failure: the CLI gate
        // constructs the indexer once and never retries new(), so a
        // transient sidecar or node outage here must not permanently
        // disable the chain (the B1b rationale, applied to both gates).
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
        let mode = crate::select_catchup_mode(state, self.config.indexer.require_archive_state)?;
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
        // Pruned mode goes straight to the watermark walk: B6's degraded
        // block walk could only drop unservable blocks, losing their
        // requests; the watermark RECOVERS them from latest state instead.
        let mut need_watermark = matches!(mode, ArchiveState::Pruned { .. });
        if checkpoint == 0 {
            // A fresh node has no gap to close: walking from genesis would
            // reprocess the whole chain, so catchup anchors live at the
            // finalized head and history before it is out of scope. That
            // holds in either mode, so no watermark walk is needed.
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
                    // The mid-catchup pruning signature: the gap reaches
                    // deeper than the node's retention even though the
                    // probe said Archive. Switch to the watermark walk for
                    // the remainder rather than restarting into the same
                    // wall (B1b's per-block rule).
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
                    // Binding 2: to run_supervised, Ok(()) is permanent
                    // SHUTDOWN and Err is a restart. An ended producer must
                    // therefore be Err, so the supervised restart re-anchors
                    // and catches up (D10); only cancel returns Ok.
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
                    requests = self.process_block(source, &mut cache, &gap) => requests?,
                };
                self.emit_block(&events_tx, &gap, requests).await?;
            }
            let requests = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                requests = self.process_block(source, &mut cache, &block) => requests?,
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

    #[test]
    fn midnight_indexer_chain_is_midnight() {
        assert_eq!(TestIndexer::CHAIN, Chain::Midnight);
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

    // ==================================================================
    // B6: run() over an injected ChainSource (Ethereum mocks its HTTP
    // transport; subxt WS cannot be mocked, so the seam is a trait).
    // ==================================================================

    use crate::sidecar::{
        ClaimedCall, DecodedCall, DecodedTransaction, DecodedTransactions, MapEntry, StateNode,
    };
    use crate::test_fixtures::{atoms_from_record, cell_of, RecordFixture};
    use crate::ArchiveState;
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

    /// The central singleton: six flat fields, the notification map at
    /// ordinal 1 (D6).
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
        /// a read can fail with e.g. the pruning signature.
        state_errors: HashMap<(String, String), String>,
        /// block hash -> decoded transactions; absent means empty.
        txs: HashMap<String, DecodedTransactions>,
        /// None means Archive (the common case for these tests).
        probe: Option<ArchiveState>,
        live: tokio::sync::Mutex<Option<mpsc::Receiver<BlockRef>>>,
    }

    impl FixtureSource {
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
            Ok(block_ref(number))
        }

        async fn contract_state_tree(
            &self,
            address_64hex: &str,
            at_hash: &str,
        ) -> anyhow::Result<Option<StateNode>> {
            let key = (address_64hex.to_string(), at_hash.to_string());
            if let Some(message) = self.state_errors.get(&key) {
                anyhow::bail!("{message}");
            }
            Ok(self.states.get(&key).cloned())
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
    async fn run_catchup_precedes_completed_and_prequeued_live_blocks() {
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

        // The FORBIDDEN-style guard: a live block is already queued BEFORE
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
        assert_sign_request(&harness.next().await, rid);
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
    async fn live_diff_emits_exactly_one_request_for_the_new_entry() {
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
                                position: 0,
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
        assert_sign_request(&harness.next().await, rid);
        assert_block(&harness.next().await, 9);
        harness.cancel_and_join_ok().await;
    }

    #[tokio::test]
    async fn provenance_absent_still_signs() {
        // The D5 invariant: attribution is advisory, and a diffed
        // notification with NO matching decoded call still signs. This is
        // the check a well-meaning implementer is most likely to make
        // fail-closed.
        let (record, rid) = caller_record_and_rid();
        let central = central_address();
        let mut source = FixtureSource {
            head: 8,
            ..Default::default()
        };
        source.set_state(&central, 8, central_state(vec![]));
        source.set_state(
            &central,
            9,
            central_state(vec![notification_entry(1, &rid)]),
        );
        source.set_state(&hex::encode(CALLER), 9, caller_state(&record, &rid));
        // No txs entry at all: decoded transactions are empty.

        let (live_tx, live_rx) = mpsc::channel(8);
        source.live = tokio::sync::Mutex::new(Some(live_rx));

        let mut harness = Harness::spawn(source, 8).await;
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));

        live_tx.send(block_ref(9)).await.expect("send live block");
        assert_sign_request(&harness.next().await, rid);
        assert_block(&harness.next().await, 9);
        harness.cancel_and_join_ok().await;
    }

    #[tokio::test]
    async fn run_stops_promptly_on_cancel_during_catchup() {
        let (live_tx, live_rx) = mpsc::channel(8);
        let source = FixtureSource {
            head: 600,
            live: tokio::sync::Mutex::new(Some(live_rx)),
            ..Default::default()
        };
        let harness = Harness::spawn(source, 100).await;
        // Give catchup a moment to be genuinely mid-range, then cancel.
        tokio::time::sleep(Duration::from_millis(50)).await;
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn run_stops_promptly_on_cancel_while_live() {
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
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn producer_termination_bails_for_the_supervisor() {
        // Binding 2: Ok(()) is SHUTDOWN to run_supervised, so an ended
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
    fn attribution_join_finds_the_committed_caller_and_rejects_decoys() {
        // Binding 5 shapes: multi-call, the matching claim NOT first, a
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
                            position: 0,
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
                                position: 0,
                                address: "aa".repeat(32),
                                entry_point: "other".to_string(),
                                commitment: "beef".to_string(),
                            },
                            ClaimedCall {
                                position: 1,
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
    async fn restart_recatches_from_checkpoint() {
        // D10's property, distinct from B6's ordering test: a RESTART
        // resumes from the persisted checkpoint rather than re-walking from
        // zero or skipping the gap. Two runs over ONE MockStateManager.
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
    async fn pruned_mode_recovers_requests_via_watermark() {
        // B6's TODO(B7) closed: a Pruned node RECOVERS the gap's requests
        // from latest state instead of dropping unservable blocks. The
        // responded rid is below the on-chain per-rid watermark (D6 field
        // 4) and is skipped; the unresponded one is recovered. BOTH rids
        // are fully resolvable on purpose: a watermark that reads the wrong
        // field or inverts the skip then emits the responded one and fails
        // the exactly-one shape below, instead of hiding behind an
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
        assert_sign_request(&harness.next().await, rid);
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
    async fn mid_catchup_pruning_switches_to_watermark() {
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
        assert_sign_request(&harness.next().await, rid);
        assert_block(&harness.next().await, 9);
        assert!(matches!(harness.next().await, ChainEvent::CatchupCompleted));
        harness.cancel_and_join_ok().await;
        drop(live_tx);
    }

    #[tokio::test]
    async fn fresh_node_anchors_live_without_catchup() {
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
    async fn midnight_indexer_rejects_an_unusable_config() {
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
