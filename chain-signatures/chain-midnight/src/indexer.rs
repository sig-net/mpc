//! Midnight indexer implementation: catchup from the persisted checkpoint,
//! then the live finalized loop, with per-block processing ordered by the
//! D5 authority split (state diff triggers, decoded transactions attribute
//! advisorily, the caller-ledger read plus the rid gate authorise).

use crate::config::MidnightConfig;
use crate::reader::{resolve_verified_record, signet_field_node};
use crate::rpc::{is_state_unservable, ArchiveState, BlockRef, MidnightRpc};
use crate::sidecar::{DecodedTransactions, MapEntry, SidecarClient, StateNode};
use crate::{decode_notification, to_sign_request, unpack_notification_v1};

use std::collections::HashSet;
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
/// trailing-zero-trimmed atoms, `[count, requestId]`, the rid re-padded to
/// 32 bytes. This is the ONE place the key layout is assumed; everything
/// downstream passes the recovered rid around. Any other atom count or a
/// non-hex or overlong atom is a malformed key, dropped by the caller with
/// its own reason.
fn signet_map_key_rid(key_atoms: &[String]) -> Option<[u8; 32]> {
    let [count_hex, rid_hex] = key_atoms else {
        return None;
    };
    let count = hex::decode(count_hex).ok()?;
    if count.len() > 8 {
        return None;
    }
    let rid = hex::decode(rid_hex).ok()?;
    if rid.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[..rid.len()].copy_from_slice(&rid);
    Some(padded)
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

impl<S: StateManager, T: ChainTelemetry> MidnightIndexer<S, T> {
    /// The central singleton's field-1 entries at `at_hash`, or the drop
    /// classification for this block. `Ok(None)` means the block is skipped
    /// as a whole in Pruned mode (state unservable, the pruning signature);
    /// transport errors propagate for the supervised restart.
    async fn notification_entries<C: ChainSource>(
        &self,
        source: &C,
        mode: ArchiveState,
        at_hash: &str,
        height: u64,
    ) -> anyhow::Result<Option<Vec<MapEntry>>> {
        let tree = match source
            .contract_state_tree(&self.config.central_address, at_hash)
            .await
        {
            Ok(Some(tree)) => tree,
            // Central not yet deployed at this block: an ordinary empty
            // block, common during catchup from before deployment.
            Ok(None) => return Ok(Some(Vec::new())),
            Err(err)
                if matches!(mode, ArchiveState::Pruned { .. }) && is_state_unservable(&err) =>
            {
                // TODO(B7): the real watermark catchup replaces this
                // skip-with-counter degraded walk.
                drop_entry(
                    "central-state-unservable",
                    height,
                    None,
                    &format!("{err:#}"),
                );
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        match signet_field_node(&tree, usize::from(NOTIFICATION_MAP_FIELD)) {
            Ok(StateNode::Map { entries }) => Ok(Some(entries.clone())),
            Ok(_) => {
                drop_entry(
                    "central-field-not-a-map",
                    height,
                    None,
                    "central field 1 is not a map; wrong central address or schema drift",
                );
                Ok(Some(Vec::new()))
            }
            Err(err) => {
                drop_entry("central-field-walk", height, None, &format!("{err:#}"));
                Ok(Some(Vec::new()))
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
        mode: ArchiveState,
        cache: &mut Option<(String, Vec<MapEntry>)>,
        block: &BlockRef,
    ) -> anyhow::Result<Vec<IndexedSignRequest>> {
        let Some(entries) = self
            .notification_entries(source, mode, &block.hash, block.number)
            .await?
        else {
            return Ok(Vec::new());
        };

        let parent_entries = match cache.take() {
            Some((hash, entries)) if hash == block.parent_hash => entries,
            _ => match self
                .notification_entries(
                    source,
                    mode,
                    &block.parent_hash,
                    block.number.saturating_sub(1),
                )
                .await?
            {
                Some(entries) => entries,
                None => {
                    cache.replace((block.hash.clone(), entries));
                    return Ok(Vec::new());
                }
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
            let attributed = match source.decoded_transactions(block).await {
                Ok(txs) => attribute_caller(&txs, &self.config.central_address),
                Err(err) => {
                    drop_entry(
                        "provenance-decode-failed",
                        block.number,
                        None,
                        &format!("{err:#}"),
                    );
                    None
                }
            };
            let indexed_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            for entry in new_entries {
                let Some(rid) = signet_map_key_rid(&entry.key) else {
                    drop_entry(
                        "malformed-map-key",
                        block.number,
                        None,
                        &format!("{} atoms in a SignetMapKey", entry.key.len()),
                    );
                    continue;
                };
                let notification = match decode_notification(&entry.value) {
                    Ok(notification) => notification,
                    Err(err) => {
                        drop_entry(
                            "notification-undecodable",
                            block.number,
                            Some(rid),
                            &format!("{err:#}"),
                        );
                        continue;
                    }
                };
                let unpacked = match unpack_notification_v1(&notification) {
                    Ok(unpacked) => unpacked,
                    Err(err) => {
                        drop_entry(
                            "notification-version",
                            block.number,
                            Some(rid),
                            &format!("{err:#}"),
                        );
                        continue;
                    }
                };
                let caller_hex = hex::encode(unpacked.caller_address);

                // Advisory comparison, never a gate (D5): absence and
                // disagreement are counters, and the read below proceeds
                // regardless.
                match &attributed {
                    Some(address) if *address != caller_hex => {
                        drop_entry(
                            "provenance-mismatch",
                            block.number,
                            Some(rid),
                            &format!("decoded caller {address} vs notification {caller_hex}"),
                        );
                    }
                    None => {
                        drop_entry(
                            "provenance-absent",
                            block.number,
                            Some(rid),
                            "no commitment pair in this block's decoded calls",
                        );
                    }
                    _ => {}
                }

                // Authority: the caller's own ledger at the SAME finalized
                // hash the notification appeared at.
                let caller_tree = match source.contract_state_tree(&caller_hex, &block.hash).await {
                    Ok(Some(tree)) => tree,
                    Ok(None) => {
                        drop_entry(
                            "caller-contract-absent",
                            block.number,
                            Some(rid),
                            &caller_hex,
                        );
                        continue;
                    }
                    Err(err)
                        if matches!(mode, ArchiveState::Pruned { .. })
                            && is_state_unservable(&err) =>
                    {
                        drop_entry(
                            "caller-state-unservable",
                            block.number,
                            Some(rid),
                            &format!("{err:#}"),
                        );
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                let field = match signet_field_node(
                    &caller_tree,
                    usize::from(unpacked.requests_index_field),
                ) {
                    Ok(field) => field,
                    Err(err) => {
                        // The field position is producer-supplied data, so
                        // out-of-range walks a per-entry drop, never an abort.
                        drop_entry(
                            "requests-field-walk",
                            block.number,
                            Some(rid),
                            &format!("{err:#}"),
                        );
                        continue;
                    }
                };
                let Some(record) = resolve_verified_record(field, rid) else {
                    // resolve_verified_record warned with its own reason.
                    drop_entry(
                        "rid-gate",
                        block.number,
                        Some(rid),
                        "recompute-and-drop rejected the record",
                    );
                    continue;
                };
                match to_sign_request(
                    &record,
                    &unpacked.caller_address,
                    &self.config.central_address,
                    rid,
                    indexed_ts,
                ) {
                    Ok(request) => requests.push(request),
                    Err(err) => {
                        // Binding 9/10: every conversion failure is a
                        // per-record data property; drop with the id and
                        // reason together, WARN not ERROR, and continue.
                        drop_entry(
                            "convert-rejected",
                            block.number,
                            Some(rid),
                            &format!("{err:#}"),
                        );
                        continue;
                    }
                }
            }
        }

        cache.replace((block.hash.clone(), entries));
        Ok(requests)
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
        if checkpoint == 0 {
            // A fresh node has no gap to close: walking from genesis would
            // reprocess the whole chain, so catchup anchors live at the
            // finalized head and history before it is out of scope.
            tracing::info!(
                anchor = anchor.number,
                "midnight fresh start: no checkpoint, anchoring at the finalized head"
            );
            last_processed = anchor.number;
        } else {
            for number in (checkpoint + 1)..=anchor.number {
                let block = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    block = source.block_at(number) => block?,
                };
                let requests = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    requests = self.process_block(source, mode, &mut cache, &block) => requests?,
                };
                self.emit_block(&events_tx, &block, requests).await?;
                last_processed = number;
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
                    requests = self.process_block(source, mode, &mut cache, &gap) => requests?,
                };
                self.emit_block(&events_tx, &gap, requests).await?;
            }
            let requests = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                requests = self.process_block(source, mode, &mut cache, &block) => requests?,
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

    /// The minimal-1word oracle record (sender 0xab * 32) and its filed id.
    fn caller_record_and_rid() -> (crate::records::SignBidirectionalRecord, [u8; 32]) {
        let file: RidVectorFile =
            serde_json::from_str(RID_VECTORS_JSON).expect("rid_vectors.json parses");
        let vector = file
            .vectors
            .into_iter()
            .find(|vector| vector.name == "minimal-1word")
            .expect("minimal-1word exists");
        let rid: [u8; 32] = hex::decode(&vector.expected_request_id_hex)
            .expect("rid hex")
            .try_into()
            .expect("32 bytes");
        (vector.record.0, rid)
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
        /// block hash -> decoded transactions; absent means empty.
        txs: HashMap<String, DecodedTransactions>,
        live: tokio::sync::Mutex<Option<mpsc::Receiver<BlockRef>>>,
    }

    impl FixtureSource {
        fn set_state(&mut self, address: &str, at: u64, tree: StateNode) {
            self.states.insert((address.to_string(), hash_of(at)), tree);
        }
    }

    #[async_trait]
    impl ChainSource for FixtureSource {
        async fn assert_sidecar_compatible(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn probe_archive_state(&self, _window: u64) -> anyhow::Result<ArchiveState> {
            Ok(ArchiveState::Archive)
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
            Ok(self
                .states
                .get(&(address_64hex.to_string(), at_hash.to_string()))
                .cloned())
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
