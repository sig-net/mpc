//! The M6 expiry evidence layer: windows extracted from serialized
//! transactions, a cross-pass memoized solidified-block cache, and the
//! absence walk. Attestations sit at the deterministic boundary — the
//! first solidified block at or past the window's end.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use futures_util::stream::{iter, StreamExt};
use futures_util::TryStreamExt;
use mpc_chain_integration_core::{unexecutable_outcome, WatchedExecution};
use mpc_primitives::{BidirectionalTx, BidirectionalTxId, ChainEvent, SignId};
use mpc_tron_wire::{pb::RawTransaction, MAX_EXPIRATION_SPAN_MS};
use tokio::sync::Mutex;

use crate::client::TronHttp;
use crate::types::SolidifiedBlock;

/// The TaPoS window extracted from a serialized transaction.
pub(crate) struct TxWindow {
    /// The expiration timestamp of the transaction.
    expiration: i64,
    /// The reference slice derived from the block ID (bytes 8..16).
    ref_block_bytes: [u8; 2],
    /// The block hash referenced by the transaction's TaPoS field.
    ref_block_hash: [u8; 8],
}

/// One flat id's entries; the txID is the hash of their (identical)
/// bytes, so they share a window and one verdict settles them.
pub(crate) type Group = Vec<(SignId, Arc<BidirectionalTx>, TxWindow)>;

/// Extracts the TaPoS window from a serialized transaction, if possible.
pub(crate) fn tx_window(tx: &BidirectionalTx) -> Option<TxWindow> {
    let window = RawTransaction::parse(&tx.serialized_transaction)
        .ok()
        .and_then(|raw| {
            Some(TxWindow {
                expiration: raw.expiration,
                ref_block_bytes: raw.ref_block_bytes.as_slice().try_into().ok()?,
                ref_block_hash: raw.ref_block_hash.as_slice().try_into().ok()?,
            })
        });

    if window.is_none() {
        tracing::warn!(
            sign_id = ?tx.sign_id(),
            ?tx.id,
            "cannot parse a window with TaPoS reference fields; admission validated these bytes"
        );
    }
    window
}

/// The M6 attestation for one expired, unexecuted entry.
pub(crate) fn expired_event(sign_id: SignId, tx: &BidirectionalTx, boundary: u64) -> ChainEvent {
    ChainEvent::ExecutionConfirmed {
        tx_id: tx.id,
        sign_id,
        source_chain: tx.source_chain,
        block_height: boundary,
        result: unexecutable_outcome(tx.source_chain),
    }
}

/// Groups pending entries whose TaPoS windows have closed relative to the given head block.
pub(crate) fn closed_groups(pending: Vec<WatchedExecution>, head: &SolidifiedBlock) -> Vec<Group> {
    let mut groups: HashMap<BidirectionalTxId, Vec<_>> = HashMap::new();
    for WatchedExecution { sign_id, tx } in pending {
        if let Some(window) = tx_window(&tx).filter(|w| head.timestamp >= w.expiration) {
            groups.entry(tx.id).or_default().push((sign_id, tx, window));
        }
    }
    groups.into_values().collect()
}

/// One walk's answer for a flat id's bytes.
#[derive(Debug)]
pub(crate) enum ExpiryVerdict {
    Included,
    Absent { boundary: u64 },
}

/// One 3 s slot.
const SLOT_MS: u64 = 3_000;

/// Bounds the linear absence walk at one 24 h window of 3 s slots,
/// the ceiling the admission rule sets (doc §4.3, anchored on the
/// source block's time) — derived from [`MAX_EXPIRATION_SPAN_MS`].
const MAX_WALK_SPAN: u64 = MAX_EXPIRATION_SPAN_MS / SLOT_MS;

/// Bounds in-flight provider requests across both arms and the span
/// walk.
pub(crate) const MAX_CONCURRENT_PROVIDER_REQUESTS: usize = 8;

/// One block's search surface.
#[derive(Clone, Copy)]
struct BlockHeader {
    timestamp: i64,
    ref_slice: [u8; 8],
}

/// Solidified reads memoized across passes;
/// full blocks are never retained, only their distilled verdicts.
#[derive(Clone, Default)]
pub(crate) struct SolidityCache {
    /// Memoized block headers, keyed by block number.
    headers: Arc<Mutex<HashMap<u64, BlockHeader>>>,
    /// Memoized membership for each transaction ID, keyed by block number.
    membership: Arc<Mutex<HashMap<BidirectionalTxId, HashMap<u64, bool>>>>,
}

impl SolidityCache {
    /// Prunes cached headers and membership entries outside the capped span and no longer scanning transactions.
    pub(crate) async fn prune(&self, head: u64, scanning: &[BidirectionalTxId]) {
        let floor = head.saturating_sub(MAX_WALK_SPAN);
        self.headers
            .lock()
            .await
            .retain(|number, _| *number >= floor);
        let mut membership = self.membership.lock().await;
        membership.retain(|id, _| scanning.contains(id));
        for blocks in membership.values_mut() {
            blocks.retain(|number, _| *number >= floor);
        }
    }
}

/// One scan pass's read surface over the shared cache.
#[derive(Clone)]
pub(crate) struct SolidityView<'a> {
    client: &'a TronHttp,
    head: u64,
    pub(crate) span_cap: u64,
    cache: SolidityCache,
}

impl<'a> SolidityView<'a> {
    pub(crate) fn new(client: &'a TronHttp, head: u64, cache: SolidityCache) -> Self {
        Self {
            client,
            head,
            span_cap: MAX_WALK_SPAN,
            cache,
        }
    }

    /// A block's header; `None` when not solidified on the serving
    /// instance.
    async fn header(&self, number: u64) -> anyhow::Result<Option<BlockHeader>> {
        if let Some(hit) = self.cache.headers.lock().await.get(&number) {
            return Ok(Some(*hit));
        }
        Ok(self.fetched_block(number).await?.as_ref().map(header_of))
    }

    /// One provider fetch, its header memoized; `None` when not
    /// solidified on the serving instance.
    async fn fetched_block(&self, number: u64) -> anyhow::Result<Option<SolidifiedBlock>> {
        let block = self.client.get_block_solidity(number).await?;
        if let Some(block) = &block {
            self.cache
                .headers
                .lock()
                .await
                .insert(number, header_of(block));
        }
        Ok(block)
    }

    /// A header that must resolve; misreading absent as ancient would
    /// converge on a wrong boundary, the height every node shares.
    async fn require_header(&self, number: u64) -> anyhow::Result<BlockHeader> {
        self.header(number)
            .await?
            .with_context(|| self.absent_below_head(number))
    }

    fn absent_below_head(&self, number: u64) -> anyhow::Error {
        anyhow::anyhow!(
            "solidified block {number} below the scan head {} is absent: \
             pruned history or a lagging instance",
            self.head
        )
    }

    /// The first block number at or past `ts`, deferring when nothing
    /// that new is solidified. Timestamps strictly increase with
    /// height, so a lower-bound binary search.
    async fn first_at_or_after(&self, ts: i64) -> anyhow::Result<u64> {
        let (mut lo, mut hi) = (0, self.head);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.require_header(mid).await?.timestamp >= ts {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        // The converged probe may be the head itself; absent there only
        // means nothing that new is solidified yet.
        self.header(lo)
            .await?
            .filter(|header| header.timestamp >= ts)
            .with_context(|| format!("nothing solidified at or past {ts}"))
            .map(|_| lo)
    }

    /// The walk's lower bound: the TaPoS reference block, after which
    /// alone the tx can land. The residue names the height mod 2^16,
    /// and at most one such height fits in the capped span — the
    /// candidate matches `ref_block_hash`, or the reference is lying
    /// or too old, and defers.
    async fn ref_block_start(&self, window: &TxWindow, boundary: u64) -> anyhow::Result<u64> {
        let residue = u16::from_be_bytes(window.ref_block_bytes) as u64;
        let floor = boundary.saturating_sub(MAX_WALK_SPAN);
        let back = (boundary % 65_536 + 65_536 - residue) % 65_536;
        let candidate = boundary
            .checked_sub(back)
            .filter(|number| *number >= floor)
            .with_context(|| format!("TaPoS reference unresolved within {floor}..={boundary}"))?;
        anyhow::ensure!(
            self.require_header(candidate).await?.ref_slice == window.ref_block_hash,
            "TaPoS reference unresolved within {floor}..={boundary}"
        );
        Ok(candidate)
    }

    /// Inclusion over the packable span — from the TaPoS reference to
    /// the first block past the window's end, which can no longer
    /// pack it — the whole M6 proof.
    pub(crate) async fn verdict(
        &self,
        tx_id: BidirectionalTxId,
        window: &TxWindow,
    ) -> anyhow::Result<ExpiryVerdict> {
        let boundary = self.first_at_or_after(window.expiration).await?;
        let start = self.ref_block_start(window, boundary).await?;
        anyhow::ensure!(
            boundary - start <= self.span_cap,
            "packable span {start}..={boundary} exceeds the {}-block walk cap",
            self.span_cap
        );
        let included = iter(start..=boundary)
            .map(|number| self.contains(tx_id, number))
            .buffer_unordered(MAX_CONCURRENT_PROVIDER_REQUESTS)
            .try_any(std::future::ready)
            .await?;
        if included {
            return Ok(ExpiryVerdict::Included);
        }
        Ok(ExpiryVerdict::Absent { boundary })
    }

    /// Whether `txid` is resident in block `number`; an absent block
    /// defers — reading it as empty would attest over a block the
    /// walk never saw.
    async fn contains(&self, txid: BidirectionalTxId, number: u64) -> anyhow::Result<bool> {
        if let Some(hit) = self
            .cache
            .membership
            .lock()
            .await
            .get(&txid)
            .and_then(|blocks| blocks.get(&number))
        {
            return Ok(*hit);
        }
        let block = self
            .fetched_block(number)
            .await?
            .with_context(|| self.absent_below_head(number))?;
        let resident = block.txids.contains(&txid.0);
        self.cache
            .membership
            .lock()
            .await
            .entry(txid)
            .or_default()
            .insert(number, resident);
        Ok(resident)
    }
}

fn header_of(block: &SolidifiedBlock) -> BlockHeader {
    BlockHeader {
        timestamp: block.timestamp,
        ref_slice: block.ref_slice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TronConfig;
    use crate::test_utils::*;
    use mpc_primitives::{Chain, ExecutionOutcome};
    use mpc_tron_wire::pb::RawTransaction;

    #[tokio::test]
    async fn prune_keeps_one_capped_span_and_scanning_membership() {
        let head = 2 * MAX_WALK_SPAN;
        let floor = MAX_WALK_SPAN;
        let cache = SolidityCache::default();
        let scanning = BidirectionalTxId([1; 32]);
        {
            let mut headers = cache.headers.lock().await;
            for number in [floor - 1, floor, floor + 1] {
                headers.insert(
                    number,
                    BlockHeader {
                        timestamp: 0,
                        ref_slice: [0; 8],
                    },
                );
            }
            let mut membership = cache.membership.lock().await;
            membership.insert(scanning, HashMap::from([(floor - 1, true), (floor, false)]));
            membership.insert(BidirectionalTxId([2; 32]), HashMap::from([(floor, true)]));
        }

        cache.prune(head, &[scanning]).await;

        let headers = cache.headers.lock().await;
        assert_eq!(headers.len(), 2, "only the capped span survives");
        assert!(!headers.contains_key(&(floor - 1)));
        let membership = cache.membership.lock().await;
        assert_eq!(membership.len(), 1, "entries no longer scanning drop");
        assert_eq!(
            membership[&scanning],
            HashMap::from([(floor, false)]),
            "scanning keeps only its in-span blocks"
        );
    }

    #[tokio::test]
    async fn memoized_reads_skip_the_provider() {
        let mut server = mockito::Server::new_async().await;
        // The header fetch and the membership fetch, once each.
        let block = server
            .mock("POST", "/walletsolidity/getblockbynum")
            .expect(2)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{ "blockID": "00000000000000000000000000000000000000000000000000000000000000ff",
                     "block_header": { "raw_data": { "number": 1, "timestamp": 1730000000000 } },
                     "transactions": [] }"#,
            )
            .create_async()
            .await;
        let config = TronConfig {
            endpoint: server.url().parse().unwrap(),
            ..TronConfig::default()
        };
        let client = TronHttp::new(&config).unwrap();
        let view = SolidityView::new(&client, 1, SolidityCache::default());

        for _ in 0..2 {
            assert_eq!(
                view.header(1).await.unwrap().unwrap().timestamp,
                1_730_000_000_000
            );
            assert!(!view.contains(BidirectionalTxId([9; 32]), 1).await.unwrap());
        }
        block.assert_async().await;
    }

    #[test]
    fn tx_window_rejects_malformed_tapos_fields() {
        use mpc_tron_wire::pb::Message as _;

        let (_, _, tx) = expiry_tx(1, Chain::Midnight, 1_728_000_060_000);
        let mut malformed = (*tx).clone();
        let mut raw = RawTransaction::parse(&tx.serialized_transaction).unwrap();
        raw.ref_block_bytes = vec![0x03];
        malformed.serialized_transaction = raw.encode_to_vec();
        assert!(
            tx_window(&malformed).is_none(),
            "old-checkpoint entries with malformed TaPoS fields never scan"
        );
    }

    /// Eligibility over a live window; assembly refuses dead ones.
    #[test]
    fn the_scan_eligibility_ends_at_or_past_the_expiration() {
        const EXPIRATION: i64 = 1_728_000_060_000;
        let head = |timestamp| SolidifiedBlock {
            number: 41,
            timestamp,
            ref_slice: [0; 8],
            txids: Vec::new(),
        };
        let tx = || expiry_tx(1, Chain::Midnight, EXPIRATION as u64).2;
        let eligible = |head_ts: i64| {
            let pending = vec![WatchedExecution {
                sign_id: SignId::new([1; 32]),
                tx: tx(),
            }];
            let groups = closed_groups(pending, &head(head_ts));
            groups.len() == 1 && groups[0].len() == 1
        };
        assert!(!eligible(EXPIRATION - 1));
        assert!(eligible(EXPIRATION), "the end block is past the window");
        assert!(eligible(i64::MAX));
        let mut unparsable = (*tx()).clone();
        unparsable.serialized_transaction = vec![0xff];
        let groups = closed_groups(
            vec![WatchedExecution {
                sign_id: SignId::new([1; 32]),
                tx: unparsable.into(),
            }],
            &head(i64::MAX),
        );
        assert!(groups.is_empty(), "unparsable bytes never scan");
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

        let mut view = SolidityView::new(&client, LADDER_TOP, SolidityCache::default());
        view.span_cap = 8;
        let err = format!("{:#}", view.verdict(tx.id, &window).await.unwrap_err());
        assert!(err.contains("walk cap"), "{err}");

        view.span_cap = 32;
        match view.verdict(tx.id, &window).await.unwrap() {
            ExpiryVerdict::Absent { boundary } => assert_eq!(boundary, 32),
            other => panic!("absence expected, got {other:?}"),
        }
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
