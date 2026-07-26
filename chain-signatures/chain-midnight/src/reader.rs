//! The reader: chunk-tree walk, capacity enumeration, and record decode
//! over sidecar `StateNode` trees.
//!
//! This is the trust-plane half of discovery: the sidecar decodes bytes
//! into an atom tree, and everything here re-derives meaning from that tree
//! in Rust. A decode discrepancy drops the request; the request-id
//! recompute downstream is what makes a wrong split a drop rather than a
//! wrong signature.

use anyhow::Context as _;

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams,
    SignBidirectionalEventNotification, SignBidirectionalRecord,
};
use crate::request_id::compute_request_id;
use crate::sidecar::StateNode;

/// compactc chunk arity: past this many ledger fields the compiler stores
/// fields in a depth-uniform tree of arity-15 chunks, filled remainder
/// FIRST, so every chunk on the rightmost spine is full.
const CHUNK_ARITY: usize = 15;

/// Atom count of a record excluding the capacity-scaled vectors: a stored
/// cell holds `REQUEST_FIXED_VALUE_ATOMS + words + entries * (2 + keys)`
/// atoms. The calldata Maybe's three fixed atoms (is_some, selector,
/// no_words) count here EVEN WHEN is_some is false: an empty Maybe still
/// occupies its atoms (D8), and treating it as absent mis-splits every
/// plain-transfer record.
pub const REQUEST_FIXED_VALUE_ATOMS: usize = 22;

/// How many rejected capacity splits the no-split error names before
/// truncating: enough to see why, bounded so an adversarial cell cannot
/// balloon the log line.
const MAX_REPORTED_REJECTIONS: usize = 8;

/// Resolve a flat ledger field index to its node in the raw state tree,
/// regardless of what field types sit before or after it.
///
/// Layout as compactc emits it: up to [`CHUNK_ARITY`] fields sit directly
/// at the root; past that, a depth-uniform chunk tree filled remainder
/// first (16 fields become chunks of [1, 15], 20 become [5, 15], 226
/// become [1, 15x15] one level deeper). Chunk detection walks the
/// rightmost spine: each consecutive arity-15 array is one level to
/// flatten. A field node is never misread as a chunk because no ledger ADT
/// stores an arity-15 array at field level (a List is a three-slot cons
/// node).
///
/// `flat_index` is ZERO-BASED, and it is exactly the `requestsIndexField`
/// byte a notification carries, passed straight in with no adjustment: the
/// 5-field golden pins that the caller contract's own `4 as Uint<8>` lands
/// on its request map here. Note that declaration order does not map one
/// to one onto flat slots (a multi-atom ADT can occupy several), so field
/// positions must always come from the producer, never be counted off the
/// contract source.
pub fn signet_field_node(root: &StateNode, flat_index: usize) -> anyhow::Result<&StateNode> {
    let StateNode::Array { children } = root else {
        if flat_index == 0 {
            return Ok(root);
        }
        anyhow::bail!("field index {flat_index} out of range: root is a leaf");
    };

    let mut chunk_levels = 0usize;
    let mut spine = children.last();
    while let Some(StateNode::Array { children: kids }) = spine {
        if kids.len() != CHUNK_ARITY {
            break;
        }
        chunk_levels += 1;
        spine = kids.last();
    }

    let mut fields: Vec<&StateNode> = children.iter().collect();
    for _ in 0..chunk_levels {
        fields = fields
            .iter()
            .flat_map(|chunk| match chunk {
                StateNode::Array { children } => children.iter().collect::<Vec<_>>(),
                // Mirrors the TS walk's `asArray() ?? []`.
                _ => Vec::new(),
            })
            .collect();
    }

    fields.get(flat_index).copied().ok_or_else(|| {
        anyhow::anyhow!(
            "field index {flat_index} out of range: {} fields after flattening {chunk_levels} chunk levels",
            fields.len()
        )
    })
}

/// A record cell whose wire form admits more than one capacity split that
/// decodes cleanly, hashes to the id it was filed under, AND would assemble
/// a different transaction from its siblings.
///
/// Typed rather than a message so the caller can label the drop by
/// downcasting instead of matching on error text. `decode_record` is called
/// directly by `resolve_verified_record` with no `retry_rpc!` in between, so
/// unlike `rpc::STATE_UNSERVABLE_MSG` nothing flattens the error chain here
/// and a downcast survives.
#[derive(Debug)]
pub struct AmbiguousRecord {
    /// How many capacity splits hashed to the filed id.
    pub splits: usize,
}

impl std::fmt::Display for AmbiguousRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} capacity splits decode to the filed request id and disagree on the transaction \
             they would sign; refusing to pick one by enumeration order",
            self.splits
        )
    }
}

impl std::error::Error for AmbiguousRecord {}

/// A record projected onto what can reach the SIGNED transaction: every
/// vector truncated to the count that governs it, per the "counts, never
/// lengths" rule, plus an absent `Maybe` contributing no calldata words at
/// all.
///
/// Deliberately stated here rather than by calling `tx.rs`, which sits a
/// layer above this one. It is CONSERVATIVE in the safe direction: equal
/// projections guarantee the same transaction, unequal ones do not
/// guarantee a different one (`selector` and `no_words` are compared even
/// when `is_some` is false). Conservative here means a spurious ambiguity
/// drops a request rather than signing the wrong bytes, and in this use the
/// over-strict fields are fixed atoms and therefore identical across every
/// split of one cell anyway.
fn capacity_canonical(record: &SignBidirectionalRecord) -> SignBidirectionalRecord {
    let mut out = record.clone();
    let params = &mut out.tx_params;
    let used_words = if params.calldata.is_some {
        usize::from(params.calldata.value.no_words)
    } else {
        0
    };
    params.calldata.value.words.truncate(used_words);
    params
        .access_list
        .truncate(usize::from(params.access_list_entry_count));
    for entry in &mut params.access_list {
        entry
            .storage_keys
            .truncate(usize::from(entry.storage_key_count));
    }
    out
}

/// Decode a stored request record by capacity enumeration.
///
/// One atom count does not determine the capacities uniquely (an
/// access-list address atom re-pads into a calldata word just as well), so
/// candidate splits are enumerated, access-list-free first, and validated
/// by the decode itself. `expected_request_id` (the id the record is filed
/// under) picks between splits that decode cleanly; when none matches it,
/// the FIRST clean decode is returned, as the TS reader does.
///
/// The id parameter DISAMBIGUATES, it does not AUTHENTICATE, and the
/// caller must still gate on its own recompute. The distinction is the
/// fallback path: when no split matches the filed id, this returns the
/// first clean decode anyway, and the downstream recompute-and-drop is the
/// only thing standing between that record and a signature over something
/// the caller filed under the wrong id. That downstream check is therefore
/// NOT dead weight, however tautological it looks against the match path.
///
/// FAIL CLOSED ON A MATERIAL AMBIGUITY, and note why collision resistance
/// does NOT make the match path unique: two splits of one cell can produce
/// BYTE-IDENTICAL preimages, which hash to one id with no collision
/// involved. The preimage width is `const + 32*V - 43*E` in the variable
/// atom count `V` and entry count `E`, so equal-width splits share an `E`
/// and differ only in how the same atoms are cut into words, addresses,
/// counts and keys. When those readings agree on everything that reaches
/// the transaction the ambiguity is immaterial and the first is returned;
/// when they disagree, picking by enumeration order would sign bytes the
/// record does not describe, so the whole record is refused with
/// [`AmbiguousRecord`]. Every split is therefore enumerated even after a
/// match: `MAX_RECORD_ATOMS` is what keeps that affordable.
pub fn decode_record(
    cell: &StateNode,
    expected_request_id: &[u8; 32],
) -> anyhow::Result<SignBidirectionalRecord> {
    let StateNode::Cell { atoms: atom_hex } = cell else {
        anyhow::bail!("request record node is not a cell");
    };
    let atoms: Vec<Vec<u8>> = atom_hex
        .iter()
        .enumerate()
        .map(|(index, atom)| {
            hex::decode(atom).with_context(|| format!("record atom {index} is not hex"))
        })
        .collect::<anyhow::Result<_>>()?;

    anyhow::ensure!(
        atoms.len() >= REQUEST_FIXED_VALUE_ATOMS,
        "request record has {} value atoms, fewer than the {REQUEST_FIXED_VALUE_ATOMS} its fixed fields need",
        atoms.len()
    );
    // The cap sits HERE, inside decode_record and before any enumeration,
    // rather than at a call site: a later caller would bypass a call-site
    // cap. Named as a cap rejection, not a malformed record, because the
    // two want different operator responses (an oversized cell is an
    // adversarial or runaway producer, not a codec drift).
    anyhow::ensure!(
        atoms.len() <= MAX_RECORD_ATOMS,
        "request record has {} atoms, above the {MAX_RECORD_ATOMS}-atom enumeration cap; \
         refusing to enumerate capacity splits for an adversarially large cell",
        atoms.len()
    );
    let variable = atoms.len() - REQUEST_FIXED_VALUE_ATOMS;
    // Schema widths are read from the LAST TWO atoms' actual lengths:
    // schemas are exact-length by protocol convention (never NUL-padded,
    // never ending in a zero byte), so stored length equals declared width.
    let len_out = atoms[atoms.len() - 2].len();
    let len_resp = atoms[atoms.len() - 1].len();

    let mut rejections: Vec<String> = Vec::new();
    // The first matching split, its transaction-relevant projection, and
    // whether any later match disagreed with that projection. Kept as three
    // scalars rather than a Vec of matches on purpose: a cell at the cap can
    // match on thousands of splits, and collecting them would trade the CPU
    // bound below for an allocation one.
    let mut matched: Option<SignBidirectionalRecord> = None;
    let mut matched_projection: Option<SignBidirectionalRecord> = None;
    let mut match_count = 0usize;
    let mut material_ambiguity = false;
    let mut fallback: Option<SignBidirectionalRecord> = None;

    let mut consider = |words: usize, entries: usize, keys: usize| {
        let record = match decode_at(&atoms, words, entries, keys, len_out, len_resp) {
            Ok(record) => record,
            Err(err) => {
                if rejections.len() < MAX_REPORTED_REJECTIONS {
                    rejections.push(format!(
                        "({words} words, {entries} entries, {keys} keys): {err:#}"
                    ));
                }
                return;
            }
        };
        if compute_request_id(&record) != *expected_request_id {
            if fallback.is_none() {
                fallback = Some(record);
            }
            return;
        }
        match_count += 1;
        let projection = capacity_canonical(&record);
        match &matched_projection {
            None => {
                matched_projection = Some(projection);
                matched = Some(record);
            }
            // A second reading of the same bytes that would sign differently.
            Some(first) if *first != projection => material_ambiguity = true,
            Some(_) => {}
        }
    };

    // No access list: the variable atoms are calldata words alone.
    consider(variable, 0, 0);
    // With an access list: E entries of (2 + K) atoms each, the rest words.
    let mut entries = 1;
    while entries * 2 <= variable {
        let mut keys = 0;
        while entries * (2 + keys) <= variable {
            consider(variable - entries * (2 + keys), entries, keys);
            keys += 1;
        }
        entries += 1;
    }

    if material_ambiguity {
        return Err(anyhow::Error::new(AmbiguousRecord {
            splits: match_count,
        }));
    }
    if let Some(record) = matched {
        return Ok(record);
    }
    if let Some(record) = fallback {
        return Ok(record);
    }
    anyhow::bail!(
        "request record with {} value atoms ({variable} variable) matches no (calldata words, \
         access-list entries, storage keys) capacity split; rejected attempts: {}",
        atoms.len(),
        rejections.join("; ")
    )
}

/// Ceiling on a record cell's atom count. The cell comes from a CALLER's own
/// contract state, so its length is attacker-controlled, and the enumeration
/// above is roughly O(V^2 log V) in the variable atom count `V` with no
/// natural ceiling (the TS reader shares the shape): each of the ~V*ln(V)
/// splits that decodes cleanly pays a keccak over a ~32*V byte preimage, so
/// the hashed volume grows as 32*V^2*ln(V). This is the ONLY thing bounding
/// that, and fail-closed decoding removed the early exit that used to keep
/// the match path cheap, so it now bounds every decode rather than only the
/// no-match ones.
///
/// The value is set from measurement, not from headroom. A cell of one-byte
/// atoms decodes cleanly at EVERY split, which is the worst case, and costs
/// ~66ms at 512 atoms against ~5.6s at 4096 (release, measured). The largest
/// real tier in the repo is 34 atoms (`tests/rid_vectors.json`, `wide-schemas`)
/// and both captured contracts carry 23, so 512 is still an order of
/// magnitude above anything a contract compiles today.
/// `enumeration_cap_stays_far_above_every_real_tier` pins that relationship
/// so raising a capacity in a fixture cannot silently outgrow the cap.
///
/// The cap sits inside `decode_record` before any enumeration rather than at
/// a call site, because a later caller would bypass a call-site cap.
const MAX_RECORD_ATOMS: usize = 512;

/// The recompute-and-drop security gate: the record filed under
/// `request_id` in the CALLER's request map, returned only if the id
/// recomputed from the decoded record equals the id it was filed under.
/// Mirrors `lookupSignetRequestAt`
/// (`signature-requests-state-reader.ts:226-257`) plus the recompute the
/// reference deliberately leaves to the MPC.
///
/// The caller's request map is `Map<RequestId, SignBidirectionalEvent>`,
/// keyed by ONE `Bytes<32>` atom, so its wire key is unambiguous: the
/// trimmed atom re-pads to exactly one 32-byte value. The central
/// singleton's composite `SignetMapKey` maps, where the lossy joined key
/// bites (D9), are B6's diff, never resolved here.
///
/// Why the recompute is NOT redundant, spelled out because it will look
/// deletable: `decode_record` uses the id to DISAMBIGUATE capacity splits
/// and falls back to first-clean-decode when no split matches, so on the
/// match path this gate passes by construction. The fallback path is where
/// it does independent work: there, this recompute is the only thing
/// standing between a record filed under the wrong id and a signature over
/// it. The reference states the division in as many words: "this
/// disambiguates; it does not authenticate (the MPC recomputes against the
/// sender-bound id before signing)"
/// (`signature-requests-state-reader.ts:112-113`). The gate is also
/// deliberately STRONGER than the reference's membership model: membership
/// alone admits a contract that byte-copied a victim's record into its OWN
/// map, and recomputing binds the id to the record's `sender`, which B5's
/// gate in turn binds to the address the record was read from.
///
/// This function REPORTS NOTHING. The id comparison is plain byte equality,
/// deliberately: both operands are public on-chain values, so a timing side
/// channel reveals nothing the chain does not already publish.
pub fn resolve_verified_record(map: &StateNode, request_id: [u8; 32]) -> Resolved {
    let StateNode::Map { entries } = map else {
        return Resolved::Dropped {
            reason: "request-index-not-a-map",
            detail: "the caller's requests field is not a map".to_string(),
        };
    };
    // Map keys are unique and re-padding a trimmed atom is injective, so at
    // most one entry can match; the id being absent from the index is the
    // ordinary negative (the reference returns undefined), not a fault.
    let Some(entry) = entries
        .iter()
        .find(|entry| key_matches_request_id(&entry.key, &request_id))
    else {
        return Resolved::Absent;
    };
    let record = match decode_record(&entry.value, &request_id) {
        Ok(record) => record,
        // Distinguished by DOWNCAST, not by error text: an ambiguous record
        // is an operator-actionable signal about one integrator's contract
        // shape, where an undecodable one is ordinary junk, and a shared
        // label would merge the two counters.
        Err(err) if err.downcast_ref::<AmbiguousRecord>().is_some() => {
            return Resolved::Dropped {
                reason: "record-ambiguous",
                detail: format!("{err:#}"),
            };
        }
        Err(err) => {
            return Resolved::Dropped {
                reason: "record-undecodable",
                detail: format!("{err:#}"),
            };
        }
    };
    let recomputed = compute_request_id(&record);
    if recomputed != request_id {
        return Resolved::Dropped {
            reason: "rid-mismatch",
            detail: format!(
                "recomputed {}, so this is a spoofed or wrongly filed record",
                hex::encode(recomputed)
            ),
        };
    }
    Resolved::Found(Box::new(record))
}

/// The outcome of resolving a filed request id against a caller's request
/// index.
///
/// Three-way rather than `Option`, and the reason is not style. With
/// `Option`, `None` is the only channel a resolver has for "why", so every
/// reason has to leave through the log instead of through the return type,
/// and the caller then logs a second line for a drop the callee already
/// explained. Each variant here maps to exactly one caller action, so
/// [`resolve_verified_record`] reports nothing at all and the caller, which
/// owns the block height, does all of it: one outcome, one line, one label.
///
/// `Found` is boxed because the record is ~384 bytes against ~40 for the
/// other variants, which is past clippy's `large_enum_variant` threshold.
#[derive(Debug, PartialEq)]
pub enum Resolved {
    /// The record, verified: it hashes to the id it was filed under.
    Found(Box<SignBidirectionalRecord>),
    /// The id is not in the caller's index. The ORDINARY NEGATIVE, not a
    /// fault: a caller that notified before its own write landed, or that
    /// computed the id wrong, lands here. Reported at DEBUG by the caller,
    /// deliberately neither WARN (manufacturable at will, so an adversary
    /// would get a free alarm bell) nor silent (this is the failure an
    /// integrator is most likely to hit and the one they cannot otherwise
    /// diagnose).
    Absent,
    /// The entry exists and must not be signed. `reason` is the countable
    /// label, `detail` the diagnosis.
    Dropped {
        reason: &'static str,
        detail: String,
    },
}

/// One trimmed `Bytes<32>` wire atom, re-padded to its declared width.
///
/// THE one implementation of this rule: map keys arrive
/// trailing-zero-trimmed, so a rid ending in `0x00` stores as fewer than 32
/// bytes and has to be re-padded before it can be compared or used. An
/// untrimmed 32-byte atom re-pads to itself, so both wire forms are handled
/// identically. Non-hex and overlong atoms yield `None` rather than a
/// truncated or garbage id. Re-padding is injective, which is what lets
/// callers treat a match as unique.
pub(crate) fn repad_atom_32(atom_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(atom_hex).ok()?;
    if bytes.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    Some(padded)
}

/// Exactly one trimmed `Bytes<32>` atom, re-padded and compared. The
/// caller's request map key is single-atom, so a key arriving with any
/// other atom count is a typed mismatch (another map's composite key or a
/// future schema), never a string that silently fails to compare.
fn key_matches_request_id(key_atoms: &[String], request_id: &[u8; 32]) -> bool {
    let [atom] = key_atoms else {
        return false;
    };
    repad_atom_32(atom) == Some(*request_id)
}

/// Decode the two-atom notification cell: version, then the 128-byte
/// payload.
pub fn decode_notification(cell: &StateNode) -> anyhow::Result<SignBidirectionalEventNotification> {
    let StateNode::Cell { atoms: atom_hex } = cell else {
        anyhow::bail!("notification node is not a cell");
    };
    anyhow::ensure!(
        atom_hex.len() == 2,
        "notification cell has {} atoms, expected 2 (version, payload)",
        atom_hex.len()
    );
    let atoms: Vec<Vec<u8>> = atom_hex
        .iter()
        .enumerate()
        .map(|(index, atom)| {
            hex::decode(atom).with_context(|| format!("notification atom {index} is not hex"))
        })
        .collect::<anyhow::Result<_>>()?;
    let cursor = &mut AtomCursor {
        atoms: &atoms,
        pos: 0,
    };
    Ok(SignBidirectionalEventNotification {
        version: uint(cursor, u128::from(u8::MAX), "notification version")? as u8,
        payload: bytes_n::<128>(cursor, "notification payload")?,
    })
}

/// The V1 notification payload, unpacked per its fixed offsets:
/// `caller_address(32) || requests_index_field(1) || zeros(95)`.
#[derive(Debug, Clone, PartialEq)]
pub struct NotificationV1 {
    pub caller_address: [u8; 32],
    /// The ledger field position of the caller's request index: a
    /// per-integrator value the notification carries, never assumed.
    pub requests_index_field: u8,
}

/// Fails closed on an unrecognised version: a future payload layout adds a
/// branch here rather than silently misinterpreting bytes under the V1
/// offsets.
pub fn unpack_notification_v1(
    notification: &SignBidirectionalEventNotification,
) -> anyhow::Result<NotificationV1> {
    anyhow::ensure!(
        notification.version == 1,
        "notification version {} is not supported (this decoder understands version 1)",
        notification.version
    );
    let mut caller_address = [0u8; 32];
    caller_address.copy_from_slice(&notification.payload[..32]);
    Ok(NotificationV1 {
        caller_address,
        requests_index_field: notification.payload[32],
    })
}

// ---- Descriptor primitives, ported from the compact runtime ----

struct AtomCursor<'a> {
    atoms: &'a [Vec<u8>],
    pos: usize,
}

impl<'a> AtomCursor<'a> {
    fn shift(&mut self, what: &'static str) -> anyhow::Result<&'a [u8]> {
        let atom = self
            .atoms
            .get(self.pos)
            .ok_or_else(|| anyhow::anyhow!("atom {} missing: expected {what}", self.pos))?;
        self.pos += 1;
        Ok(atom)
    }
}

/// `Bytes<N>`: the stored atom is trailing-zero-trimmed; re-pad to the
/// declared width, rejecting an atom wider than it.
fn bytes_n<const N: usize>(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<[u8; N]> {
    let atom = cursor.shift(what)?;
    anyhow::ensure!(
        atom.len() <= N,
        "{what}: atom is {} bytes, wider than Bytes<{N}>",
        atom.len()
    );
    let mut out = [0u8; N];
    out[..atom.len()].copy_from_slice(atom);
    Ok(out)
}

/// Runtime-width `Bytes<Len>`: same rule at a width known only at runtime.
fn bytes_dyn(cursor: &mut AtomCursor, len: usize, what: &'static str) -> anyhow::Result<Vec<u8>> {
    let atom = cursor.shift(what)?;
    anyhow::ensure!(
        atom.len() <= len,
        "{what}: atom is {} bytes, wider than Bytes<{len}>",
        atom.len()
    );
    let mut out = atom.to_vec();
    out.resize(len, 0);
    Ok(out)
}

/// `Uint` and enum atoms fold little-endian at whatever stored length they
/// have; only the folded value is range-checked, mirroring the runtime
/// descriptors (which check `res > maxValue`, not the atom length).
fn uint(cursor: &mut AtomCursor, max: u128, what: &'static str) -> anyhow::Result<u128> {
    let atom = cursor.shift(what)?;
    let mut value: u128 = 0;
    for (index, byte) in atom.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        anyhow::ensure!(index < 16, "{what}: atom wider than 128 bits");
        value |= u128::from(*byte) << (8 * index);
    }
    anyhow::ensure!(value <= max, "{what}: {value} exceeds the maximum {max}");
    Ok(value)
}

/// `Boolean`: the empty atom is false, `[1]` is true, anything else
/// rejects.
fn boolean(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<bool> {
    let atom = cursor.shift(what)?;
    anyhow::ensure!(atom.is_empty() || atom == [1], "{what}: not a Boolean atom");
    Ok(!atom.is_empty())
}

/// One full record decode at a fixed capacity split. Every enumerated split
/// consumes exactly `REQUEST_FIXED_VALUE_ATOMS + words + entries * (2 +
/// keys)` atoms by construction, and the enumeration derives those counts
/// from the cell's own atom count, so a clean decode always lands exactly on
/// the end of the cell. Nothing is ever left over, which is why no leftover
/// check is needed here.
fn decode_at(
    atoms: &[Vec<u8>],
    words: usize,
    entries: usize,
    keys: usize,
    len_out: usize,
    len_resp: usize,
) -> anyhow::Result<SignBidirectionalRecord> {
    let cursor = &mut AtomCursor { atoms, pos: 0 };
    let record = SignBidirectionalRecord {
        sender: bytes_n::<32>(cursor, "sender")?,
        request_nonce: uint(cursor, u128::from(u64::MAX), "request_nonce")? as u64,
        key_version: uint(cursor, u128::from(u8::MAX), "key_version")? as u8,
        path: bytes_n::<32>(cursor, "path")?,
        algo: uint(cursor, 1, "algo")? as u8,
        dest: uint(cursor, 1, "dest")? as u8,
        params: bytes_n::<64>(cursor, "params")?,
        tx_param_type: uint(cursor, 1, "tx_param_type")? as u8,
        tx_params: decode_tx_params(cursor, words, entries, keys)?,
        caip2_id: bytes_n::<32>(cursor, "caip2_id")?,
        output_deserialization_schema: bytes_dyn(cursor, len_out, "output_deserialization_schema")?,
        respond_serialization_schema: bytes_dyn(cursor, len_resp, "respond_serialization_schema")?,
    };
    Ok(record)
}

fn decode_tx_params(
    cursor: &mut AtomCursor,
    words: usize,
    entries: usize,
    keys: usize,
) -> anyhow::Result<EvmType2TxParams> {
    let chain_id = uint(cursor, u128::from(u64::MAX), "chain_id")? as u64;
    let nonce = uint(cursor, u128::from(u64::MAX), "nonce")? as u64;
    let max_priority_fee_per_gas = uint(cursor, u128::MAX, "max_priority_fee_per_gas")?;
    let max_fee_per_gas = uint(cursor, u128::MAX, "max_fee_per_gas")?;
    let gas_limit = uint(cursor, u128::from(u64::MAX), "gas_limit")? as u64;
    let to = bytes_n::<20>(cursor, "to")?;
    let value = uint(cursor, u128::MAX, "value")?;

    // D8: the flag does not gate the atoms. The full calldata block,
    // selector and no_words and every word slot, is consumed whether or not
    // is_some is set; skipping it for an empty Maybe would shift every
    // later field onto the wrong atoms.
    let is_some = boolean(cursor, "calldata.is_some")?;
    let selector = bytes_n::<4>(cursor, "calldata.selector")?;
    let no_words = uint(cursor, u128::from(u16::MAX), "calldata.no_words")? as u16;
    let mut word_slots = Vec::with_capacity(words);
    for _ in 0..words {
        word_slots.push(bytes_n::<32>(cursor, "calldata word")?);
    }

    let access_list_entry_count =
        uint(cursor, u128::from(u8::MAX), "access_list_entry_count")? as u8;
    let mut access_list = Vec::with_capacity(entries);
    for _ in 0..entries {
        let address = bytes_n::<20>(cursor, "access list address")?;
        let storage_key_count = uint(cursor, u128::from(u8::MAX), "storage_key_count")? as u8;
        let mut storage_keys = Vec::with_capacity(keys);
        for _ in 0..keys {
            storage_keys.push(bytes_n::<32>(cursor, "storage key")?);
        }
        access_list.push(EvmAccessListEntry {
            address,
            storage_key_count,
            storage_keys,
        });
    }

    Ok(EvmType2TxParams {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        calldata: CompactMaybe {
            is_some,
            value: EvmCalldata {
                selector,
                no_words,
                words: word_slots,
            },
        },
        access_list_entry_count,
        access_list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{SignBidirectionalEventNotification, SignBidirectionalRecord};
    use crate::sidecar::StateNode;
    use crate::test_fixtures::{atoms_from_record, cell_of, RecordFixture};
    use serde::Deserialize;

    /// Captured by gen-b3-fixtures.ts from the two in-repo caller contracts
    /// via the TS reader (the oracle). Never hand-edit one.
    const FIVE_FIELD_JSON: &str = include_str!("../tests/records/5-field.json");
    const TWENTY_FIELD_JSON: &str = include_str!("../tests/records/20-field.json");
    const RID_VECTORS_JSON: &str = include_str!("../tests/rid_vectors.json");

    const ORACLE: &str =
        "lookupSignetRequestAt/@sig-net/midnight (TS reader over the simulator state)";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReaderFixture {
        generated_from: String,
        oracle: String,
        contract: String,
        requests_index_field: usize,
        request_id_hex: String,
        state: StateNode,
        expected_record: RecordFixture,
    }

    fn load_fixture(json: &str) -> ReaderFixture {
        let fixture: ReaderFixture = serde_json::from_str(json).expect("reader fixture parses");
        assert_eq!(
            fixture.oracle, ORACLE,
            "fixture came from a different oracle (generated from {}); review before adopting",
            fixture.generated_from
        );
        fixture
    }

    fn rid_bytes(hex_id: &str) -> [u8; 32] {
        hex::decode(hex_id)
            .expect("request id hex")
            .try_into()
            .expect("request id is 32 bytes")
    }

    fn leaf(marker: u8) -> StateNode {
        StateNode::Cell {
            atoms: vec![hex::encode([marker])],
        }
    }

    fn marker_of(node: &StateNode) -> u8 {
        let StateNode::Cell { atoms } = node else {
            panic!("expected a leaf cell, got a non-cell node")
        };
        hex::decode(&atoms[0]).expect("marker hex")[0]
    }

    #[test]
    fn golden_records_decode_from_captured_state() {
        for json in [FIVE_FIELD_JSON, TWENTY_FIELD_JSON] {
            let fixture = load_fixture(json);
            // The index convention golden: the fixture's field position is
            // the value the contract itself passes on the wire (the
            // caller's `4 as Uint<8>` requestsIndexField, and 19 for the
            // 20-field contract), fed to signet_field_node with no
            // adjustment. An off-by-one in either direction fails to find
            // the map below, so B6 can pass the notification byte straight
            // through.
            let expected_field = if fixture.contract == "5-field" { 4 } else { 19 };
            assert_eq!(
                fixture.requests_index_field, expected_field,
                "{}: the captured field position must be the contract's own on-wire value",
                fixture.contract
            );
            let field = signet_field_node(&fixture.state, fixture.requests_index_field)
                .unwrap_or_else(|err| panic!("{}: field walk failed: {err}", fixture.contract));
            let StateNode::Map { entries } = field else {
                panic!("{}: request index field is not a map", fixture.contract)
            };
            let entry = entries
                .iter()
                .find(|entry| entry.key.len() == 1 && entry.key[0] == fixture.request_id_hex)
                .unwrap_or_else(|| panic!("{}: request id not in the map", fixture.contract));

            let decoded = decode_record(&entry.value, &rid_bytes(&fixture.request_id_hex))
                .unwrap_or_else(|err| panic!("{}: decode failed: {err}", fixture.contract));
            assert_eq!(
                decoded, fixture.expected_record.0,
                "{}: decoded record diverges from the TS reader",
                fixture.contract
            );
            assert_eq!(
                crate::request_id::compute_request_id(&decoded),
                rid_bytes(&fixture.request_id_hex),
                "{}: recomputed id must match the id the record is filed under",
                fixture.contract
            );
        }
    }

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

    #[test]
    fn rid_vector_records_round_trip_through_decode() {
        // Every A4 oracle record, re-trimmed into wire atoms and decoded
        // back: exercises the capacity enumeration across all tiers,
        // including no-calldata (the D8 case: is_some is false and the full
        // calldata block still occupies its atoms) and the access-list
        // splits where the id is what disambiguates.
        let file: RidVectorFile =
            serde_json::from_str(RID_VECTORS_JSON).expect("rid_vectors.json parses");
        assert!(file.vectors.len() >= 13, "the tier set shrank");
        for vector in &file.vectors {
            let atoms = atoms_from_record(&vector.record.0);
            let cell = cell_of(&atoms);
            let expected_rid = rid_bytes(&vector.expected_request_id_hex);
            let decoded = decode_record(&cell, &expected_rid)
                .unwrap_or_else(|err| panic!("vector {}: decode failed: {err}", vector.name));
            // The consensus property holds for every vector: the recovered
            // record hashes to the id it was filed under.
            assert_eq!(
                crate::request_id::compute_request_id(&decoded),
                expected_rid,
                "vector {}: recomputed id diverged",
                vector.name
            );
            if vector.name == "al-capacity-unused" {
                // This wire form is PROVABLY capacity-ambiguous, so exact
                // record equality is the wrong assertion. Its variable
                // atoms after trimming are one calldata word then all
                // zeros, and every entries=2 split spans the same 202
                // preimage bytes (words shrink by exactly what the entry
                // blocks grow: 32*(5-2k) + 2*(21+32k) = 202 for k = 0..2)
                // with identical zero content, hence one shared request
                // id. First match wins in the TS reader and here alike,
                // so both return the (5 words, 2 entries, 0 keys) reading.
                // Here the ambiguity is IMMATERIAL: every matching split
                // assembles the same transaction, which is the only reason
                // decode_record is allowed to pick one. It is NOT a general
                // property that the semantic fields survive a capacity
                // ambiguity: `access_list_entry_count` demonstrably does
                // not, which is what
                // `a_material_capacity_ambiguity_is_refused_rather_than_resolved_by_order`
                // pins and why the decode fails closed when the readings
                // disagree on what would be signed.
                assert!(decoded.tx_params.calldata.is_some);
                assert_eq!(decoded.tx_params.calldata.value.no_words, 1);
                assert_eq!(
                    decoded.tx_params.calldata.value.words[0],
                    vector.record.0.tx_params.calldata.value.words[0]
                );
                assert_eq!(decoded.tx_params.access_list_entry_count, 0);
                continue;
            }
            assert_eq!(
                decoded, vector.record.0,
                "vector {}: round trip diverged",
                vector.name
            );
        }
    }

    #[test]
    fn chunk_shapes_flatten_correctly() {
        // Navigation-only synthetic trees, no record bytes. The expected
        // layouts are DERIVED FROM THE TS RULE, not from this
        // implementation: signature-state-reading.ts:67-75 documents, from
        // probes of real compiler output, that fields chunk remainder
        // FIRST ("16 fields become chunks of [1, 15], 20 become [5, 15],
        // 226 become [1, 15x15] one level deeper") and that every chunk on
        // the rightmost spine is always FULL. The real one-level case is
        // anchored empirically by the 20-field capture in the golden test;
        // these trees extend the cited rule to depths the checkout cannot
        // produce.
        // Direct layout: up to 15 fields sit at the root.
        let direct = StateNode::Array {
            children: (0..7).map(leaf).collect(),
        };
        assert_eq!(marker_of(signet_field_node(&direct, 4).unwrap()), 4);
        assert!(signet_field_node(&direct, 7).is_err());

        // 16 fields chunk to [1, 15], remainder FIRST.
        let sixteen = StateNode::Array {
            children: vec![
                StateNode::Array {
                    children: vec![leaf(0)],
                },
                StateNode::Array {
                    children: (1..16).map(leaf).collect(),
                },
            ],
        };
        for index in [0usize, 1, 5, 15] {
            assert_eq!(
                marker_of(signet_field_node(&sixteen, index).unwrap()),
                index as u8,
                "16-field layout, index {index}"
            );
        }

        // 20 fields chunk to [5, 15]: the captured 20-field golden covers
        // this against REAL compiler output; 27 chunks to [12, 15].
        let twenty_seven = StateNode::Array {
            children: vec![
                StateNode::Array {
                    children: (0..12).map(leaf).collect(),
                },
                StateNode::Array {
                    children: (12..27).map(leaf).collect(),
                },
            ],
        };
        for index in [0usize, 11, 12, 26] {
            assert_eq!(
                marker_of(signet_field_node(&twenty_seven, index).unwrap()),
                index as u8,
                "27-field layout, index {index}"
            );
        }
        assert!(signet_field_node(&twenty_seven, 27).is_err());

        // Two chunk levels: a full arity-15 spine of full arity-15 chunks,
        // the 226-field shape one level deeper. 1 + 15x15 = 226 fields.
        let two_level = StateNode::Array {
            children: vec![
                StateNode::Array {
                    children: vec![StateNode::Array {
                        children: (0..1).map(leaf).collect(),
                    }],
                },
                StateNode::Array {
                    children: (0..15)
                        .map(|chunk| StateNode::Array {
                            children: (0..15).map(|i| leaf((1 + chunk * 15 + i) as u8)).collect(),
                        })
                        .collect(),
                },
            ],
        };
        for index in [0usize, 1, 15, 16, 225] {
            assert_eq!(
                marker_of(signet_field_node(&two_level, index).unwrap()),
                index as u8,
                "226-field layout, index {index}"
            );
        }

        // A leaf root is field 0 and nothing else.
        let single = leaf(9);
        assert_eq!(marker_of(signet_field_node(&single, 0).unwrap()), 9);
        let err = signet_field_node(&single, 1).unwrap_err().to_string();
        assert!(err.contains("leaf"), "unexpected error: {err}");
    }

    #[test]
    fn trailing_junk_is_rejected_not_id_matched() {
        // A cell whose first 23 atoms are a valid record plus one junk
        // atom. Junk is never simply left dangling at the end: splits are
        // derived from the total atom count, so every attempt consumes
        // exactly all atoms. The protection story is three layers.
        // 1. Junk must therefore be ABSORBED into some field of some split.
        // 2. Absorption then fails type checks on the shifted tail fields.
        //    That layer is fixture-specific, deliberately: this junk shape
        //    shifts a 34-byte schema atom onto the one-byte entry-count
        //    position of the words-absorbing split; a different junk shape
        //    could decode cleanly.
        // 3. The id chain is the structural backstop for those shapes: a
        //    clean absorption either fails the filed-id match and dies as a
        //    fallback at the downstream recompute gate, or, by collision
        //    resistance, IS the original record. Junk can only produce a
        //    rejection, a fallback the gate drops, or the truth.
        let fixture = load_fixture(FIVE_FIELD_JSON);
        let field = signet_field_node(&fixture.state, fixture.requests_index_field).expect("field");
        let StateNode::Map { entries } = field else {
            panic!("request index field is not a map")
        };
        let StateNode::Cell { atoms } = &entries[0].value else {
            panic!("record cell expected")
        };
        let mut with_junk = atoms.clone();
        with_junk.push("00".repeat(33));
        let err = decode_record(
            &StateNode::Cell { atoms: with_junk },
            &rid_bytes(&fixture.request_id_hex),
        )
        .expect_err("trailing junk must reject every split")
        .to_string();
        assert!(
            err.contains("24") && err.contains("capacity split"),
            "diagnostics must carry the atom count and what was enumerated: {err}"
        );
    }

    #[test]
    fn too_few_atoms_is_a_named_error() {
        let short = StateNode::Cell {
            atoms: vec!["ab".to_string(); 21],
        };
        let err = decode_record(&short, &[0u8; 32])
            .expect_err("21 atoms cannot hold the fixed fields")
            .to_string();
        assert!(
            err.contains("21") && err.contains("22"),
            "the error must name both counts: {err}"
        );
    }

    #[test]
    fn notification_v1_unpacks_and_other_versions_fail_closed() {
        let mut payload = [0u8; 128];
        payload[..32].copy_from_slice(&[0xab; 32]);
        payload[32] = 4;

        let cell = StateNode::Cell {
            atoms: vec![hex::encode([1u8]), hex::encode(payload)],
        };
        let notification = decode_notification(&cell).expect("v1 notification decodes");
        assert_eq!(
            notification,
            SignBidirectionalEventNotification {
                version: 1,
                payload
            }
        );
        let unpacked = unpack_notification_v1(&notification).expect("v1 payload unpacks");
        assert_eq!(unpacked.caller_address, [0xab; 32]);
        assert_eq!(unpacked.requests_index_field, 4);

        // Fail closed on an unrecognised version rather than reinterpreting
        // the payload under V1 offsets.
        let future = SignBidirectionalEventNotification {
            version: 2,
            payload,
        };
        let err = unpack_notification_v1(&future)
            .expect_err("future versions must fail closed")
            .to_string();
        assert!(err.contains("version 2"), "unexpected error: {err}");
    }

    // ------------------------------------------------------------------
    // The recompute-and-drop gate (B4).
    // ------------------------------------------------------------------

    /// A named rid vector's record and the id the oracle filed it under.
    fn record_and_rid(name: &str) -> (SignBidirectionalRecord, [u8; 32]) {
        let file: RidVectorFile =
            serde_json::from_str(RID_VECTORS_JSON).expect("rid_vectors.json parses");
        let vector = file
            .vectors
            .into_iter()
            .find(|vector| vector.name == name)
            .unwrap_or_else(|| panic!("no rid vector named {name}"));
        let rid = rid_bytes(&vector.expected_request_id_hex);
        (vector.record.0, rid)
    }

    /// A map whose keys are SINGLE atoms (the caller-map shape). Central-map
    /// tests with composite keys build `MapEntry` directly.
    fn map_of(entries: Vec<(String, StateNode)>) -> StateNode {
        StateNode::Map {
            entries: entries
                .into_iter()
                .map(|(key, value)| crate::sidecar::MapEntry {
                    key: vec![key],
                    value,
                })
                .collect(),
        }
    }

    #[test]
    fn recompute_gate_drops_spoofed() {
        let (record, rid) = record_and_rid("minimal-1word");
        let cell = cell_of(&atoms_from_record(&record));

        // Genuine filing: the id it is stored under is the id it hashes to.
        let map = map_of(vec![(hex::encode(rid), cell.clone())]);
        assert_eq!(
            resolve_verified_record(&map, rid),
            Resolved::Found(Box::new(record))
        );

        // Spoofed filing: the same record bytes stored under an id they do
        // NOT hash to. decode_record ACCEPTS this cell, asserted explicitly:
        // no split matches the filed id, so decode falls back to
        // first-clean-decode, and the drop below is therefore provably the
        // GATE's independent work on the fallback path, the one place the
        // recompute is not tautological.
        let spoofed = [0x99; 32];
        assert!(
            decode_record(&cell, &spoofed).is_ok(),
            "decode must accept the spoofed filing via its fallback; only the gate drops it"
        );
        let map = map_of(vec![(hex::encode(spoofed), cell)]);
        assert!(
            matches!(
                resolve_verified_record(&map, spoofed),
                Resolved::Dropped {
                    reason: "rid-mismatch",
                    ..
                }
            ),
            "the gate must drop the fallback under its own reason"
        );
    }

    #[test]
    fn poisoned_entry_skipped_and_absent_id_is_absent() {
        let (record, rid) = record_and_rid("minimal-1word");
        let poisoned_rid = [0x55; 32];
        let map = map_of(vec![
            (
                hex::encode(poisoned_rid),
                cell_of(&[vec![1], vec![2], vec![3]]),
            ),
            (hex::encode(rid), cell_of(&atoms_from_record(&record))),
        ]);

        // The undecodable cell drops without panicking...
        assert!(matches!(
            resolve_verified_record(&map, poisoned_rid),
            Resolved::Dropped {
                reason: "record-undecodable",
                ..
            }
        ));
        // ...and does not block the sibling genuine entry.
        assert_eq!(
            resolve_verified_record(&map, rid),
            Resolved::Found(Box::new(record))
        );
        // An id absent from the index is the ordinary negative, and it is a
        // DISTINCT outcome from a drop: the caller reports it at DEBUG, so
        // collapsing the two back into one would either silence real drops
        // or hand an adversary a WARN it can manufacture at will.
        assert_eq!(resolve_verified_record(&map, [0x44; 32]), Resolved::Absent);
        // A non-map node is a drop, never a panic, and never Absent.
        assert!(matches!(
            resolve_verified_record(&StateNode::Null, rid),
            Resolved::Dropped {
                reason: "request-index-not-a-map",
                ..
            }
        ));
    }

    #[test]
    fn trimmed_key_repadded() {
        // Find a nonce whose record hashes to an id ending in 0x00, so the
        // wire key (trailing-zero-trimmed, per the sidecar's own rendering)
        // is SHORTER than 32 bytes. Bounded fixture search, not an
        // assertion branch; expected hit within ~256 tries.
        let (mut record, _) = record_and_rid("minimal-1word");
        let mut found = None;
        for nonce in 0..100_000u64 {
            record.request_nonce = nonce;
            let rid = compute_request_id(&record);
            if rid[31] == 0 {
                found = Some(rid);
                break;
            }
        }
        let rid = found.expect("a nonce with a trailing-zero id exists in range");

        let mut trimmed = rid.to_vec();
        while trimmed.last() == Some(&0) {
            trimmed.pop();
        }
        assert!(trimmed.len() < 32, "the key must actually be trimmed");

        let map = map_of(vec![(
            hex::encode(&trimmed),
            cell_of(&atoms_from_record(&record)),
        )]);
        assert_eq!(
            resolve_verified_record(&map, rid),
            Resolved::Found(Box::new(record))
        );
    }

    // ------------------------------------------------------------------
    // Fail-closed capacity ambiguity.
    // ------------------------------------------------------------------

    /// The atom list that made the old first-match-wins decode sign a
    /// transaction its own record does not describe.
    ///
    /// 25 atoms, three of them contested. Two splits decode cleanly from
    /// them and produce BYTE-IDENTICAL preimages (`0x01` then 53 zeros in
    /// both), so they share a request id with no keccak collision involved:
    ///
    ///   A = (1 word, 1 entry, 0 keys)  reads [01] as a calldata word and
    ///       the three empty atoms as entry_count=0, address, key_count=0
    ///   B = (0 words, 1 entry, 1 key)  reads [01] as entry_count=1 and the
    ///       three empty atoms as address, key_count=0, storage_key
    ///
    /// A assembles with NO access list; B assembles with one entry. The
    /// enumeration tries A first, so before this defence the MPC signed A's
    /// bytes for a caller that filed B, and the rid gate passed because the
    /// id really is the filed one.
    fn ambiguous_cell_atoms() -> Vec<Vec<u8>> {
        vec![
            vec![0xab; 32],               // sender
            vec![7],                      // request_nonce
            vec![1],                      // key_version
            b"caller-path".to_vec(),      // path
            Vec::new(),                   // algo = 0
            Vec::new(),                   // dest = 0
            Vec::new(),                   // params = 0
            Vec::new(),                   // tx_param_type = 0
            vec![0x69, 0x7a],             // chain_id 31337, little-endian
            vec![3],                      // nonce
            vec![1],                      // max_priority_fee_per_gas
            vec![2],                      // max_fee_per_gas
            vec![0x08, 0x52],             // gas_limit 21000, little-endian
            vec![0xcd; 20],               // to
            vec![5],                      // value
            vec![1],                      // calldata.is_some
            vec![0xca, 0x11, 0xab, 0x1e], // calldata.selector
            Vec::new(),                   // calldata.no_words = 0
            vec![1],                      // contested: word[0] | entry_count
            Vec::new(),                   // contested
            Vec::new(),                   // contested
            Vec::new(),                   // contested
            b"eip155:31337".to_vec(),     // caip2_id
            b"uint256".to_vec(),          // output schema
            b"uint256".to_vec(),          // respond schema
        ]
    }

    /// The two readings of [`ambiguous_cell_atoms`], as records.
    fn ambiguous_pair() -> (SignBidirectionalRecord, SignBidirectionalRecord) {
        use crate::records::{CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams};

        let build = |words: Vec<[u8; 32]>, count: u8, access_list: Vec<EvmAccessListEntry>| {
            let mut path = [0u8; 32];
            path[..11].copy_from_slice(b"caller-path");
            let mut caip2_id = [0u8; 32];
            caip2_id[..12].copy_from_slice(b"eip155:31337");
            SignBidirectionalRecord {
                sender: [0xab; 32],
                request_nonce: 7,
                key_version: 1,
                path,
                algo: 0,
                dest: 0,
                params: [0; 64],
                tx_param_type: 0,
                tx_params: EvmType2TxParams {
                    chain_id: 31337,
                    nonce: 3,
                    max_priority_fee_per_gas: 1,
                    max_fee_per_gas: 2,
                    gas_limit: 21000,
                    to: [0xcd; 20],
                    value: 5,
                    calldata: CompactMaybe {
                        is_some: true,
                        value: EvmCalldata {
                            selector: [0xca, 0x11, 0xab, 0x1e],
                            no_words: 0,
                            words,
                        },
                    },
                    access_list_entry_count: count,
                    access_list,
                },
                caip2_id,
                output_deserialization_schema: b"uint256".to_vec(),
                respond_serialization_schema: b"uint256".to_vec(),
            }
        };

        let mut word = [0u8; 32];
        word[0] = 1;
        let split_a = build(
            vec![word],
            0,
            vec![EvmAccessListEntry {
                address: [0; 20],
                storage_key_count: 0,
                storage_keys: Vec::new(),
            }],
        );
        let split_b = build(
            Vec::new(),
            1,
            vec![EvmAccessListEntry {
                address: [0; 20],
                storage_key_count: 0,
                storage_keys: vec![[0u8; 32]],
            }],
        );
        (split_a, split_b)
    }

    #[test]
    fn a_material_capacity_ambiguity_is_refused_rather_than_resolved_by_order() {
        let (split_a, split_b) = ambiguous_pair();
        let rid = compute_request_id(&split_b);

        // The premise, asserted rather than assumed: two DISTINCT records
        // share one request id, and they would be signed differently. Both
        // halves matter. Without the first there is no ambiguity to refuse;
        // without the second the ambiguity would be immaterial and refusing
        // it would drop a legitimate record.
        assert_eq!(
            compute_request_id(&split_a),
            rid,
            "the two splits must share a request id"
        );
        assert_ne!(split_a, split_b, "but they must be different records");
        assert_ne!(
            crate::tx::serialized_transaction(&split_a).expect("a assembles"),
            crate::tx::serialized_transaction(&split_b).expect("b assembles"),
            "and they must assemble to different transactions, or this proves nothing"
        );

        let err = decode_record(&cell_of(&ambiguous_cell_atoms()), &rid)
            .expect_err("a material ambiguity must be refused, not resolved by enumeration order");
        let ambiguous = err
            .downcast_ref::<AmbiguousRecord>()
            .expect("the refusal must be typed so the caller can label it");
        assert_eq!(ambiguous.splits, 2, "both splits matched the filed id");

        // And it reaches the caller as its own drop reason, not merged with
        // ordinary junk.
        let map = map_of(vec![(hex::encode(rid), cell_of(&ambiguous_cell_atoms()))]);
        assert!(matches!(
            resolve_verified_record(&map, rid),
            Resolved::Dropped {
                reason: "record-ambiguous",
                ..
            }
        ));
    }

    #[test]
    fn an_immaterial_capacity_ambiguity_still_decodes() {
        // The other side of fail-closed, and the reason the check compares
        // the SIGNED projection rather than the whole record: this oracle
        // vector is provably capacity-ambiguous too (every entries=2 split
        // spans the same 202 preimage bytes of zeros, hence one shared id),
        // but every matching split assembles the SAME transaction, so
        // refusing it would drop a record the oracle itself produced.
        let (record, rid) = record_and_rid("al-capacity-unused");
        let decoded = decode_record(&cell_of(&atoms_from_record(&record)), &rid)
            .expect("an immaterial ambiguity must still decode");
        assert_eq!(
            crate::tx::serialized_transaction(&decoded).expect("assembles"),
            crate::tx::serialized_transaction(&record).expect("assembles"),
            "the returned split must sign what the filed record describes"
        );
    }

    #[test]
    fn the_enumeration_cap_stays_in_band_against_the_real_tiers() {
        // The cap is a CPU bound (see its doc), and it is wrong in BOTH
        // directions, so this is a band rather than a floor. Too low and
        // real records stop decoding; too high and the bound stops binding,
        // which is the state it was found in: 4096 against a largest real
        // tier of 34 let one caller-controlled cell cost 5.6s of indexer
        // time, enough that ~56 of them in a block outlast the 315s
        // `live_block_timeout(Midnight)` watchdog and restart-loop the
        // chain. A wall-clock assertion would be flaky, so the band is the
        // proxy: the cost is quadratic in the cap, so holding the cap near
        // the tiers is what holds the cost near the measurement in its doc.
        let file: RidVectorFile =
            serde_json::from_str(RID_VECTORS_JSON).expect("rid_vectors.json parses");
        let largest = file
            .vectors
            .iter()
            .map(|vector| atoms_from_record(&vector.record.0).len())
            .max()
            .expect("the fixture has vectors");
        assert!(
            largest * 8 <= MAX_RECORD_ATOMS,
            "the largest real tier is {largest} atoms and the cap is {MAX_RECORD_ATOMS}: too \
             close, so a legitimate capacity would stop decoding"
        );
        assert!(
            MAX_RECORD_ATOMS <= largest * 32,
            "the largest real tier is {largest} atoms and the cap is {MAX_RECORD_ATOMS}: too far \
             above it for the cost bound in the cap's doc to still hold. Redo that arithmetic \
             (the hashed volume grows as 32*V^2*ln(V)) before widening this band"
        );
    }

    #[test]
    fn a_composite_key_is_a_typed_mismatch_not_a_lossy_match() {
        // The caller's request map is keyed by ONE Bytes<32> atom. A key with
        // any other atom count belongs to a different map (the central
        // singleton's composite SignetMapKey) or to a future schema, and must
        // not resolve. Both shapes below DO resolve under a weaker reading: the
        // first under "take key_atoms[0]", the second under any implementation
        // that joins the atoms, since the sidecar's own golden shows a one-atom
        // key and a two-atom key concatenating identically (D9).
        let (record, rid) = record_and_rid("minimal-1word");
        let cell = cell_of(&atoms_from_record(&record));

        // Absent rather than Dropped: an unmatched key means the id is not in
        // this index at all, which is the ordinary negative.
        let leading = StateNode::Map {
            entries: vec![crate::sidecar::MapEntry {
                key: vec![hex::encode(rid), "00".to_string()],
                value: cell.clone(),
            }],
        };
        assert_eq!(
            resolve_verified_record(&leading, rid),
            Resolved::Absent,
            "a two-atom key whose FIRST atom is the rid must not resolve"
        );

        let joined = StateNode::Map {
            entries: vec![crate::sidecar::MapEntry {
                key: vec![String::new(), hex::encode(rid)],
                value: cell,
            }],
        };
        assert_eq!(
            resolve_verified_record(&joined, rid),
            Resolved::Absent,
            "a composite key that CONCATENATES to the rid must not resolve"
        );
    }

    #[test]
    fn wire_atoms_are_type_checked_never_coerced() {
        // Every atom here originates in a CALLER's own contract state, so a
        // decode that coerces instead of rejecting lets the caller choose which
        // record the MPC reconstructs.
        let (record, rid) = record_and_rid("minimal-1word");
        let atoms = atoms_from_record(&record);

        // A Compact Boolean is the EMPTY atom or [1]; [2] is not "true".
        let mut not_boolean = atoms.clone();
        not_boolean[15] = vec![2];
        let err = decode_record(&cell_of(&not_boolean), &rid)
            .expect_err("a non-Boolean calldata.is_some atom must reject")
            .to_string();
        assert!(err.contains("Boolean"), "err: {err}");

        // An atom wider than its declared Bytes<N> is a typed mismatch, never a
        // truncation: silently dropping the tail would change the record while
        // leaving the decode looking clean.
        let mut over_wide = atoms.clone();
        over_wide[0] = vec![0xab; 33];
        let err = decode_record(&cell_of(&over_wide), &rid)
            .expect_err("a 33-byte sender atom must reject")
            .to_string();
        assert!(err.contains("wider than Bytes<32>"), "err: {err}");
    }

    #[test]
    fn a_notification_cell_must_carry_exactly_two_atoms() {
        // version and payload, nothing else: a cell of any other shape is a
        // schema change and must fail closed rather than decode whatever the
        // first two atoms happen to be.
        let mut payload = [0u8; 128];
        payload[..32].copy_from_slice(&[0xab; 32]);
        payload[32] = 4;
        for atoms in [
            vec![hex::encode([1u8])],
            vec![hex::encode([1u8]), hex::encode(payload), hex::encode([0u8])],
        ] {
            let count = atoms.len();
            let err = decode_notification(&StateNode::Cell { atoms })
                .expect_err("only a two-atom notification cell decodes")
                .to_string();
            assert!(err.contains("expected 2"), "{count} atoms: {err}");
        }
    }

    #[test]
    fn oversized_cell_is_rejected_by_the_cap_before_enumeration() {
        // 33-byte atoms, deliberately: IF enumeration ever ran on these,
        // every split would die instantly on the first fixed field (33 > 32
        // for sender's Bytes<32>), so the mutant that removes the cap fails
        // FAST here on the error class rather than hanging CI. The real
        // cost the cap prevents (an adversarial cell with plausible atoms
        // grinding the roughly O(V^2 log V) split space) is argued in the
        // cap's doc; a wall-clock assertion would be flaky.
        let over = vec![vec![0xaa; 33]; MAX_RECORD_ATOMS + 1];
        let err = decode_record(&cell_of(&over), &[0x11; 32])
            .expect_err("a cell above the cap is refused")
            .to_string();
        assert!(
            err.contains("enumeration cap"),
            "the cap error must name itself, got: {err}"
        );
        assert!(
            !err.contains("matches no"),
            "a capped cell is a cap rejection, not a malformed record, got: {err}"
        );

        // At exactly the cap, enumeration RUNS and reports the ordinary
        // no-split rejection: the boundary is exclusive-above.
        let at_cap = vec![vec![0xaa; 33]; MAX_RECORD_ATOMS];
        let err = decode_record(&cell_of(&at_cap), &[0x11; 32])
            .expect_err("no split can match 33-byte atoms")
            .to_string();
        assert!(
            err.contains("matches no"),
            "an at-cap cell goes through enumeration, got: {err}"
        );
        assert!(
            !err.contains("enumeration cap"),
            "an at-cap cell is not a cap rejection, got: {err}"
        );
    }
}
