//! Chunk-tree walk, capacity enumeration, and record decode over sidecar
//! `StateNode` trees.
//!
//! The trust-plane half of discovery: the sidecar turns bytes into an atom
//! tree, everything here re-derives meaning from that tree in Rust, and the
//! request-id recompute makes a wrong reading a drop rather than a signature.

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

/// Atom count of a record excluding the capacity-scaled vectors: a stored cell
/// holds `REQUEST_FIXED_VALUE_ATOMS + words + entries * (2 + keys)` atoms.
///
/// The calldata Maybe's three fixed atoms count here even when `is_some` is
/// false. An empty Maybe still occupies them, and treating it as absent
/// mis-splits every plain-transfer record.
pub const REQUEST_FIXED_VALUE_ATOMS: usize = 22;

/// How many rejected capacity splits the no-split error names before
/// truncating: enough to see why, bounded so an adversarial cell cannot
/// balloon the log line.
const MAX_REPORTED_REJECTIONS: usize = 8;

/// Resolve a flat ledger field index to its node in the raw state tree.
///
/// Layout as compactc emits it: up to [`CHUNK_ARITY`] fields sit at the root,
/// and past that a depth-uniform chunk tree filled remainder first (16 fields
/// become [1, 15], 20 become [5, 15], 226 become [1, 15x15] one level deeper).
/// Detection walks the rightmost spine, one level to flatten per consecutive
/// arity-15 array. No ledger ADT stores an arity-15 array at field level (a
/// List is a three-slot cons node), so a field is never misread as a chunk.
///
/// `flat_index` is zero-based and is the notification's `requestsIndexField`
/// byte passed straight in. Declaration order does not map one to one onto flat
/// slots, since a multi-atom ADT can occupy several, so field positions must
/// come from the producer and never be counted off the contract source.
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

/// A record cell admitting more than one capacity split that decodes cleanly,
/// hashes to the filed id, and would assemble a different transaction.
///
/// Typed so the caller can label the drop by downcast rather than by matching
/// error text. Nothing flattens the error chain between here and
/// `resolve_verified_record`, so the downcast survives.
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

/// A record projected onto what can reach the signed transaction: every vector
/// truncated to the count that governs it, and an absent `Maybe` contributing
/// no calldata words.
///
/// Restated here rather than calling `tx.rs`, which sits a layer above. It errs
/// strict: equal projections guarantee the same transaction, unequal ones do
/// not guarantee a different one, since `selector` and `no_words` are compared
/// even when `is_some` is false. That way a spurious ambiguity drops a request
/// rather than signing the wrong bytes.
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
/// An atom count does not fix the capacities uniquely, so splits are enumerated
/// and validated by the decode itself. `expected_request_id` disambiguates but
/// does not authenticate: when no split matches, the first clean decode is
/// returned, and the caller's recompute-and-drop is the only thing between that
/// guess and a signature.
///
/// Two splits of one cell can produce byte-identical preimages, so a shared id
/// proves nothing on its own. Where the readings agree on everything reaching
/// the transaction the ambiguity is immaterial; where they disagree, picking by
/// enumeration order would sign bytes the record does not describe, so the
/// record is refused with [`AmbiguousRecord`]. Hence every split is enumerated
/// even after a match, which `MAX_RECORD_ATOMS` bounds.
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
    // Before any enumeration, and inside this function rather than at a call
    // site a later caller could bypass. Reported as a cap rejection, not a
    // malformed record: an oversized cell is an adversarial or runaway
    // producer, which wants a different operator response from codec drift.
    anyhow::ensure!(
        atoms.len() <= MAX_RECORD_ATOMS,
        "request record has {} atoms, above the {MAX_RECORD_ATOMS}-atom enumeration cap; \
         refusing to enumerate capacity splits for an adversarially large cell",
        atoms.len()
    );
    let variable = atoms.len() - REQUEST_FIXED_VALUE_ATOMS;
    // Schemas are exact-length by protocol convention, never NUL-padded and
    // never ending in a zero byte, so the last two atoms' stored lengths are
    // their declared widths.
    let len_out = atoms[atoms.len() - 2].len();
    let len_resp = atoms[atoms.len() - 1].len();

    let mut rejections: Vec<String> = Vec::new();
    // Scalars rather than a Vec of matches: a cell at the cap can match on
    // thousands of splits, and collecting them would trade the CPU bound for an
    // allocation one.
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

/// Ceiling on a record cell's atom count, and the only bound on the
/// enumeration above.
///
/// The cell comes from a caller's own contract state, so its length is
/// attacker-controlled, and enumeration is roughly O(V^2 log V) in the variable
/// atom count `V`: each of the ~V*ln(V) cleanly decoding splits pays a keccak
/// over a ~32*V byte preimage.
///
/// Set from measurement, not headroom. A cell of one-byte atoms decodes cleanly
/// at every split, the worst case, costing ~66ms at 512 atoms against ~5.6s at
/// 4096 (release). The largest real tier in the repo is 34 atoms and both
/// captured contracts carry 23, so 512 is an order of magnitude above anything
/// a contract compiles today.
const MAX_RECORD_ATOMS: usize = 512;

/// The recompute-and-drop security gate: the record filed under `request_id` in
/// the caller's request map, returned only if the id recomputed from the
/// decoded record equals the id it was filed under.
///
/// The recompute is not redundant, though it will look deletable: on the match
/// path it passes by construction, but on `decode_record`'s fallback path it is
/// the only thing between a record filed under the wrong id and a signature
/// over it. It is also stronger than a membership check, which alone admits a
/// contract that byte-copied a victim's record into its own map.
///
/// Reports nothing, and compares with plain byte equality since both operands
/// are public on-chain values.
pub fn resolve_verified_record(map: &StateNode, request_id: [u8; 32]) -> Resolved {
    let StateNode::Map { entries } = map else {
        return Resolved::Dropped {
            reason: "request-index-not-a-map",
            detail: "the caller's requests field is not a map".to_string(),
        };
    };
    // Keys are unique and re-padding is injective, so at most one entry can
    // match. An absent id is the ordinary negative, not a fault.
    let Some(entry) = entries
        .iter()
        .find(|entry| key_matches_request_id(&entry.key, &request_id))
    else {
        return Resolved::Absent;
    };
    let record = match decode_record(&entry.value, &request_id) {
        Ok(record) => record,
        // Downcast rather than error text: an ambiguous record is an
        // operator-actionable signal about one integrator's contract shape,
        // where an undecodable one is ordinary junk.
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

/// The outcome of resolving a filed request id against a caller's request index.
///
/// Three-way rather than `Option` so the reason travels through the return type
/// instead of the log. Each variant maps to one caller action, which lets
/// [`resolve_verified_record`] report nothing and the caller, which owns the
/// block height, emit one line per outcome.
///
/// `Found` is boxed because the record is ~384 bytes against ~40 for the others,
/// past clippy's `large_enum_variant` threshold.
#[derive(Debug, PartialEq)]
pub enum Resolved {
    /// The record, verified: it hashes to the id it was filed under.
    Found(Box<SignBidirectionalRecord>),
    /// The id is not in the caller's index. The ordinary negative rather than a
    /// fault: a caller that notified before its write landed, or computed the id
    /// wrong, lands here. Logged at DEBUG, neither WARN (manufacturable at will,
    /// so an adversary gets a free alarm bell) nor silent (the failure an
    /// integrator is most likely to hit and cannot otherwise diagnose).
    Absent,
    /// The entry exists and must not be signed. `reason` is the countable label,
    /// `detail` the diagnosis.
    Dropped {
        reason: &'static str,
        detail: String,
    },
}

/// One trimmed `Bytes<32>` wire atom, re-padded to its declared width, and the
/// only implementation of that rule.
///
/// Atoms arrive trailing-zero-trimmed, so a rid ending in `0x00` stores short
/// and must be re-padded before use; an untrimmed 32-byte atom re-pads to
/// itself, so both wire forms behave identically. Non-hex and overlong atoms
/// yield `None` rather than a garbage id. Re-padding is injective, which is
/// what lets callers treat a match as unique.
pub(crate) fn repad_atom_32(atom_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(atom_hex).ok()?;
    if bytes.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    Some(padded)
}

/// Exactly one trimmed `Bytes<32>` atom, re-padded and compared. The caller's
/// request map key is single-atom, so any other atom count is a typed mismatch
/// (another map's composite key, or a future schema) rather than a string that
/// silently fails to compare.
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

/// One full record decode at a fixed capacity split.
///
/// Every split consumes exactly `REQUEST_FIXED_VALUE_ATOMS + words + entries *
/// (2 + keys)` atoms by construction, and the enumeration derives those counts
/// from the cell's own atom count, so a clean decode lands on the end of the
/// cell and needs no leftover check.
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

    // The flag does not gate the atoms: selector, no_words and every word slot
    // are consumed either way. Skipping them for an empty Maybe would shift
    // every later field onto the wrong atoms.
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
    fn decode_record_reads_captured_state() {
        for json in [FIVE_FIELD_JSON, TWENTY_FIELD_JSON] {
            let fixture = load_fixture(json);
            // The index convention golden: the fixture's field position is
            // the value the contract itself passes on the wire (the
            // caller's `4 as Uint<8>` requestsIndexField, and 19 for the
            // 20-field contract), fed to signet_field_node with no
            // adjustment. An off-by-one in either direction fails to find
            // the map below, so the indexer can pass the notification byte
            // straight through.
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
    fn decode_record_round_trips_rid_vectors() {
        // Every oracle record, re-trimmed into wire atoms and decoded back.
        // Exercises the capacity enumeration across all tiers, including
        // no-calldata, where is_some is false and the calldata block still
        // occupies its atoms, and the access-list splits the id disambiguates.
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
                // Capacity-ambiguous by construction, so exact record equality
                // is the wrong assertion. Every entries=2 split spans the same
                // 202 preimage bytes with identical zero content
                // (32*(5-2k) + 2*(21+32k) = 202 for k = 0..2), hence one shared
                // id, and first match wins in the TS reader and here alike. The
                // ambiguity is immaterial: every matching split assembles the
                // same transaction, which is the only reason decode_record may
                // pick one. Semantic fields do not generally survive an
                // ambiguity, which is what
                // `decode_record_refuses_material_capacity_ambiguity` pins.
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
    fn signet_field_node_flattens_chunk_shapes() {
        // Navigation-only synthetic trees, no record bytes. Expected layouts
        // come from the TS reader's documented rule rather than from this
        // implementation: fields chunk remainder first and every chunk on the
        // rightmost spine is full. The one-level case is anchored empirically
        // by the 20-field capture in the golden test; these trees extend the
        // rule to depths the checkout cannot produce.
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
    fn decode_record_rejects_trailing_junk() {
        // A valid record plus one junk atom. Splits are derived from the total
        // atom count, so junk is never left dangling; it must be absorbed into
        // some field of some split. Here absorption fails a type check on the
        // shifted tail, which is fixture-specific: another junk shape could
        // decode cleanly. The id chain is the structural backstop for those,
        // since a clean absorption either misses the filed id and dies at the
        // downstream recompute gate or, by collision resistance, is the
        // original record.
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
    fn decode_record_names_too_few_atoms() {
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
    fn unpack_notification_v1_rejects_other_versions() {
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

    // The recompute-and-drop gate.

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
    fn resolve_verified_record_drops_spoofed_filing() {
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
    fn resolve_verified_record_reports_absent_and_dropped() {
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
    fn repad_atom_32_repads_trimmed_key() {
        // This nonce makes minimal-1word hash to an id ending in 0x00, so its
        // wire key trims to fewer than 32 bytes. Found by search once and
        // pinned; the assertion below fails loudly if it ever stops holding.
        let (mut record, _) = record_and_rid("minimal-1word");
        record.request_nonce = 272;
        let rid = compute_request_id(&record);

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

    /// An atom list where first-match-wins would sign a transaction the record
    /// does not describe.
    ///
    /// 25 atoms, three contested. Two splits decode cleanly and produce
    /// byte-identical preimages (`0x01` then 53 zeros), so they share a request
    /// id with no keccak collision involved:
    ///
    ///   A = (1 word, 1 entry, 0 keys)  reads [01] as a calldata word and
    ///       the three empty atoms as entry_count=0, address, key_count=0
    ///   B = (0 words, 1 entry, 1 key)  reads [01] as entry_count=1 and the
    ///       three empty atoms as address, key_count=0, storage_key
    ///
    /// A assembles with no access list, B with one entry, and the enumeration
    /// tries A first. The rid gate cannot catch this, since the id really is
    /// the filed one.
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
    fn decode_record_refuses_material_capacity_ambiguity() {
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
    fn decode_record_accepts_immaterial_capacity_ambiguity() {
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
    fn resolve_verified_record_rejects_composite_key() {
        // The caller's request map is keyed by ONE Bytes<32> atom. A key with
        // any other atom count belongs to a different map (the central
        // singleton's composite SignetMapKey) or to a future schema, and must
        // not resolve. Both shapes below DO resolve under a weaker reading: the
        // first under "take key_atoms[0]", the second under any implementation
        // that joins the atoms, since the sidecar's own golden shows a one-atom
        // key and a two-atom key concatenating identically.
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
    fn decode_record_type_checks_wire_atoms() {
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
    fn decode_notification_requires_two_atoms() {
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
    fn decode_record_rejects_oversized_cell() {
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
