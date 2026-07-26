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
/// On the match path itself, collision resistance means at most one split
/// can hash to a given id, so a match is deterministic rather than merely
/// first-come.
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
    let variable = atoms.len() - REQUEST_FIXED_VALUE_ATOMS;
    // Schema widths are read from the LAST TWO atoms' actual lengths:
    // schemas are exact-length by protocol convention (never NUL-padded,
    // never ending in a zero byte), so stored length equals declared width.
    let len_out = atoms[atoms.len() - 2].len();
    let len_resp = atoms[atoms.len() - 1].len();

    let mut rejections: Vec<String> = Vec::new();
    let mut attempt = |words: usize, entries: usize, keys: usize| match decode_at(
        &atoms, words, entries, keys, len_out, len_resp,
    ) {
        Ok(record) => Some(record),
        Err(err) => {
            if rejections.len() < MAX_REPORTED_REJECTIONS {
                rejections.push(format!(
                    "({words} words, {entries} entries, {keys} keys): {err:#}"
                ));
            }
            None
        }
    };
    let mut fallback: Option<SignBidirectionalRecord> = None;
    let mut consider = |record: SignBidirectionalRecord| {
        if compute_request_id(&record) == *expected_request_id {
            return Some(record);
        }
        if fallback.is_none() {
            fallback = Some(record);
        }
        None
    };

    // No access list: the variable atoms are calldata words alone.
    if let Some(record) = attempt(variable, 0, 0) {
        if let Some(hit) = consider(record) {
            return Ok(hit);
        }
    }
    // With an access list: E entries of (2 + K) atoms each, the rest words.
    let mut entries = 1;
    while entries * 2 <= variable {
        let mut keys = 0;
        while entries * (2 + keys) <= variable {
            let words = variable - entries * (2 + keys);
            if let Some(record) = attempt(words, entries, keys) {
                if let Some(hit) = consider(record) {
                    return Ok(hit);
                }
            }
            keys += 1;
        }
        entries += 1;
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

    fn leftover(&self) -> usize {
        self.atoms.len() - self.pos
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

/// One full record decode at a fixed capacity split. Every enumerated
/// split consumes exactly `REQUEST_FIXED_VALUE_ATOMS + words + entries *
/// (2 + keys)` atoms by construction, so the leftover check at the end is
/// a defensive invariant (ported from the TS reader) rather than a
/// reachable rejection under this enumeration.
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
    anyhow::ensure!(
        cursor.leftover() == 0,
        "{} atoms left over after a clean field decode",
        cursor.leftover()
    );
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
    use crate::test_fixtures::RecordFixture;
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

    /// Wire-form atoms of a record: each field trimmed exactly as the state
    /// layer stores it (trailing zeros dropped; a false Boolean is the
    /// EMPTY atom, a true one is [1]; integers are little-endian trimmed).
    /// Used to turn A4's oracle-produced records into decode INPUTS whose
    /// expected outputs and ids come from the same oracle fixture; only
    /// this trimming transform is local, and it is the documented wire
    /// rule, not a golden.
    fn atoms_from_record(record: &SignBidirectionalRecord) -> Vec<Vec<u8>> {
        fn trim(bytes: &[u8]) -> Vec<u8> {
            let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
            bytes[..end].to_vec()
        }
        let tx = &record.tx_params;
        let mut atoms: Vec<Vec<u8>> = vec![
            trim(&record.sender),
            trim(&record.request_nonce.to_le_bytes()),
            trim(&[record.key_version]),
            trim(&record.path),
            trim(&[record.algo]),
            trim(&[record.dest]),
            trim(&record.params),
            trim(&[record.tx_param_type]),
            trim(&tx.chain_id.to_le_bytes()),
            trim(&tx.nonce.to_le_bytes()),
            trim(&tx.max_priority_fee_per_gas.to_le_bytes()),
            trim(&tx.max_fee_per_gas.to_le_bytes()),
            trim(&tx.gas_limit.to_le_bytes()),
            trim(&tx.to),
            trim(&tx.value.to_le_bytes()),
            if tx.calldata.is_some {
                vec![1]
            } else {
                Vec::new()
            },
            trim(&tx.calldata.value.selector),
            trim(&tx.calldata.value.no_words.to_le_bytes()),
        ];
        for word in &tx.calldata.value.words {
            atoms.push(trim(word));
        }
        atoms.push(trim(&[tx.access_list_entry_count]));
        for entry in &tx.access_list {
            atoms.push(trim(&entry.address));
            atoms.push(trim(&[entry.storage_key_count]));
            for key in &entry.storage_keys {
                atoms.push(trim(key));
            }
        }
        atoms.push(trim(&record.caip2_id));
        // Schemas are exact-length by protocol convention, never ending in a
        // zero byte, so stored length equals declared length.
        atoms.push(record.output_deserialization_schema.clone());
        atoms.push(record.respond_serialization_schema.clone());
        atoms
    }

    fn cell_of(atoms: &[Vec<u8>]) -> StateNode {
        StateNode::Cell {
            atoms: atoms.iter().map(hex::encode).collect(),
        }
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
                .find(|entry| entry.key == fixture.request_id_hex)
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
                // The semantic fields all survive; only the zero-filled
                // capacity SHAPE is canonicalised.
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
        // A cell whose first 23 atoms are a valid record plus one junk atom
        // no split can absorb: every split must be REJECTED, including the
        // one that decodes the valid prefix and leaves the junk over. If
        // the leftover check were dropped, that split would decode the
        // original record, its recomputed id would MATCH, and the junk
        // would be silently accepted.
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

    #[test]
    fn d8_an_empty_maybe_still_occupies_its_atoms() {
        // The no-calldata tier from A4's oracle set: is_some is false, the
        // calldata block still holds selector, no_words, and a full word
        // slot of atoms. A decoder that skips those atoms for an empty
        // Maybe mis-splits every plain-transfer record.
        let file: RidVectorFile =
            serde_json::from_str(RID_VECTORS_JSON).expect("rid_vectors.json parses");
        let vector = file
            .vectors
            .iter()
            .find(|v| v.name == "no-calldata")
            .expect("no-calldata vector present");
        assert!(!vector.record.0.tx_params.calldata.is_some);
        let atoms = atoms_from_record(&vector.record.0);
        let decoded = decode_record(
            &cell_of(&atoms),
            &rid_bytes(&vector.expected_request_id_hex),
        )
        .expect("no-calldata decodes");
        assert_eq!(decoded, vector.record.0);
        assert_eq!(decoded.tx_params.calldata.value.words.len(), 1);
    }
}
