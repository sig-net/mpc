//! Chunk-tree walk and record decode over sidecar `StateNode` trees.

use anyhow::Context as _;

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams,
    SignBidirectionalEventNotification, SignBidirectionalRecord,
};
use crate::request_id::compute_request_id;
use crate::sidecar::{AlignmentAtom, AlignmentSegment, StateNode};

/// compactc chunk arity: past this many ledger fields the compiler stores fields in a
/// depth-uniform tree of arity-15 chunks, filled remainder FIRST, so every chunk on the
/// rightmost spine is full.
const CHUNK_ARITY: usize = 15;

/// Atoms of a record excluding its capacity-scaled vectors. The calldata `Maybe`'s
/// three atoms count even when `is_some` is false.
pub const REQUEST_FIXED_VALUE_ATOMS: usize = 22;

/// `sender` through `calldata.no_words`; the calldata words begin here.
const RECORD_HEAD_ATOMS: usize = 18;

/// `caip2_id` and the two schemas.
const RECORD_TAIL_ATOMS: usize = 3;

/// Resolve a flat ledger field index to its node in the raw state tree.
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

/// A cell's atoms beside each one's declared width. Signet declares only `Bytes` atoms,
/// so a widthless or nested segment is refused rather than assigned a width.
fn cell_parts(cell: &StateNode, what: &str) -> anyhow::Result<(Vec<Vec<u8>>, Vec<u32>)> {
    let StateNode::Cell { atoms, alignment } = cell else {
        anyhow::bail!("{what} node is not a cell");
    };
    anyhow::ensure!(
        alignment.len() == atoms.len(),
        "{what} cell declares {} alignment segments for {} atoms",
        alignment.len(),
        atoms.len()
    );
    let decoded = atoms
        .iter()
        .enumerate()
        .map(|(index, atom)| {
            hex::decode(atom).with_context(|| format!("{what} atom {index} is not hex"))
        })
        .collect::<anyhow::Result<Vec<Vec<u8>>>>()?;
    let widths = alignment
        .iter()
        .enumerate()
        .map(|(index, segment)| match segment {
            AlignmentSegment::Atom {
                value: AlignmentAtom::Bytes { length },
            } => Ok(*length),
            AlignmentSegment::Atom { value } => anyhow::bail!(
                "{what} atom {index} is aligned {value:?}, which carries no byte width"
            ),
            AlignmentSegment::Option { .. } => anyhow::bail!(
                "{what} atom {index} is an alignment option, which no signet type declares"
            ),
        })
        .collect::<anyhow::Result<Vec<u32>>>()?;
    Ok((decoded, widths))
}

struct Capacities {
    words: usize,
    entries: usize,
    keys: usize,
}

/// Each scaled vector's capacity, read off the declared widths. The tail is taken from
/// the end because `caip2_id` and a storage key are both `Bytes<32>`.
fn capacities(widths: &[u32], atom_count: usize) -> anyhow::Result<Capacities> {
    anyhow::ensure!(
        atom_count >= REQUEST_FIXED_VALUE_ATOMS,
        "request record has {atom_count} value atoms, fewer than the \
         {REQUEST_FIXED_VALUE_ATOMS} its fixed fields need"
    );
    let tail = atom_count - RECORD_TAIL_ATOMS;

    let mut index = RECORD_HEAD_ATOMS;
    while index < tail && widths[index] == 32 {
        index += 1;
    }
    let words = index - RECORD_HEAD_ATOMS;

    anyhow::ensure!(
        index < tail && widths[index] == 1,
        "expected the Bytes<1> access-list entry count after {words} calldata words, found {}",
        widths
            .get(index)
            .map_or("the record's tail".to_string(), |width| format!(
                "Bytes<{width}>"
            ))
    );
    index += 1;

    let region = &widths[index..tail];
    let entries = region.iter().filter(|width| **width == 20).count();
    let keys = if entries == 0 {
        anyhow::ensure!(
            region.is_empty(),
            "the access-list region holds {} atoms but declares no Bytes<20> entry address",
            region.len()
        );
        0
    } else {
        anyhow::ensure!(
            region.len().is_multiple_of(entries),
            "the access-list region's {} atoms do not divide evenly across {entries} entries",
            region.len()
        );
        let per_entry = region.len() / entries;
        anyhow::ensure!(
            per_entry >= 2,
            "each access-list entry needs at least an address and a key count, got {per_entry} atoms"
        );
        per_entry - 2
    };
    Ok(Capacities {
        words,
        entries,
        keys,
    })
}

/// Decode a stored request record in one pass, refusing a cell whose declared widths
/// are not a signet record's.
pub fn decode_record(cell: &StateNode) -> anyhow::Result<SignBidirectionalRecord> {
    let (atoms, widths) = cell_parts(cell, "request record")?;
    let capacities = capacities(&widths, atoms.len())?;
    decode_at(&atoms, &widths, &capacities)
}

/// The recompute-and-drop gate. The decode never sees `request_id`, so this comparison
/// is the only thing binding a record's contents to the key it was filed under.
pub fn resolve_verified_record(map: &StateNode, request_id: [u8; 32]) -> Resolved {
    let StateNode::Map { entries } = map else {
        return Resolved::Dropped {
            reason: "request-index-not-a-map",
            detail: "the caller's requests field is not a map".to_string(),
        };
    };
    // Keys are unique and re-padding is injective, so at most one entry can match.
    let Some(entry) = entries
        .iter()
        .find(|entry| key_matches_request_id(&entry.key, &request_id))
    else {
        return Resolved::Absent;
    };
    let record = match decode_record(&entry.value) {
        Ok(record) => record,
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
#[derive(Debug, PartialEq)]
pub enum Resolved {
    /// The record, verified: it hashes to the id it was filed under.
    Found(Box<SignBidirectionalRecord>),
    /// The id is not in the caller's index.
    Absent,
    /// The entry exists and must not be signed.
    Dropped {
        reason: &'static str,
        detail: String,
    },
}

/// One trimmed `Bytes<32>` wire atom, re-padded to its declared width, and the only
/// implementation of that rule.
pub(crate) fn repad_atom_32(atom_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(atom_hex).ok()?;
    if bytes.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    Some(padded)
}

/// Exactly one trimmed `Bytes<32>` atom, re-padded and compared.
fn key_matches_request_id(key_atoms: &[String], request_id: &[u8; 32]) -> bool {
    let [atom] = key_atoms else {
        return false;
    };
    repad_atom_32(atom) == Some(*request_id)
}

/// Decode the two-atom notification cell: version, then the 128-byte payload.
pub fn decode_notification(cell: &StateNode) -> anyhow::Result<SignBidirectionalEventNotification> {
    let (atoms, widths) = cell_parts(cell, "notification")?;
    anyhow::ensure!(
        atoms.len() == 2,
        "notification cell has {} atoms, expected 2 (version, payload)",
        atoms.len()
    );
    let cursor = &mut AtomCursor {
        atoms: &atoms,
        widths: &widths,
        pos: 0,
    };
    Ok(SignBidirectionalEventNotification {
        version: uint(cursor, 1, u128::from(u8::MAX), "notification version")? as u8,
        payload: bytes_n::<128>(cursor, "notification payload")?,
    })
}

/// The V1 notification payload, unpacked per its fixed offsets: `caller_address(32) ||
/// requests_index_field(1) || zeros(95)`.
#[derive(Debug, Clone, PartialEq)]
pub struct NotificationV1 {
    pub caller_address: [u8; 32],
    /// The ledger field position of the caller's request index: a per-integrator value
    /// the notification carries, never assumed.
    pub requests_index_field: u8,
}

/// Fails closed on an unrecognised version: a future payload layout adds a branch here
/// rather than silently misinterpreting bytes under the V1 offsets.
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
    widths: &'a [u32],
    pos: usize,
}

impl<'a> AtomCursor<'a> {
    /// Consume one atom, asserting the width the ledger declared for it. That assertion
    /// is the type check: stored bytes that merely fit prove nothing.
    fn shift(&mut self, declared: u32, what: &'static str) -> anyhow::Result<&'a [u8]> {
        let atom = self
            .atoms
            .get(self.pos)
            .ok_or_else(|| anyhow::anyhow!("atom {} missing: expected {what}", self.pos))?;
        let found = self.widths[self.pos];
        anyhow::ensure!(
            found == declared,
            "{what}: atom {} is declared Bytes<{found}>, expected Bytes<{declared}>",
            self.pos
        );
        anyhow::ensure!(
            atom.len() <= declared as usize,
            "{what}: atom {} stores {} bytes under a declared Bytes<{declared}>",
            self.pos,
            atom.len()
        );
        self.pos += 1;
        Ok(atom)
    }

    fn peek_width(&self) -> anyhow::Result<u32> {
        self.widths
            .get(self.pos)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("atom {} missing: the record ends early", self.pos))
    }
}

/// `Bytes<N>`, re-padded from its trailing-zero-trimmed stored form.
fn bytes_n<const N: usize>(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<[u8; N]> {
    let atom = cursor.shift(N as u32, what)?;
    let mut out = [0u8; N];
    out[..atom.len()].copy_from_slice(atom);
    Ok(out)
}

/// `Bytes<Len>` at the per-integrator width the alignment declares.
fn bytes_dyn(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<Vec<u8>> {
    let declared = cursor.peek_width()? as usize;
    let atom = cursor.shift(declared as u32, what)?;
    let mut out = atom.to_vec();
    out.resize(declared, 0);
    Ok(out)
}

/// `Uint` and enum atoms, folded little-endian and range-checked as the runtime
/// descriptors do.
fn uint(
    cursor: &mut AtomCursor,
    declared: u32,
    max: u128,
    what: &'static str,
) -> anyhow::Result<u128> {
    let atom = cursor.shift(declared, what)?;
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

/// `Boolean`: the empty atom is false, `[1]` is true.
fn boolean(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<bool> {
    let atom = cursor.shift(1, what)?;
    anyhow::ensure!(atom.is_empty() || atom == [1], "{what}: not a Boolean atom");
    Ok(!atom.is_empty())
}

fn decode_at(
    atoms: &[Vec<u8>],
    widths: &[u32],
    capacities: &Capacities,
) -> anyhow::Result<SignBidirectionalRecord> {
    let cursor = &mut AtomCursor {
        atoms,
        widths,
        pos: 0,
    };
    let record = SignBidirectionalRecord {
        sender: bytes_n::<32>(cursor, "sender")?,
        request_nonce: uint(cursor, 8, u128::from(u64::MAX), "request_nonce")? as u64,
        key_version: uint(cursor, 1, u128::from(u8::MAX), "key_version")? as u8,
        path: bytes_n::<32>(cursor, "path")?,
        algo: uint(cursor, 1, 1, "algo")? as u8,
        dest: uint(cursor, 1, 1, "dest")? as u8,
        params: bytes_n::<64>(cursor, "params")?,
        tx_param_type: uint(cursor, 1, 1, "tx_param_type")? as u8,
        tx_params: decode_tx_params(cursor, capacities)?,
        caip2_id: bytes_n::<32>(cursor, "caip2_id")?,
        output_deserialization_schema: bytes_dyn(cursor, "output_deserialization_schema")?,
        respond_serialization_schema: bytes_dyn(cursor, "respond_serialization_schema")?,
    };
    // A leftover atom means the capacities and this pass disagree.
    anyhow::ensure!(
        cursor.pos == atoms.len(),
        "request record decoded {} of {} atoms",
        cursor.pos,
        atoms.len()
    );
    Ok(record)
}

fn decode_tx_params(
    cursor: &mut AtomCursor,
    &Capacities {
        words,
        entries,
        keys,
    }: &Capacities,
) -> anyhow::Result<EvmType2TxParams> {
    let chain_id = uint(cursor, 8, u128::from(u64::MAX), "chain_id")? as u64;
    let nonce = uint(cursor, 8, u128::from(u64::MAX), "nonce")? as u64;
    let max_priority_fee_per_gas = uint(cursor, 16, u128::MAX, "max_priority_fee_per_gas")?;
    let max_fee_per_gas = uint(cursor, 16, u128::MAX, "max_fee_per_gas")?;
    let gas_limit = uint(cursor, 8, u128::from(u64::MAX), "gas_limit")? as u64;
    let to = bytes_n::<20>(cursor, "to")?;
    let value = uint(cursor, 16, u128::MAX, "value")?;

    // The flag does not gate the atoms: selector, no_words and every word slot are
    // consumed either way.
    let is_some = boolean(cursor, "calldata.is_some")?;
    let selector = bytes_n::<4>(cursor, "calldata.selector")?;
    let no_words = uint(cursor, 2, u128::from(u16::MAX), "calldata.no_words")? as u16;
    let mut word_slots = Vec::with_capacity(words);
    for _ in 0..words {
        word_slots.push(bytes_n::<32>(cursor, "calldata word")?);
    }

    let access_list_entry_count =
        uint(cursor, 1, u128::from(u8::MAX), "access_list_entry_count")? as u8;
    let mut access_list = Vec::with_capacity(entries);
    for _ in 0..entries {
        let address = bytes_n::<20>(cursor, "access list address")?;
        let storage_key_count = uint(cursor, 1, u128::from(u8::MAX), "storage_key_count")? as u8;
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
    use crate::test_utils::{
        alignment_of, atoms_from_record, cell_from_record, cell_of, minimal_record, sample_record,
        sample_record_with_partial_access_list, sample_record_with_unused_access_list,
        widths_from_record,
    };
    fn leaf(marker: u8) -> StateNode {
        cell_of(&[vec![marker]], &[1])
    }

    fn marker_of(node: &StateNode) -> u8 {
        let StateNode::Cell { atoms, .. } = node else {
            panic!("expected a leaf cell, got a non-cell node")
        };
        hex::decode(&atoms[0]).expect("marker hex")[0]
    }

    #[test]
    fn signet_field_node_flattens_chunk_shapes() {
        // Navigation-only synthetic trees, no record bytes.
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

        // 20 fields chunk to [5, 15]; 27 chunks to [12, 15].
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

        // Two chunk levels: a full arity-15 spine of full arity-15 chunks, the
        // 226-field shape one level deeper.
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
    fn unpack_notification_v1_rejects_other_versions() {
        let mut payload = [0u8; 128];
        payload[..32].copy_from_slice(&[0xab; 32]);
        payload[32] = 4;

        let cell = cell_of(&[vec![1u8], payload.to_vec()], &[1, 128]);
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

        // Fail closed on an unrecognised version rather than reinterpreting the payload
        // under V1 offsets.
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

    /// A record and the id it files itself under.
    fn record_and_rid() -> (SignBidirectionalRecord, [u8; 32]) {
        let record = sample_record();
        let rid = crate::request_id::compute_request_id(&record);
        (record, rid)
    }

    /// A map whose keys are SINGLE atoms (the caller-map shape).
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
        let (record, rid) = record_and_rid();
        let cell = cell_from_record(&record);

        // Genuine filing: the id it is stored under is the id it hashes to.
        let map = map_of(vec![(hex::encode(rid), cell.clone())]);
        assert_eq!(
            resolve_verified_record(&map, rid),
            Resolved::Found(Box::new(record))
        );

        // Spoofed filing: the same record bytes stored under an id they do NOT hash to.
        let spoofed = [0x99; 32];
        assert!(
            decode_record(&cell).is_ok(),
            "the decode never sees the id, so only the gate can drop this"
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
            "the gate must drop it under its own reason"
        );
    }

    #[test]
    fn resolve_verified_record_reports_absent_and_dropped() {
        let (record, rid) = record_and_rid();
        let poisoned_rid = [0x55; 32];
        let map = map_of(vec![
            (
                hex::encode(poisoned_rid),
                cell_of(&[vec![1], vec![2], vec![3]], &[1, 1, 1]),
            ),
            (hex::encode(rid), cell_from_record(&record)),
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
        // An id absent from the index is the ordinary negative, and it is a DISTINCT
        // outcome from a drop: the caller reports it at DEBUG, so collapsing the two
        // back into one would either silence real drops or hand an adversary a WARN it
        // can manufacture at will.
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
        // Search for a nonce whose id ends in 0x00, so its wire key trims short.
        let (mut record, _) = record_and_rid();
        let rid = (0u64..)
            .find_map(|nonce| {
                record.request_nonce = nonce;
                let rid = compute_request_id(&record);
                (rid[31] == 0).then_some(rid)
            })
            .expect("some nonce hashes to an id ending in 0x00");

        let mut trimmed = rid.to_vec();
        while trimmed.last() == Some(&0) {
            trimmed.pop();
        }
        assert!(trimmed.len() < 32, "the key must actually be trimmed");

        let map = map_of(vec![(hex::encode(&trimmed), cell_from_record(&record))]);
        assert_eq!(
            resolve_verified_record(&map, rid),
            Resolved::Found(Box::new(record))
        );
    }

    #[test]
    fn resolve_verified_record_rejects_composite_key() {
        // The caller's request map is keyed by ONE Bytes<32> atom.
        let (record, rid) = record_and_rid();
        let cell = cell_from_record(&record);

        // Absent rather than Dropped: an unmatched key means the id is not in this
        // index at all, which is the ordinary negative.
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
        // Every atom here originates in a CALLER's own contract state, so a decode that
        // coerces instead of rejecting lets the caller choose which record the MPC
        // reconstructs.
        let record = sample_record();
        let atoms = atoms_from_record(&record);
        let widths = widths_from_record(&record);

        // A Compact Boolean is the EMPTY atom or [1]; [2] is not "true".
        let mut not_boolean = atoms.clone();
        not_boolean[15] = vec![2];
        let err = decode_record(&cell_of(&not_boolean, &widths))
            .expect_err("a non-Boolean calldata.is_some atom must reject")
            .to_string();
        assert!(err.contains("Boolean"), "err: {err}");

        // An atom storing more than its declared width is a typed mismatch, never a
        // truncation: silently dropping the tail would change the record while leaving
        // the decode looking clean.
        let mut over_wide = atoms.clone();
        over_wide[0] = vec![0xab; 33];
        let err = decode_record(&cell_of(&over_wide, &widths))
            .expect_err("a 33-byte sender atom must reject")
            .to_string();
        assert!(err.contains("stores 33 bytes"), "err: {err}");
    }

    #[test]
    fn decode_record_reads_capacities_from_declared_widths() {
        // Counts below capacity throughout, so a decode inferring the split from
        // anything but the widths would misread it.
        for record in [
            minimal_record(),
            sample_record(),
            sample_record_with_unused_access_list(),
            sample_record_with_partial_access_list(),
        ] {
            let decoded = decode_record(&cell_from_record(&record))
                .unwrap_or_else(|err| panic!("the record must decode: {err:#}"));
            assert_eq!(decoded, record, "the decode must round-trip the record");
        }

        let minimal = cell_from_record(&minimal_record());
        let StateNode::Cell { atoms, .. } = &minimal else {
            panic!("cell_from_record must build a cell")
        };
        assert_eq!(atoms.len(), REQUEST_FIXED_VALUE_ATOMS);

        // One atom below the boundary is refused rather than underflowing the tail.
        let err = decode_record(&cell_of(&vec![vec![0xab]; 21], &[1u32; 21]))
            .expect_err("21 atoms cannot hold the fixed fields")
            .to_string();
        assert!(err.contains("21") && err.contains("22"), "err: {err}");
    }

    #[test]
    fn decode_record_rejects_a_malformed_access_list_region() {
        // A region whose arithmetic works out but whose layout is wrong must still die
        // in the per-atom pass rather than decode into some other record.
        let record = sample_record_with_partial_access_list();
        let atoms = atoms_from_record(&record);
        let mut widths = widths_from_record(&record);
        // The SECOND Bytes<20>: the first is `to` in the fixed head. Swapping an
        // entry's address with its key count leaves the capacity arithmetic unchanged.
        let first_entry = widths
            .iter()
            .enumerate()
            .filter(|(_, width)| **width == 20)
            .map(|(index, _)| index)
            .nth(1)
            .expect("the partial-access-list record has an entry address after `to`");
        widths.swap(first_entry, first_entry + 1);
        let err = decode_record(&cell_of(&atoms, &widths))
            .expect_err("a permuted access-list entry must not decode")
            .to_string();
        assert!(
            err.contains("access list address"),
            "the refusal must name the field it failed on: {err}"
        );
    }

    #[test]
    fn decode_record_rejects_a_width_the_layout_does_not_declare() {
        // A sender stored in 20 bytes fits a Bytes<20> perfectly well, so only the
        // alignment catches this.
        let record = sample_record();
        let atoms = atoms_from_record(&record);
        let mut widths = widths_from_record(&record);
        widths[0] = 20;
        let err = decode_record(&cell_of(&atoms, &widths))
            .expect_err("a sender declared Bytes<20> is not a signet record")
            .to_string();
        assert!(
            err.contains("Bytes<20>") && err.contains("Bytes<32>"),
            "the error must name both widths: {err}"
        );
    }

    #[test]
    fn decode_record_rejects_an_alignment_that_does_not_cover_the_atoms() {
        let record = sample_record();
        let atoms = atoms_from_record(&record);
        let mut widths = widths_from_record(&record);
        widths.pop();
        let err = decode_record(&cell_of(&atoms, &widths))
            .expect_err("one segment per atom, or the pairing is a guess")
            .to_string();
        assert!(err.contains("alignment segments"), "err: {err}");
    }

    #[test]
    fn decode_record_rejects_widthless_alignment_atoms() {
        // Assert the REASON, not merely that it failed: an implementation that invented
        // a width for these would also fail, just with a width mismatch further down.
        let record = sample_record();
        let atoms = atoms_from_record(&record);
        let widths = widths_from_record(&record);
        for (name, segment, expected) in [
            (
                "compress",
                AlignmentSegment::Atom {
                    value: AlignmentAtom::Compress,
                },
                "carries no byte width",
            ),
            (
                "field",
                AlignmentSegment::Atom {
                    value: AlignmentAtom::Field,
                },
                "carries no byte width",
            ),
            (
                "option",
                AlignmentSegment::Option {
                    value: vec![alignment_of(&[32])],
                },
                "alignment option",
            ),
        ] {
            let mut alignment = alignment_of(&widths);
            alignment[0] = segment;
            let cell = StateNode::Cell {
                atoms: atoms.iter().map(hex::encode).collect(),
                alignment,
            };
            let err = decode_record(&cell).unwrap_err().to_string();
            assert!(
                err.contains("atom 0") && err.contains(expected),
                "the {name} segment must be refused as a widthless alignment, got: {err}"
            );
        }
    }

    #[test]
    fn decode_notification_rejects_any_other_shape() {
        // Bytes<1> then Bytes<128>, and nothing else. A payload declared narrower is a
        // different type, and its trimmed bytes cannot say so.
        let mut payload = [0u8; 128];
        payload[..32].copy_from_slice(&[0xab; 32]);
        for (atoms, widths, expected) in [
            (vec![vec![1u8]], vec![1u32], "expected 2"),
            (
                vec![vec![1u8], payload.to_vec(), vec![0u8]],
                vec![1, 128, 1],
                "expected 2",
            ),
            (vec![vec![1u8], payload.to_vec()], vec![1, 64], "Bytes<128>"),
        ] {
            let err = decode_notification(&cell_of(&atoms, &widths))
                .expect_err("only a two-atom Bytes<1>/Bytes<128> cell decodes")
                .to_string();
            assert!(err.contains(expected), "err: {err}");
        }
    }
}
