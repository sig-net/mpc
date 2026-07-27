//! Chunk-tree walk and record decode over the ledger's own `StateValue`.

use midnight_base_crypto::fab::{AlignedValue, AlignmentAtom, AlignmentSegment, ValueAtom};
use midnight_onchain_state::state::StateValue;
use midnight_storage::DefaultDB;

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams,
    SignBidirectionalEventNotification, SignBidirectionalRecord,
};
use crate::request_id::compute_request_id;

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

pub type Node = StateValue<DefaultDB>;

/// Resolve a flat ledger field index to its node in the state tree.
pub fn signet_field_node(root: &Node, flat_index: usize) -> anyhow::Result<&Node> {
    let StateValue::Array(children) = root else {
        if flat_index == 0 {
            return Ok(root);
        }
        anyhow::bail!("field index {flat_index} out of range: root is a leaf");
    };

    let mut chunk_levels = 0usize;
    let mut spine = children.iter_deref().last();
    while let Some(StateValue::Array(kids)) = spine {
        if kids.len() != CHUNK_ARITY {
            break;
        }
        chunk_levels += 1;
        spine = kids.iter_deref().last();
    }

    let mut fields: Vec<&Node> = children.iter_deref().collect();
    for _ in 0..chunk_levels {
        fields = fields
            .iter()
            .flat_map(|chunk| match chunk {
                StateValue::Array(children) => children.iter_deref().collect::<Vec<_>>(),
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

/// The declared width of each atom. Signet declares only `Bytes` atoms, so a widthless
/// or nested segment is refused rather than assigned a width.
fn declared_widths(cell: &AlignedValue, what: &str) -> anyhow::Result<Vec<u32>> {
    anyhow::ensure!(
        cell.alignment.0.len() == cell.value.0.len(),
        "{what} declares {} alignment segments for {} atoms",
        cell.alignment.0.len(),
        cell.value.0.len()
    );
    cell.alignment
        .0
        .iter()
        .enumerate()
        .map(|(index, segment)| match segment {
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length }) => Ok(*length),
            AlignmentSegment::Atom(atom) => anyhow::bail!(
                "{what} atom {index} is aligned {atom:?}, which carries no byte width"
            ),
            AlignmentSegment::Option(_) => anyhow::bail!(
                "{what} atom {index} is an alignment option, which no signet type declares"
            ),
        })
        .collect()
}

fn cell_of<'a>(node: &'a Node, what: &str) -> anyhow::Result<&'a AlignedValue> {
    let StateValue::Cell(cell) = node else {
        anyhow::bail!("{what} node is not a cell");
    };
    Ok(cell)
}

struct Capacities {
    words: usize,
    entries: usize,
    keys: usize,
}

/// Each scaled vector's capacity, read off the declared widths. The tail is taken from
/// the end because `caip2_id` and a storage key are both `Bytes<32>`.
fn capacities(widths: &[u32]) -> anyhow::Result<Capacities> {
    anyhow::ensure!(
        widths.len() >= REQUEST_FIXED_VALUE_ATOMS,
        "request record has {} value atoms, fewer than the {REQUEST_FIXED_VALUE_ATOMS} its \
         fixed fields need",
        widths.len()
    );
    let tail = widths.len() - RECORD_TAIL_ATOMS;

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
            .map_or("the record's tail".to_string(), |w| format!("Bytes<{w}>"))
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
pub fn decode_record(node: &Node) -> anyhow::Result<SignBidirectionalRecord> {
    let cell = cell_of(node, "request record")?;
    let widths = declared_widths(cell, "request record")?;
    decode_at(cell, &widths, &capacities(&widths)?)
}

/// The recompute-and-drop gate. The decode never sees `request_id`, so this comparison
/// is the only thing binding a record's contents to the key it was filed under.
pub fn resolve_verified_record(map: &Node, request_id: [u8; 32]) -> Resolved {
    let StateValue::Map(entries) = map else {
        return Resolved::Dropped {
            reason: "request-index-not-a-map",
            detail: "the caller's requests field is not a map".to_string(),
        };
    };
    // The ledger's own keyed lookup on the ledger's own key type: no scan, and no
    // re-padding of a trimmed wire key.
    let Some(entry) = entries.get(&AlignedValue::from(request_id)) else {
        return Resolved::Absent;
    };
    let record = match decode_record(&entry) {
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

/// Decode the two-atom notification cell: version, then the 128-byte payload.
pub fn decode_notification(node: &Node) -> anyhow::Result<SignBidirectionalEventNotification> {
    let cell = cell_of(node, "notification")?;
    let widths = declared_widths(cell, "notification")?;
    anyhow::ensure!(
        widths.len() == 2,
        "notification cell has {} atoms, expected 2 (version, payload)",
        widths.len()
    );
    let cursor = &mut AtomCursor {
        atoms: &cell.value.0,
        widths: &widths,
        pos: 0,
    };
    Ok(SignBidirectionalEventNotification {
        version: uint::<u8>(cursor, 1, "notification version")?,
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

struct AtomCursor<'a> {
    atoms: &'a [ValueAtom],
    widths: &'a [u32],
    pos: usize,
}

impl<'a> AtomCursor<'a> {
    /// Consume one atom, asserting the width the ledger declared for it. That assertion
    /// is the type check: stored bytes that merely fit prove nothing.
    fn shift(&mut self, declared: u32, what: &'static str) -> anyhow::Result<&'a ValueAtom> {
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

/// `Bytes<N>`, re-padded from its trimmed stored form by the ledger's own conversion.
fn bytes_n<const N: usize>(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<[u8; N]> {
    let atom = cursor.shift(N as u32, what)?;
    <[u8; N]>::try_from(atom.clone()).map_err(|err| anyhow::anyhow!("{what}: {err}"))
}

/// `Bytes<Len>` at the per-integrator width the alignment declares.
fn bytes_dyn(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<Vec<u8>> {
    let declared = cursor.peek_width()? as usize;
    let atom = cursor.shift(declared as u32, what)?;
    anyhow::ensure!(
        atom.0.len() <= declared,
        "{what}: atom stores {} bytes under a declared Bytes<{declared}>",
        atom.0.len()
    );
    let mut out = atom.0.clone();
    out.resize(declared, 0);
    Ok(out)
}

/// `Uint` and enum atoms, decoded by the ledger's own little-endian conversion.
fn uint<T>(cursor: &mut AtomCursor, declared: u32, what: &'static str) -> anyhow::Result<T>
where
    for<'a> T: TryFrom<&'a ValueAtom>,
    for<'a> <T as TryFrom<&'a ValueAtom>>::Error: std::fmt::Display,
{
    let atom = cursor.shift(declared, what)?;
    T::try_from(atom).map_err(|err| anyhow::anyhow!("{what}: {err}"))
}

/// `Boolean`: the empty atom is false, `[1]` is true.
fn boolean(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<bool> {
    let atom = cursor.shift(1, what)?;
    bool::try_from(atom).map_err(|err| anyhow::anyhow!("{what}: {err}"))
}

/// A two-variant Compact enum: one declared byte, and only 0 or 1 is in range.
fn bounded_enum(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<u8> {
    let value = uint::<u8>(cursor, 1, what)?;
    anyhow::ensure!(value <= 1, "{what}: {value} exceeds the maximum 1");
    Ok(value)
}

fn decode_at(
    cell: &AlignedValue,
    widths: &[u32],
    capacities: &Capacities,
) -> anyhow::Result<SignBidirectionalRecord> {
    let cursor = &mut AtomCursor {
        atoms: &cell.value.0,
        widths,
        pos: 0,
    };
    let record = SignBidirectionalRecord {
        sender: bytes_n::<32>(cursor, "sender")?,
        request_nonce: uint::<u64>(cursor, 8, "request_nonce")?,
        key_version: uint::<u8>(cursor, 1, "key_version")?,
        path: bytes_n::<32>(cursor, "path")?,
        algo: bounded_enum(cursor, "algo")?,
        dest: bounded_enum(cursor, "dest")?,
        params: bytes_n::<64>(cursor, "params")?,
        tx_param_type: bounded_enum(cursor, "tx_param_type")?,
        tx_params: decode_tx_params(cursor, capacities)?,
        caip2_id: bytes_n::<32>(cursor, "caip2_id")?,
        output_deserialization_schema: bytes_dyn(cursor, "output_deserialization_schema")?,
        respond_serialization_schema: bytes_dyn(cursor, "respond_serialization_schema")?,
    };
    // A leftover atom means the capacities and this pass disagree.
    anyhow::ensure!(
        cursor.pos == cell.value.0.len(),
        "request record decoded {} of {} atoms",
        cursor.pos,
        cell.value.0.len()
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
    let chain_id = uint::<u64>(cursor, 8, "chain_id")?;
    let nonce = uint::<u64>(cursor, 8, "nonce")?;
    let max_priority_fee_per_gas = uint::<u128>(cursor, 16, "max_priority_fee_per_gas")?;
    let max_fee_per_gas = uint::<u128>(cursor, 16, "max_fee_per_gas")?;
    let gas_limit = uint::<u64>(cursor, 8, "gas_limit")?;
    let to = bytes_n::<20>(cursor, "to")?;
    let value = uint::<u128>(cursor, 16, "value")?;

    // The flag does not gate the atoms: selector, no_words and every word slot are
    // consumed either way.
    let is_some = boolean(cursor, "calldata.is_some")?;
    let selector = bytes_n::<4>(cursor, "calldata.selector")?;
    let no_words = uint::<u16>(cursor, 2, "calldata.no_words")?;
    let mut word_slots = Vec::with_capacity(words);
    for _ in 0..words {
        word_slots.push(bytes_n::<32>(cursor, "calldata word")?);
    }

    let access_list_entry_count = uint::<u8>(cursor, 1, "access_list_entry_count")?;
    let mut access_list = Vec::with_capacity(entries);
    for _ in 0..entries {
        let address = bytes_n::<20>(cursor, "access list address")?;
        let storage_key_count = uint::<u8>(cursor, 1, "storage_key_count")?;
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
    use crate::records::SignBidirectionalEventNotification;
    use crate::test_utils::{
        aligned_cell, alignment_of, array_of, atoms_from_record, cell_from_record, cell_of, key_of,
        map_of, minimal_record, sample_record, sample_record_with_partial_access_list,
        sample_record_with_unused_access_list, widths_from_record,
    };
    use midnight_base_crypto::fab::Alignment;

    fn leaf(marker: u8) -> Node {
        cell_of(&[vec![marker]], &[1])
    }

    fn marker_of(node: &Node) -> u8 {
        let StateValue::Cell(cell) = node else {
            panic!("expected a leaf cell")
        };
        cell.value.0[0].0[0]
    }

    #[test]
    fn signet_field_node_flattens_chunk_shapes() {
        // Flat: fields are the root's children.
        let direct = array_of((0..5).map(leaf).collect());
        for index in 0..5u8 {
            assert_eq!(
                marker_of(signet_field_node(&direct, index.into()).unwrap()),
                index
            );
        }
        assert!(signet_field_node(&direct, 5).is_err());

        // 16 fields chunk to [1, 15], remainder FIRST.
        let sixteen = array_of(vec![
            array_of(vec![leaf(0)]),
            array_of((1..16).map(leaf).collect()),
        ]);
        for index in [0usize, 1, 5, 15] {
            assert_eq!(
                marker_of(signet_field_node(&sixteen, index).unwrap()),
                index as u8
            );
        }

        // 27 fields chunk to [12, 15].
        let twenty_seven = array_of(vec![
            array_of((0..12).map(leaf).collect()),
            array_of((12..27).map(leaf).collect()),
        ]);
        for index in [0usize, 11, 12, 26] {
            assert_eq!(
                marker_of(signet_field_node(&twenty_seven, index).unwrap()),
                index as u8
            );
        }
        assert!(signet_field_node(&twenty_seven, 27).is_err());

        // Two chunk levels: the 226-field shape, one level deeper.
        let two_level = array_of(vec![
            array_of(vec![array_of(vec![leaf(0)])]),
            array_of(
                (0..15)
                    .map(|chunk| {
                        array_of((0..15).map(|i| leaf((1 + chunk * 15 + i) as u8)).collect())
                    })
                    .collect(),
            ),
        ]);
        for index in [0usize, 1, 15, 16, 225] {
            assert_eq!(
                marker_of(signet_field_node(&two_level, index).unwrap()),
                index as u8
            );
        }

        // A leaf root is field 0 and nothing else.
        let single = leaf(9);
        assert_eq!(marker_of(signet_field_node(&single, 0).unwrap()), 9);
        assert!(signet_field_node(&single, 1)
            .unwrap_err()
            .to_string()
            .contains("leaf"));
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

        assert_eq!(
            widths_from_record(&minimal_record()).len(),
            REQUEST_FIXED_VALUE_ATOMS
        );

        // One atom below the boundary is refused rather than underflowing the tail.
        let err = decode_record(&cell_of(&vec![vec![0xab]; 21], &[1u32; 21]))
            .expect_err("21 atoms cannot hold the fixed fields")
            .to_string();
        assert!(err.contains("21") && err.contains("22"), "err: {err}");
    }

    #[test]
    fn decode_record_rejects_a_width_the_layout_does_not_declare() {
        // A sender stored in 20 bytes fits a Bytes<20> perfectly well, so only the
        // alignment catches this.
        let record = sample_record();
        let mut widths = widths_from_record(&record);
        widths[0] = 20;
        let err = decode_record(&cell_of(&atoms_from_record(&record), &widths))
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
        let mut widths = widths_from_record(&record);
        widths.pop();
        let err = decode_record(&cell_of(&atoms_from_record(&record), &widths))
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
                AlignmentSegment::Atom(AlignmentAtom::Compress),
                "carries no byte width",
            ),
            (
                "field",
                AlignmentSegment::Atom(AlignmentAtom::Field),
                "carries no byte width",
            ),
            (
                "option",
                AlignmentSegment::Option(vec![alignment_of(&[32])]),
                "alignment option",
            ),
        ] {
            let Alignment(mut segments) = alignment_of(&widths);
            segments[0] = segment;
            let err = decode_record(&aligned_cell(&atoms, Alignment(segments)))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("atom 0") && err.contains(expected),
                "the {name} segment must be refused as a widthless alignment, got: {err}"
            );
        }
    }

    #[test]
    fn decode_record_rejects_a_malformed_access_list_region() {
        // A region whose arithmetic works out but whose layout is wrong must still die
        // in the per-atom pass rather than decode into some other record.
        let record = sample_record_with_partial_access_list();
        let mut widths = widths_from_record(&record);
        // The SECOND Bytes<20>: the first is `to` in the fixed head. Swapping an
        // entry's address with its key count leaves the capacity arithmetic unchanged.
        let entry = widths
            .iter()
            .enumerate()
            .filter(|(_, w)| **w == 20)
            .map(|(i, _)| i)
            .nth(1)
            .expect("an entry address after `to`");
        widths.swap(entry, entry + 1);
        let err = decode_record(&cell_of(&atoms_from_record(&record), &widths))
            .expect_err("a permuted access-list entry must not decode")
            .to_string();
        assert!(err.contains("access list address"), "err: {err}");
    }

    #[test]
    fn decode_record_type_checks_wire_atoms() {
        // Every atom originates in a CALLER's own contract state, so a decode that
        // coerces instead of rejecting lets the caller choose which record is built.
        let record = sample_record();
        let widths = widths_from_record(&record);

        let mut not_boolean = atoms_from_record(&record);
        not_boolean[15] = vec![2];
        let err = decode_record(&cell_of(&not_boolean, &widths))
            .expect_err("a non-Boolean calldata.is_some atom must reject")
            .to_string();
        assert!(err.contains("calldata.is_some"), "err: {err}");

        let mut over_wide = atoms_from_record(&record);
        over_wide[0] = vec![0xab; 33];
        assert!(
            decode_record(&cell_of(&over_wide, &widths)).is_err(),
            "a 33-byte sender atom must reject"
        );
    }

    #[test]
    fn resolve_verified_record_drops_spoofed_filing() {
        let record = sample_record();
        let rid = compute_request_id(&record);
        let cell = cell_from_record(&record);

        let map = map_of(vec![(key_of(rid), cell.clone())]);
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
        let map = map_of(vec![(key_of(spoofed), cell)]);
        assert!(matches!(
            resolve_verified_record(&map, spoofed),
            Resolved::Dropped {
                reason: "rid-mismatch",
                ..
            }
        ));
    }

    #[test]
    fn resolve_verified_record_reports_absent_and_dropped() {
        let record = sample_record();
        let rid = compute_request_id(&record);
        let poisoned = [0x55; 32];
        let map = map_of(vec![
            (
                key_of(poisoned),
                cell_of(&[vec![1], vec![2], vec![3]], &[1, 1, 1]),
            ),
            (key_of(rid), cell_from_record(&record)),
        ]);

        // The undecodable cell drops without panicking...
        assert!(matches!(
            resolve_verified_record(&map, poisoned),
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
        // An id absent from the index is the ordinary negative, distinct from a drop.
        assert_eq!(resolve_verified_record(&map, [0x44; 32]), Resolved::Absent);
        assert!(matches!(
            resolve_verified_record(&StateValue::Null, rid),
            Resolved::Dropped {
                reason: "request-index-not-a-map",
                ..
            }
        ));
    }

    #[test]
    fn decode_notification_rejects_any_other_shape() {
        // Bytes<1> then Bytes<128>, and nothing else.
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

    #[test]
    fn unpack_notification_v1_rejects_other_versions() {
        let mut payload = [0u8; 128];
        payload[..32].copy_from_slice(&[0xab; 32]);
        payload[32] = 4;

        let notification = decode_notification(&cell_of(&[vec![1u8], payload.to_vec()], &[1, 128]))
            .expect("v1 notification decodes");
        let unpacked = unpack_notification_v1(&notification).expect("v1 payload unpacks");
        assert_eq!(unpacked.caller_address, [0xab; 32]);
        assert_eq!(unpacked.requests_index_field, 4);

        let future = SignBidirectionalEventNotification {
            version: 2,
            payload,
        };
        let err = unpack_notification_v1(&future)
            .expect_err("future versions must fail closed")
            .to_string();
        assert!(err.contains("version 2"), "err: {err}");
    }
}
