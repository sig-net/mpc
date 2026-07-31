//! Ledger-tree path walk and record decode over the ledger's own `StateValue`.

use midnight_base_crypto::fab::{AlignedValue, AlignmentAtom, AlignmentSegment, ValueAtom};
use midnight_onchain_state::state::StateValue;
use midnight_storage::DefaultDB;

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams,
    SignBidirectionalEventNotification, SignBidirectionalRecord,
};
use crate::request_id::compute_request_id;

/// Atoms of a record excluding its capacity-scaled vectors. The calldata `Maybe`'s
/// three atoms count even when `is_some` is false.
const REQUEST_FIXED_VALUE_ATOMS: usize = 22;

/// `sender` through `calldata.no_words`; the calldata words begin here.
const RECORD_HEAD_ATOMS: usize = 18;

/// `caip2_id` and the two schemas.
const RECORD_TAIL_ATOMS: usize = 3;

pub type Node = StateValue<DefaultDB>;

/// Follow a resolved ledger-tree path to its node in the state tree.
///
/// The path is the value compactc records for a field in the caller's own
/// `contract-info.json` (`"index"`), carried in the notification: a
/// single-element path (`[4]`) for a flat contract's field, a longer one
/// (`[1, 14]`) once a contract declares more than 15 fields and the compiler
/// stores them in a chunk tree. This walks the path node for node, exactly as
/// the generated `ledger()` accessor does, and never inspects array widths or
/// re-derives the chunk structure, so no field whose own value is an array can
/// be mistaken for a compiler chunk.
pub fn signet_field_node_by_path<'a>(root: &'a Node, path: &[u8]) -> anyhow::Result<&'a Node> {
    anyhow::ensure!(!path.is_empty(), "ledger field path is empty");
    let mut node = root;
    for (level, &index) in path.iter().enumerate() {
        let StateValue::Array(children) = node else {
            // A one-field contract stores its field as the bare (non-array)
            // root, addressable only as the whole state at a final [0]; the
            // compiled accessor reads it the same way.
            if index == 0 && level == path.len() - 1 {
                return Ok(node);
            }
            anyhow::bail!("ledger field path {path:?} steps into a non-array at level {level}");
        };
        // `Array::get` is the ledger storage type's own indexed accessor, the read-side
        // equivalent of the `asArray()[i]` step the generated `ledger()` accessor emits.
        node = children.get(usize::from(index)).ok_or_else(|| {
            anyhow::anyhow!(
                "ledger field path {path:?} index {index} out of range at level {level}"
            )
        })?;
    }
    Ok(node)
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

/// Maximum ledger-tree path depth the V1 payload carries, matching the
/// `Vector<4, Uint<8>>` the contract's `constructSignBidirectionalEventNotificationV1`
/// circuit packs. Depth 1 addresses up to 15 fields, depth 4 up to 15^4.
const MAX_LEDGER_PATH_DEPTH: u8 = 4;

/// The V1 notification payload, unpacked per its fixed offsets: `caller_address(32) ||
/// requests_path_depth(1) || requests_path(4) || zeros(91)`, where only the first
/// `requests_path_depth` path bytes are meaningful.
#[derive(Debug, Clone, PartialEq)]
pub struct NotificationV1 {
    pub caller_address: [u8; 32],
    /// The resolved ledger-tree path of the caller's request index, as compactc records
    /// it in the caller's `contract-info.json`: a per-integrator value the notification
    /// carries, never assumed. Trimmed to its declared depth.
    pub requests_path: Vec<u8>,
}

/// Fails closed on an unrecognised version: a future payload layout adds a branch here
/// rather than silently misinterpreting bytes under the V1 offsets. Also fails closed on
/// a depth of zero or one past [`MAX_LEDGER_PATH_DEPTH`], the width the circuit packs.
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
    let depth = notification.payload[32];
    anyhow::ensure!(
        (1..=MAX_LEDGER_PATH_DEPTH).contains(&depth),
        "notification requests_path_depth {depth} is out of range (expected 1 to {MAX_LEDGER_PATH_DEPTH})"
    );
    let requests_path = notification.payload[33..33 + usize::from(depth)].to_vec();
    Ok(NotificationV1 {
        caller_address,
        requests_path,
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
        aligned_cell, alignment_of, array_of, atoms_from_record, cell_from_atoms, cell_from_record,
        key_of, map_of, minimal_record, sample_record, sample_record_with_partial_access_list,
        sample_record_with_unused_access_list, widths_from_record,
    };
    use midnight_base_crypto::fab::Alignment;

    fn leaf(marker: u8) -> Node {
        cell_from_atoms(&[vec![marker]], &[1])
    }

    fn marker_of(node: &Node) -> u8 {
        let StateValue::Cell(cell) = node else {
            panic!("expected a leaf cell")
        };
        cell.value.0[0].0[0]
    }

    #[test]
    fn signet_field_node_by_path_threads_levels_and_maps_edges() {
        // Over the ledger's own `Array::get`, this function adds only a path
        // loop, an empty-path guard, leaf/non-array handling, and mapping a
        // missing index to our error. Only that glue is tested here; that
        // `Array::get` indexes correctly at any position or depth is the ledger
        // library's to test, not ours.
        let nested = array_of(vec![
            array_of(vec![leaf(0), leaf(1)]),
            array_of(vec![leaf(2), leaf(3)]),
        ]);

        // The loop threads `node` through each level to the addressed leaf.
        assert_eq!(
            marker_of(signet_field_node_by_path(&nested, &[1, 0]).unwrap()),
            2
        );

        // A missing index at any level becomes our error rather than a panic.
        assert!(signet_field_node_by_path(&nested, &[1, 9])
            .unwrap_err()
            .to_string()
            .contains("out of range"));

        // An empty path resolves nothing.
        assert!(signet_field_node_by_path(&nested, &[])
            .unwrap_err()
            .to_string()
            .contains("empty"));

        // A leaf (non-array) node is addressable only as the whole state at a
        // final [0]; any other step into it is refused.
        let single = leaf(9);
        assert_eq!(
            marker_of(signet_field_node_by_path(&single, &[0]).unwrap()),
            9
        );
        assert!(signet_field_node_by_path(&single, &[1])
            .unwrap_err()
            .to_string()
            .contains("non-array"));
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
        let err = decode_record(&cell_from_atoms(&vec![vec![0xab]; 21], &[1u32; 21]))
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
        let err = decode_record(&cell_from_atoms(&atoms_from_record(&record), &widths))
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
        let err = decode_record(&cell_from_atoms(&atoms_from_record(&record), &widths))
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
        let err = decode_record(&cell_from_atoms(&atoms_from_record(&record), &widths))
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
        let err = decode_record(&cell_from_atoms(&not_boolean, &widths))
            .expect_err("a non-Boolean calldata.is_some atom must reject")
            .to_string();
        assert!(err.contains("calldata.is_some"), "err: {err}");

        let mut over_wide = atoms_from_record(&record);
        over_wide[0] = vec![0xab; 33];
        assert!(
            decode_record(&cell_from_atoms(&over_wide, &widths)).is_err(),
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
                cell_from_atoms(&[vec![1], vec![2], vec![3]], &[1, 1, 1]),
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
            let err = decode_notification(&cell_from_atoms(&atoms, &widths))
                .expect_err("only a two-atom Bytes<1>/Bytes<128> cell decodes")
                .to_string();
            assert!(err.contains(expected), "err: {err}");
        }
    }

    #[test]
    fn unpack_notification_v1_decodes_path_and_fails_closed() {
        // A depth-2 path [1, 14], with a non-zero byte past the depth to prove
        // the decode trims to the declared depth rather than reading padding.
        let mut payload = [0u8; 128];
        payload[..32].copy_from_slice(&[0xab; 32]);
        payload[32] = 2; // requests_path_depth
        payload[33] = 1; // path[0]
        payload[34] = 14; // path[1]
        payload[35] = 99; // past the depth: must not appear in requests_path

        let notification =
            decode_notification(&cell_from_atoms(&[vec![1u8], payload.to_vec()], &[1, 128]))
                .expect("v1 notification decodes");
        let unpacked = unpack_notification_v1(&notification).expect("v1 payload unpacks");
        assert_eq!(unpacked.caller_address, [0xab; 32]);
        assert_eq!(unpacked.requests_path, vec![1, 14]);

        // A future version fails closed.
        let future = SignBidirectionalEventNotification {
            version: 2,
            payload,
        };
        let err = unpack_notification_v1(&future)
            .expect_err("future versions must fail closed")
            .to_string();
        assert!(err.contains("version 2"), "err: {err}");

        // A depth of zero or one past the packed width fails closed.
        for bad_depth in [0u8, MAX_LEDGER_PATH_DEPTH + 1] {
            let mut p = [0u8; 128];
            p[..32].copy_from_slice(&[0xab; 32]);
            p[32] = bad_depth;
            let bad = SignBidirectionalEventNotification {
                version: 1,
                payload: p,
            };
            let err = unpack_notification_v1(&bad)
                .expect_err("an out-of-range depth must fail closed")
                .to_string();
            assert!(err.contains("requests_path_depth"), "err: {err}");
        }
    }
}
