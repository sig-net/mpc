//! Test-only record builders shared by the unit tests.

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord,
};
use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
};
use midnight_onchain_state::state::StateValue;
use midnight_storage::storage::{Array, HashMap};
use midnight_storage::DefaultDB;

use crate::reader::Node;

pub(crate) fn hex_32(value: &str) -> [u8; 32] {
    let mut decoded = [0u8; 32];
    hex::decode_to_slice(value, &mut decoded).expect("fixture constant is 32-byte hex");
    decoded
}

pub(crate) fn notification_payload(
    version: u8,
    request_id: [u8; 32],
    caller_address: [u8; 32],
    requests_path: &[u8],
) -> [u8; crate::emissions::MISC_PAYLOAD_LEN] {
    assert!(
        requests_path.len() <= 4,
        "notification path exceeds V1 capacity"
    );
    let mut payload = [0u8; crate::emissions::MISC_PAYLOAD_LEN];
    payload[0] = version;
    payload[1..33].copy_from_slice(&request_id);
    payload[33..65].copy_from_slice(&caller_address);
    payload[65] = requests_path.len() as u8;
    payload[66..66 + requests_path.len()].copy_from_slice(requests_path);
    payload
}

pub(crate) fn response_payload(
    request_id: [u8; 32],
    x: [u8; 32],
    y: [u8; 32],
    s: [u8; 32],
    recovery_id: u8,
) -> [u8; crate::emissions::MISC_PAYLOAD_LEN] {
    let mut payload = [0u8; crate::emissions::MISC_PAYLOAD_LEN];
    payload[..32].copy_from_slice(&request_id);
    payload[32..64].copy_from_slice(&x);
    payload[64..96].copy_from_slice(&y);
    payload[96..128].copy_from_slice(&s);
    payload[128] = recovery_id;
    payload
}

/// Trailing-zero trim, the form the state layer stores every atom in.
pub(crate) fn trim(bytes: &[u8]) -> Vec<u8> {
    let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    bytes[..end].to_vec()
}

/// Wire-form atoms of a record, each field trimmed as the state layer stores it:
/// trailing zeros dropped, a false Boolean the empty atom and a true one `[1]`,
/// integers little-endian trimmed.
pub(crate) fn atoms_from_record(record: &SignBidirectionalRecord) -> Vec<Vec<u8>> {
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
    // Schemas are exact-length by protocol convention, never ending in a zero byte, so
    // stored length equals declared length.
    atoms.push(record.output_deserialization_schema.clone());
    atoms.push(record.respond_serialization_schema.clone());
    atoms
}

/// The width the contract declares for each atom of a record, in atom order. The wire
/// carries this beside the atoms, so a fixture without it is not a record cell.
pub(crate) fn widths_from_record(record: &SignBidirectionalRecord) -> Vec<u32> {
    let tx = &record.tx_params;
    let mut widths: Vec<u32> = vec![
        32, // sender
        8,  // request_nonce
        1,  // key_version
        32, // path
        1,  // algo
        1,  // dest
        64, // params
        1,  // tx_param_type
        8,  // chain_id
        8,  // nonce
        16, // max_priority_fee_per_gas
        16, // max_fee_per_gas
        8,  // gas_limit
        20, // to
        16, // value
        1,  // calldata.is_some
        4,  // calldata.selector
        2,  // calldata.no_words
    ];
    widths.extend(std::iter::repeat_n(32, tx.calldata.value.words.len()));
    widths.push(1); // access_list_entry_count
    for entry in &tx.access_list {
        widths.push(20);
        widths.push(1);
        widths.extend(std::iter::repeat_n(32, entry.storage_keys.len()));
    }
    widths.push(32); // caip2_id
    widths.push(record.output_deserialization_schema.len() as u32);
    widths.push(record.respond_serialization_schema.len() as u32);
    widths
}

pub(crate) fn cell_from_atoms(atoms: &[Vec<u8>], widths: &[u32]) -> Node {
    aligned_cell(atoms, alignment_of(widths))
}

/// A cell at an explicit alignment, for the cases that need a segment `alignment_of`
/// cannot express.
pub(crate) fn aligned_cell(atoms: &[Vec<u8>], alignment: Alignment) -> Node {
    StateValue::from(AlignedValue {
        value: Value(atoms.iter().map(|a| ValueAtom(a.clone())).collect()),
        alignment,
    })
}

/// `Bytes<width>` segments, the only alignment a signet record or notification uses.
pub(crate) fn alignment_of(widths: &[u32]) -> Alignment {
    Alignment(
        widths
            .iter()
            .map(|length| AlignmentSegment::Atom(AlignmentAtom::Bytes { length: *length }))
            .collect(),
    )
}

/// The stored cell for `record`: its trimmed atoms beside the widths it declares.
pub(crate) fn cell_from_record(record: &SignBidirectionalRecord) -> Node {
    StateValue::from(aligned_value_from_record(record))
}

/// The aligned cell value for `record`, before it is wrapped as ledger state.
pub(crate) fn aligned_value_from_record(record: &SignBidirectionalRecord) -> AlignedValue {
    AlignedValue {
        value: Value(
            atoms_from_record(record)
                .into_iter()
                .map(ValueAtom)
                .collect(),
        ),
        alignment: alignment_of(&widths_from_record(record)),
    }
}

/// A `Bytes<32>` map key, the shape both counter maps and a caller's request index use.
pub(crate) fn key_of(bytes: [u8; 32]) -> AlignedValue {
    AlignedValue::from(bytes)
}

/// A ledger map from key/value pairs.
pub(crate) fn map_of(entries: Vec<(AlignedValue, Node)>) -> Node {
    let mut map: HashMap<AlignedValue, StateValue<DefaultDB>, DefaultDB> = HashMap::new();
    for (key, value) in entries {
        map = map.insert(key, value);
    }
    StateValue::Map(map)
}

/// A ledger array of fields.
pub(crate) fn array_of(children: Vec<Node>) -> Node {
    StateValue::Array(Array::new_from_slice(&children))
}

/// `text` left-aligned in an all-NUL `[u8; N]`, the `pad(N, "text")` convention.
pub(crate) fn ascii_padded<const N: usize>(text: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out[..text.len()].copy_from_slice(text);
    out
}

fn ascii_padded_vec(text: &[u8], width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    out[..text.len()].copy_from_slice(text);
    out
}

/// The canonical record the unit tests build on: sender `0xab * 32`, path
/// `"caller-path"`, one used calldata word, no access list. The smallest shape that
/// still exercises every capacity-scaled vector.
pub(crate) fn sample_record() -> SignBidirectionalRecord {
    SignBidirectionalRecord {
        sender: [0xab; 32],
        request_nonce: 7,
        key_version: 1,
        path: ascii_padded(b"caller-path"),
        algo: 0,
        dest: 0,
        params: [0u8; 64],
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
                    no_words: 1,
                    words: vec![[0x11; 32]],
                },
            },
            access_list_entry_count: 0,
            access_list: Vec::new(),
        },
        caip2_id: ascii_padded(b"eip155:31337"),
        output_deserialization_schema: ascii_padded_vec(b"uint256", 34),
        respond_serialization_schema: ascii_padded_vec(b"uint256", 34),
    }
}

/// The smallest legal record: both scaled vectors empty, so the cell sits exactly on
/// `REQUEST_FIXED_VALUE_ATOMS`. This is the plain-transfer shape.
pub(crate) fn minimal_record() -> SignBidirectionalRecord {
    let mut record = sample_record();
    record.tx_params.calldata = CompactMaybe {
        is_some: false,
        value: EvmCalldata {
            selector: [0; 4],
            no_words: 0,
            words: Vec::new(),
        },
    };
    record.tx_params.access_list_entry_count = 0;
    record.tx_params.access_list = Vec::new();
    record
}

/// `sample_record` carrying an access list at capacity with every slot unused.
pub(crate) fn sample_record_with_unused_access_list() -> SignBidirectionalRecord {
    let mut record = sample_record();
    record.tx_params.access_list_entry_count = 0;
    record.tx_params.access_list = vec![
        EvmAccessListEntry {
            address: [0u8; 20],
            storage_key_count: 0,
            storage_keys: vec![[0u8; 32]; 2],
        };
        2
    ];
    record
}

/// A record at capacity on every scaled vector, with one access-list entry in use:
/// 2 calldata words, 2 access-list entries, 3 storage keys each.
pub(crate) fn sample_record_with_partial_access_list() -> SignBidirectionalRecord {
    let mut record = sample_record();
    record.tx_params.calldata.value.no_words = 2;
    record.tx_params.calldata.value.words = vec![[0x11; 32], [0x22; 32]];
    record.tx_params.access_list_entry_count = 1;
    record.tx_params.access_list = vec![
        EvmAccessListEntry {
            address: [0xef; 20],
            storage_key_count: 3,
            storage_keys: vec![[0x01; 32], [0x02; 32], [0x03; 32]],
        },
        EvmAccessListEntry {
            address: [0u8; 20],
            storage_key_count: 0,
            storage_keys: vec![[0u8; 32]; 3],
        },
    ];
    record
}
