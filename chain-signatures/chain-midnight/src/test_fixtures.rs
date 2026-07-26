//! Test-only serde shims for deserializing fixture records: shared by the
//! request-id golden tests and the reader golden tests. Byte fields are hex
//! strings and wide integers are decimal strings, because a u128 does not
//! survive a JSON number.
//!
//! The definitions are serde `remote` shims: field names must match the
//! record structs exactly and serde builds those structs directly, so no
//! field can be mapped, renamed, or reordered on the way in.
//! `deny_unknown_fields` closes the other direction: a fixture key with no
//! matching field is an error rather than a silent drop.

use serde::de::{self, Deserializer};
use serde::Deserialize;
use std::fmt::Display;
use std::str::FromStr;

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord,
};
use crate::sidecar::StateNode;

/// Wire-form atoms of a record: each field trimmed exactly as the state
/// layer stores it (trailing zeros dropped; a false Boolean is the
/// EMPTY atom, a true one is [1]; integers are little-endian trimmed).
/// Used to turn A4's oracle-produced records into decode INPUTS whose
/// expected outputs and ids come from the same oracle fixture; only
/// this trimming transform is local, and it is the documented wire
/// rule, not a golden. Shared by the reader gate tests and the indexer
/// run() fixtures.
pub(crate) fn atoms_from_record(record: &SignBidirectionalRecord) -> Vec<Vec<u8>> {
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

pub(crate) fn cell_of(atoms: &[Vec<u8>]) -> StateNode {
    StateNode::Cell {
        atoms: atoms.iter().map(hex::encode).collect(),
    }
}

/// A standalone fixture record: `RecordFixture::deserialize` applies the
/// remote shims to a bare record object.
#[derive(Deserialize)]
pub(crate) struct RecordFixture(#[serde(with = "RecordDef")] pub(crate) SignBidirectionalRecord);

#[derive(Deserialize)]
#[serde(remote = "SignBidirectionalRecord", deny_unknown_fields)]
pub(crate) struct RecordDef {
    #[serde(deserialize_with = "hex_array")]
    sender: [u8; 32],
    #[serde(deserialize_with = "decimal")]
    request_nonce: u64,
    #[serde(deserialize_with = "decimal")]
    key_version: u8,
    #[serde(deserialize_with = "hex_array")]
    path: [u8; 32],
    algo: u8,
    dest: u8,
    #[serde(deserialize_with = "hex_array")]
    params: [u8; 64],
    tx_param_type: u8,
    #[serde(with = "TxParamsDef")]
    tx_params: EvmType2TxParams,
    #[serde(deserialize_with = "hex_array")]
    caip2_id: [u8; 32],
    #[serde(deserialize_with = "hex_bytes")]
    output_deserialization_schema: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    respond_serialization_schema: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(remote = "EvmType2TxParams", deny_unknown_fields)]
pub(crate) struct TxParamsDef {
    #[serde(deserialize_with = "decimal")]
    chain_id: u64,
    #[serde(deserialize_with = "decimal")]
    nonce: u64,
    #[serde(deserialize_with = "decimal")]
    max_priority_fee_per_gas: u128,
    #[serde(deserialize_with = "decimal")]
    max_fee_per_gas: u128,
    #[serde(deserialize_with = "decimal")]
    gas_limit: u64,
    #[serde(deserialize_with = "hex_array")]
    to: [u8; 20],
    #[serde(deserialize_with = "decimal")]
    value: u128,
    #[serde(deserialize_with = "calldata")]
    calldata: CompactMaybe<EvmCalldata>,
    #[serde(deserialize_with = "decimal")]
    access_list_entry_count: u8,
    #[serde(deserialize_with = "access_list")]
    access_list: Vec<EvmAccessListEntry>,
}

#[derive(Deserialize)]
#[serde(remote = "EvmCalldata", deny_unknown_fields)]
pub(crate) struct CalldataDef {
    #[serde(deserialize_with = "hex_array")]
    selector: [u8; 4],
    #[serde(deserialize_with = "decimal")]
    no_words: u16,
    #[serde(deserialize_with = "hex_words")]
    words: Vec<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(remote = "EvmAccessListEntry", deny_unknown_fields)]
pub(crate) struct AccessListEntryDef {
    #[serde(deserialize_with = "hex_array")]
    address: [u8; 20],
    #[serde(deserialize_with = "decimal")]
    storage_key_count: u8,
    #[serde(deserialize_with = "hex_words")]
    storage_keys: Vec<[u8; 32]>,
}

/// `CompactMaybe<T>` is generic, which serde's `remote` shim cannot name,
/// so its two fields are moved across by shorthand: a swap would not
/// compile.
fn calldata<'de, D>(deserializer: D) -> Result<CompactMaybe<EvmCalldata>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MaybeCalldata {
        is_some: bool,
        #[serde(with = "CalldataDef")]
        value: EvmCalldata,
    }

    let MaybeCalldata { is_some, value } = MaybeCalldata::deserialize(deserializer)?;
    Ok(CompactMaybe { is_some, value })
}

fn access_list<'de, D>(deserializer: D) -> Result<Vec<EvmAccessListEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Entry(#[serde(with = "AccessListEntryDef")] EvmAccessListEntry);

    Ok(Vec::<Entry>::deserialize(deserializer)?
        .into_iter()
        .map(|Entry(entry)| entry)
        .collect())
}

fn hex_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    hex::decode(String::deserialize(deserializer)?).map_err(de::Error::custom)
}

fn hex_array<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = hex_bytes(deserializer)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| de::Error::custom(format!("expected {N} hex bytes, got {len}")))
}

fn hex_words<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(|word| {
            let bytes = hex::decode(word).map_err(de::Error::custom)?;
            let len = bytes.len();
            bytes.try_into().map_err(|_: Vec<u8>| {
                de::Error::custom(format!("expected 32 hex bytes, got {len}"))
            })
        })
        .collect()
}

pub(crate) fn decimal<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(de::Error::custom)
}
