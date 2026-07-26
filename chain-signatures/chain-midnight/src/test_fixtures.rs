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
