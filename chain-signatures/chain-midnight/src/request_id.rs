//! The request-id twin: a keccak256 over the contract's own byte layout for
//! a `SignBidirectionalRecord`.
//!
//! The Compact circuit mints a request id as `keccak256<T>(record)`, which
//! hashes `toBinaryRepr(record)`: every field re-padded to its declared width
//! and concatenated in declaration order, with no tags, framing, or length
//! prefixes. This module rebuilds that preimage in Rust so the node can
//! recompute the id of an indexed request and drop anything that disagrees.
//! It is a field-aligned byte layout, not an ABI or EIP-712 encoding, so it
//! shares the hash family with the other chains but none of their padding.
//!
//! A wrong byte here fails in one direction only: the recomputed id stops
//! matching and every request is dropped. It cannot missign, because
//! epsilon derivation never consumes the request id; a broken twin starves
//! the node of requests rather than signing under an unexpected key.
//! The vectors in `tests/rid_vectors.json` were produced by the
//! contract package's `calculateRequestId`, which its simulator tests pin to
//! the compiled circuit, and are the only authority for what is correct
//! here. Never hand-author one.

use mpc_chain_integration_core::utils::hashing::hash_payload;

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord,
};

/// The request id the contract mints for `record`.
///
/// The id is capacity-sensitive: unused vector slots and an absent
/// `calldata`'s value are all part of the preimage. `record` must therefore
/// arrive at its declared capacities with unused slots zero-filled, and its
/// two schema buffers at their per-integrator widths, exactly as the wire
/// form is re-padded on decode. A `Vec` that arrives short declares a
/// narrower type and yields a different id.
pub fn compute_request_id(record: &SignBidirectionalRecord) -> [u8; 32] {
    hash_payload(&binary_repr(record))
}

/// The hash preimage: each field at its declared width, in declaration
/// order.
///
/// Every multi-byte integer is emitted little-endian through `to_le_bytes`
/// on its declared Rust type, so the emitted width is the declared atom
/// width and the two can only change together. Byte fields are emitted whole
/// and never trimmed: the wire form drops trailing zeros, the preimage pads
/// them back.
fn binary_repr(record: &SignBidirectionalRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&record.sender);
    buf.extend_from_slice(&record.request_nonce.to_le_bytes());
    buf.push(record.key_version);
    buf.extend_from_slice(&record.path);
    buf.push(record.algo);
    buf.push(record.dest);
    buf.extend_from_slice(&record.params);
    buf.push(record.tx_param_type);
    push_tx_params(&mut buf, &record.tx_params);
    buf.extend_from_slice(&record.caip2_id);
    // The two schemas are `Bytes<N>` at per-integrator widths, so the buffer
    // the record carries is itself the declared width.
    buf.extend_from_slice(&record.output_deserialization_schema);
    buf.extend_from_slice(&record.respond_serialization_schema);
    buf
}

fn push_tx_params(buf: &mut Vec<u8>, params: &EvmType2TxParams) {
    buf.extend_from_slice(&params.chain_id.to_le_bytes());
    buf.extend_from_slice(&params.nonce.to_le_bytes());
    // The priority fee precedes the fee cap, and `to` sits after the gas
    // limit rather than first: the contract's payload order is the hash
    // order and reads backwards against EVM habit.
    buf.extend_from_slice(&params.max_priority_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.max_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.gas_limit.to_le_bytes());
    buf.extend_from_slice(&params.to);
    buf.extend_from_slice(&params.value.to_le_bytes());
    // Calldata precedes the access-list pair, also backwards against habit.
    push_calldata(buf, &params.calldata);
    buf.push(params.access_list_entry_count);
    // Every slot of the declared capacity, including the entries past
    // `access_list_entry_count`, which are zero-filled but still hashed.
    for entry in &params.access_list {
        push_access_list_entry(buf, entry);
    }
}

fn push_calldata(buf: &mut Vec<u8>, calldata: &CompactMaybe<EvmCalldata>) {
    // Compact's `Maybe<T>` is a plain struct, not a tagged union: the flag
    // byte is followed by a full-width `T` whether or not the flag is set.
    // Emitting nothing for an absent calldata shortens the preimage and
    // changes the id of every request that carries none.
    buf.push(u8::from(calldata.is_some));
    buf.extend_from_slice(&calldata.value.selector);
    buf.extend_from_slice(&calldata.value.no_words.to_le_bytes());
    // Every slot of the declared capacity, including the ones past
    // `no_words`, which are zero-filled but still hashed.
    for word in &calldata.value.words {
        buf.extend_from_slice(word);
    }
}

fn push_access_list_entry(buf: &mut Vec<u8>, entry: &EvmAccessListEntry) {
    buf.extend_from_slice(&entry.address);
    buf.push(entry.storage_key_count);
    for storage_key in &entry.storage_keys {
        buf.extend_from_slice(storage_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::RecordDef;
    use serde::Deserialize;

    /// Copied verbatim from the generator's output. Regenerating it is a
    /// deliberate act: a record and its digest only agree because the oracle
    /// produced them together, so never hand-edit one.
    const VECTORS_JSON: &str = include_str!("../tests/rid_vectors.json");

    /// The oracle these vectors came from. Pinned so a fixture generated by
    /// anything else has to be reviewed rather than silently adopted.
    const ORACLE: &str =
        "calculateRequestId (packages/signet-midnight/src/signet-evtype2tx-requests.ts)";

    /// Every tier the fixture covers. Listed here so dropping a vector is a
    /// test failure: several are the only vector that catches their own class
    /// of layout bug, and which ones is not obvious from reading them.
    /// `no-calldata` alone catches an absent `Maybe` that emits nothing,
    /// `access-list-partial` alone catches unused access-list slots,
    /// `wide-schemas` alone catches the two schemas being swapped (every
    /// other vector carries two identical 34-byte schemas), and the three
    /// `enum-*` vectors are the only ones whose one-byte enums and `params`
    /// are not all zero.
    const VECTOR_NAMES: [&str; 13] = [
        "minimal-1word",
        "no-calldata",
        "zero-words-capacity",
        "unused-word-slot",
        "access-list-1x1",
        "access-list-partial",
        "wide-schemas",
        "enum-algo-set",
        "enum-dest-set",
        "enum-txparamtype-set",
        "al-entry-zero-keys",
        "no-calldata-wide",
        "al-capacity-unused",
    ];

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VectorFile {
        generated_from: String,
        oracle: String,
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Vector {
        name: String,
        capacities: Capacities,
        expected_request_id_hex: String,
        /// Alignment atom count the runtime reported for this record.
        preimage_atoms: usize,
        /// Total preimage width the runtime reported. Asserting it alongside
        /// the digest localises a layout bug: a length mismatch names the
        /// tier that is misaligned, where a digest mismatch only says
        /// something somewhere is wrong.
        preimage_bytes: usize,
        declared_widths: Vec<usize>,
        #[serde(with = "RecordDef")]
        record: SignBidirectionalRecord,
    }

    /// The capacity generics the oracle recovered from the record itself.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Capacities {
        max_calldata_words: usize,
        max_access_list_entries: usize,
        max_storage_keys_per_entry: usize,
        len_output_deserialization_schema: usize,
        len_respond_serialization_schema: usize,
    }

    fn load_vectors() -> VectorFile {
        let file: VectorFile = serde_json::from_str(VECTORS_JSON).expect("rid_vectors.json");
        assert_eq!(
            file.oracle, ORACLE,
            "vectors came from a different oracle (generated from {}); review before adopting",
            file.generated_from
        );
        file
    }

    // These goldens pin the emitted byte layout, not the Rust declaration
    // order: binary_repr reads fields by name, so a reordered declaration
    // stays green here. Declaration order is pinned by the records module's
    // own order tests.
    #[test]
    fn request_id_matches_the_ts_oracle() {
        let file = load_vectors();
        for vector in &file.vectors {
            // The width is asserted alongside the digest because it
            // localises the fault: a length mismatch names the misaligned
            // tier, where a digest mismatch only says something is wrong.
            assert_eq!(
                binary_repr(&vector.record).len(),
                vector.preimage_bytes,
                "vector {}: preimage width disagrees with the runtime's own alignment",
                vector.name
            );
            assert_eq!(
                hex::encode(compute_request_id(&vector.record)),
                vector.expected_request_id_hex,
                "vector {}",
                vector.name
            );
        }
    }

    #[test]
    fn every_tier_is_covered() {
        let file = load_vectors();
        let names: Vec<&str> = file.vectors.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(
            names, VECTOR_NAMES,
            "a vector was dropped, renamed, or reordered; each one is the only cover for its own layout bug"
        );

        // The D8 pin, stated as an identity: an absent calldata occupies the
        // same width as a present one and differs only in the bytes, so a
        // twin that skips the value of an empty `Maybe` fails here alone.
        let by_name = |name: &str| {
            let vector = file
                .vectors
                .iter()
                .find(|v| v.name == name)
                .unwrap_or_else(|| panic!("vector {name} missing"));
            (
                binary_repr(&vector.record).len(),
                vector.expected_request_id_hex.as_str(),
            )
        };
        let (present_len, present_id) = by_name("minimal-1word");
        let (absent_len, absent_id) = by_name("no-calldata");
        assert_eq!(
            present_len, absent_len,
            "an absent calldata must occupy the same preimage width as a present one"
        );
        assert_ne!(present_id, absent_id);

        // wide-schemas only does its job (pinning that per-integrator schema
        // widths reach the preimage) while its two schemas actually differ;
        // a fixture edit that equalised them would quietly demote it to a
        // duplicate of the identical-schema tiers.
        let wide = file
            .vectors
            .iter()
            .find(|v| v.name == "wide-schemas")
            .expect("wide-schemas vector present");
        assert_ne!(
            wide.record.output_deserialization_schema.len(),
            wide.record.respond_serialization_schema.len(),
            "wide-schemas must carry two schemas of different widths"
        );
    }

    #[test]
    fn vectors_sit_at_their_declared_capacities() {
        // The oracle recovers the capacity generics from the record itself,
        // so a vector whose vectors are short of capacity silently pins a
        // narrower type than it claims.
        let file = load_vectors();
        for vector in &file.vectors {
            let name = &vector.name;
            let capacities = &vector.capacities;
            let params = &vector.record.tx_params;
            assert_eq!(
                params.calldata.value.words.len(),
                capacities.max_calldata_words,
                "vector {name}: calldata words short of capacity"
            );
            assert_eq!(
                params.access_list.len(),
                capacities.max_access_list_entries,
                "vector {name}: access list short of capacity"
            );
            for entry in &params.access_list {
                assert_eq!(
                    entry.storage_keys.len(),
                    capacities.max_storage_keys_per_entry,
                    "vector {name}: storage keys short of capacity"
                );
            }
            assert_eq!(
                vector.record.output_deserialization_schema.len(),
                capacities.len_output_deserialization_schema,
                "vector {name}: output schema is not at its declared width"
            );
            assert_eq!(
                vector.record.respond_serialization_schema.len(),
                capacities.len_respond_serialization_schema,
                "vector {name}: respond schema is not at its declared width"
            );

            // The runtime's own alignment, checked against itself: the
            // widths it declared must add up to the width it reported.
            assert_eq!(
                vector.declared_widths.len(),
                vector.preimage_atoms,
                "vector {name}: declared widths disagree with the atom count"
            );
            assert_eq!(
                vector.declared_widths.iter().sum::<usize>(),
                vector.preimage_bytes,
                "vector {name}: declared widths do not sum to the preimage width"
            );
        }
    }
}
