//! The request-id twin: keccak256 over the contract's byte layout for a
//! `SignBidirectionalRecord`.
//!
//! The Compact circuit mints ids as `keccak256(toBinaryRepr(record))`, a
//! field-aligned layout rather than an ABI or EIP-712 encoding: each field
//! re-padded to its declared width and concatenated in declaration order, no
//! tags, framing or length prefixes. Rebuilding it here lets the node
//! recompute an indexed request's id and drop anything that disagrees.
//!
//! A wrong byte fails in one direction only. Epsilon never consumes the request
//! id, so a broken twin starves the node of requests rather than signing under
//! an unexpected key.
//!
//! `tests/rid_vectors.json` comes from the contract package's
//! `calculateRequestId` and is the only authority here. Never hand-author one.

use mpc_chain_integration_core::utils::hashing::hash_payload;

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord,
};

/// The request id the contract mints for `record`.
///
/// Capacity-sensitive: unused vector slots and an absent `calldata`'s value are
/// part of the preimage, so `record` must arrive at its declared capacities
/// with unused slots zero-filled and both schema buffers at their
/// per-integrator widths. A short `Vec` declares a narrower type and yields a
/// different id.
pub fn compute_request_id(record: &SignBidirectionalRecord) -> [u8; 32] {
    hash_payload(&binary_repr(record))
}

/// The hash preimage: each field at its declared width, in declaration order.
///
/// Integers go through `to_le_bytes` on their declared Rust type, so emitted
/// width and declared width can only change together. Byte fields are never
/// trimmed: the wire form drops trailing zeros, the preimage pads them back.
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
    // `Bytes<N>` at per-integrator widths, so the carried buffer is itself the
    // declared width.
    buf.extend_from_slice(&record.output_deserialization_schema);
    buf.extend_from_slice(&record.respond_serialization_schema);
    buf
}

fn push_tx_params(buf: &mut Vec<u8>, params: &EvmType2TxParams) {
    buf.extend_from_slice(&params.chain_id.to_le_bytes());
    buf.extend_from_slice(&params.nonce.to_le_bytes());
    // Priority fee before the fee cap, `to` after the gas limit: the contract's
    // payload order is the hash order, and it reads backwards against habit.
    buf.extend_from_slice(&params.max_priority_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.max_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.gas_limit.to_le_bytes());
    buf.extend_from_slice(&params.to);
    buf.extend_from_slice(&params.value.to_le_bytes());
    push_calldata(buf, &params.calldata);
    buf.push(params.access_list_entry_count);
    // Every slot of the declared capacity: entries past the count are
    // zero-filled and still hashed.
    for entry in &params.access_list {
        push_access_list_entry(buf, entry);
    }
}

fn push_calldata(buf: &mut Vec<u8>, calldata: &CompactMaybe<EvmCalldata>) {
    // `Maybe<T>` is a plain struct, not a tagged union: the flag byte is
    // followed by a full-width `T` either way. Emitting nothing for an absent
    // calldata changes the id of every request that carries none.
    buf.push(u8::from(calldata.is_some));
    buf.extend_from_slice(&calldata.value.selector);
    buf.extend_from_slice(&calldata.value.no_words.to_le_bytes());
    // Slots past `no_words` are zero-filled and still hashed.
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

    /// Oracle output, verbatim. A record and its digest agree only because the
    /// oracle produced them together, so never hand-edit one.
    const VECTORS_JSON: &str = include_str!("../tests/rid_vectors.json");

    /// Pinned so a fixture from any other generator is reviewed, not adopted.
    const ORACLE: &str =
        "calculateRequestId (packages/signet-midnight/src/signet-evtype2tx-requests.ts)";

    /// Listed so dropping a vector fails the suite. Several are the sole cover
    /// for their own class of layout bug, which is not obvious from reading
    /// them: `no-calldata` for an absent `Maybe` that emits nothing,
    /// `access-list-partial` for unused access-list slots, `wide-schemas` for
    /// the two schemas being swapped, and the `enum-*` trio for one-byte enums
    /// and `params` that are not all zero.
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
        /// Total preimage width the runtime reported. Asserted alongside the
        /// digest because it localises the fault: a width mismatch names the
        /// misaligned tier, a digest mismatch only says something is wrong.
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

    // Pins the emitted byte layout, not the Rust declaration order:
    // `binary_repr` reads fields by name, so a reordered declaration stays
    // green here. The records module's order tests cover that.
    #[test]
    fn compute_request_id_matches_ts_oracle() {
        let file = load_vectors();
        for vector in &file.vectors {
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
    fn rid_vectors_cover_every_tier() {
        let file = load_vectors();
        let names: Vec<&str> = file.vectors.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(
            names, VECTOR_NAMES,
            "a vector was dropped, renamed, or reordered; each one is the only cover for its own layout bug"
        );

        // An absent calldata occupies the same width as a present one and
        // differs only in bytes, so a twin that skips an empty `Maybe`'s value
        // fails here alone.
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

        // wide-schemas only pins that per-integrator widths reach the preimage
        // while its two schemas differ; equalising them would quietly demote it
        // to a duplicate of the identical-schema tiers.
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
    fn rid_vectors_sit_at_declared_capacities() {
        // The oracle recovers capacity generics from the record itself, so a
        // vector short of capacity silently pins a narrower type than it claims.
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

            // The runtime's own alignment checked against itself: declared
            // widths must add up to the width it reported.
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
