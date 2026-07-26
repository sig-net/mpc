//! The request-id twin: keccak256 over the contract's byte layout for a
//! `SignBidirectionalRecord`.

use mpc_chain_integration_core::utils::hashing::hash_payload;

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord,
};

/// The request id the contract mints for `record`.
pub fn compute_request_id(record: &SignBidirectionalRecord) -> [u8; 32] {
    hash_payload(&binary_repr(record))
}

/// The hash preimage: each field at its declared width, in declaration order.
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
    // `Bytes<N>` at per-integrator widths, so the carried buffer is itself the declared
    // width.
    buf.extend_from_slice(&record.output_deserialization_schema);
    buf.extend_from_slice(&record.respond_serialization_schema);
    buf
}

fn push_tx_params(buf: &mut Vec<u8>, params: &EvmType2TxParams) {
    buf.extend_from_slice(&params.chain_id.to_le_bytes());
    buf.extend_from_slice(&params.nonce.to_le_bytes());
    // Priority fee before the fee cap, `to` after the gas limit: the contract's payload
    // order is the hash order, and it reads backwards against habit.
    buf.extend_from_slice(&params.max_priority_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.max_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.gas_limit.to_le_bytes());
    buf.extend_from_slice(&params.to);
    buf.extend_from_slice(&params.value.to_le_bytes());
    push_calldata(buf, &params.calldata);
    buf.push(params.access_list_entry_count);
    // Every slot of the declared capacity: entries past the count are zero-filled and
    // still hashed.
    for entry in &params.access_list {
        push_access_list_entry(buf, entry);
    }
}

fn push_calldata(buf: &mut Vec<u8>, calldata: &CompactMaybe<EvmCalldata>) {
    // `Maybe<T>` is a plain struct, not a tagged union: the flag byte is followed by a
    // full-width `T` either way.
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

    /// Oracle output, verbatim.
    const VECTORS_JSON: &str = include_str!("../tests/rid_vectors.json");

    /// Pinned so a fixture from any other generator is reviewed, not adopted.
    const ORACLE: &str =
        "calculateRequestId (packages/signet-midnight/src/signet-evtype2tx-requests.ts)";

    /// Every tier the fixture covers.
    const VECTOR_COUNT: usize = 13;

    #[derive(Deserialize)]
    struct VectorFile {
        generated_from: String,
        oracle: String,
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        expected_request_id_hex: String,
        /// Asserted alongside the digest because it localises the fault: a width
        /// mismatch names the misaligned tier, a digest mismatch only says something is
        /// wrong.
        preimage_bytes: usize,
        #[serde(with = "RecordDef")]
        record: SignBidirectionalRecord,
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

    // Pins the emitted byte layout, not the Rust declaration order: `binary_repr`
    // writes fields by name, so a reordered declaration is not observable here or
    // anywhere else.
    #[test]
    fn compute_request_id_matches_ts_oracle() {
        let file = load_vectors();
        assert_eq!(
            file.vectors.len(),
            VECTOR_COUNT,
            "a vector was dropped; each is the only cover for its own layout bug"
        );
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
}
