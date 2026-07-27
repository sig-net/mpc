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
