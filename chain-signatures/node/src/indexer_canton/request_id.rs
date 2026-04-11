use alloy::primitives::{keccak256, U256};
use super::{CantonEvmTransactionParams, CantonSignBidirectionalRequestedEvent};

/// keccak256(utf8(text)), or keccak256("") for empty string.
/// Mirrors Daml's `hashText` in Eip712.daml.
fn hash_text(text: &str) -> [u8; 32] {
    keccak256(text.as_bytes()).into()
}

/// Left-pad a hex string to 32 bytes (big-endian U256).
fn pad_left_32(hex_str: &str) -> [u8; 32] {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    U256::from_str_radix(stripped, 16)
        .unwrap_or(U256::ZERO)
        .to_be_bytes::<32>()
}

/// keccak256(concat(map keccak256 items)), or keccak256("") for empty list.
/// Mirrors Daml's `hashBytesList` in Eip712.daml.
fn hash_bytes_list(items: &[String]) -> [u8; 32] {
    if items.is_empty() {
        return keccak256(b"").into();
    }
    let mut concatenated = Vec::new();
    for item in items {
        let bytes = hex::decode(item).unwrap_or_default();
        let h: [u8; 32] = keccak256(&bytes).into();
        concatenated.extend_from_slice(&h);
    }
    keccak256(&concatenated).into()
}

/// Hash EvmTransactionParams — mirrors Daml's `hashEvmParams` in RequestId.daml.
fn hash_evm_params(p: &CantonEvmTransactionParams) -> [u8; 32] {
    let mut buf = Vec::with_capacity(9 * 32);
    buf.extend_from_slice(&pad_left_32(&p.to));
    buf.extend_from_slice(&hash_text(&p.function_signature));
    buf.extend_from_slice(&hash_bytes_list(&p.args));
    buf.extend_from_slice(&pad_left_32(&p.value));
    buf.extend_from_slice(&pad_left_32(&p.nonce));
    buf.extend_from_slice(&pad_left_32(&p.gas_limit));
    buf.extend_from_slice(&pad_left_32(&p.max_fee_per_gas));
    buf.extend_from_slice(&pad_left_32(&p.max_priority_fee));
    buf.extend_from_slice(&pad_left_32(&p.chain_id));
    keccak256(&buf).into()
}

/// Compute the request ID using flat keccak256(concat(hashed fields)).
/// Mirrors Daml's `computeRequestId` in RequestId.daml.
pub(super) fn compute_request_id(event: &CantonSignBidirectionalRequestedEvent) -> [u8; 32] {
    let key_version_hex = format!("{:x}", event.key_version);

    let mut buf = Vec::with_capacity(9 * 32);
    buf.extend_from_slice(&hash_text(&event.sender));
    buf.extend_from_slice(&hash_evm_params(&event.evm_tx_params));
    buf.extend_from_slice(&hash_text(&event.caip2_id));
    buf.extend_from_slice(&pad_left_32(&key_version_hex));
    buf.extend_from_slice(&hash_text(&event.path));
    buf.extend_from_slice(&hash_text(&event.algo));
    buf.extend_from_slice(&hash_text(&event.dest));
    buf.extend_from_slice(&hash_text(&event.params));
    buf.extend_from_slice(&hash_text(&event.nonce_cid_text));
    keccak256(&buf).into()
}
