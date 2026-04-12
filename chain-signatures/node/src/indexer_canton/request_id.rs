// EIP-712 primitive encoding via alloy's SolValue::eip712_data_word().
// The outer compute_request_id remains flat keccak256(concat(...)) to match
// the Daml implementation -- only the per-field encoding uses EIP-712 rules.

use super::CantonSignBidirectionalRequestedEvent;
use super::contracts::{TxParams, EvmTransactionParams as CantonEvmTransactionParams};
use alloy::primitives::{Address, U256, keccak256};
use alloy_sol_types::SolValue;

/// Hash EvmTransactionParams -- mirrors Daml's `hashEvmParams` in RequestId.daml.
fn hash_evm_params(p: &CantonEvmTransactionParams) -> [u8; 32] {
    let mut buf = Vec::with_capacity(9 * 32);

    // EIP-712 address encoding
    let to_bytes = hex::decode(&p.to).unwrap_or_default();
    let addr_start = to_bytes.len().saturating_sub(20);
    let addr = Address::from_slice(&to_bytes[addr_start..]);
    buf.extend_from_slice(addr.eip712_data_word().as_slice());

    // EIP-712 string encoding
    buf.extend_from_slice(p.function_signature.as_str().eip712_data_word().as_slice());

    // EIP-712 bytes[] encoding
    let args_bytes: Vec<Vec<u8>> = p
        .args
        .iter()
        .map(|h| hex::decode(h).unwrap_or_default())
        .collect();
    buf.extend_from_slice(args_bytes.eip712_data_word().as_slice());

    // EIP-712 uint256 encoding
    let value = U256::from_str_radix(&p.value, 16).unwrap_or(U256::ZERO);
    buf.extend_from_slice(value.eip712_data_word().as_slice());

    let nonce = U256::from_str_radix(&p.nonce, 16).unwrap_or(U256::ZERO);
    buf.extend_from_slice(nonce.eip712_data_word().as_slice());

    let gas_limit = U256::from_str_radix(&p.gas_limit, 16).unwrap_or(U256::ZERO);
    buf.extend_from_slice(gas_limit.eip712_data_word().as_slice());

    let max_fee = U256::from_str_radix(&p.max_fee_per_gas, 16).unwrap_or(U256::ZERO);
    buf.extend_from_slice(max_fee.eip712_data_word().as_slice());

    let max_priority = U256::from_str_radix(&p.max_priority_fee, 16).unwrap_or(U256::ZERO);
    buf.extend_from_slice(max_priority.eip712_data_word().as_slice());

    let chain_id = U256::from_str_radix(&p.chain_id, 16).unwrap_or(U256::ZERO);
    buf.extend_from_slice(chain_id.eip712_data_word().as_slice());

    keccak256(&buf).into()
}

/// Dispatch to the correct chain-specific hash function.
/// Mirrors Daml's `hashTxParams` in RequestId.daml.
fn hash_tx_params(cp: &TxParams) -> [u8; 32] {
    match cp {
        TxParams::EvmTxParams(p) => hash_evm_params(p),
    }
}

/// Compute the request ID using flat keccak256(concat(hashed fields)).
/// Mirrors Daml's `computeRequestId` in RequestId.daml.
///
/// TODO(test): golden-test against the TypeScript/Daml reference implementation.
/// Generate expected request IDs from the TS canton-sig package with known
/// event payloads, then assert this function produces identical outputs.
pub(super) fn compute_request_id(event: &CantonSignBidirectionalRequestedEvent) -> [u8; 32] {
    let key_version = U256::from(event.key_version);

    let mut buf = Vec::with_capacity(9 * 32);
    buf.extend_from_slice(event.sender.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(&hash_tx_params(&event.tx_params));
    buf.extend_from_slice(event.caip2_id.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(key_version.eip712_data_word().as_slice());
    buf.extend_from_slice(event.path.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.algo.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.dest.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.params.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.nonce_cid_text.as_str().eip712_data_word().as_slice());
    keccak256(&buf).into()
}
