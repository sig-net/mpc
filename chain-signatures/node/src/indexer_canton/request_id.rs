use super::contracts::{EvmTransactionParams as CantonEvmTransactionParams, TxParams};
use super::CantonSignBidirectionalRequestedEvent;
use alloy::primitives::{keccak256, U256};
use alloy_sol_types::SolValue;

fn hash_evm_params(p: &CantonEvmTransactionParams) -> [u8; 32] {
    let mut buf = Vec::with_capacity(9 * 32);

    buf.extend_from_slice(p.parse_to_address().eip712_data_word().as_slice());
    buf.extend_from_slice(p.function_signature.as_str().eip712_data_word().as_slice());

    let args_bytes: Vec<Vec<u8>> = p
        .args
        .iter()
        .map(|h| hex::decode(h).unwrap_or_default())
        .collect();
    buf.extend_from_slice(args_bytes.eip712_data_word().as_slice());

    buf.extend_from_slice(p.parse_value_u256().eip712_data_word().as_slice());
    buf.extend_from_slice(p.parse_nonce_u256().eip712_data_word().as_slice());
    buf.extend_from_slice(p.parse_gas_limit_u256().eip712_data_word().as_slice());
    buf.extend_from_slice(p.parse_max_fee_per_gas_u256().eip712_data_word().as_slice());
    buf.extend_from_slice(
        p.parse_max_priority_fee_u256()
            .eip712_data_word()
            .as_slice(),
    );
    buf.extend_from_slice(p.parse_chain_id_u256().eip712_data_word().as_slice());

    keccak256(&buf).into()
}

fn hash_tx_params(cp: &TxParams) -> [u8; 32] {
    match cp {
        TxParams::EvmTxParams(p) => hash_evm_params(p),
    }
}

/// TODO(test): golden-test against the TypeScript/Daml reference implementation.
/// Generate expected request IDs from the TS canton-sig package with known
/// event payloads, then assert this function produces identical outputs.
pub fn compute_request_id(event: &CantonSignBidirectionalRequestedEvent) -> [u8; 32] {
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
