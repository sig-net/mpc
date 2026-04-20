use super::contracts::{EvmTransactionParams as CantonEvmTransactionParams, TxParams};
use super::CantonSignBidirectionalRequestedEvent;
use alloy::primitives::{keccak256, U256};
use alloy_sol_types::SolValue;

fn hex_u256(field: &'static str, hex: &str) -> anyhow::Result<U256> {
    U256::from_str_radix(hex, 16).map_err(|e| anyhow::anyhow!("invalid hex in '{field}': {e}"))
}

fn hash_evm_params(p: &CantonEvmTransactionParams) -> anyhow::Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(9 * 32);

    buf.extend_from_slice(p.parse_to_address()?.eip712_data_word().as_slice());
    buf.extend_from_slice(p.function_signature.as_str().eip712_data_word().as_slice());

    let args_bytes = hex::decode(&p.encoded_args)
        .map_err(|e| anyhow::anyhow!("invalid hex in encodedArgs: {e}"))?;
    buf.extend_from_slice(args_bytes.as_slice().eip712_data_word().as_slice());

    buf.extend_from_slice(hex_u256("value", &p.value)?.eip712_data_word().as_slice());
    buf.extend_from_slice(hex_u256("nonce", &p.nonce)?.eip712_data_word().as_slice());
    buf.extend_from_slice(
        hex_u256("gas_limit", &p.gas_limit)?
            .eip712_data_word()
            .as_slice(),
    );
    buf.extend_from_slice(
        hex_u256("max_fee_per_gas", &p.max_fee_per_gas)?
            .eip712_data_word()
            .as_slice(),
    );
    buf.extend_from_slice(
        hex_u256("max_priority_fee_per_gas", &p.max_priority_fee_per_gas)?
            .eip712_data_word()
            .as_slice(),
    );
    buf.extend_from_slice(
        hex_u256("chain_id", &p.chain_id)?
            .eip712_data_word()
            .as_slice(),
    );

    Ok(keccak256(&buf).into())
}

fn hash_tx_params(cp: &TxParams) -> anyhow::Result<[u8; 32]> {
    match cp {
        TxParams::EvmTxParams(p) => hash_evm_params(p),
    }
}

/// TODO(test): golden-test against the TypeScript/Daml reference implementation.
/// Generate expected request IDs from the TS canton-sig package with known
/// event payloads, then assert this function produces identical outputs.
pub fn compute_request_id(
    event: &CantonSignBidirectionalRequestedEvent,
) -> anyhow::Result<[u8; 32]> {
    let key_version = U256::from(event.key_version);

    let mut buf = Vec::with_capacity(8 * 32);
    buf.extend_from_slice(event.sender.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(&hash_tx_params(&event.tx_params)?);
    buf.extend_from_slice(event.caip2_id.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(key_version.eip712_data_word().as_slice());
    buf.extend_from_slice(event.path.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.algo.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.dest.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.params.as_str().eip712_data_word().as_slice());
    Ok(keccak256(&buf).into())
}
