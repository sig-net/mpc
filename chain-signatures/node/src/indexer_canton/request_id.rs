use super::contracts::{
    EvmAccessListEntry, EvmType2TransactionParams as CantonEvmType2TransactionParams,
    SignBidirectionalRequestedEvent, TxParams,
};
use alloy::primitives::{keccak256, Address, U256};
use alloy_sol_types::SolValue;

fn extend_eip712_u256(buf: &mut Vec<u8>, hex: &str) -> anyhow::Result<()> {
    let value = U256::from_str_radix(hex, 16)?;
    buf.extend_from_slice(value.eip712_data_word().as_slice());
    Ok(())
}

fn hash_storage_keys(storage_keys: &[String]) -> anyhow::Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(storage_keys.len() * 32);
    for storage_key in storage_keys {
        buf.extend(hex::decode(storage_key)?);
    }
    Ok(keccak256(&buf).into())
}

fn hash_access_list_entry(entry: &EvmAccessListEntry) -> anyhow::Result<[u8; 32]> {
    let address: Address = format!("0x{}", entry.address).parse()?;

    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(address.eip712_data_word().as_slice());
    buf.extend_from_slice(&hash_storage_keys(&entry.storage_keys)?);
    Ok(keccak256(&buf).into())
}

fn hash_access_list(access_list: &[EvmAccessListEntry]) -> anyhow::Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(access_list.len() * 32);
    for entry in access_list {
        buf.extend_from_slice(&hash_access_list_entry(entry)?);
    }
    Ok(keccak256(&buf).into())
}

fn hash_evm_type2_params(p: &CantonEvmType2TransactionParams) -> anyhow::Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(9 * 32);

    for value in [
        &p.chain_id,
        &p.nonce,
        &p.max_priority_fee_per_gas,
        &p.max_fee_per_gas,
        &p.gas_limit,
    ] {
        extend_eip712_u256(&mut buf, value)?;
    }
    match &p.to {
        Some(address) => {
            let address: Address = format!("0x{address}").parse()?;
            buf.extend_from_slice(address.eip712_data_word().as_slice());
        }
        None => {
            let empty_hash: [u8; 32] = keccak256([]).into();
            buf.extend_from_slice(&empty_hash);
        }
    }
    extend_eip712_u256(&mut buf, &p.value)?;
    buf.extend_from_slice(keccak256(hex::decode(&p.calldata)?).as_slice());
    buf.extend_from_slice(&hash_access_list(&p.access_list)?);

    Ok(keccak256(&buf).into())
}

fn hash_tx_params(cp: &TxParams) -> anyhow::Result<[u8; 32]> {
    match cp {
        TxParams::EvmType2TxParams(p) => hash_evm_type2_params(p),
    }
}

pub fn compute_request_id(event: &SignBidirectionalRequestedEvent) -> anyhow::Result<[u8; 32]> {
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
