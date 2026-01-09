use anyhow::{anyhow, Result};
use alloy::primitives::{keccak256, Address as AlloyAddress};
use alloy_sol_types::SolValue;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::eth_client::EthClient;

pub fn client(endpoint: &str, secret_key: &str, chain_id: u64) -> Result<EthClient> {
    Ok(EthClient::new(endpoint, secret_key, chain_id)?)
}

#[derive(Debug, Clone)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
    pub algo: String,
    pub dest: String,
    pub params: String,
}

pub async fn deploy_chain_signatures(client: &EthClient, mpc_address: AlloyAddress, signature_deposit: u64) -> Result<AlloyAddress> {
    // Read artifact bytecode
    let mut file = File::open("../chain-signatures/contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json")?;
    let mut s = String::new();
    file.read_to_string(&mut s)?;
    let v: Value = serde_json::from_str(&s)?;
    let bytecode_hex = v["bytecode"].as_str().ok_or_else(|| anyhow!("missing bytecode"))?;
    let bytecode_bytes = hex::decode(bytecode_hex.trim_start_matches("0x"))?;

    // constructor args encoding: (address, uint256)
    let args = (mpc_address, signature_deposit);
    let mut concat = bytecode_bytes.clone();
    let encoded_args = args.abi_encode();
    concat.extend_from_slice(&encoded_args);

    let tx_hash = client.send_raw_tx(None, 0, concat).await?;
    let receipt = client.wait_for_receipt(&tx_hash, std::time::Duration::from_secs(10)).await?;
    let contract_addr = receipt.get("contractAddress").ok_or_else(|| anyhow!("missing contract address"))?;
    let addr_str = contract_addr.as_str().ok_or_else(|| anyhow!("invalid contract address"))?;
    let bytes = hex::decode(addr_str.trim_start_matches("0x"))?;
    if bytes.len() != 20 {
        anyhow::bail!("invalid contract address length: {}", bytes.len());
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    let addr = AlloyAddress::from(arr);
    Ok(addr)
}

#[allow(clippy::too_many_arguments)]
pub fn compute_request_id(
    requester: AlloyAddress,
    payload: [u8; 32],
    path: &str,
    key_version: u32,
    chain_id: u64,
    algo: &str,
    dest: &str,
    params: &str,
) -> [u8; 32] {
    // Encode using alloy ABI encode (non-packed) to match solidity `abi.encode(...)`
    let encoded = (
        requester,
        payload.to_vec(),
        path.to_string(),
        key_version,
        chain_id,
        algo.to_string(),
        dest.to_string(),
        params.to_string(),
    )
    .abi_encode();

    *keccak256(&encoded)
}

pub async fn send_sign_request(client: &EthClient, contract: AlloyAddress, request: SignRequest, value: u64) -> Result<String> {
    // selector: sign((bytes32,string,uint32,string,string,string))
    let sig = "sign((bytes32,string,uint32,string,string,string))";
    let selector = &keccak256(sig.as_bytes())[0..4];

    let args = (
        request.payload.to_vec(),
        request.path.clone(),
        request.key_version,
        request.algo.clone(),
        request.dest.clone(),
        request.params.clone(),
    );
    let mut data = selector.to_vec();
    data.extend_from_slice(&args.abi_encode());

    client.send_raw_tx(Some(contract), value, data).await
}

