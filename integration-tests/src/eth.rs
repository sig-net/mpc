use anyhow::Result;
use alloy::primitives::{keccak256, Address as AlloyAddress};
use alloy_sol_types::SolValue;
use ethers::contract::abigen;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, H256, U256};
use std::str::FromStr;
use std::sync::Arc;

abigen!(
    ChainSignaturesContract,
    "../chain-signatures/contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
);

pub type SandboxMiddleware = SignerMiddleware<Provider<Http>, LocalWallet>;

pub fn client(
    endpoint: &str,
    secret_key: &str,
    chain_id: u64,
) -> Result<(Arc<SandboxMiddleware>, Address)> {
    let provider = Provider::<Http>::try_from(endpoint)?;
    let wallet = LocalWallet::from_str(secret_key)?;
    let address = wallet.address();
    let wallet = wallet.with_chain_id(chain_id);
    let client = Arc::new(SignerMiddleware::new(provider, wallet));
    Ok((client, address))
}

pub async fn deploy_chain_signatures(
    client: Arc<SandboxMiddleware>,
    mpc_address: Address,
    signature_deposit: U256,
) -> Result<Address> {
    let contract =
        ChainSignaturesContract::deploy(client.clone(), (mpc_address, signature_deposit))?
            .send()
            .await?;
    Ok(contract.address())
}

#[allow(clippy::too_many_arguments)]
pub fn compute_request_id(
    requester: Address,
    payload: [u8; 32],
    path: &str,
    key_version: u32,
    chain_id: U256,
    algo: &str,
    dest: &str,
    params: &str,
) -> H256 {
    // Encode using alloy ABI encode (non-packed) to match solidity `abi.encode(...)`
    let encoded = (
        AlloyAddress::from(requester.0),
        payload.to_vec(),
        path.to_string(),
        key_version,
        chain_id.as_u64(),
        algo.to_string(),
        dest.to_string(),
        params.to_string(),
    )
    .abi_encode();

    let hash: [u8; 32] = *keccak256(&encoded);
    H256::from(hash)
}

pub use chain_signatures_contract::{
    ChainSignaturesContract, ChainSignaturesContractEvents, SignRequest, SignatureRespondedFilter,
};
