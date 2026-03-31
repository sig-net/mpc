use anyhow::Result;
use alloy::primitives::{keccak256, Address as AlloyAddress, U256 as AlloyU256};
use alloy::sol_types::SolEvent;
use ethers::contract::abigen;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, H256, U256};
use std::str::FromStr;
use std::sync::Arc;

alloy::sol! {
    event SignatureRequestedEncoding(
        address sender,
        bytes payload,
        string path,
        uint32 keyVersion,
        uint256 chainId,
        string algo,
        string dest,
        string params
    );
}

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
    let mut chain_id_bytes = [0u8; 32];
    chain_id.to_big_endian(&mut chain_id_bytes);

    let event = SignatureRequestedEncoding {
        sender: AlloyAddress::from_slice(requester.as_bytes()),
        payload: payload.to_vec().into(),
        path: path.to_string(),
        keyVersion: key_version,
        chainId: AlloyU256::from_be_bytes(chain_id_bytes),
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    };

    H256::from_slice(keccak256(event.encode_data()).as_slice())
}

pub use chain_signatures_contract::{
    ChainSignaturesContract, ChainSignaturesContractEvents, SignRequest, SignatureRespondedFilter,
};
