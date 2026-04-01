use anyhow::{Context, Result};
use alloy::primitives::{keccak256, Address as AlloyAddress, U256 as AlloyU256};
use alloy::sol_types::SolEvent;
use ethers::contract::abigen;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address as EthersAddress, H256, TransactionRequest, U256 as EthersU256};
use rand::thread_rng;
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

pub type Address = AlloyAddress;
pub type U256 = AlloyU256;
pub type SandboxMiddleware = SignerMiddleware<Provider<Http>, LocalWallet>;

pub fn to_ethers_address(address: Address) -> EthersAddress {
    EthersAddress::from_slice(address.as_slice())
}

pub fn to_ethers_u256(value: U256) -> EthersU256 {
    EthersU256::from_big_endian(&value.to_be_bytes::<32>())
}

fn from_ethers_address(address: EthersAddress) -> Address {
    Address::from_slice(address.as_bytes())
}

pub fn client(
    endpoint: &str,
    secret_key: &str,
    chain_id: u64,
) -> Result<(Arc<SandboxMiddleware>, Address)> {
    let provider = Provider::<Http>::try_from(endpoint)?;
    let wallet = LocalWallet::from_str(secret_key)?;
    let address = from_ethers_address(wallet.address());
    let wallet = wallet.with_chain_id(chain_id);
    let client = Arc::new(SignerMiddleware::new(provider, wallet));
    Ok((client, address))
}

pub fn random_client(endpoint: &str, chain_id: u64) -> Result<(Arc<SandboxMiddleware>, Address)> {
    let provider = Provider::<Http>::try_from(endpoint)?;
    let wallet = LocalWallet::new(&mut thread_rng()).with_chain_id(chain_id);
    let address = from_ethers_address(wallet.address());
    let client = Arc::new(SignerMiddleware::new(provider, wallet));
    Ok((client, address))
}

pub fn address_from_low_u64_be(value: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&value.to_be_bytes());
    Address::from_slice(&bytes)
}

pub fn value_transfer(to: Address, value: U256) -> TransactionRequest {
    TransactionRequest::new()
        .to(to_ethers_address(to))
        .value(to_ethers_u256(value))
}

pub async fn send_transaction_and_wait(
    client: &Arc<SandboxMiddleware>,
    tx: TransactionRequest,
    dropped_message: &'static str,
) -> Result<()> {
    client
        .send_transaction(tx, None)
        .await?
        .await?
        .context(dropped_message)?;

    Ok(())
}

pub fn signature_from_coordinates(
    x: &[u8],
    y: &[u8],
    s: &[u8],
    recovery_id: u8,
) -> chain_signatures_contract::Signature {
    let big_r = chain_signatures_contract::AffinePoint {
        x: EthersU256::from_big_endian(x),
        y: EthersU256::from_big_endian(y),
    };

    chain_signatures_contract::Signature {
        big_r,
        s: EthersU256::from_big_endian(s),
        recovery_id,
    }
}

pub fn signature_responded_topic() -> H256 {
    H256::from_slice(
        keccak256("SignatureResponded(bytes32,address,((uint256,uint256),uint256,uint8))")
            .as_slice(),
    )
}

pub async fn deploy_chain_signatures(
    client: Arc<SandboxMiddleware>,
    mpc_address: Address,
    signature_deposit: U256,
) -> Result<Address> {
    let contract =
        ChainSignaturesContract::deploy(
            client.clone(),
            (to_ethers_address(mpc_address), to_ethers_u256(signature_deposit)),
        )?
            .send()
            .await?;
    Ok(from_ethers_address(contract.address()))
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
    let chain_id_bytes = chain_id.to_be_bytes::<32>();

    let event = SignatureRequestedEncoding {
        sender: AlloyAddress::from_slice(requester.as_slice()),
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
