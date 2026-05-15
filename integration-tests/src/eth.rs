use anyhow::Result;
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
    H256::from(encode_request_id(
        requester,
        payload,
        path,
        key_version,
        chain_id,
        algo,
        dest,
        params,
    ))
}

#[allow(clippy::too_many_arguments)]
fn encode_request_id(
    requester: Address,
    payload: [u8; 32],
    path: &str,
    key_version: u32,
    chain_id: U256,
    algo: &str,
    dest: &str,
    params: &str,
) -> [u8; 32] {
    const HEAD_WORDS: usize = 8;
    const WORD_SIZE: usize = 32;

    fn push_dynamic(
        heads: &mut Vec<[u8; WORD_SIZE]>,
        tails: &mut Vec<u8>,
        head_size: usize,
        bytes: &[u8],
    ) {
        let mut offset_word = [0u8; WORD_SIZE];
        offset_word[WORD_SIZE - 8..]
            .copy_from_slice(&(head_size + tails.len() as usize).to_be_bytes());
        heads.push(offset_word);

        let mut len_word = [0u8; WORD_SIZE];
        len_word[WORD_SIZE - 8..].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        tails.extend_from_slice(&len_word);
        tails.extend_from_slice(bytes);

        let padding = (WORD_SIZE - (bytes.len() % WORD_SIZE)) % WORD_SIZE;
        tails.extend(std::iter::repeat_n(0u8, padding));
    }

    let mut heads = Vec::with_capacity(HEAD_WORDS);
    let mut tails = Vec::new();
    let head_size = HEAD_WORDS * WORD_SIZE;

    let mut address_word = [0u8; WORD_SIZE];
    address_word[12..].copy_from_slice(requester.as_bytes());
    heads.push(address_word);

    push_dynamic(&mut heads, &mut tails, head_size, payload.as_slice());
    push_dynamic(&mut heads, &mut tails, head_size, path.as_bytes());

    let mut key_version_word = [0u8; WORD_SIZE];
    key_version_word[WORD_SIZE - 4..].copy_from_slice(&key_version.to_be_bytes());
    heads.push(key_version_word);

    let mut chain_id_word = [0u8; WORD_SIZE];
    chain_id.to_big_endian(&mut chain_id_word);
    heads.push(chain_id_word);

    push_dynamic(&mut heads, &mut tails, head_size, algo.as_bytes());
    push_dynamic(&mut heads, &mut tails, head_size, dest.as_bytes());
    push_dynamic(&mut heads, &mut tails, head_size, params.as_bytes());

    let mut encoded = Vec::with_capacity(head_size + tails.len());
    for head in heads {
        encoded.extend_from_slice(&head);
    }
    encoded.extend_from_slice(&tails);

    *alloy::primitives::keccak256(encoded)
}

pub use chain_signatures_contract::{
    ChainSignaturesContract, ChainSignaturesContractEvents, SignRequest, SignatureRespondedFilter,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::abi::{encode, Token};
    use ethers::utils::keccak256;

    #[test]
    fn compute_request_id_matches_legacy_ethabi() {
        let requester = Address::from_low_u64_be(0x1234);
        let payload = [0x42; 32];
        let path = "test-path";
        let key_version = 7;
        let chain_id = U256::from(31337_u64);
        let algo = "secp256k1";
        let dest = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
        let params = "{}";

        let legacy = H256::from(keccak256(encode(&[
            Token::Address(requester),
            Token::Bytes(payload.to_vec()),
            Token::String(path.to_string()),
            Token::Uint(U256::from(key_version)),
            Token::Uint(chain_id),
            Token::String(algo.to_string()),
            Token::String(dest.to_string()),
            Token::String(params.to_string()),
        ])));

        let alloy = compute_request_id(
            requester,
            payload,
            path,
            key_version,
            chain_id,
            algo,
            dest,
            params,
        );

        assert_eq!(alloy, legacy);
    }
}
