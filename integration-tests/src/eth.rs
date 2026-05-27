use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy::providers::{Provider, ProviderBuilder, RootProvider, WalletProvider};
use alloy::rpc::types::request::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use mpc_node::indexer_eth::abi::ChainSignaturesConstructor;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::Value;
use std::time::Duration;

pub type SandboxMiddleware = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<
                alloy::providers::fillers::GasFiller,
                JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

pub fn client(
    endpoint: &str,
    secret_key: &str,
    chain_id: u64,
) -> Result<(SandboxMiddleware, Address)> {
    let signer: PrivateKeySigner = secret_key.parse()?;
    let signer = signer.with_chain_id(Some(chain_id));
    let address = signer.address();
    let wallet = EthereumWallet::from(signer);
    let client = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(endpoint.parse()?);
    Ok((client, address))
}

pub async fn deploy_chain_signatures<P>(
    client: P,
    deployer_address: Address,
    mpc_address: Address,
    signature_deposit: U256,
) -> Result<Address>
where
    P: Provider + Clone + 'static,
{
    let artifact: Value = serde_json::from_slice(include_bytes!(
        "../../chain-signatures/contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
    ))?;

    let bytecode = artifact
        .get("bytecode")
        .and_then(Value::as_str)
        .context("bytecode missing from artifact")?;
    let mut deployment = hex::decode(bytecode.trim_start_matches("0x"))?;

    let constructor_args = ChainSignaturesConstructor {
        mpcNetwork: mpc_address,
        signatureDeposit: signature_deposit,
    };
    deployment.extend_from_slice(&constructor_args.abi_encode());

    let tx = <TransactionRequest as TransactionBuilder<Ethereum>>::with_input(
        <TransactionRequest as TransactionBuilder<Ethereum>>::with_from(
            <TransactionRequest as TransactionBuilder<Ethereum>>::into_create(
                TransactionRequest::default(),
            ),
            deployer_address,
        ),
        Bytes::from(deployment),
    );

    let pending = client.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;
    let contract_address = receipt
        .contract_address
        .context("deployment receipt missing contract address")?;
    Ok(contract_address)
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
) -> B256 {
    B256::from(encode_request_id(
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
        offset_word[WORD_SIZE - 8..].copy_from_slice(&(head_size + tails.len()).to_be_bytes());
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
    address_word[12..].copy_from_slice(requester.as_slice());
    heads.push(address_word);

    push_dynamic(&mut heads, &mut tails, head_size, payload.as_slice());
    push_dynamic(&mut heads, &mut tails, head_size, path.as_bytes());

    let mut key_version_word = [0u8; WORD_SIZE];
    key_version_word[WORD_SIZE - 4..].copy_from_slice(&key_version.to_be_bytes());
    heads.push(key_version_word);

    heads.push(chain_id.to_be_bytes::<WORD_SIZE>());

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

pub async fn submit_sign_request<P>(
    contract: &ChainSignatures::ChainSignaturesInstance<P>,
    seed: usize,
) -> anyhow::Result<()>
where
    P: Provider + WalletProvider + Clone + Send + Sync + 'static,
{
    const MAX_ATTEMPTS: usize = 3;
    let sender = contract.provider().default_signer_address();

    for attempt in 1..=MAX_ATTEMPTS {
        let payload = [seed as u8; 32];
        let request = SignRequest {
            payload: payload.into(),
            path: format!("offline_test_{seed}"),
            keyVersion: LATEST_MPC_KEY_VERSION,
            algo: "secp256k1".to_string(),
            dest: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            params: "{}".to_string(),
        };

        let nonce = contract
            .provider()
            .get_transaction_count(sender)
            .pending()
            .await?;

        match contract
            .sign(request)
            .value(U256::from(1_u64))
            .nonce(nonce)
            .send()
            .await
        {
            Ok(pending) => {
                pending.get_receipt().await?;
                return Ok(());
            }
            Err(err) => {
                let err_msg = err.to_string();
                let retryable_nonce_error = err_msg.contains("nonce too low")
                    || err_msg.contains("replacement transaction underpriced");
                if retryable_nonce_error && attempt < MAX_ATTEMPTS {
                    tracing::warn!(attempt, nonce, %err, "retrying ethereum sign after nonce conflict");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }

                return Err(err.into());
            }
        }
    }

    Ok(())
}

pub use mpc_node::indexer_eth::abi::ChainSignatures;
pub use mpc_node::indexer_eth::abi::ChainSignatures::{SignRequest, SignatureResponded};

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::b256;

    #[test]
    fn compute_request_id_matches_legacy_ethabi() {
        let requester = Address::from([0u8; 20]);
        let payload = [0x42; 32];
        let path = "test-path";
        let key_version = 7;
        let chain_id = U256::from(31337_u64);
        let algo = "secp256k1";
        let dest = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
        let params = "{}";

        let request_id = compute_request_id(
            requester,
            payload,
            path,
            key_version,
            chain_id,
            algo,
            dest,
            params,
        );

        assert_eq!(
            request_id,
            b256!("33da60f71a3866e6b632c9bbc217017203800f863652bf49d8eba63db977d91c")
        );
    }
}
