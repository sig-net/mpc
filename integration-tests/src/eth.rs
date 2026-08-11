use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy::providers::{Provider, ProviderBuilder, RootProvider, WalletProvider};
use alloy::rpc::types::request::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use mpc_chain_ethereum::abi::{
    ChainSignatures::{self, SignRequest},
    ChainSignaturesConstructor,
};
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
    B256::from(mpc_chain_ethereum::generate_request_id(
        requester,
        &payload,
        path,
        key_version,
        chain_id,
        algo,
        dest,
        params,
    ))
}
