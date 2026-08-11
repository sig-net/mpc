//! Test harness for the `integration` feature: spawns a local Anvil node and
//! deploys the real `ChainSignatures` contract bytecode, so the publisher's
//! publish path can be exercised end-to-end against a real EVM.

use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::request::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use mpc_chain_ethereum::abi::ChainSignaturesConstructor;
use mpc_chain_ethereum::{EthConfig, PublisherConfig};
use serde_json::Value;
use std::time::Duration;

pub type AnvilWalletProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

/// Local Anvil + deployed `ChainSignatures`
#[allow(dead_code)]
pub struct EthTestEnv {
    /// Anvil instance, killed when dropped.
    pub anvil: AnvilInstance,
    /// Wallet-backed provider (anvil dev account #0) for deploys, reads, sign requests.
    pub provider: AnvilWalletProvider,
    pub contract_address: Address,
    pub signer: PrivateKeySigner,
    pub chain_id: u64,
    /// Ethereum chain integration configuration for the publisher.
    pub eth_config: EthConfig,
}

impl EthTestEnv {
    pub async fn new() -> Result<Self> {
        // TODO: replace manual spawn + key extraction with `ProviderBuilder::new().connect_anvil_with_wallet()` after alloy crate update to 2.0.0
        let anvil = Anvil::new().spawn();
        let chain_id = anvil.chain_id();
        let endpoint = anvil.endpoint();

        let key_bytes = anvil.first_key().to_bytes();
        let signer = PrivateKeySigner::from_slice(&key_bytes)
            .expect("anvil dev key is valid")
            .with_chain_id(Some(chain_id));
        let address = signer.address();

        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(endpoint.parse()?);

        let contract_address =
            deploy_chain_signatures(provider.clone(), address, address, U256::from(1_u64))
                .await?;

        let eth_config = EthConfig {
            account_sk: signer.clone(),
            consensus_rpc_http_url: endpoint.clone(),
            execution_rpc_http_url: endpoint.parse()?,
            contract_address,
            network: "anvil".to_string(),
            helios_data_path: String::new(),
            refresh_finalized_interval: 1000,
            optimistic_requests: false,
            light_client: false,
            rpc: Default::default(),
            gas: Default::default(),
            publisher: PublisherConfig {
                batch_flush_interval: Duration::from_millis(100), // faster flush for tests
                ..Default::default()
            },
            indexer: Default::default(),
        };

        Ok(Self {
            anvil,
            provider,
            contract_address,
            signer,
            chain_id,
            eth_config,
        })
    }

    /// Fresh contract instance bound to this env's provider.
    pub fn contract(
        &self,
    ) -> ChainSignatures::ChainSignaturesInstance<AnvilWalletProvider> {
        ChainSignatures::new(self.contract_address, self.provider.clone())
    }
}

/// Deploy `ChainSignatures` (uninitialized) via raw bytecode + constructor args.
///
/// Ported from `integration-tests/src/eth.rs`. The manual create-tx path is used
/// because `alloy::sol!` on a JSON artifact generates an interface (not a
/// contract) on 1.0.38, so the idiomatic `deploy()`/`deploy_builder()` are not
/// available.
pub async fn deploy_chain_signatures<P>(
    provider: P,
    deployer: Address,
    mpc_address: Address,
    signature_deposit: U256,
) -> Result<Address>
where
    P: Provider + Clone + 'static,
{
    let artifact: Value = serde_json::from_slice(include_bytes!(
        "../../../contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
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
            deployer,
        ),
        Bytes::from(deployment),
    );

    let pending = provider.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;
    Ok(receipt
        .contract_address
        .context("deployment receipt missing contract address")?)
}
