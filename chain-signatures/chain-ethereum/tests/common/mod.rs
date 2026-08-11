//! Test harness for the `integration` feature: spawns a local Anvil node and
//! deploys the real `ChainSignatures` contract bytecode, so the publisher's
//! publish path can be exercised end-to-end against a real EVM.

use alloy::network::EthereumWallet;
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use mpc_chain_ethereum::abi::ChainSignatures;
use mpc_chain_ethereum::utils::test::deploy_chain_signatures;
pub use mpc_chain_ethereum::utils::test::submit_sign_request;
use mpc_chain_ethereum::{EthConfig, PublisherConfig};
use std::time::{Duration, Instant};

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
            deploy_chain_signatures(provider.clone(), address, address, U256::from(1_u64)).await?;

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
    pub fn contract(&self) -> ChainSignatures::ChainSignaturesInstance<AnvilWalletProvider> {
        ChainSignatures::new(self.contract_address, self.provider.clone())
    }
}

/// Poll for the `SignatureResponded` log matching `request_id`, returning the
/// responder address.
pub async fn wait_for_responded(
    env: &EthTestEnv,
    request_id: B256,
    timeout: Duration,
) -> Result<Address> {
    let filter = Filter::new()
        .address(env.contract_address)
        .event_signature(ChainSignatures::SignatureResponded::SIGNATURE_HASH)
        .topic1(request_id);
    let deadline = Instant::now() + timeout;
    loop {
        let logs = env.provider.get_logs(&filter).await.context("get_logs")?;
        if let Some(log) = logs.into_iter().next() {
            let event = ChainSignatures::SignatureResponded::decode_log_data(log.data())
                .context("decode SignatureResponded")?;
            return Ok(event.responder);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "SignatureResponded for request_id {request_id:?} not mined within {timeout:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
