use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy::providers::{ProviderBuilder, RootProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use anyhow::Result;

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
