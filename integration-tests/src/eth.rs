use alloy::network::EthereumWallet;
use alloy::primitives::{Address, B256, U256};
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
