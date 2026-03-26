use anyhow::{Context, Result};
use ethers::abi::{encode, Token};
use ethers::contract::abigen;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, H256, U256};
use ethers::utils::keccak256;
use mpc_node::indexer_eth::EthConfig;
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use std::sync::Arc;

abigen!(
    ChainSignaturesContract,
    "../chain-signatures/contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
);

pub type SandboxMiddleware = SignerMiddleware<Provider<Http>, LocalWallet>;

#[derive(Clone, Debug)]
pub struct KurtosisEthereumConfig {
    pub account_sk: String,
    pub consensus_rpc_http_url: String,
    pub execution_rpc_http_url: String,
    pub network: String,
    pub helios_data_path: String,
    pub refresh_finalized_interval: u64,
}

impl KurtosisEthereumConfig {
    pub fn from_env() -> Result<Self> {
        let account_sk = env::var("KURTOSIS_ETH_ACCOUNT_SK")
            .context("missing KURTOSIS_ETH_ACCOUNT_SK for Kurtosis Ethereum tests")?;
        let execution_rpc_http_url = env::var("KURTOSIS_ETH_EXECUTION_RPC_HTTP_URL")
            .context("missing KURTOSIS_ETH_EXECUTION_RPC_HTTP_URL for Kurtosis Ethereum tests")?;
        let consensus_rpc_http_url = env::var("KURTOSIS_ETH_CONSENSUS_RPC_HTTP_URL")
            .unwrap_or_else(|_| execution_rpc_http_url.clone());
        let network = env::var("KURTOSIS_ETH_NETWORK").unwrap_or_else(|_| "sepolia".to_string());
        let helios_data_path = env::var("KURTOSIS_ETH_HELIOS_DATA_PATH")
            .unwrap_or_else(|_| "/tmp/helios-kurtosis".to_string());
        let refresh_finalized_interval = env::var("KURTOSIS_ETH_REFRESH_FINALIZED_INTERVAL_MS")
            .ok()
            .map(|value| value.parse())
            .transpose()
            .context("invalid KURTOSIS_ETH_REFRESH_FINALIZED_INTERVAL_MS")?
            .unwrap_or(1_000);

        Ok(Self {
            account_sk,
            consensus_rpc_http_url,
            execution_rpc_http_url,
            network,
            helios_data_path,
            refresh_finalized_interval,
        })
    }

    pub fn eth_config(&self, contract_address: Address, optimistic_requests: bool) -> EthConfig {
        EthConfig {
            account_sk: self.account_sk.clone(),
            consensus_rpc_http_url: self.consensus_rpc_http_url.clone(),
            execution_rpc_http_url: self.execution_rpc_http_url.clone(),
            contract_address: format!("{:x}", contract_address),
            network: self.network.clone(),
            helios_data_path: self.helios_data_path.clone(),
            refresh_finalized_interval: self.refresh_finalized_interval,
            optimistic_requests,
            light_client: false,
        }
    }

    pub fn from_kurtosis_values_env(
        values_env: &str,
        execution_rpc_http_url: String,
        consensus_rpc_http_url: String,
        helios_data_path: String,
        refresh_finalized_interval: u64,
    ) -> Result<(Self, u64)> {
        let values = parse_kurtosis_values_env(values_env)?;
        let mnemonic = values
            .get("EL_AND_CL_MNEMONIC")
            .context("missing EL_AND_CL_MNEMONIC in Kurtosis values.env")?;
        let chain_id = values
            .get("CHAIN_ID")
            .context("missing CHAIN_ID in Kurtosis values.env")?
            .parse::<u64>()
            .context("invalid CHAIN_ID in Kurtosis values.env")?;

        Ok((
            Self {
                account_sk: derive_secret_key(mnemonic)?,
                consensus_rpc_http_url,
                execution_rpc_http_url,
                network: "sepolia".to_string(),
                helios_data_path,
                refresh_finalized_interval,
            },
            chain_id,
        ))
    }
}

#[derive(Clone, Debug)]
pub enum EthereumTarget {
    Sandbox,
    Kurtosis,
}

pub fn parse_kurtosis_values_env(contents: &str) -> Result<HashMap<String, String>> {
    let mut values = HashMap::new();

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || !line.starts_with("export ") {
            continue;
        }

        let Some((key, value)) = line[7..].split_once('=') else {
            continue;
        };

        values.insert(key.trim().to_string(), strip_shell_quotes(value.trim()).to_string());
    }

    Ok(values)
}

fn strip_shell_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value)
}

fn derive_secret_key(mnemonic: &str) -> Result<String> {
    use ethers::signers::{coins_bip39::English, MnemonicBuilder};

    let wallet = MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .derivation_path("m/44'/60'/0'/0/0")?
        .build()?;
    let bytes = wallet.signer().to_bytes();

    Ok(format!("0x{}", hex::encode(bytes)))
}

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
    let tokens = vec![
        Token::Address(requester),
        Token::Bytes(payload.to_vec()),
        Token::String(path.to_string()),
        Token::Uint(U256::from(key_version)),
        Token::Uint(chain_id),
        Token::String(algo.to_string()),
        Token::String(dest.to_string()),
        Token::String(params.to_string()),
    ];
    H256::from(keccak256(encode(&tokens)))
}

pub use chain_signatures_contract::{
    ChainSignaturesContract, ChainSignaturesContractEvents, SignRequest, SignatureRespondedFilter,
};
