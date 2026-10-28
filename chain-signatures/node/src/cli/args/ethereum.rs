use anyhow::Context as _;
use mpc_chain_ethereum::EthConfig;
use secrecy::{ExposeSecret, SecretString};

const DEFAULT_ETH_NETWORK: &str = "sepolia";

// Configures Ethereum indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_eth_options")]
pub struct EthArgs {
    // -- Core --
    /// The ethereum account secret key used to sign eth respond txn.
    #[arg(
        long,
        env("MPC_ETH_ACCOUNT_SK"),
        hide_env_values = true,
        requires_all = ["eth_execution_rpc_http_url", "eth_contract_address"]
    )]
    pub eth_account_sk: Option<SecretString>,
    /// The contract address to watch, with or without the `0x` prefix
    #[arg(long, env("MPC_ETH_CONTRACT_ADDRESS"), requires = "eth_account_sk")]
    pub eth_contract_address: Option<String>,

    // -- RPC endpoints --
    /// Ethereum execution RPC URL
    #[arg(
        long,
        env("MPC_ETH_EXECUTION_RPC_HTTP_URL"),
        hide_env_values = true,
        requires = "eth_account_sk"
    )]
    pub eth_execution_rpc_http_url: Option<String>,

    /// The network that the eth indexer is running on: "sepolia"/"mainnet",
    /// or "anvil" for local dev chains (anvil never reports finalized blocks,
    /// so requests are emitted without waiting for finality).
    #[arg(
        long,
        env("MPC_ETH_NETWORK"),
        default_value = DEFAULT_ETH_NETWORK,
        value_parser = ["sepolia", "mainnet", "anvil"],
    )]
    pub eth_network: String,
}

impl EthArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(10);
        if let Some(eth_account_sk) = self.eth_account_sk {
            args.extend([
                "--eth-account-sk".to_string(),
                eth_account_sk.expose_secret().to_string(),
            ]);
        }
        if let Some(eth_execution_rpc_http_url) = self.eth_execution_rpc_http_url {
            args.extend([
                "--eth-execution-rpc-http-url".to_string(),
                eth_execution_rpc_http_url,
            ]);
        }
        if let Some(eth_contract_address) = self.eth_contract_address {
            args.extend(["--eth-contract-address".to_string(), eth_contract_address]);
        }
        args.extend(["--eth-network".to_string(), self.eth_network]);
        args
    }

    pub fn into_config(self) -> anyhow::Result<Option<EthConfig>> {
        let network = self.eth_network;
        let Some(account_sk) = self.eth_account_sk else {
            return Ok(None);
        };
        let account_sk = account_sk
            .expose_secret()
            .parse()
            .context("invalid eth account sk")?;
        let execution_rpc_http_url = self
            .eth_execution_rpc_http_url
            .context("eth execution rpc http url is required")?
            .parse()
            .context("invalid eth execution rpc http url")?;
        let contract_address = self
            .eth_contract_address
            .context("eth contract address is required")?
            .parse()
            .context("invalid eth contract address")?;

        Ok(Some(EthConfig {
            account_sk, // this is safe because EthConfig has custom Debug implementation that redacts the account_sk field
            execution_rpc_http_url,
            contract_address,
            // anvil never reports finalized blocks, so requests are emitted without waiting for finality
            optimistic_requests: network == "anvil",
            network,
            // TODO: currently we only have Ethereum and Sepolia, so defaults
            // are fine. Make these configurable when we add more chains.
            rpc: Default::default(),
            gas: Default::default(),
            publisher: Default::default(),
            indexer: Default::default(),
        }))
    }

    pub fn from_config(config: Option<EthConfig>) -> Self {
        match config {
            Some(config) => Self {
                eth_account_sk: Some(hex::encode(config.account_sk.credential().to_bytes()).into()),
                eth_execution_rpc_http_url: Some(config.execution_rpc_http_url.to_string()),
                eth_contract_address: Some(config.contract_address.to_string()),
                eth_network: config.network,
            },
            _ => Self {
                eth_account_sk: None,
                eth_execution_rpc_http_url: None,
                eth_contract_address: None,
                eth_network: DEFAULT_ETH_NETWORK.to_string(),
            },
        }
    }
}
