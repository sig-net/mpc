use anyhow::Context as _;
use mpc_chain_ethereum::{EthConfig, IndexerConfig};
use secrecy::{ExposeSecret, SecretString};

const DEFAULT_ETH_NETWORK: &str = "sepolia";

/// The indexer's production cadence, as `mpc-chain-ethereum` defines it.
#[cfg(not(feature = "test-feature"))]
fn indexer_config() -> IndexerConfig {
    IndexerConfig::default()
}

/// Test builds run the mock cadence so finality-gated tests finish in seconds.
#[cfg(feature = "test-feature")]
fn indexer_config() -> IndexerConfig {
    mock_indexer_config()
}

/// Polls the finalized head every 100ms instead of the production cadence.
#[cfg(any(test, feature = "test-feature"))]
pub fn mock_indexer_config() -> IndexerConfig {
    IndexerConfig {
        refresh_interval: std::time::Duration::from_millis(100),
        ..Default::default()
    }
}

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

    /// Emit requests without waiting for block finality. FOR DEV/DEMO USE ONLY:
    /// on live networks a reorg can orphan already-emitted sign requests.
    #[arg(long, env("MPC_ETH_OPTIMISTIC_REQUESTS"), default_value = "false")]
    pub eth_optimistic_requests: bool,
}

impl EthArgs {
    pub fn into_config(self) -> anyhow::Result<Option<EthConfig>> {
        let network = self.eth_network;
        if self.eth_optimistic_requests && network == "mainnet" {
            tracing::warn!(
                "eth optimistic requests enabled on mainnet: emitted requests are NOT \
                 reorg-safe; this flag is intended for dev/demo use only"
            );
        }

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
            optimistic_requests: self.eth_optimistic_requests || network == "anvil", // anvil never reports finalized blocks, so requests are emitted without waiting for finality
            network,
            // TODO: currently we only have Ethereum and Sepolia, so defaults
            // are fine. Make these configurable when we add more chains.
            rpc: Default::default(),
            gas: Default::default(),
            publisher: Default::default(),
            indexer: indexer_config(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mock cadence exists to be faster than production; pin that.
    #[test]
    fn mock_cadence_polls_faster_than_production() {
        assert!(mock_indexer_config().refresh_interval < IndexerConfig::default().refresh_interval);
    }

    /// A production build runs the library's cadence.
    #[cfg(not(feature = "test-feature"))]
    #[test]
    fn production_builds_run_the_default_cadence() {
        assert_eq!(
            indexer_config().refresh_interval,
            IndexerConfig::default().refresh_interval
        );
    }

    /// A test build runs the mock cadence.
    #[cfg(feature = "test-feature")]
    #[test]
    fn test_builds_run_the_mock_cadence() {
        assert_eq!(
            indexer_config().refresh_interval,
            mock_indexer_config().refresh_interval
        );
    }
}
