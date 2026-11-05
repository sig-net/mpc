use anyhow::Context as _;
use clap::builder::{PossibleValuesParser, TypedValueParser as _};
use mpc_chain_ethereum::{EthConfig, EthNetwork, IndexerConfig};
use secrecy::{ExposeSecret, SecretString};

/// Networks a production node may serve.
#[cfg(not(feature = "test-feature"))]
const NETWORKS: &[EthNetwork] = &[EthNetwork::Sepolia, EthNetwork::Mainnet];

/// Test builds add anvil, whose requests skip finality: it never reports
/// finalized blocks.
#[cfg(feature = "test-feature")]
const NETWORKS: &[EthNetwork] = &[EthNetwork::Sepolia, EthNetwork::Mainnet, EthNetwork::Anvil];

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
        requires_all = ["eth_execution_rpc_http_url", "eth_contract_address", "eth_network"]
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

    /// The network the RPC serves.
    #[arg(
        long,
        env("MPC_ETH_NETWORK"),
        requires = "eth_account_sk",
        value_parser = PossibleValuesParser::new(NETWORKS.iter().map(|network| network.as_str()))
            .try_map(|name| name.parse::<EthNetwork>()),
    )]
    pub eth_network: Option<EthNetwork>,
}

impl EthArgs {
    pub fn into_config(self) -> anyhow::Result<Option<EthConfig>> {
        let Some(account_sk) = self.eth_account_sk else {
            return Ok(None);
        };
        let account_sk = account_sk
            .expose_secret()
            .parse()
            .context("invalid eth account sk")?;
        let network = self.eth_network.context("eth network is required")?;
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
            optimistic_requests: network.is_optimistic(),
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
    use clap::Parser as _;

    const ACCOUNT_SK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const RPC_URL: &str = "http://127.0.0.1:8545";
    const CONTRACT: &str = "0x1234567890123456789012345678901234567890";

    fn configured(network: &str) -> EthArgs {
        EthArgs::parse_from(argv(network, CONTRACT))
    }

    fn argv<'a>(network: &'a str, contract: &'a str) -> [&'a str; 9] {
        [
            "test",
            "--eth-account-sk",
            ACCOUNT_SK,
            "--eth-execution-rpc-http-url",
            RPC_URL,
            "--eth-contract-address",
            contract,
            "--eth-network",
            network,
        ]
    }

    #[test]
    fn unconfigured_yields_no_config() {
        assert!(EthArgs::parse_from(["test"])
            .into_config()
            .unwrap()
            .is_none());
    }

    #[test]
    fn into_config_parses_the_configured_fields() {
        let config = configured("mainnet")
            .into_config()
            .unwrap()
            .expect("configured chain");
        assert_eq!(
            config.execution_rpc_http_url.as_str(),
            "http://127.0.0.1:8545/"
        );
        assert_eq!(config.contract_address.to_string().to_lowercase(), CONTRACT);
        assert_eq!(config.network, EthNetwork::Mainnet);
        assert_eq!(
            config.indexer.refresh_interval,
            indexer_config().refresh_interval
        );
    }

    #[test]
    fn production_networks_wait_for_finality() {
        for network in ["sepolia", "mainnet"] {
            let config = configured(network)
                .into_config()
                .unwrap()
                .expect("configured chain");
            assert!(!config.optimistic_requests, "{network}");
        }
    }

    /// Only anvil skips finality; it never reports finalized blocks.
    #[cfg(feature = "test-feature")]
    #[test]
    fn anvil_is_optimistic_in_test_builds() {
        let config = configured("anvil")
            .into_config()
            .unwrap()
            .expect("configured chain");
        assert!(config.optimistic_requests);
    }

    #[cfg(not(feature = "test-feature"))]
    #[test]
    fn anvil_is_rejected_in_production_builds() {
        assert!(EthArgs::try_parse_from(argv("anvil", CONTRACT)).is_err());
    }

    #[test]
    fn unknown_networks_are_rejected_by_the_cli() {
        assert!(EthArgs::try_parse_from(argv("goerli", CONTRACT)).is_err());
    }

    /// No default network: a configured chain names the network it serves.
    #[test]
    fn the_network_is_required_with_the_chain() {
        let without_network = argv("mainnet", CONTRACT);
        assert!(EthArgs::try_parse_from(&without_network[..7]).is_err());
        assert!(EthArgs::try_parse_from(["test", "--eth-network", "mainnet"]).is_err());
    }

    #[test]
    fn into_config_rejects_an_invalid_rpc_url() {
        let args = EthArgs::parse_from([
            "test",
            "--eth-account-sk",
            ACCOUNT_SK,
            "--eth-execution-rpc-http-url",
            "not a url",
            "--eth-contract-address",
            CONTRACT,
            "--eth-network",
            "mainnet",
        ]);
        assert!(args.into_config().is_err());
    }

    /// The two cadences, pinned: 100ms is also what the Ethereum crate's own
    /// tests use, so a change here must be made there too.
    #[test]
    fn cadences_are_pinned() {
        assert_eq!(
            mock_indexer_config().refresh_interval,
            std::time::Duration::from_millis(100)
        );
        assert_eq!(
            IndexerConfig::default().refresh_interval,
            std::time::Duration::from_secs(10)
        );
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
