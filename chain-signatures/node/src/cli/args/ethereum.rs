use alloy::primitives::Address;
use anyhow::Context as _;
use clap::builder::{PossibleValuesParser, TypedValueParser as _};
use mpc_chain_ethereum::{EthConfig, EthNetwork, IndexerConfig};
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;
use url::Url;

fn indexer_config(eth_refresh: Duration) -> IndexerConfig {
    IndexerConfig {
        refresh_interval: eth_refresh,
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
    pub eth_contract_address: Option<Address>,

    // -- RPC endpoints --
    /// Ethereum execution RPC URL
    #[arg(
        long,
        env("MPC_ETH_EXECUTION_RPC_HTTP_URL"),
        hide_env_values = true,
        requires = "eth_account_sk"
    )]
    pub eth_execution_rpc_http_url: Option<Url>,

    /// The network the RPC serves. On anvil (local dev chains) requests are
    /// emitted without waiting for finality: it never reports finalized blocks.
    #[arg(
        long,
        env("MPC_ETH_NETWORK"),
        default_value_t = EthNetwork::Sepolia,
        value_parser = PossibleValuesParser::new(EthNetwork::ALL.map(EthNetwork::as_str))
            .try_map(|name| name.parse::<EthNetwork>()),
    )]
    pub eth_network: EthNetwork,
}

impl EthArgs {
    pub fn into_config(self, eth_refresh: Duration) -> anyhow::Result<Option<EthConfig>> {
        let Some(account_sk) = self.eth_account_sk else {
            return Ok(None);
        };
        let account_sk = account_sk
            .expose_secret()
            .parse()
            .context("invalid eth account sk")?;
        let execution_rpc_http_url = self
            .eth_execution_rpc_http_url
            .context("eth execution rpc http url is required")?;
        let contract_address = self
            .eth_contract_address
            .context("eth contract address is required")?;

        Ok(Some(EthConfig {
            account_sk, // this is safe because EthConfig has custom Debug implementation that redacts the account_sk field
            execution_rpc_http_url,
            contract_address,
            network: self.eth_network,
            // TODO: currently we only have Ethereum and Sepolia, so defaults
            // are fine. Make these configurable when we add more chains.
            rpc: Default::default(),
            gas: Default::default(),
            publisher: Default::default(),
            indexer: indexer_config(eth_refresh),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cadence::Cadence;
    use clap::Parser as _;

    const ACCOUNT_SK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const RPC_URL: &str = "http://127.0.0.1:8545";
    const CONTRACT: &str = "0x1234567890123456789012345678901234567890";

    fn configured(extra: &[&str]) -> EthArgs {
        let argv = [
            "test",
            "--eth-account-sk",
            ACCOUNT_SK,
            "--eth-execution-rpc-http-url",
            RPC_URL,
            "--eth-contract-address",
            CONTRACT,
        ];
        EthArgs::parse_from(argv.into_iter().chain(extra.iter().copied()))
    }

    #[test]
    fn unconfigured_yields_no_config() {
        assert!(EthArgs::parse_from(["test"])
            .into_config(Cadence::default().eth_refresh())
            .unwrap()
            .is_none());
    }

    #[test]
    fn into_config_parses_the_configured_fields() {
        let refresh = Cadence::default().eth_refresh();
        let config = configured(&["--eth-network", "mainnet"])
            .into_config(refresh)
            .unwrap()
            .expect("configured chain");
        assert_eq!(
            config.execution_rpc_http_url.as_str(),
            "http://127.0.0.1:8545/"
        );
        assert_eq!(
            config.contract_address,
            CONTRACT.parse::<Address>().unwrap()
        );
        assert_eq!(config.network, EthNetwork::Mainnet);
        assert_eq!(config.indexer.refresh_interval, refresh);
    }

    /// Only anvil skips finality; it never reports finalized blocks.
    #[test]
    fn only_anvil_is_optimistic() {
        for (network, optimistic) in [("sepolia", false), ("mainnet", false), ("anvil", true)] {
            let config = configured(&["--eth-network", network])
                .into_config(Cadence::default().eth_refresh())
                .unwrap()
                .expect("configured chain");
            assert_eq!(config.network.is_optimistic(), optimistic, "{network}");
        }
    }

    #[test]
    fn unknown_networks_are_rejected_by_the_cli() {
        assert!(EthArgs::try_parse_from(["test", "--eth-network", "goerli"]).is_err());
    }

    #[test]
    fn the_cli_rejects_an_invalid_rpc_url() {
        assert!(EthArgs::try_parse_from([
            "test",
            "--eth-account-sk",
            ACCOUNT_SK,
            "--eth-execution-rpc-http-url",
            "not a url",
            "--eth-contract-address",
            CONTRACT,
        ])
        .is_err());
    }

    /// The help text promises both spellings.
    #[test]
    fn the_contract_address_parses_with_and_without_the_0x_prefix() {
        let parse = |address| {
            EthArgs::try_parse_from([
                "test",
                "--eth-account-sk",
                ACCOUNT_SK,
                "--eth-execution-rpc-http-url",
                RPC_URL,
                "--eth-contract-address",
                address,
            ])
            .map(|args| args.eth_contract_address.unwrap())
        };
        assert_eq!(parse(CONTRACT).unwrap(), parse(&CONTRACT[2..]).unwrap());
        let error = parse("0x1234").unwrap_err().to_string();
        assert!(
            error.contains("--eth-contract-address"),
            "unexpected address error: {error}"
        );
    }

    /// The two cadences, pinned: 100ms is also what the Ethereum crate's own
    /// tests use, so a change here must be made there too.
    #[test]
    fn cadences_are_pinned() {
        assert_eq!(Cadence::test().eth_refresh(), Duration::from_millis(100));
        assert_eq!(Cadence::default().eth_refresh(), Duration::from_secs(10));
    }
}
