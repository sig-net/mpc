use anyhow::Context as _;
use mpc_chain_tron::TronConfig;
use secrecy::{ExposeSecret as _, SecretString};
use std::time::Duration;

/// CLI arguments for the Tron execution watcher (target-only chain).
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_tron_options")]
pub struct TronArgs {
    /// Tron HTTP API endpoint (e.g. https://api.trongrid.io).
    #[arg(long, env("MPC_TRON_ENDPOINT"), hide_env_values = true)]
    pub tron_endpoint: Option<String>,
    /// `TRON-PRO-API-KEY` header value when the provider is TronGrid.
    #[arg(
        long,
        env("MPC_TRON_API_KEY"),
        hide_env_values = true,
        requires = "tron_endpoint"
    )]
    pub tron_api_key: Option<SecretString>,
    /// Delay between receipt polls, in milliseconds.
    #[arg(
        long,
        env("MPC_TRON_POLL_INTERVAL_MS"),
        default_value_t = TronConfig::DEFAULT_POLL_INTERVAL_MS
    )]
    pub tron_poll_interval_ms: u64,
}

impl TronArgs {
    pub fn into_config(self) -> anyhow::Result<Option<TronConfig>> {
        let Some(tron_endpoint) = self.tron_endpoint else {
            return Ok(None);
        };
        let config = TronConfig {
            endpoint: tron_endpoint.parse().context("invalid tron endpoint")?,
            api_key: self.tron_api_key.map(|key| key.expose_secret().to_string()),
            poll_interval: Duration::from_millis(self.tron_poll_interval_ms),
            ..TronConfig::default()
        };
        config.validate()?;
        Ok(Some(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use url::Url;

    #[test]
    fn unconfigured_yields_no_config() {
        assert!(TronArgs::parse_from(["test"])
            .into_config()
            .unwrap()
            .is_none());
    }

    #[test]
    fn into_config_parses_the_configured_fields() {
        let args = TronArgs {
            tron_endpoint: Some("https://api.trongrid.io".to_string()),
            tron_api_key: Some("tron-key".to_string().into()),
            tron_poll_interval_ms: 250,
        };
        let config = args.into_config().unwrap().expect("configured chain");
        assert_eq!(
            config.endpoint,
            Url::parse("https://api.trongrid.io").unwrap()
        );
        assert_eq!(config.api_key.as_deref(), Some("tron-key"));
        assert_eq!(config.poll_interval, Duration::from_millis(250));
    }

    #[test]
    fn into_config_rejects_an_invalid_endpoint() {
        let args = TronArgs::parse_from(["test", "--tron-endpoint", "not a url"]);
        assert!(args.into_config().is_err());
    }

    /// `validate` gates what `spawn_indexers` builds the watcher from.
    #[test]
    fn into_config_runs_config_validation() {
        let args = TronArgs {
            tron_endpoint: Some("https://api.trongrid.io".to_string()),
            tron_api_key: None,
            tron_poll_interval_ms: 0,
        };
        assert!(args.into_config().is_err());
    }
}
