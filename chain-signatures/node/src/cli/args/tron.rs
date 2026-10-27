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
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(6);

        // Only emit flags if Tron is configured
        if let Some(tron_endpoint) = self.tron_endpoint {
            args.extend(["--tron-endpoint".to_string(), tron_endpoint]);
            if let Some(tron_api_key) = self.tron_api_key {
                args.extend([
                    "--tron-api-key".to_string(),
                    tron_api_key.expose_secret().to_string(),
                ]);
            }
            args.extend([
                "--tron-poll-interval-ms".to_string(),
                self.tron_poll_interval_ms.to_string(),
            ]);
        }
        args
    }

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

    pub fn from_config(config: Option<TronConfig>) -> Self {
        match config {
            Some(config) => Self {
                tron_endpoint: Some(config.endpoint.to_string()),
                tron_api_key: config.api_key.map(Into::into),
                tron_poll_interval_ms: config.poll_interval.as_millis() as u64,
            },
            None => Self {
                tron_endpoint: None,
                tron_api_key: None,
                tron_poll_interval_ms: TronConfig::DEFAULT_POLL_INTERVAL_MS,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_emits_no_args() {
        assert!(TronArgs::from_config(None).into_str_args().is_empty());
    }
}
