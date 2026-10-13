use mpc_chain_integration_core::utils::retry::RetryConfig;
use std::fmt;
use std::time::Duration;
use url::Url;

/// Tron chain integration configuration.
#[derive(Clone, PartialEq)]
pub struct TronConfig {
    /// Base URL of the provider's HTTP API
    pub endpoint: Url,
    /// `TRON-PRO-API-KEY` header value when the provider is TronGrid, None for other providers.
    pub api_key: Option<String>,
    /// Timeout for HTTP requests to the provider.
    pub request_timeout: Duration,
    /// Retry configuration for HTTP requests to the provider.
    pub retry: RetryConfig,
    /// Delay between `gettransactioninfobyid` polls per pending watcher.
    pub poll_interval: Duration,
}

impl Default for TronConfig {
    fn default() -> Self {
        Self {
            endpoint: Url::parse("https://api.trongrid.io").expect("static URL parses"),
            api_key: None,
            request_timeout: Duration::from_secs(10),
            retry: RetryConfig {
                min_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(10),
                max_times: 5,
                jitter: true,
            },
            poll_interval: Duration::from_secs(15),
        }
    }
}

/// Custom `Debug` implementation that redacts the `api_key` field
impl fmt::Debug for TronConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TronConfig")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"<redacted>")
            .field("request_timeout", &self.request_timeout)
            .field("retry", &self.retry)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

impl TronConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_base_url("endpoint", &self.endpoint)?;
        if let Some(api_key) = &self.api_key {
            anyhow::ensure!(
                !api_key.trim().is_empty(),
                "tron config: api_key must not be blank"
            );
        }
        anyhow::ensure!(
            !self.request_timeout.is_zero(),
            "tron config: request_timeout must be greater than zero"
        );
        anyhow::ensure!(
            !self.poll_interval.is_zero(),
            "tron config: poll_interval must be greater than zero"
        );
        Ok(())
    }
}

fn validate_base_url(field: &str, url: &Url) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "tron config: {field} must use http or https, got {}",
        url.scheme()
    );
    anyhow::ensure!(
        url.path() == "/",
        "tron config: {field} must be a base URL without a path, got {}",
        url
    );
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "tron config: {field} must not carry a query or fragment"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_pinned() {
        let config = TronConfig::default();
        assert_eq!(config.endpoint.as_str(), "https://api.trongrid.io/");
        assert_eq!(config.api_key, None);
        assert_eq!(config.request_timeout, Duration::from_secs(10));
        assert_eq!(config.poll_interval, Duration::from_secs(15));
        config.validate().expect("defaults are valid");
    }

    #[test]
    fn debug_redacts_the_api_key() {
        let key = "secret-trongrid-key";
        let config = TronConfig {
            api_key: Some(key.to_string()),
            ..TronConfig::default()
        };

        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains(key),
            "the api key reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "the field must render redacted rather than vanish, or a later \
             derive(Debug) reinstates the leak unnoticed: {rendered}"
        );
    }
}
