//! Midnight node configuration.

use crate::types::MidnightAddress;
use mpc_chain_integration_core::utils::retry::RetryConfig;
use secrecy::{ExposeSecret as _, SecretString};
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

/// Timeouts and retry budget for the subxt node RPC client.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub retry: RetryConfig,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
            retry: RetryConfig {
                min_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(10),
                max_times: 5,
                jitter: true,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IndexerConfig {
    /// Delay between finalized-head samples after each completed live iteration.
    pub poll_interval: Duration,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(6),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OutputStorageConfig {
    pub bucket: String,
    /// Object namespace; use a distinct prefix for deployments that reset chain state.
    pub prefix: String,
    /// Maximum time for one initialization or upload attempt.
    pub timeout: Duration,
    #[cfg(feature = "sandbox")]
    pub emulator_endpoint: Option<String>,
}

impl OutputStorageConfig {
    pub fn new(bucket: String, prefix: String, timeout: Duration) -> Self {
        Self {
            bucket,
            prefix,
            timeout,
            #[cfg(feature = "sandbox")]
            emulator_endpoint: None,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.bucket.trim().is_empty(),
            "midnight config: publisher.output_storage.bucket must not be empty"
        );
        anyhow::ensure!(
            !self.prefix.trim_matches('/').trim().is_empty(),
            "midnight config: publisher.output_storage.prefix is required"
        );
        anyhow::ensure!(
            !self.timeout.is_zero(),
            "midnight config: publisher.output_storage.timeout must be greater than zero"
        );
        Ok(())
    }
}

/// Builds, proves, pays for and posts respond transactions in process.
#[derive(Clone, Debug)]
pub struct PublisherConfig {
    /// Optional output cache. Runtime storage failures warn and do not prevent on-chain responses.
    /// Initialization retries in the background with backoff until the cache is available.
    pub output_storage: Option<OutputStorageConfig>,
    /// Funds respond transactions.
    ///
    /// Carried as a [`SecretString`] so derived `Debug` redacts it; exposed only
    /// when validated or parsed into a signing key.
    pub funding_seed: SecretString,
    /// The indexer's GraphQL subscription URL: spendable DUST derives only from the
    /// ledger events it serves.
    pub indexer_ws_url: Url,
    /// The responder's packaged proving artifacts, `@sig-net/midnight-responder`'s
    /// `dist/managed`: `keys/<circuit>.{prover,verifier}` and `zkir/<circuit>.bzkir`.
    pub contract_artifacts_dir: PathBuf,
    /// The KZG parameters and DUST spend keys. A missing file is fetched into it from
    /// Midnight's parameter store and checked against the ledger's pinned hash.
    pub zk_params_dir: PathBuf,
    /// The build's share of a respond intent's TTL, which `submit_timeout` completes.
    pub build_budget: Duration,
    /// Ceiling on one submit, from the DUST wait to the finalized landing.
    pub submit_timeout: Duration,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            output_storage: None,
            funding_seed: String::new().into(),
            // Replaced by every real config; the empty funding seed fails validation.
            indexer_ws_url: Url::parse("ws://placeholder.invalid").expect("a valid literal"),
            // Where the node image installs them.
            contract_artifacts_dir: PathBuf::from("/usr/local/share/midnight/signet-responder"),
            zk_params_dir: PathBuf::from("/usr/local/share/midnight/zk-params"),
            build_budget: Duration::from_secs(120),
            submit_timeout: Duration::from_secs(420),
        }
    }
}

/// Midnight chain integration configuration.
#[derive(Clone, Debug)]
pub struct MidnightConfig {
    pub node_url: Url,
    /// Address of the central singleton contract, where clients notify their requests.
    pub central_address: MidnightAddress,
    /// Address of the signet responder contract, where responses are posted and read.
    pub responder_address: MidnightAddress,
    pub publisher: PublisherConfig,
    pub rpc: RpcConfig,
    pub indexer: IndexerConfig,
}

impl MidnightConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_scheme("node_url", &self.node_url, &["http", "https"])?;
        anyhow::ensure!(
            self.responder_address != self.central_address,
            "midnight config: responder_address must differ from central_address"
        );
        anyhow::ensure!(
            !self.indexer.poll_interval.is_zero(),
            "midnight config: indexer.poll_interval must be greater than zero"
        );
        self.publisher.validate()
    }
}

impl PublisherConfig {
    pub fn validate_output_storage(&self) -> anyhow::Result<()> {
        if let Some(config) = &self.output_storage {
            config.validate()?;
        }
        Ok(())
    }

    fn validate(&self) -> anyhow::Result<()> {
        self.validate_output_storage()?;
        validate_funding_seed(self.funding_seed.expose_secret())?;
        for (field, dir) in [
            (
                "publisher.contract_artifacts_dir",
                &self.contract_artifacts_dir,
            ),
            ("publisher.zk_params_dir", &self.zk_params_dir),
        ] {
            anyhow::ensure!(
                dir.is_absolute(),
                "midnight config: {field} must be an absolute path"
            );
        }
        anyhow::ensure!(
            !self.submit_timeout.is_zero(),
            "midnight config: publisher.submit_timeout must be greater than zero"
        );
        validate_scheme(
            "publisher.indexer_ws_url",
            &self.indexer_ws_url,
            &["ws", "wss"],
        )?;
        Ok(())
    }
}

fn validate_funding_seed(value: &str) -> anyhow::Result<()> {
    // The parse error is dropped: it may quote a character of the seed.
    anyhow::ensure!(
        crate::funding::parse_seed(value).is_ok_and(|seed| (16..=64).contains(&seed.len())),
        "midnight config: publisher.funding_seed must be 16 to 64 bytes of hex"
    );
    Ok(())
}

fn validate_scheme(field: &str, url: &Url, schemes: &[&str]) -> anyhow::Result<()> {
    anyhow::ensure!(
        schemes.contains(&url.scheme()),
        "midnight config: {field} must use one of {}, got {}",
        schemes.join(", "),
        url.scheme()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> MidnightConfig {
        MidnightConfig {
            node_url: "http://127.0.0.1:9944".parse().unwrap(),
            central_address: MidnightAddress::from_bytes([0xab; 32]),
            responder_address: MidnightAddress::from_bytes([0xcd; 32]),
            publisher: PublisherConfig {
                funding_seed: "0f".repeat(32).into(),
                indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".parse().unwrap(),
                ..Default::default()
            },
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    #[test]
    fn publisher_defaults_are_pinned() {
        // The budgets have no flags, so only this assert observes a retune.
        let publisher = PublisherConfig::default();
        assert_eq!(publisher.build_budget, Duration::from_secs(120));
        assert_eq!(publisher.submit_timeout, Duration::from_secs(420));
    }

    #[test]
    fn the_node_image_installs_the_artifacts_where_the_defaults_read_them() {
        // No pull-request job builds the runtime image, so this ties the two together.
        let dockerfile = include_str!("../../../Dockerfile");
        let publisher = PublisherConfig::default();
        for dir in [&publisher.contract_artifacts_dir, &publisher.zk_params_dir] {
            let dir = dir.to_str().unwrap();
            assert!(
                dockerfile
                    .lines()
                    .any(|line| line.starts_with("COPY --from=midnight-artifacts ")
                        && line.ends_with(&format!(" {dir}"))),
                "the runtime image installs nothing at {dir}"
            );
        }
    }

    #[test]
    fn debug_redacts_the_funding_seed() {
        let seed = "0123456789abcdef0123456789abcdef";
        let mut config = valid_config();
        config.publisher.funding_seed = seed.into();

        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains(seed),
            "the funding seed reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "the field must render redacted rather than vanish, or a later \
             derive(Debug) reinstates the leak unnoticed: {rendered}"
        );
    }

    #[cfg(feature = "sandbox")]
    #[test]
    fn debug_includes_the_output_storage_emulator_endpoint_without_exposing_the_funding_seed() {
        let seed = "0123456789abcdef0123456789abcdef";
        let endpoint = "http://127.0.0.1:4443";
        let mut config = valid_config();
        config.publisher.funding_seed = seed.into();
        config.publisher.output_storage = Some(OutputStorageConfig {
            emulator_endpoint: Some(endpoint.to_string()),
            ..OutputStorageConfig::new("outputs".into(), "v1".into(), Duration::from_secs(30))
        });

        let rendered = format!("{config:?}");
        assert!(
            rendered.contains("emulator_endpoint"),
            "the sandbox-only field is missing from Debug: {rendered}"
        );
        assert!(
            rendered.contains(endpoint),
            "the emulator endpoint is missing from Debug: {rendered}"
        );
        assert!(
            !rendered.contains(seed),
            "the funding seed reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "the funding seed must remain visibly redacted: {rendered}"
        );
    }

    #[test]
    fn a_complete_config_validates() {
        valid_config().validate().expect("every field is valid");
    }

    #[test]
    fn output_storage_settings_are_validated_from_the_top_level() {
        valid_config()
            .validate()
            .expect("output storage is optional by default");

        let mut configured = valid_config();
        configured.publisher.output_storage = Some(OutputStorageConfig::new(
            "outputs".into(),
            "v1/test-deployment".into(),
            Duration::from_secs(1),
        ));
        configured
            .validate()
            .expect("configured output storage is valid");

        for (field, apply) in [
            (
                "output_storage.bucket",
                (|config: &mut OutputStorageConfig| {
                    config.bucket = " ".to_string();
                }) as fn(&mut OutputStorageConfig),
            ),
            (
                "output_storage.prefix",
                |config: &mut OutputStorageConfig| {
                    config.prefix = String::new();
                },
            ),
            (
                "output_storage.timeout",
                |config: &mut OutputStorageConfig| {
                    config.timeout = Duration::ZERO;
                },
            ),
        ] {
            let mut invalid = configured.clone();
            apply(invalid.publisher.output_storage.as_mut().unwrap());
            let error = invalid.validate().unwrap_err().to_string();
            assert!(
                error.contains(field),
                "unexpected error for {field}: {error}"
            );
        }
    }

    #[test]
    fn artifact_directories_must_be_absolute() {
        for (field, apply) in [
            (
                "contract_artifacts_dir",
                (|config: &mut PublisherConfig| {
                    config.contract_artifacts_dir = PathBuf::from("managed");
                }) as fn(&mut PublisherConfig),
            ),
            ("zk_params_dir", |config: &mut PublisherConfig| {
                config.zk_params_dir = PathBuf::from("./zk-params");
            }),
        ] {
            let mut relative = valid_config();
            apply(&mut relative.publisher);
            let error = relative.validate().unwrap_err().to_string();
            assert!(
                error.contains(field),
                "unexpected error for {field}: {error}"
            );
        }
    }

    #[test]
    fn validate_names_offending_field() {
        let mut zero_poll = valid_config();
        zero_poll.indexer.poll_interval = Duration::ZERO;
        let err = zero_poll.validate().unwrap_err().to_string();
        assert!(err.contains("poll_interval"), "unexpected error: {err}");

        for (field, apply) in [
            (
                "node_url",
                (|config: &mut MidnightConfig| {
                    config.node_url = "ws://127.0.0.1:9944".parse().unwrap();
                }) as fn(&mut MidnightConfig),
            ),
            ("funding_seed", |config: &mut MidnightConfig| {
                config.publisher.funding_seed = "not hex".into();
            }),
            ("submit_timeout", |config: &mut MidnightConfig| {
                config.publisher.submit_timeout = Duration::ZERO;
            }),
            ("indexer_ws_url", |config: &mut MidnightConfig| {
                config.publisher.indexer_ws_url = "http://127.0.0.1:8088".parse().unwrap();
            }),
            ("responder_address", |config: &mut MidnightConfig| {
                config.responder_address = config.central_address;
            }),
        ] {
            let mut invalid = valid_config();
            apply(&mut invalid);
            let err = invalid.validate().unwrap_err().to_string();
            assert!(err.contains(field), "unexpected error for {field}: {err}");
        }
    }

    #[test]
    fn publisher_seed_uses_the_sdk_hex_contract() {
        for valid in [
            "ab".repeat(16),
            "ab".repeat(64),
            format!("0X{}", "AB".repeat(32)),
        ] {
            let mut config = valid_config();
            config.publisher.funding_seed = valid.into();
            config.validate().expect("the SDK accepts this hex seed");
        }

        for invalid in [
            "".to_string(),
            "ab".repeat(15),
            "ab".repeat(65),
            "a".repeat(33),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string(),
        ] {
            let mut config = valid_config();
            config.publisher.funding_seed = invalid.clone().into();
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("funding_seed"), "unexpected error: {error}");
            assert!(
                invalid.is_empty() || !error.contains(&invalid),
                "the rejected seed reached its error: {error}"
            );
        }
    }
}
