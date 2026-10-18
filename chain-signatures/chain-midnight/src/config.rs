//! Midnight node configuration.

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::RetryConfig;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

const PUBLISHER_NETWORK_IDS: &[&str] = &["undeployed", "stagenet", "preview", "preprod", "mainnet"];

/// Timeouts and retry budget for the subxt node RPC client.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// Must exceed the node's own response cap (15 MiB by default) so an oversized
    /// state arrives as the server's refusal, not a frame that kills the client.
    pub max_response_size: u32,
    pub retry: RetryConfig,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
            max_response_size: 32 * 1024 * 1024,
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
            poll_interval: Duration::from_secs(2),
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
#[derive(Clone, PartialEq)]
pub struct PublisherConfig {
    /// Optional output cache. Runtime storage failures warn and do not prevent on-chain responses.
    /// Initialization retries in the background with backoff until the cache is available.
    pub output_storage: Option<OutputStorageConfig>,
    /// Funds respond transactions.
    pub funding_seed: String,
    /// The indexer's GraphQL subscription URL: spendable DUST derives only from the
    /// ledger events it serves.
    pub indexer_ws_url: String,
    /// The singleton's packaged proving artifacts, `@sig-net/midnight-contract`'s
    /// `dist/managed`: `keys/<circuit>.{prover,verifier}` and `zkir/<circuit>.bzkir`.
    pub contract_artifacts_dir: PathBuf,
    /// The KZG parameters and DUST spend keys. A missing file is fetched into it from
    /// Midnight's parameter store and checked against the ledger's pinned hash.
    pub zk_params_dir: PathBuf,
    /// The build's share of a respond intent's TTL, which `submit_timeout` completes.
    pub request_timeout: Duration,
    /// Ceiling on one submit, from the DUST wait to the finalized landing.
    pub submit_timeout: Duration,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            output_storage: None,
            funding_seed: String::new(),
            indexer_ws_url: String::new(),
            // Where the node image installs them.
            contract_artifacts_dir: PathBuf::from("/usr/local/share/midnight/signet-contract"),
            zk_params_dir: PathBuf::from("/usr/local/share/midnight/zk-params"),
            request_timeout: Duration::from_secs(120),
            submit_timeout: Duration::from_secs(420),
        }
    }
}

/// Hand-written so `funding_seed` cannot reach the log via `Debug`. Redacted rather
/// than skipped, so a later `derive(Debug)` cannot silently restore the leak.
impl fmt::Debug for PublisherConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublisherConfig")
            .field("output_storage", &self.output_storage)
            .field("funding_seed", &"<redacted>")
            .field("indexer_ws_url", &self.indexer_ws_url)
            .field("contract_artifacts_dir", &self.contract_artifacts_dir)
            .field("zk_params_dir", &self.zk_params_dir)
            .field("request_timeout", &self.request_timeout)
            .field("submit_timeout", &self.submit_timeout)
            .finish()
    }
}

/// A Midnight contract address in its native 32-byte representation.
///
/// Text input is normalized to 64 lowercase hex characters without a `0x` prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MidnightAddress([u8; 32]);

impl MidnightAddress {
    pub fn from_hex(value: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes)?;
        Ok(Self(bytes))
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Midnight chain integration configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct MidnightConfig {
    pub node_url: String,
    /// Address of the central singleton contract.
    pub central_address: MidnightAddress,
    pub publisher: PublisherConfig,
    pub rpc: RpcConfig,
    pub indexer: IndexerConfig,
}

impl MidnightConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.node_url.starts_with("http://") || self.node_url.starts_with("https://"),
            "midnight config: node_url must use a lowercase http or https scheme"
        );
        validate_url("node_url", &self.node_url, &["http", "https"])?;
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
        validate_funding_seed(&self.funding_seed)?;
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
        validate_url(
            "publisher.indexer_ws_url",
            &self.indexer_ws_url,
            &["ws", "wss"],
        )?;
        Ok(())
    }
}

fn validate_funding_seed(value: &str) -> anyhow::Result<()> {
    let trimmed = value.trim();
    let compact = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    anyhow::ensure!(
        compact.len() >= 32
            && compact.len() <= 128
            && compact.len().is_multiple_of(2)
            && compact.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "midnight config: publisher.funding_seed must be 16 to 64 bytes of hex"
    );
    Ok(())
}

pub(crate) fn validate_publisher_network_id(value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        PUBLISHER_NETWORK_IDS.contains(&value),
        "midnight config: network_id is not supported by the publisher"
    );
    Ok(())
}

fn validate_url(field: &str, value: &str, schemes: &[&str]) -> anyhow::Result<()> {
    let parsed = Url::parse(value)
        .with_context(|| format!("midnight config: {field} must be an absolute URL"))?;
    anyhow::ensure!(
        schemes.contains(&parsed.scheme()),
        "midnight config: {field} must use one of {}, got {}",
        schemes.join(", "),
        parsed.scheme()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midnight_address_round_trips_bytes_and_canonical_hex() {
        let bytes = [
            0x00, 0x0f, 0x10, 0xab, 0xcd, 0xef, 0x80, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x09, 0x08,
            0x07, 0x06, 0x05, 0x04,
        ];
        let expected = "000f10abcdef80ff0123456789aabbccddeefedcba9876543210090807060504";

        let address = MidnightAddress::from_bytes(bytes);

        assert_eq!(address.as_bytes(), &bytes);
        assert_eq!(address.to_hex(), expected);
        assert_eq!(MidnightAddress::from_hex(expected).unwrap(), address);
        assert_eq!(
            MidnightAddress::from_hex(&expected.to_ascii_uppercase()).unwrap(),
            address
        );
    }

    #[test]
    fn midnight_address_rejects_invalid_hex() {
        for input in [
            "ab".repeat(31),
            "ab".repeat(33),
            format!("0x{}", "ab".repeat(31)),
            "zz".repeat(32),
        ] {
            assert!(
                MidnightAddress::from_hex(&input).is_err(),
                "unexpectedly accepted {input}"
            );
        }
    }

    fn valid_config() -> MidnightConfig {
        MidnightConfig {
            node_url: "http://127.0.0.1:9944".to_string(),
            central_address: MidnightAddress::from_bytes([0xab; 32]),
            publisher: PublisherConfig {
                funding_seed: "0f".repeat(32),
                indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".to_string(),
                ..Default::default()
            },
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    #[test]
    fn publisher_defaults_are_pinned() {
        // The timeouts have no flags, so only this assert observes a retune.
        let publisher = PublisherConfig::default();
        assert_eq!(publisher.request_timeout, Duration::from_secs(120));
        assert_eq!(publisher.submit_timeout, Duration::from_secs(420));
    }

    #[test]
    fn debug_redacts_the_funding_seed() {
        let seed = "0123456789abcdef0123456789abcdef";
        let mut config = valid_config();
        config.publisher.funding_seed = seed.to_string();

        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains(seed),
            "the funding seed reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
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
        config.publisher.funding_seed = seed.to_string();
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
            rendered.contains("<redacted>"),
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
        let mut uppercase_url = valid_config();
        uppercase_url.node_url = "HTTP://127.0.0.1:9944".to_string();
        let err = uppercase_url.validate().unwrap_err().to_string();
        assert!(err.contains("lowercase"), "unexpected error: {err}");

        let mut zero_poll = valid_config();
        zero_poll.indexer.poll_interval = Duration::ZERO;
        let err = zero_poll.validate().unwrap_err().to_string();
        assert!(err.contains("poll_interval"), "unexpected error: {err}");

        for (field, apply) in [
            (
                "funding_seed",
                (|config: &mut MidnightConfig| {
                    config.publisher.funding_seed = "not hex".to_string();
                }) as fn(&mut MidnightConfig),
            ),
            ("submit_timeout", |config: &mut MidnightConfig| {
                config.publisher.submit_timeout = Duration::ZERO;
            }),
            ("indexer_ws_url", |config: &mut MidnightConfig| {
                config.publisher.indexer_ws_url = "http://127.0.0.1:8088".to_string();
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
            config.publisher.funding_seed = valid;
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
            config.publisher.funding_seed = invalid.clone();
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("funding_seed"), "unexpected error: {error}");
            assert!(
                invalid.is_empty() || !error.contains(&invalid),
                "the rejected seed reached its error: {error}"
            );
        }
    }

    #[test]
    fn publisher_network_ids_match_the_sdk() {
        for network_id in PUBLISHER_NETWORK_IDS {
            validate_publisher_network_id(network_id).expect("the SDK supports this network");
        }
        let error = validate_publisher_network_id("unknown-network").unwrap_err();
        assert!(error.to_string().contains("network_id"), "{error:#}");
    }
}
