//! Midnight node configuration.

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::RetryConfig;
use std::fmt;
use std::path::Path;
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
    /// Silence budget before `run()` returns for a restart: ~10 missed blocks at
    /// Midnight's ~6s cadence.
    pub stall_timeout: Duration,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            stall_timeout: Duration::from_secs(60),
        }
    }
}

/// Runs the out-of-process intent builder, the piece that stays TypeScript for its proving stack.
#[derive(Clone, PartialEq)]
pub struct PublisherConfig {
    /// argv of the builder, program first: a list so no operator path is word-split.
    pub intent_gen_command: Vec<String>,
    /// Funds respond transactions.
    pub funding_seed: String,
    /// These contracts are zkir-v3, which cannot be proven in process.
    pub proof_server_url: String,
    /// Spendable DUST derives only from the ledger events the indexer serves.
    pub indexer_url: String,
    pub indexer_ws_url: String,
    /// Ceiling on one build.
    pub request_timeout: Duration,
    /// Ceiling on getting a built intent accepted by the node.
    pub submit_timeout: Duration,
    /// Budget for bringing the builder back up after it dies.
    pub restart_backoff: RetryConfig,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            // The `bin` name the TypeScript package installs, resolved on the fixed child PATH.
            intent_gen_command: vec!["midnight-publisher".to_string()],
            funding_seed: String::new(),
            proof_server_url: String::new(),
            indexer_url: String::new(),
            indexer_ws_url: String::new(),
            request_timeout: Duration::from_secs(120),
            // The child owns the 360 second submit deadline. Rust is only its looser
            // process-supervision backstop, checked against the child's ready reply.
            submit_timeout: Duration::from_secs(420),
            restart_backoff: RetryConfig {
                min_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(10),
                max_times: 5,
                jitter: true,
            },
        }
    }
}

/// Hand-written so `funding_seed` cannot reach the log via `Debug`. Redacted rather
/// than skipped, so a later `derive(Debug)` cannot silently restore the leak.
impl fmt::Debug for PublisherConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublisherConfig")
            .field("intent_gen_command", &self.intent_gen_command)
            .field("funding_seed", &"<redacted>")
            .field("proof_server_url", &self.proof_server_url)
            .field("indexer_url", &self.indexer_url)
            .field("indexer_ws_url", &self.indexer_ws_url)
            .field("request_timeout", &self.request_timeout)
            .field("submit_timeout", &self.submit_timeout)
            .field("restart_backoff", &self.restart_backoff)
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
    fn validate(&self) -> anyhow::Result<()> {
        let program = self
            .intent_gen_command
            .first()
            .map(String::as_str)
            .unwrap_or_default();
        anyhow::ensure!(
            !program.is_empty(),
            "midnight config: publisher.intent_gen_command must name a program"
        );
        let path = Path::new(program);
        anyhow::ensure!(
            path.is_absolute()
                || path
                    .file_name()
                    .is_some_and(|name| name == path.as_os_str()),
            "midnight config: publisher.intent_gen_command program must be a bare name or an \
             absolute path"
        );
        validate_funding_seed(&self.funding_seed)?;
        validate_url(
            "publisher.proof_server_url",
            &self.proof_server_url,
            &["http", "https"],
        )?;
        validate_url(
            "publisher.indexer_url",
            &self.indexer_url,
            &["http", "https"],
        )?;
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
        "midnight config: network_id is not supported by the publisher SDK"
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
                proof_server_url: "http://127.0.0.1:6300".to_string(),
                indexer_url: "http://127.0.0.1:8088/api/v3/graphql".to_string(),
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

    #[test]
    fn a_complete_config_validates() {
        valid_config().validate().expect("every field is valid");
    }

    #[test]
    fn publisher_command_is_a_bare_name_or_an_absolute_path() {
        for program in ["midnight-publisher", "/opt/midnight-publisher"] {
            let mut config = valid_config();
            config.publisher.intent_gen_command[0] = program.to_string();
            config
                .validate()
                .expect("the command shape is deterministic");
        }

        for program in ["./publisher", "tools/publisher"] {
            let mut relative = valid_config();
            relative.publisher.intent_gen_command[0] = program.to_string();
            let error = relative.validate().unwrap_err().to_string();
            assert!(
                error.contains("intent_gen_command"),
                "unexpected error: {error}"
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

        let mut empty_command = valid_config();
        empty_command.publisher.intent_gen_command.clear();
        let err = empty_command.validate().unwrap_err().to_string();
        assert!(
            err.contains("intent_gen_command"),
            "unexpected error: {err}"
        );

        for (field, apply) in [
            (
                "funding_seed",
                (|config: &mut MidnightConfig| {
                    config.publisher.funding_seed = "not hex".to_string();
                }) as fn(&mut MidnightConfig),
            ),
            ("proof_server_url", |config: &mut MidnightConfig| {
                config.publisher.proof_server_url = "ws://127.0.0.1:6300".to_string();
            }),
            ("indexer_url", |config: &mut MidnightConfig| {
                config.publisher.indexer_url = "not a URL".to_string();
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
