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

/// Midnight chain integration configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct MidnightConfig {
    pub node_url: String,
    /// Address of the central singleton contract: 64 hex characters, no `0x` prefix
    pub central_address: String,
    pub publisher: PublisherConfig,
    pub rpc: RpcConfig,
    pub indexer: IndexerConfig,
}

impl MidnightConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some((scheme, _)) = self.node_url.split_once(':') {
            anyhow::ensure!(
                !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https")
                    || matches!(scheme, "http" | "https"),
                "midnight config: node_url must use a lowercase http or https scheme"
            );
        }
        validate_url("node_url", &self.node_url, &["http", "https"])?;
        anyhow::ensure!(
            self.central_address.len() == 64
                && self.central_address.bytes().all(|b| b.is_ascii_hexdigit()),
            "midnight config: central_address must be 64 hex characters with no 0x prefix, \
             got {} characters",
            self.central_address.len()
        );
        // Required rather than normalised: attribution compares this against the
        // decoder's lowercase addresses, so uppercase would silently never match.
        anyhow::ensure!(
            !self.central_address.bytes().any(|b| b.is_ascii_uppercase()),
            "midnight config: central_address must be lowercase hex, the canonical form \
             every comparison site assumes"
        );
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

    fn valid_config() -> MidnightConfig {
        MidnightConfig {
            node_url: "http://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
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
    fn indexer_polling_defaults_and_busy_loop_guard_are_pinned() {
        let indexer = IndexerConfig::default();
        assert_eq!(indexer.poll_interval, Duration::from_secs(2));
        assert_eq!(indexer.stall_timeout, Duration::from_secs(60));

        let mut config = valid_config();
        config.indexer.poll_interval = Duration::ZERO;
        let error = config
            .validate()
            .expect_err("a zero poll interval would create a busy loop");
        assert!(error.to_string().contains("poll_interval"), "{error:#}");
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
    fn node_url_accepts_http_and_rejects_websocket() {
        for valid in ["http://127.0.0.1:9944", "https://node.example.com"] {
            let mut config = valid_config();
            config.node_url = valid.to_string();
            config.validate().expect("HTTP node URLs are supported");
        }

        for invalid in ["", "ws://127.0.0.1:9944", "wss://node.example.com"] {
            let mut config = valid_config();
            config.node_url = invalid.to_string();
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("node_url"), "unexpected error: {error}");
        }
    }

    #[test]
    fn node_url_rejects_non_lowercase_http_schemes_without_rewriting() {
        for invalid in ["HTTP://127.0.0.1:9944", "HTTPS://node.example.com"] {
            let mut config = valid_config();
            config.node_url = invalid.to_string();
            let error = config
                .validate()
                .expect_err("the publisher's HTTP-to-WS conversion is case-sensitive");
            let diagnostic = error.to_string();
            assert!(diagnostic.contains("node_url"), "{diagnostic}");
            assert!(diagnostic.contains("lowercase"), "{diagnostic}");
            assert_eq!(
                config.node_url, invalid,
                "validation must not rewrite the URL"
            );
        }
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
        let mut short_address = valid_config();
        short_address.central_address = "ab".repeat(31);
        let err = short_address.validate().unwrap_err().to_string();
        assert!(err.contains("central_address"), "unexpected error: {err}");

        let mut non_hex = valid_config();
        non_hex.central_address = "zz".repeat(32);
        let err = non_hex.validate().unwrap_err().to_string();
        assert!(err.contains("central_address"), "unexpected error: {err}");

        let mut prefixed = valid_config();
        prefixed.central_address = format!("0x{}", "ab".repeat(31));
        let err = prefixed.validate().unwrap_err().to_string();
        assert!(err.contains("central_address"), "unexpected error: {err}");

        // Lowercase is canonical: attribution compares against decoder-returned lowercase hex.
        let mut uppercase = valid_config();
        uppercase.central_address = "AB".repeat(32);
        let err = uppercase.validate().unwrap_err().to_string();
        assert!(err.contains("lowercase"), "unexpected error: {err}");

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
