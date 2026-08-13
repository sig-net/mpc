//! Midnight node configuration.

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::RetryConfig;
use std::fmt;
use std::time::Duration;
use url::Url;

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
    pub live_block_buffer: usize,
    /// Silence budget before `run()` returns for a restart: ~10 missed blocks at
    /// Midnight's ~6s cadence.
    pub stall_timeout: Duration,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            live_block_buffer: 16384,
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
    /// Duplicates `MidnightConfig::node_ws_url`: `into_config` fills both from one flag
    /// so they cannot disagree.
    pub node_ws_url: String,
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
            // The `bin` name the TypeScript package installs, resolved on PATH.
            intent_gen_command: vec!["midnight-publisher".to_string()],
            funding_seed: String::new(),
            node_ws_url: String::new(),
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
            .field("node_ws_url", &self.node_ws_url)
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
    pub node_ws_url: String,
    /// Address of the central singleton contract: 64 hex characters, no `0x` prefix
    pub central_address: String,
    /// `None` is an indexer-only node. `Some` is a complete responder configuration.
    pub publisher: Option<PublisherConfig>,
    pub rpc: RpcConfig,
    pub indexer: IndexerConfig,
}

impl MidnightConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_url("node_ws_url", &self.node_ws_url, &["ws", "wss"])?;
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
        if let Some(publisher) = &self.publisher {
            publisher.validate()?;
            anyhow::ensure!(
                publisher.node_ws_url == self.node_ws_url,
                "midnight config: publisher.node_ws_url must match node_ws_url"
            );
        }
        Ok(())
    }
}

impl PublisherConfig {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.intent_gen_command
                .first()
                .is_some_and(|program| !program.is_empty()),
            "midnight config: publisher.intent_gen_command must name a program"
        );
        Ok(())
    }
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
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
            publisher: None,
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    /// A node that answers as well as indexes: the whole submit half filled.
    fn responding_config() -> MidnightConfig {
        let mut config = valid_config();
        config.publisher = Some(PublisherConfig {
            funding_seed: "0f".repeat(32),
            node_ws_url: config.node_ws_url.clone(),
            proof_server_url: "http://127.0.0.1:6300".to_string(),
            indexer_url: "http://127.0.0.1:8088/api/v3/graphql".to_string(),
            indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".to_string(),
            ..Default::default()
        });
        config
    }

    fn publisher_mut(config: &mut MidnightConfig) -> &mut PublisherConfig {
        config.publisher.as_mut().expect("the test config responds")
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
        let mut config = responding_config();
        publisher_mut(&mut config).funding_seed = seed.to_string();

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
    fn indexer_only_and_responding_shapes_validate() {
        valid_config()
            .validate()
            .expect("an indexer-only node has no publisher config");
        responding_config()
            .validate()
            .expect("the publisher's owned values are valid");
    }

    #[test]
    fn validate_names_offending_field() {
        for invalid in ["", "http://127.0.0.1:9944"] {
            let mut bad_ws = valid_config();
            bad_ws.node_ws_url = invalid.to_string();
            let err = bad_ws.validate().unwrap_err().to_string();
            assert!(err.contains("node_ws_url"), "unexpected error: {err}");
        }

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

        let mut mismatched_node = responding_config();
        publisher_mut(&mut mismatched_node).node_ws_url = "ws://127.0.0.1:9999".to_string();
        let err = mismatched_node.validate().unwrap_err().to_string();
        assert!(err.contains("must match"), "unexpected error: {err}");

        let mut empty_command = responding_config();
        publisher_mut(&mut empty_command).intent_gen_command.clear();
        let err = empty_command.validate().unwrap_err().to_string();
        assert!(
            err.contains("intent_gen_command"),
            "unexpected error: {err}"
        );
    }
}
