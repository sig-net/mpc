//! Midnight node configuration.

use mpc_chain_integration_core::utils::retry::RetryConfig;
use std::fmt;
use std::time::Duration;

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
    /// Funds respond transactions; empty is the indexer-only deployment.
    pub funding_seed: String,
    /// Duplicates `MidnightConfig::node_ws_url`: `into_config` fills both from one flag
    /// so they cannot disagree; the child validates the submit half all-or-none.
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
            // Blank as a set: the child reads all five blank as "no funding wallet".
            funding_seed: String::new(),
            node_ws_url: String::new(),
            proof_server_url: String::new(),
            indexer_url: String::new(),
            indexer_ws_url: String::new(),
            request_timeout: Duration::from_secs(120),
            submit_timeout: Duration::from_secs(300),
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
    pub network_id: String,
    pub publisher: PublisherConfig,
    pub rpc: RpcConfig,
    pub indexer: IndexerConfig,
}

impl MidnightConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.node_ws_url.is_empty(),
            "midnight config: node_ws_url is empty"
        );
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
        // Presence only: legal ids belong to the builder's own schema.
        anyhow::ensure!(
            !self.network_id.is_empty(),
            "midnight config: network_id is empty"
        );
        // An empty seed is the legal indexer-only deployment; no case rule either,
        // unlike central_address, because the seed is decoded and never compared.
        if !self.publisher.funding_seed.is_empty() {
            let seed = &self.publisher.funding_seed;
            anyhow::ensure!(
                seed.len().is_multiple_of(2)
                    && (32..=128).contains(&seed.len())
                    && seed.bytes().all(|b| b.is_ascii_hexdigit()),
                "midnight config: publisher.funding_seed must be 16 to 64 bytes of hex with \
                 no 0x prefix, got {} characters",
                seed.len()
            );
        }
        self.validate_submit_half()
    }

    /// The five values a respond needs, all-or-none the way the child checks them, so
    /// the missing one is named at startup rather than on a stderr nobody reads. Only
    /// the names are rendered; one of the five is a spending key.
    fn validate_submit_half(&self) -> anyhow::Result<()> {
        let publisher = &self.publisher;
        let submit_half = [
            ("publisher.funding_seed", &publisher.funding_seed),
            ("publisher.node_ws_url", &publisher.node_ws_url),
            ("publisher.proof_server_url", &publisher.proof_server_url),
            ("publisher.indexer_url", &publisher.indexer_url),
            ("publisher.indexer_ws_url", &publisher.indexer_ws_url),
        ];
        let missing: Vec<&str> = submit_half
            .iter()
            .filter(|(_, value)| value.is_empty())
            .map(|(name, _)| *name)
            .collect();
        anyhow::ensure!(
            missing.is_empty() || missing.len() == submit_half.len(),
            "midnight config: responding needs all of {}, or none of them for a node that \
             only indexes; missing {}",
            submit_half
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
                .join(", "),
            missing.join(", ")
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> MidnightConfig {
        MidnightConfig {
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".to_string(),
            publisher: Default::default(),
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    /// A node that answers as well as indexes: the whole submit half filled.
    fn responding_config() -> MidnightConfig {
        let mut config = valid_config();
        config.publisher.funding_seed = "0f".repeat(32);
        config.publisher.node_ws_url = config.node_ws_url.clone();
        config.publisher.proof_server_url = "http://127.0.0.1:6300".to_string();
        config.publisher.indexer_url = "http://127.0.0.1:8088/api/v3/graphql".to_string();
        config.publisher.indexer_ws_url = "ws://127.0.0.1:8088/api/v3/graphql/ws".to_string();
        config
    }

    #[test]
    fn publisher_defaults_are_pinned() {
        // The timeouts have no flags, so only this assert observes a retune.
        let publisher = PublisherConfig::default();
        assert_eq!(publisher.request_timeout, Duration::from_secs(120));
        assert_eq!(publisher.submit_timeout, Duration::from_secs(300));
        assert!(publisher.funding_seed.is_empty());
        assert!(publisher.node_ws_url.is_empty());
        assert!(publisher.proof_server_url.is_empty());
        assert!(publisher.indexer_url.is_empty());
        assert!(publisher.indexer_ws_url.is_empty());
    }

    #[test]
    fn debug_redacts_the_funding_seed() {
        let seed = "0123456789abcdef0123456789abcdef";
        let mut config = responding_config();
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
    fn an_empty_funding_seed_validates() {
        let mut seedless = valid_config();
        seedless.publisher.funding_seed = String::new();
        seedless
            .validate()
            .expect("a node that only indexes needs no funding seed");

        responding_config()
            .validate()
            .expect("64 hex characters is 32 bytes");

        // Uppercase stays legal, unlike central_address: the seed is never compared.
        let mut uppercase = responding_config();
        uppercase.publisher.funding_seed = "0F".repeat(32);
        uppercase
            .validate()
            .expect("the seed is decoded, never compared against anything");
    }

    #[test]
    fn the_submit_half_validates_as_one_set_or_not_at_all() {
        // Each of the five has to be the one missing, or a value left off the checked list stays green.
        for blank in [
            "funding_seed",
            "node_ws_url",
            "proof_server_url",
            "indexer_url",
            "indexer_ws_url",
        ] {
            let mut config = responding_config();
            let publisher = &mut config.publisher;
            match blank {
                "funding_seed" => publisher.funding_seed = String::new(),
                "node_ws_url" => publisher.node_ws_url = String::new(),
                "proof_server_url" => publisher.proof_server_url = String::new(),
                "indexer_url" => publisher.indexer_url = String::new(),
                _ => publisher.indexer_ws_url = String::new(),
            }
            let err = config.validate().unwrap_err().to_string();
            assert!(
                err.contains(&format!("missing publisher.{blank}")),
                "a config missing only {blank} must say so: {err}"
            );
        }
    }

    #[test]
    fn a_half_configured_publisher_never_renders_the_seed_it_does_have() {
        let seed = "0123456789abcdef0123456789abcdef";
        let mut config = responding_config();
        config.publisher.funding_seed = seed.to_string();
        config.publisher.indexer_url = String::new();

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("missing publisher.indexer_url"), "got: {err}");
        assert!(
            !err.contains(seed),
            "the funding seed reached an error: {err}"
        );
    }

    #[test]
    fn validate_rejects_a_malformed_funding_seed() {
        // A typo would otherwise surface as a child failing to derive a wallet.
        for seed in [
            // Odd length, so the last byte has one nibble.
            "0f".repeat(16) + "a",
            // Hex-shaped but not hex.
            "zz".repeat(16),
            // Under 16 bytes.
            "0f".repeat(15),
            // Over 64 bytes.
            "0f".repeat(65),
        ] {
            // Endpoint-complete, so the shape check is unambiguously what refuses.
            let mut config = responding_config();
            config.publisher.funding_seed = seed.clone();
            let err = config.validate().unwrap_err().to_string();
            assert!(
                err.contains("16 to 64 bytes of hex"),
                "unexpected error for {seed:?}: {err}"
            );
        }
    }

    #[test]
    fn validate_names_offending_field() {
        let mut empty_ws = valid_config();
        empty_ws.node_ws_url = String::new();
        let err = empty_ws.validate().unwrap_err().to_string();
        assert!(err.contains("node_ws_url"), "unexpected error: {err}");

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

        let mut empty_network = valid_config();
        empty_network.network_id = String::new();
        let err = empty_network.validate().unwrap_err().to_string();
        assert!(err.contains("network_id"), "unexpected error: {err}");
    }
}
