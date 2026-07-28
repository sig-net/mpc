//! Midnight node configuration.

use mpc_chain_integration_core::utils::retry::RetryConfig;
use std::fmt;
use std::time::Duration;

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

/// Tuning for the indexing pipeline (catchup and the live finalized-head loop).
#[derive(Clone, Debug, PartialEq)]
pub struct IndexerConfig {
    /// How many blocks back a contract-state read may walk when the node has pruned the
    /// state at the block being asked for; also the depth of the startup archive-state
    /// probe, which asks for state at `finalized head - archive_probe_window`
    pub archive_probe_window: u64,
    /// Refuse to start when the startup probe finds the node pruned within
    /// `archive_probe_window`.
    pub require_archive_state: bool,
    pub live_block_buffer: usize,
    /// How long the finalized-head subscription may go silent before `run()` returns
    /// and lets the supervisor restart it
    pub stall_timeout: Duration,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            archive_probe_window: 1024,
            require_archive_state: false,
            live_block_buffer: 16384,
            stall_timeout: Duration::from_secs(60),
        }
    }
}

/// How the node runs the out-of-process intent builder, the only piece of the respond
/// path that stays in TypeScript because the proving stack lives there.
#[derive(Clone, PartialEq)]
pub struct PublisherConfig {
    /// argv of the builder, program first. A list rather than one shell string so no
    /// operator-supplied path is word-split behind their back, and so a test can point
    /// this at a stub.
    pub intent_gen_command: Vec<String>,
    /// Root of the compiled-contract assets (`contract/`, `keys/`, `zkir/`) the builder
    /// proves against. Reaches the child as `MIDNIGHT_PUB_MANAGED_DIR`.
    pub managed_dir: String,
    /// Hex seed of the wallet that funds respond transactions. Empty is the indexer-only
    /// deployment, which never spends and so is never asked for a credential.
    pub funding_seed: String,
    /// Where the funding wallet reaches the chain: the node, the prover and the indexer,
    /// all four of them plus the seed above present or absent as one set. The child
    /// validates that half all-or-none and refuses to boot on any subset, so a
    /// deployment holding three of them has no builder at all, and `validate` naming the
    /// missing one is what keeps that from being read off a dead child's stderr.
    ///
    /// The four sitting together mirrors the `Endpoints` interface they feed on the
    /// TypeScript side, and that grouping is load-bearing for the validation rather than
    /// cosmetic: it is what lets the all-or-none rule be stated in one place instead of
    /// scattered across whatever holds each value.
    ///
    /// Which is why `MidnightConfig::node_ws_url` is duplicated here rather than
    /// `IntentGen::spawn` being widened to carry it alongside `network_id`: widening it
    /// changes a public signature and four call sites across three files to move one
    /// value, and splits the set. `into_config` fills this off the same flag, so the two
    /// cannot disagree.
    pub node_ws_url: String,
    /// Mandatory wherever the wallet is: these contracts are zkir-v3, which cannot be
    /// proven in process, so a proof server is the only configuration that exists and no
    /// second one is offered.
    pub proof_server_url: String,
    /// Spendable DUST is derived by replaying every block's ledger events from genesis,
    /// and the indexer is the only surface that serves them. No node RPC carries it,
    /// which is why an absent indexer is a publisher that cannot spend at all rather
    /// than one that is merely slower.
    pub indexer_url: String,
    pub indexer_ws_url: String,
    /// Ceiling on one build. Generous because a proving run is seconds, and because
    /// exceeding it costs a child restart.
    pub request_timeout: Duration,
    /// Ceiling on getting a built intent accepted by the node, which waits on block
    /// production rather than on local work, so it is the looser of the two.
    pub submit_timeout: Duration,
    /// Budget for bringing the builder back up after it dies.
    pub restart_backoff: RetryConfig,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            // The `bin` name the TypeScript package installs, resolved on PATH.
            intent_gen_command: vec!["midnight-publisher".to_string()],
            managed_dir: String::new(),
            // Empty across the whole submit half, which is the deployment that only
            // builds intents: the child reads all five blank as "no funding wallet" and
            // boots, and any other combination is what it refuses.
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

/// Hand-written so `funding_seed` cannot be printed: `cli::log_startup` renders the
/// chain configs with `Debug`, so a derived one puts the operator's spending key in the
/// node's log. Redacted rather than skipped, because a vanished field reads as a struct
/// that never had one and a later `derive(Debug)` would restore the leak unnoticed.
impl fmt::Debug for PublisherConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublisherConfig")
            .field("intent_gen_command", &self.intent_gen_command)
            .field("managed_dir", &self.managed_dir)
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
    /// Ledger network id.
    pub network_id: String,
    pub publisher: PublisherConfig,
    pub rpc: RpcConfig,
    pub indexer: IndexerConfig,
}

impl MidnightConfig {
    /// Rejects endpoints that cannot work, before anything dials them, so an unusable
    /// config fails once at construction with the field named rather than forever at
    /// runtime.
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
        // Required rather than normalised: the address flows verbatim into chain_ctx
        // and is compared against the decoder's lowercase addresses during attribution,
        // so an uppercase value would silently never match.
        anyhow::ensure!(
            !self.central_address.bytes().any(|b| b.is_ascii_uppercase()),
            "midnight config: central_address must be lowercase hex, the canonical form \
             every comparison site assumes"
        );
        // Checked only when set. Midnight deploys indexer-only today, so every existing
        // deployment carries the three endpoint flags and no seed; demanding one from a
        // node that never spends would only put an invented secret in its deployment.
        // A publisher without a seed is left unregistered instead.
        //
        // Either case, where central_address above is lowercase-only: that address is
        // compared against decoder output, so its case decides whether attribution
        // matches. This seed is only ever decoded, never compared, so a case rule here
        // would reject a working credential to buy nothing.
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

    /// The five values a respond needs, checked as the one set the child treats them as.
    ///
    /// The child validates its submit half all-or-none and refuses to boot on any
    /// subset, and what it says about which value was missing goes to its stderr, which
    /// is a place nobody reads before the first signature goes unanswered. Named here
    /// instead, at startup, off the flags an operator actually sets.
    ///
    /// Only the names are rendered. One of the five is a spending key.
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

    /// A node that answers as well as indexes: the whole submit half filled, which is
    /// the only shape in which any one of those five values validates.
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
    fn default_config_does_not_require_archive_state() {
        // Probe-and-degrade is the default policy: a pruned node logs loudly and falls
        // back to watermark catchup.
        assert!(!IndexerConfig::default().require_archive_state);
    }

    #[test]
    fn publisher_defaults_are_pinned() {
        // The timeouts have no flags, so nothing else observes them: retune
        // `submit_timeout` or `request_timeout` by accident and this assert is the only
        // thing that goes red.
        let publisher = PublisherConfig::default();
        assert_eq!(publisher.request_timeout, Duration::from_secs(120));
        assert_eq!(publisher.submit_timeout, Duration::from_secs(300));
        // The submit half defaults blank as a set, which is the deployment that only
        // builds intents. A default endpoint would be worse than none: it would name a
        // host nobody chose, and the child would boot believing it can spend.
        assert!(publisher.funding_seed.is_empty());
        assert!(publisher.node_ws_url.is_empty());
        assert!(publisher.proof_server_url.is_empty());
        assert!(publisher.indexer_url.is_empty());
        assert!(publisher.indexer_ws_url.is_empty());
    }

    #[test]
    fn debug_redacts_the_funding_seed() {
        // `cli::log_startup` renders the chain configs with `Debug`, so whatever `Debug`
        // prints is in the node's startup line and in every `?config` after it.
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
        // The indexer-only deployment, which is every deployment today: a node that
        // never responds has nothing to fund, and rejecting it here would force an
        // invented secret into its config.
        let mut seedless = valid_config();
        seedless.publisher.funding_seed = String::new();
        seedless
            .validate()
            .expect("a node that only indexes needs no funding seed");

        responding_config()
            .validate()
            .expect("64 hex characters is 32 bytes");
    }

    #[test]
    fn a_funding_seed_may_be_uppercase_hex() {
        // Pins the asymmetry with central_address, which is lowercase-only, so it reads
        // as a decision rather than an oversight: this seed is decoded and never
        // compared, so tightening it to lowercase would reject a working credential.
        // Nothing else would go red if someone did.
        let mut config = responding_config();
        config.publisher.funding_seed = "0F".repeat(32);
        config
            .validate()
            .expect("the seed is decoded, never compared against anything");
    }

    #[test]
    fn the_submit_half_validates_as_one_set_or_not_at_all() {
        // The defect this exists for: the child validates these five all-or-none and
        // dies at boot on any subset, so a node holding four of them has no builder and
        // learns why only from a stderr line nobody is reading. Every one of the five
        // has to be the one that is missing, because a check written against a list can
        // leave a value off it and stay green for the other four.
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
        // The refusal above lists the five names, and one of them holds a spending key.
        // Rendering the values would put it in the startup error of exactly the
        // deployment most likely to be misconfigured.
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
        // Caught here or not at all: the seed is opaque to the node, which forwards it
        // to the builder, so a typo would otherwise surface as a child that fails to
        // derive a wallet long after startup.
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
            // Endpoint-complete, so the shape check is unambiguously what refuses:
            // against a blank submit half the all-or-none refusal names this field too,
            // and the assertion could not tell the two apart.
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

        // Lowercase is canonical, not a courtesy: attribution compares this address
        // against decoder-returned lowercase hex, so an uppercase config value would
        // silently never match.
        let mut uppercase = valid_config();
        uppercase.central_address = "AB".repeat(32);
        let err = uppercase.validate().unwrap_err().to_string();
        assert!(err.contains("lowercase"), "unexpected error: {err}");
    }
}
