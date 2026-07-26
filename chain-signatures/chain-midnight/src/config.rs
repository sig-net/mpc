//! Midnight node and sidecar configuration.

use mpc_chain_integration_core::utils::retry::RetryConfig;
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

/// Timeouts and retry budget for the `midnight-publisher-ts` sidecar.
#[derive(Clone, Debug, PartialEq)]
pub struct SidecarConfig {
    pub request_timeout: Duration,
    /// Slower and shorter than the node budget: retrying hard only deepens wallet
    /// contention
    pub retry: RetryConfig,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            retry: RetryConfig {
                min_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(30),
                max_times: 3,
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

/// Midnight chain integration configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct MidnightConfig {
    pub sidecar_url: String,
    pub node_ws_url: String,
    /// Address of the central singleton contract: 64 hex characters, no `0x` prefix
    pub central_address: String,
    /// Ledger network id.
    pub network_id: String,
    pub rpc: RpcConfig,
    pub sidecar: SidecarConfig,
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
            !self.sidecar_url.is_empty(),
            "midnight config: sidecar_url is empty"
        );
        anyhow::ensure!(
            self.central_address.len() == 64
                && self.central_address.bytes().all(|b| b.is_ascii_hexdigit()),
            "midnight config: central_address must be 64 hex characters with no 0x prefix, \
             got {} characters",
            self.central_address.len()
        );
        // Required rather than normalised: the address flows verbatim into chain_ctx
        // and is compared against the sidecar's lowercase addresses during attribution,
        // so an uppercase value would silently never match.
        anyhow::ensure!(
            !self.central_address.bytes().any(|b| b.is_ascii_uppercase()),
            "midnight config: central_address must be lowercase hex, the canonical form \
             every comparison site assumes"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> MidnightConfig {
        MidnightConfig {
            sidecar_url: "http://127.0.0.1:8790".to_string(),
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".to_string(),
            rpc: Default::default(),
            sidecar: Default::default(),
            indexer: Default::default(),
        }
    }

    #[test]
    fn default_config_does_not_require_archive_state() {
        // Probe-and-degrade is the default policy: a pruned node logs loudly and falls
        // back to watermark catchup.
        assert!(!IndexerConfig::default().require_archive_state);
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

        let mut empty_sidecar = valid_config();
        empty_sidecar.sidecar_url = String::new();
        let err = empty_sidecar.validate().unwrap_err().to_string();
        assert!(err.contains("sidecar_url"), "unexpected error: {err}");

        // Lowercase is canonical, not a courtesy: attribution compares this address
        // against sidecar-returned lowercase hex, so an uppercase config value would
        // silently never match.
        let mut uppercase = valid_config();
        uppercase.central_address = "AB".repeat(32);
        let err = uppercase.validate().unwrap_err().to_string();
        assert!(err.contains("lowercase"), "unexpected error: {err}");
    }
}
