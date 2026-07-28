//! Midnight node configuration.

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

/// Tuning for the indexing pipeline (catchup and the live finalized-head loop).
#[derive(Clone, Debug, PartialEq)]
pub struct IndexerConfig {
    pub live_block_buffer: usize,
    /// How long the finalized-head subscription may go silent before `run()` returns
    /// and lets the supervisor restart it
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

/// Midnight chain integration configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct MidnightConfig {
    pub node_ws_url: String,
    /// Address of the central singleton contract: 64 hex characters, no `0x` prefix
    pub central_address: String,
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
            rpc: Default::default(),
            indexer: Default::default(),
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
