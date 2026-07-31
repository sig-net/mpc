//! Midnight node configuration.

use mpc_chain_integration_core::utils::retry::RetryConfig;
use std::time::Duration;

/// Timeouts and retry budget for the subxt node RPC client.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub retry: RetryConfig,
}

/// Hand-written because `RetryConfig` is not `PartialEq`. Destructured rather than
/// field-selected so a field added upstream fails to compile here instead of being
/// silently excluded from the comparison the CLI round-trip test depends on.
impl PartialEq for RpcConfig {
    fn eq(&self, other: &Self) -> bool {
        let RetryConfig {
            min_delay,
            max_delay,
            max_times,
            jitter,
        } = self.retry;
        self.connect_timeout == other.connect_timeout
            && self.request_timeout == other.request_timeout
            && min_delay == other.retry.min_delay
            && max_delay == other.retry.max_delay
            && max_times == other.retry.max_times
            && jitter == other.retry.jitter
    }
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
        // Required rather than normalised: the address is compared against the decoder's
        // lowercase addresses during attribution, so an uppercase value would silently
        // never match.
        anyhow::ensure!(
            !self.central_address.bytes().any(|b| b.is_ascii_uppercase()),
            "midnight config: central_address must be lowercase hex, the canonical form \
             every comparison site assumes"
        );
        Ok(())
    }
}
