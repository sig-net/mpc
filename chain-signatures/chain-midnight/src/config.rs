//! Midnight node and sidecar configuration.

use mpc_chain_integration_core::utils::retry::RetryConfig;
use std::time::Duration;

/// Timeouts and retry budget for outbound Midnight calls. Shared by the subxt
/// node RPC client and the sidecar HTTP client.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// Timeout for establishing the node WebSocket connection
    pub connect_timeout: Duration,
    /// Timeout for a single node RPC or sidecar request
    pub request_timeout: Duration,
    /// How long the finalized-head subscription may go silent before `run()`
    /// returns and lets the supervisor restart it
    pub stall_timeout: Duration,
    /// Retry strategy shared by all outbound calls
    pub retry: RetryConfig,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
            stall_timeout: Duration::from_secs(60),
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
#[derive(Clone, Debug)]
pub struct IndexerConfig {
    /// How many blocks back a contract-state read may walk when the node has
    /// pruned the state at the block being asked for
    pub archive_probe_window: u64,
    /// Capacity of the live-block channel
    pub live_block_buffer: usize,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            archive_probe_window: 1024,
            live_block_buffer: 16384,
        }
    }
}

/// Midnight chain integration configuration. Supplying it is what turns the
/// integration on; the node leaves Midnight unspawned when it is absent.
#[derive(Clone, Debug, Default)]
pub struct MidnightConfig {
    /// Base URL of the `midnight-publisher-ts` sidecar
    pub sidecar_url: String,
    /// Midnight node WebSocket RPC URL
    pub node_ws_url: String,
    /// Address of the central singleton contract: 64 hex characters, no `0x` prefix
    pub central_address: String,
    /// Ledger network id. Must equal the sidecar's `MIDNIGHT_PUB_NETWORK_ID`
    pub network_id: String,
    pub rpc: RpcConfig,
    pub indexer: IndexerConfig,
}
