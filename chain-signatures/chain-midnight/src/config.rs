//! Midnight node and sidecar configuration.

use mpc_chain_integration_core::utils::retry::RetryConfig;
use std::time::Duration;

/// Timeouts and retry budget for the subxt node RPC client. The sidecar has its
/// own budget in [`SidecarConfig`]: a node call slow enough to be a proving run
/// is a fault, not a wait.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcConfig {
    /// Timeout for establishing the node WebSocket connection
    pub connect_timeout: Duration,
    /// Timeout for a single node RPC request
    pub request_timeout: Duration,
    /// Retry strategy for node RPC calls
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

/// Timeouts and retry budget for the `midnight-publisher-ts` sidecar. Kept apart
/// from [`RpcConfig`] because the two have incomparable budgets: a decode call
/// is cheap, but `POST /respond` proves a circuit and takes minutes.
#[derive(Clone, Debug, PartialEq)]
pub struct SidecarConfig {
    /// Timeout for the decode and health routes, which do no proving
    pub request_timeout: Duration,
    /// Timeout for `POST /respond`. Must exceed the sidecar's own six-minute
    /// `RESPOND_TIMEOUT` so its structured error wins over a client-side abort
    /// part way through a proof
    pub respond_timeout: Duration,
    /// Retry strategy for sidecar calls. Slower and shorter than the node RPC
    /// budget: a sidecar call can be queued behind the single-dust-UTXO wallet,
    /// where retrying hard only deepens the contention
    pub retry: RetryConfig,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            respond_timeout: Duration::from_secs(420),
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
    /// How many blocks back a contract-state read may walk when the node has
    /// pruned the state at the block being asked for
    pub archive_probe_window: u64,
    /// Capacity of the live-block channel
    pub live_block_buffer: usize,
    /// How long the finalized-head subscription may go silent before `run()`
    /// returns and lets the supervisor restart it
    pub stall_timeout: Duration,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            archive_probe_window: 1024,
            live_block_buffer: 16384,
            stall_timeout: Duration::from_secs(60),
        }
    }
}

/// Midnight chain integration configuration. Supplying it is what turns the
/// integration on; the node leaves Midnight unspawned when it is absent.
/// Deliberately NOT `Default`: a defaulted config has empty endpoints, so
/// any `unwrap_or_default()` on the gate would spawn a Midnight indexer
/// pointed at nothing. Keeping the derive off makes that a compile error.
#[derive(Clone, Debug, PartialEq)]
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
    pub sidecar: SidecarConfig,
    pub indexer: IndexerConfig,
}
