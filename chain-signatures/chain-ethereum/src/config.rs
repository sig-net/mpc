use alloy::primitives::Address;
use alloy_signer_local::PrivateKeySigner;
use mpc_chain_integration_core::utils::retry::RetryConfig;
use reqwest::Url;
use std::fmt;
use std::time::Duration;

/// Timeouts and retry budget for the read-side Ethereum RPC client.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// Timeout for single-call RPC requests
    pub timeout: Duration,
    /// Timeout for batched RPC requests
    pub batch_timeout: Duration,
    /// Retry strategy shared by all RPC calls
    pub retry: RetryConfig,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            batch_timeout: Duration::from_secs(5),
            retry: RetryConfig {
                min_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(10),
                max_times: 5,
                jitter: true,
            },
        }
    }
}

/// Gas limits for `respond` transactions. Chain-specific: other EVM chains
/// need their own values.
#[derive(Clone, Debug)]
pub struct GasConfig {
    /// Minimum gas limit; estimated gas is never clamped below this
    pub base_gas_limit: u64,
    /// Per-request gas used by the static fallback heuristic
    pub batch_gas_per_request: u64,
    /// Maximum gas limit per transaction
    pub max_gas_limit: u64,
    /// Fractional buffer applied on top of the dynamically estimated gas.
    /// Absorbs variance between estimation and execution so transactions
    /// don't revert on chain.
    pub estimation_buffer_percent: u64,
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            base_gas_limit: 40_000,
            batch_gas_per_request: 20_000,
            max_gas_limit: 16_777_216,
            estimation_buffer_percent: 20,
        }
    }
}

impl GasConfig {
    /// Gas limit from a dynamic `eth_estimateGas` result: buffered, then
    /// clamped to `[base_gas_limit, max_gas_limit]`.
    pub fn clamp_estimate(&self, estimate: u64) -> u64 {
        let buffered = estimate + (estimate / 100).saturating_mul(self.estimation_buffer_percent);
        buffered.min(self.max_gas_limit).max(self.base_gas_limit)
    }

    /// Static fallback heuristic when dynamic estimation fails.
    pub fn fallback_gas(&self, num_requests: u64) -> u64 {
        self.base_gas_limit
            .max(self.batch_gas_per_request * num_requests)
    }
}

/// Batching behavior and retry budgets for the publish path.
#[derive(Clone, Debug)]
pub struct PublisherConfig {
    /// Maximum number of responses per `respond` transaction
    pub max_batch_size: usize,
    /// Flush pending responses after this long even if the batch isn't full
    pub batch_flush_interval: Duration,
    /// Capacity of the channel feeding the background batching task
    pub channel_capacity: usize,
    /// Timeout for a single transaction send attempt
    pub send_timeout: Duration,
    /// Retry strategy for sending the `respond` transaction
    pub send_retry: RetryConfig,
    /// Timeout for a single receipt poll attempt
    pub receipt_timeout: Duration,
    /// Retry strategy for polling the transaction receipt
    pub receipt_retry: RetryConfig,
    /// Retry strategy for the whole batch publish (retries indefinitely)
    pub batch_publish_retry: RetryConfig,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 10,
            batch_flush_interval: Duration::from_millis(2000),
            channel_capacity: 1024,
            send_timeout: Duration::from_secs(5),
            send_retry: RetryConfig {
                min_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(10),
                max_times: 3,
                jitter: true,
            },
            receipt_timeout: Duration::from_secs(2),
            receipt_retry: RetryConfig {
                min_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(20),
                max_times: 6,
                jitter: true,
            },
            batch_publish_retry: RetryConfig {
                min_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(10),
                max_times: usize::MAX,
                jitter: true,
            },
        }
    }
}

/// Tuning for the indexing pipeline (catchup, live stream, finality waits).
#[derive(Clone, Debug)]
pub struct IndexerConfig {
    /// Blocks per catchup batch (`eth_getBlockByNumber` JSON-RPC batch)
    pub catchup_block_batch_size: u64,
    /// Capacity of the live-block channel
    pub live_block_buffer: usize,
    /// Consecutive `get_block(Finalized)` failures tolerated before
    /// `wait_for_finalized_block` gives up
    pub max_finalized_failures: u32,
    /// Re-warn interval (seconds) while the finalized head is stalled
    pub stall_rewarn_secs: u64,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            catchup_block_batch_size: 32,
            live_block_buffer: 16384,
            max_finalized_failures: 20,
            stall_rewarn_secs: 300,
        }
    }
}

#[derive(Clone)]
pub struct EthConfig {
    /// The ethereum account secret key used to sign eth respond txn.
    pub account_sk: PrivateKeySigner,
    /// Ethereum consensus HTTP RPC URL
    pub consensus_rpc_http_url: String,
    /// Ethereum execution HTTP RPC URL
    pub execution_rpc_http_url: Url,
    /// The contract address to watch
    pub contract_address: Address,
    /// must be one of sepolia, mainnet
    pub network: String,
    /// path to store helios data
    pub helios_data_path: String,
    /// refresh finalized block interval in milliseconds
    pub refresh_finalized_interval: u64,
    /// Emit requests without waiting for block finality. Only for dev chains
    /// (anvil never reports finalized blocks); unsafe on live networks.
    pub optimistic_requests: bool,
    /// light client is true if using helios, false if using direct rpc
    pub light_client: bool,
    pub rpc: RpcConfig,
    pub gas: GasConfig,
    pub publisher: PublisherConfig,
    pub indexer: IndexerConfig,
}

impl EthConfig {
    /// Ethereum address derived from the configured account secret key.
    pub fn signer_address(&self) -> String {
        self.account_sk.address().to_string()
    }
}

impl fmt::Debug for EthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthConfig")
            .field("account_sk", &"<hidden>")
            .field("consensus_rpc_http_url", &self.consensus_rpc_http_url)
            .field("execution_rpc_http_url", &self.execution_rpc_http_url)
            .field("contract_address", &self.contract_address)
            .field("network", &self.network)
            .field("helios_data_path", &self.helios_data_path)
            .field(
                "refresh_finalized_interval",
                &self.refresh_finalized_interval,
            )
            .field("optimistic_requests", &self.optimistic_requests)
            .field("light_client", &self.light_client)
            .field("rpc", &self.rpc)
            .field("gas", &self.gas)
            .field("publisher", &self.publisher)
            .field("indexer", &self.indexer)
            .finish()
    }
}
