use mpc_chain_solana::{SolConfig, SolIndexerConfig};
use std::time::Duration;

/// Configures Solana indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_sol_options")]
pub struct SolArgs {
    /// The solana account secret key used to sign solana respond txn.
    #[arg(
        long,
        env("MPC_SOL_ACCOUNT_SK"),
        hide_env_values = true,
        requires_all = ["sol_rpc_http_url", "sol_program_address"]
    )]
    pub sol_account_sk: Option<String>,
    /// Solana RPC HTTP URL
    #[arg(
        long,
        env("MPC_SOL_RPC_HTTP_URL"),
        hide_env_values = true,
        requires = "sol_account_sk"
    )]
    pub sol_rpc_http_url: Option<String>,
    /// The program address to watch
    #[arg(long, env("MPC_SOL_PROGRAM_ADDRESS"), requires = "sol_account_sk")]
    pub sol_program_address: Option<String>,
    /// Polling interval for the Solana indexer in milliseconds
    #[arg(long, env("MPC_SOL_POLL_INTERVAL_MS"), default_value = "1000")]
    pub sol_poll_interval_ms: u64,
}

impl SolArgs {
    pub fn into_config(self) -> Option<SolConfig> {
        Some(SolConfig {
            account_sk: self.sol_account_sk?,
            rpc_http_url: self.sol_rpc_http_url?,
            program_address: self.sol_program_address?,
            indexer: SolIndexerConfig {
                poll_interval: Duration::from_millis(self.sol_poll_interval_ms),
            },
        })
    }
}
