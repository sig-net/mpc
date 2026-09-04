use mpc_chain_solana::{SolConfig, SolIndexerConfig};
use std::time::Duration;

/// Configures Solana indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_sol_options")]
pub struct SolArgs {
    /// The solana account secret key used to sign solana respond txn.
    #[arg(long, env("MPC_SOL_ACCOUNT_SK"))]
    pub sol_account_sk: Option<String>,
    /// Solana RPC HTTP URL
    #[clap(long, env("MPC_SOL_RPC_HTTP_URL"), requires = "sol_account_sk")]
    pub sol_rpc_http_url: Option<String>,
    /// The program address to watch
    #[clap(long, env("MPC_SOL_PROGRAM_ADDRESS"), requires = "sol_account_sk")]
    pub sol_program_address: Option<String>,
    /// Polling interval for the Solana indexer in milliseconds
    #[clap(long, env("MPC_SOL_POLL_INTERVAL_MS"), default_value = "1000")]
    pub sol_poll_interval_ms: u64,
}

impl SolArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(6);
        if let Some(sol_account_sk) = self.sol_account_sk {
            args.extend(["--sol-account-sk".to_string(), sol_account_sk]);
        }
        if let Some(sol_rpc_http_url) = self.sol_rpc_http_url {
            args.extend(["--sol-rpc-http-url".to_string(), sol_rpc_http_url]);
        }
        if let Some(sol_program_address) = self.sol_program_address {
            args.extend(["--sol-program-address".to_string(), sol_program_address]);
        }
        args.extend([
            "--sol-poll-interval-ms".to_string(),
            self.sol_poll_interval_ms.to_string(),
        ]);
        args
    }

    pub fn into_config(self) -> Option<SolConfig> {
        Some(SolConfig {
            account_sk: self.sol_account_sk?,
            rpc_http_url: self.sol_rpc_http_url?,
            program_address: self.sol_program_address?,
            indexer: SolIndexerConfig {
                poll_interval: Duration::from_millis(self.sol_poll_interval_ms),
                ..SolIndexerConfig::default()
            },
        })
    }

    pub fn from_config(config: Option<SolConfig>) -> Self {
        match config {
            Some(config) => SolArgs {
                sol_account_sk: Some(config.account_sk),
                sol_rpc_http_url: Some(config.rpc_http_url),
                sol_program_address: Some(config.program_address),
                sol_poll_interval_ms: config.indexer.poll_interval.as_millis() as u64,
            },
            None => SolArgs {
                sol_account_sk: None,
                sol_rpc_http_url: None,
                sol_program_address: None,
                sol_poll_interval_ms: SolIndexerConfig::default().poll_interval.as_millis() as u64,
            },
        }
    }
}
