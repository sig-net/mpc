use mpc_chain_solana::{SolConfig, SolIndexerConfig};
use url::Url;

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
    pub sol_rpc_http_url: Option<Url>,
    /// The program address to watch
    #[arg(long, env("MPC_SOL_PROGRAM_ADDRESS"), requires = "sol_account_sk")]
    pub sol_program_address: Option<String>,
}

impl SolArgs {
    pub fn into_config(self) -> Option<SolConfig> {
        Some(SolConfig {
            account_sk: self.sol_account_sk?,
            rpc_http_url: self.sol_rpc_http_url?,
            program_address: self.sol_program_address?,
            indexer: SolIndexerConfig::default(),
        })
    }
}
