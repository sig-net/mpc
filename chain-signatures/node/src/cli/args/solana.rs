use mpc_chain_solana::{Pubkey, SolConfig, SolIndexerConfig};
use url::Url;

/// Configures Solana indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_sol_options")]
pub struct SolArgs {
    /// Keypair that signs and pays for the node's Solana responses, in base58,
    /// not the JSON byte array `solana-keygen` writes.
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
    pub sol_program_address: Option<Pubkey>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn the_cli_rejects_a_malformed_program_address() {
        let error = SolArgs::try_parse_from([
            "test",
            "--sol-account-sk",
            "sk",
            "--sol-rpc-http-url",
            "http://127.0.0.1:8899",
            "--sol-program-address",
            "not-a-pubkey",
        ])
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("--sol-program-address"),
            "unexpected address error: {error}"
        );
    }
}
