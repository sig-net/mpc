use mpc_chain_solana::{Keypair, Pubkey, SolConfig, SolIndexerConfig};
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
        value_parser = parse_account_sk,
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

/// The Solana client loads the key with a call that panics on a malformed key,
/// so clap checks it first.
fn parse_account_sk(value: &str) -> Result<String, String> {
    Keypair::try_from_base58_string(value)
        .map(|_| value.to_owned())
        .map_err(|e| e.to_string())
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

    /// The system program id: any valid address will do.
    const PROGRAM_ADDRESS: &str = "11111111111111111111111111111111";

    fn parse(account_sk: &str, program_address: &str) -> Result<SolArgs, clap::Error> {
        SolArgs::try_parse_from([
            "test",
            "--sol-account-sk",
            account_sk,
            "--sol-rpc-http-url",
            "http://127.0.0.1:8899",
            "--sol-program-address",
            program_address,
        ])
    }

    #[test]
    fn the_cli_rejects_a_malformed_program_address() {
        let account_sk = Keypair::new().to_base58_string();
        let error = parse(&account_sk, "not-a-pubkey").unwrap_err().to_string();
        assert!(
            error.contains("--sol-program-address"),
            "unexpected address error: {error}"
        );
    }

    /// The Solana client panics on a key it cannot load, so the CLI must
    /// refuse one first.
    #[test]
    fn the_cli_rejects_a_malformed_account_sk() {
        let account_sk = Keypair::new().to_base58_string();
        assert!(parse(&account_sk, PROGRAM_ADDRESS).is_ok());

        for malformed in ["not-a-keypair", "", &account_sk[1..]] {
            let error = parse(malformed, PROGRAM_ADDRESS).unwrap_err().to_string();
            assert!(
                error.contains("--sol-account-sk"),
                "unexpected key error: {error}"
            );
        }
    }
}
