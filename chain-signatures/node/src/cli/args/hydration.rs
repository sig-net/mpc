use mpc_chain_hydration::HydrationConfig;

/// Configures Hydration indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_hydration_options")]
pub struct HydrationArgs {
    /// Hydration RPC ws URL
    #[arg(
        long = "hydration-rpc-ws-url",
        env("MPC_HYDRATION_RPC_WS_URL"),
        hide_env_values = true,
        requires = "signer_uri"
    )]
    pub rpc_ws_url: Option<String>,
    /// Hydration signer URI
    #[arg(
        long = "hydration-signer-uri",
        env("MPC_HYDRATION_SIGNER_URI"),
        hide_env_values = true,
        requires = "rpc_ws_url"
    )]
    pub signer_uri: Option<String>,
}

impl HydrationArgs {
    pub fn into_config(self) -> Option<HydrationConfig> {
        Some(HydrationConfig {
            rpc_ws_url: self.rpc_ws_url?,
            signer_uri: self.signer_uri?,
        })
    }
}
