use mpc_chain_hydration::HydrationConfig;
use url::Url;

/// Configures Hydration indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_hydration_options")]
pub struct HydrationArgs {
    /// Hydration RPC ws URL
    #[arg(
        long,
        env("MPC_HYDRATION_RPC_WS_URL"),
        hide_env_values = true,
        requires = "hydration_signer_uri"
    )]
    pub hydration_rpc_ws_url: Option<Url>,
    /// Hydration signer URI
    #[arg(
        long,
        env("MPC_HYDRATION_SIGNER_URI"),
        hide_env_values = true,
        requires = "hydration_rpc_ws_url"
    )]
    pub hydration_signer_uri: Option<String>,
}

impl HydrationArgs {
    pub fn into_config(self) -> Option<HydrationConfig> {
        Some(HydrationConfig {
            rpc_ws_url: self.hydration_rpc_ws_url?,
            signer_uri: self.hydration_signer_uri?,
        })
    }
}
