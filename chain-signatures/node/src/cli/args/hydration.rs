use crate::indexer_hydration::HydrationConfig;

/// Configures Hydration indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_hydration_options")]
pub struct HydrationArgs {
    /// Hydration RPC ws URL
    #[clap(long = "hydration-rpc-ws-url", env("MPC_HYDRATION_RPC_WS_URL"))]
    pub rpc_ws_url: Option<String>,
    /// Hydration signer URI
    #[clap(long = "hydration-signer-uri", env("MPC_HYDRATION_SIGNER_URI"))]
    pub signer_uri: Option<String>,
}

impl HydrationArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(2);
        if let Some(rpc_ws_url) = self.rpc_ws_url {
            args.extend(["--hydration-rpc-ws-url".to_string(), rpc_ws_url]);
        }
        if let Some(signer_uri) = self.signer_uri {
            args.extend(["--hydration-signer-uri".to_string(), signer_uri]);
        }
        args
    }

    pub fn into_config(self) -> Option<HydrationConfig> {
        Some(HydrationConfig {
            rpc_ws_url: self.rpc_ws_url?,
            signer_uri: self.signer_uri?,
        })
    }

    pub fn from_config(config: Option<HydrationConfig>) -> Self {
        match config {
            Some(config) => HydrationArgs {
                rpc_ws_url: Some(config.rpc_ws_url),
                signer_uri: Some(config.signer_uri),
            },
            None => HydrationArgs {
                rpc_ws_url: None,
                signer_uri: None,
            },
        }
    }
}
