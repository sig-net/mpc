use mpc_chain_midnight::MidnightConfig;

/// CLI arguments for the Midnight indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_midnight_options")]
pub struct MidnightArgs {
    /// Midnight node WebSocket RPC URL.
    #[arg(
        long,
        env("MPC_MIDNIGHT_NODE_WS_URL"),
        requires = "midnight_central_address"
    )]
    pub midnight_node_ws_url: Option<String>,
    /// Address of the central singleton contract: 64 hex characters, no `0x` prefix.
    #[arg(
        long,
        env("MPC_MIDNIGHT_CENTRAL_ADDRESS"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_central_address: Option<String>,
}

impl MidnightArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(4);
        if let Some(v) = self.midnight_node_ws_url {
            args.extend(["--midnight-node-ws-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_central_address {
            args.extend(["--midnight-central-address".to_string(), v]);
        }
        args
    }

    /// Validates at the config boundary, the way `EthArgs::into_config` does.
    /// Ethereum can validate by parsing into `Url`/`Address`/`PrivateKeySigner`,
    /// which make an invalid value unrepresentable; these fields are `String`,
    /// so the boundary check is `validate()` instead. clap's `requires` only
    /// guarantees the two flags arrive together, never that `central_address`
    /// is 64 lowercase hex.
    pub fn into_config(self) -> anyhow::Result<Option<MidnightConfig>> {
        let (Some(node_ws_url), Some(central_address)) =
            (self.midnight_node_ws_url, self.midnight_central_address)
        else {
            return Ok(None);
        };
        let config = MidnightConfig {
            node_ws_url,
            central_address,
            rpc: Default::default(),
            indexer: Default::default(),
        };
        config.validate()?;
        Ok(Some(config))
    }

    pub fn from_config(config: Option<MidnightConfig>) -> Self {
        match config {
            Some(c) => {
                // The rpc/indexer tuning sub-structs have no CLI flags;
                // into_config reinstates their defaults on the other side.
                let MidnightConfig {
                    node_ws_url,
                    central_address,
                    rpc: _,
                    indexer: _,
                } = c;
                MidnightArgs {
                    midnight_node_ws_url: Some(node_ws_url),
                    midnight_central_address: Some(central_address),
                }
            }
            None => MidnightArgs {
                midnight_node_ws_url: None,
                midnight_central_address: None,
            },
        }
    }
}
