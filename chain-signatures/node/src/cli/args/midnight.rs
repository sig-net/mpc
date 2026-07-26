use mpc_chain_midnight::MidnightConfig;

/// CLI arguments for the Midnight indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_midnight_options")]
pub struct MidnightArgs {
    /// Base URL of the `midnight-publisher-ts` sidecar.
    #[arg(
        long,
        env("MPC_MIDNIGHT_SIDECAR_URL"),
        requires_all = [
            "midnight_node_ws_url",
            "midnight_central_address",
            "midnight_network_id",
        ]
    )]
    pub midnight_sidecar_url: Option<String>,
    /// Midnight node WebSocket RPC URL.
    #[arg(
        long,
        env("MPC_MIDNIGHT_NODE_WS_URL"),
        requires = "midnight_sidecar_url"
    )]
    pub midnight_node_ws_url: Option<String>,
    /// Address of the central singleton contract: 64 hex characters, no `0x` prefix.
    #[arg(
        long,
        env("MPC_MIDNIGHT_CENTRAL_ADDRESS"),
        requires = "midnight_sidecar_url"
    )]
    pub midnight_central_address: Option<String>,
    /// Ledger network id. Must equal the sidecar's `MIDNIGHT_PUB_NETWORK_ID`.
    #[arg(
        long,
        env("MPC_MIDNIGHT_NETWORK_ID"),
        requires = "midnight_sidecar_url"
    )]
    pub midnight_network_id: Option<String>,
}

impl MidnightArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(8);
        if let Some(v) = self.midnight_sidecar_url {
            args.extend(["--midnight-sidecar-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_node_ws_url {
            args.extend(["--midnight-node-ws-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_central_address {
            args.extend(["--midnight-central-address".to_string(), v]);
        }
        if let Some(v) = self.midnight_network_id {
            args.extend(["--midnight-network-id".to_string(), v]);
        }
        args
    }

    pub fn into_config(self) -> Option<MidnightConfig> {
        Some(MidnightConfig {
            sidecar_url: self.midnight_sidecar_url?,
            node_ws_url: self.midnight_node_ws_url?,
            central_address: self.midnight_central_address?,
            network_id: self.midnight_network_id?,
            rpc: Default::default(),
            sidecar: Default::default(),
            indexer: Default::default(),
        })
    }

    pub fn from_config(config: Option<MidnightConfig>) -> Self {
        match config {
            Some(c) => {
                // The rpc/sidecar/indexer tuning sub-structs have no CLI flags;
                // into_config reinstates their defaults on the other side.
                let MidnightConfig {
                    sidecar_url,
                    node_ws_url,
                    central_address,
                    network_id,
                    rpc: _,
                    sidecar: _,
                    indexer: _,
                } = c;
                MidnightArgs {
                    midnight_sidecar_url: Some(sidecar_url),
                    midnight_node_ws_url: Some(node_ws_url),
                    midnight_central_address: Some(central_address),
                    midnight_network_id: Some(network_id),
                }
            }
            None => MidnightArgs {
                midnight_sidecar_url: None,
                midnight_node_ws_url: None,
                midnight_central_address: None,
                midnight_network_id: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn into_str_args_round_trips_into_config() {
        // Load-bearing here: this test reparses via try_parse_from and then
        // asserts equality, so a flag dropped by into_str_args would be
        // silently backfilled from a set MPC_MIDNIGHT_* env var and the
        // assertion would still pass.
        crate::cli::tests::assert_midnight_env_unset();

        let cfg = MidnightConfig {
            sidecar_url: "http://127.0.0.1:8790".into(),
            node_ws_url: "ws://127.0.0.1:9944".into(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".into(),
            rpc: Default::default(),
            sidecar: Default::default(),
            indexer: Default::default(),
        };
        let args = MidnightArgs::from_config(Some(cfg.clone()));
        let reparsed = MidnightArgs::try_parse_from(
            std::iter::once("test".to_string()).chain(args.clone().into_str_args()),
        )
        .unwrap();
        assert_eq!(reparsed.into_config(), Some(cfg));
    }
}
