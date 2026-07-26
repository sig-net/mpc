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

    /// Validates at the config boundary, the way `EthArgs::into_config` does.
    /// Ethereum can validate by parsing into `Url`/`Address`/`PrivateKeySigner`,
    /// which make an invalid value unrepresentable; these fields are `String`,
    /// so the boundary check is `validate()` instead. clap's `requires_all`
    /// only guarantees the four flags arrive together, never that
    /// `central_address` is 64 lowercase hex.
    pub fn into_config(self) -> anyhow::Result<Option<MidnightConfig>> {
        let (Some(sidecar_url), Some(node_ws_url), Some(central_address), Some(network_id)) = (
            self.midnight_sidecar_url,
            self.midnight_node_ws_url,
            self.midnight_central_address,
            self.midnight_network_id,
        ) else {
            return Ok(None);
        };
        let config = MidnightConfig {
            sidecar_url,
            node_ws_url,
            central_address,
            network_id,
            rpc: Default::default(),
            sidecar: Default::default(),
            indexer: Default::default(),
        };
        config.validate()?;
        Ok(Some(config))
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
    use mpc_chain_midnight::IndexerConfig;

    #[test]
    fn tuning_fields_do_not_survive_the_cli_round_trip() {
        // Known limitation, pinned deliberately: only the four
        // endpoint/identity fields have CLI flags, so from_config discards
        // the rpc/sidecar/indexer tuning sub-structs and into_config
        // reinstates their defaults on the other side. In particular,
        // archive_probe_window and require_archive_state cannot traverse the
        // recommended process-restart path. Dropping MidnightConfig's
        // Default derive closed the accidental empty-config path; it did NOT
        // close this one. If operators need to tune these, the fix is real
        // flags, at which point this pin flips into a round-trip assert.
        crate::cli::tests::assert_midnight_env_unset();

        let mut cfg = MidnightConfig {
            sidecar_url: "http://127.0.0.1:8790".into(),
            node_ws_url: "ws://127.0.0.1:9944".into(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".into(),
            rpc: Default::default(),
            sidecar: Default::default(),
            indexer: Default::default(),
        };
        cfg.indexer.archive_probe_window = 77;
        cfg.indexer.require_archive_state = true;
        assert_ne!(
            cfg.indexer,
            IndexerConfig::default(),
            "the pin is vacuous unless the tuning actually differs"
        );

        let reparsed = MidnightArgs::try_parse_from(
            std::iter::once("test".to_string())
                .chain(MidnightArgs::from_config(Some(cfg.clone())).into_str_args()),
        )
        .unwrap()
        .into_config()
        .expect("a valid config passes the boundary check")
        .expect("all four flagged fields are set");

        assert_eq!(reparsed.sidecar_url, cfg.sidecar_url);
        assert_eq!(reparsed.node_ws_url, cfg.node_ws_url);
        assert_eq!(reparsed.central_address, cfg.central_address);
        assert_eq!(reparsed.network_id, cfg.network_id);
        assert_eq!(
            reparsed.indexer,
            IndexerConfig::default(),
            "tuning does not traverse the CLI; if this fails, flags were added and this test should become a round-trip assert"
        );
    }

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
        assert_eq!(reparsed.into_config().unwrap(), Some(cfg));
    }
}
