use anyhow::Context as _;
use mpc_chain_midnight::{MidnightConfig, PublisherConfig};

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
    /// Hex seed of the wallet that funds respond transactions.
    #[arg(
        long,
        env("MPC_MIDNIGHT_FUNDING_SEED"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_funding_seed: Option<String>,
    /// argv of the intent builder child process, JSON-encoded:
    /// `["node","dist/main.js"]`. One clap value rather than a multi-value
    /// flag, whose forms stop at anything flag-shaped; JSON escapes instead
    /// of terminating, so every argv survives the round trip.
    #[arg(
        long,
        env("MPC_MIDNIGHT_INTENT_GEN_COMMAND"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_intent_gen_command: Option<String>,
    /// Proof server URL. Required to respond: these contracts are zkir-v3 and
    /// cannot be proven in process.
    #[arg(
        long,
        env("MPC_MIDNIGHT_PROOF_SERVER_URL"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_proof_server_url: Option<String>,
    /// Indexer GraphQL URL. Required to respond: the funding wallet's spendable
    /// DUST is only derivable from the ledger events the indexer serves.
    #[arg(
        long,
        env("MPC_MIDNIGHT_INDEXER_URL"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_indexer_url: Option<String>,
    /// Indexer GraphQL subscription URL: the wallet catches up over the URL
    /// above and follows over this one.
    #[arg(
        long,
        env("MPC_MIDNIGHT_INDEXER_WS_URL"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_indexer_ws_url: Option<String>,
}

impl MidnightArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(14);
        if let Some(v) = self.midnight_node_ws_url {
            args.extend(["--midnight-node-ws-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_central_address {
            args.extend(["--midnight-central-address".to_string(), v]);
        }
        if let Some(v) = self.midnight_funding_seed {
            args.extend(["--midnight-funding-seed".to_string(), v]);
        }
        if let Some(v) = self.midnight_intent_gen_command {
            args.extend(["--midnight-intent-gen-command".to_string(), v]);
        }
        if let Some(v) = self.midnight_proof_server_url {
            args.extend(["--midnight-proof-server-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_indexer_url {
            args.extend(["--midnight-indexer-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_indexer_ws_url {
            args.extend(["--midnight-indexer-ws-url".to_string(), v]);
        }
        args
    }

    /// These fields are `String`, so the boundary check is `validate()` after the
    /// structural publisher group is assembled.
    pub fn into_config(self) -> anyhow::Result<Option<MidnightConfig>> {
        let (Some(node_ws_url), Some(central_address)) =
            (self.midnight_node_ws_url, self.midnight_central_address)
        else {
            return Ok(None);
        };
        let publisher_requested = self.midnight_funding_seed.is_some()
            || self.midnight_intent_gen_command.is_some()
            || self.midnight_proof_server_url.is_some()
            || self.midnight_indexer_url.is_some()
            || self.midnight_indexer_ws_url.is_some();
        let publisher = if publisher_requested {
            let missing = [
                (
                    "--midnight-funding-seed",
                    self.midnight_funding_seed.is_none(),
                ),
                (
                    "--midnight-proof-server-url",
                    self.midnight_proof_server_url.is_none(),
                ),
                (
                    "--midnight-indexer-url",
                    self.midnight_indexer_url.is_none(),
                ),
                (
                    "--midnight-indexer-ws-url",
                    self.midnight_indexer_ws_url.is_none(),
                ),
            ]
            .into_iter()
            .filter_map(|(name, absent)| absent.then_some(name))
            .collect::<Vec<_>>();
            anyhow::ensure!(
                missing.is_empty(),
                "midnight config: responding also requires {}",
                missing.join(", ")
            );
            let mut publisher = PublisherConfig {
                funding_seed: self.midnight_funding_seed.expect("checked above"),
                node_ws_url: node_ws_url.clone(),
                proof_server_url: self.midnight_proof_server_url.expect("checked above"),
                indexer_url: self.midnight_indexer_url.expect("checked above"),
                indexer_ws_url: self.midnight_indexer_ws_url.expect("checked above"),
                ..Default::default()
            };
            if let Some(command) = self.midnight_intent_gen_command {
                publisher.intent_gen_command = serde_json::from_str(&command).with_context(|| {
                    format!("midnight config: --midnight-intent-gen-command must be a JSON array of strings, got {command}")
                })?;
            }
            Some(publisher)
        } else {
            None
        };
        let config = MidnightConfig {
            node_ws_url,
            central_address,
            publisher,
            rpc: Default::default(),
            indexer: Default::default(),
        };
        config.validate()?;
        Ok(Some(config))
    }

    pub fn from_config(config: Option<MidnightConfig>) -> Self {
        match config {
            Some(c) => {
                // The tuning sub-structs have no CLI flags; into_config
                // reinstates their defaults on the other side.
                let MidnightConfig {
                    node_ws_url,
                    central_address,
                    publisher,
                    rpc: _,
                    indexer: _,
                } = c;
                let (
                    funding_seed,
                    intent_gen_command,
                    proof_server_url,
                    indexer_url,
                    indexer_ws_url,
                ) = publisher.map_or((None, None, None, None, None), |publisher| {
                    (
                        Some(publisher.funding_seed),
                        Some(
                            serde_json::to_string(&publisher.intent_gen_command)
                                .expect("a Vec<String> always serializes"),
                        ),
                        Some(publisher.proof_server_url),
                        Some(publisher.indexer_url),
                        Some(publisher.indexer_ws_url),
                    )
                });
                MidnightArgs {
                    midnight_node_ws_url: Some(node_ws_url),
                    midnight_central_address: Some(central_address),
                    midnight_funding_seed: funding_seed,
                    midnight_intent_gen_command: intent_gen_command,
                    midnight_proof_server_url: proof_server_url,
                    midnight_indexer_url: indexer_url,
                    midnight_indexer_ws_url: indexer_ws_url,
                }
            }
            None => MidnightArgs {
                midnight_node_ws_url: None,
                midnight_central_address: None,
                midnight_funding_seed: None,
                midnight_intent_gen_command: None,
                midnight_proof_server_url: None,
                midnight_indexer_url: None,
                midnight_indexer_ws_url: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use mpc_chain_midnight::IndexerConfig;
    use std::time::Duration;

    /// Publisher fields all distinguishable from their defaults, so an
    /// assertion cannot pass on a dropped flag.
    fn configured() -> MidnightConfig {
        MidnightConfig {
            node_ws_url: "ws://127.0.0.1:9944".into(),
            central_address: "ab".repeat(32),
            publisher: Some(PublisherConfig {
                funding_seed: "0f".repeat(32),
                // A space and a leading dash, which only a structured encoding gets back out intact.
                intent_gen_command: vec![
                    "node".into(),
                    "/opt/midnight publisher/dist/main.js".into(),
                    "--child-option".into(),
                ],
                proof_server_url: "http://127.0.0.1:6300".into(),
                indexer_url: "http://127.0.0.1:8088/api/v3/graphql".into(),
                indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".into(),
                // `into_config` copies it off `--midnight-node-ws-url`.
                node_ws_url: "ws://127.0.0.1:9944".into(),
                ..Default::default()
            }),
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    #[test]
    fn tuning_fields_do_not_survive_the_cli_round_trip() {
        // Known limitation, pinned deliberately: no tuning traverses a process
        // restart. Adding real flags flips this into a round-trip assert.
        crate::cli::tests::assert_midnight_env_unset();

        let mut cfg = configured();
        cfg.indexer.live_block_buffer = 77;
        cfg.indexer.stall_timeout = Duration::from_secs(7);
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
        .expect("all the gating fields are set");

        assert_eq!(reparsed.node_ws_url, cfg.node_ws_url);
        assert_eq!(reparsed.central_address, cfg.central_address);
        assert_eq!(
            reparsed.indexer,
            IndexerConfig::default(),
            "tuning does not traverse the CLI; if this fails, flags were added and this test should become a round-trip assert"
        );
    }

    #[test]
    fn into_str_args_round_trips_into_config() {
        // A flag dropped by into_str_args would be silently backfilled from a
        // set MPC_MIDNIGHT_* env var and still pass.
        crate::cli::tests::assert_midnight_env_unset();

        let cfg = configured();
        let args = MidnightArgs::from_config(Some(cfg.clone()));
        let reparsed = MidnightArgs::try_parse_from(
            std::iter::once("test".to_string()).chain(args.clone().into_str_args()),
        )
        .unwrap();
        assert_eq!(reparsed.into_config().unwrap(), Some(cfg));
    }

    #[test]
    fn the_publisher_flags_are_gated_on_the_node_ws_url() {
        // A publisher flag accepted on its own would let a node carry a funding
        // seed with no chain configured to spend it on, unnoticed.
        crate::cli::tests::assert_midnight_env_unset();

        for flag in [
            "--midnight-funding-seed",
            "--midnight-intent-gen-command",
            "--midnight-proof-server-url",
            "--midnight-indexer-url",
            "--midnight-indexer-ws-url",
        ] {
            let err = MidnightArgs::try_parse_from(["test", flag, "x"])
                .expect_err("clap must reject a publisher flag supplied on its own");
            assert!(
                err.to_string().contains("midnight-node-ws-url"),
                "{flag} is not gated on the node ws url: {err}"
            );
        }
    }

    #[test]
    fn contract_assets_are_not_an_operator_input() {
        crate::cli::tests::assert_midnight_env_unset();

        let err = MidnightArgs::try_parse_from(["test", "--midnight-managed-dir", "/tmp/managed"])
            .expect_err("the TypeScript package owns its matching contract assets");
        assert!(
            err.to_string().contains("unexpected argument"),
            "got: {err}"
        );
    }

    #[test]
    fn the_builder_s_node_url_is_taken_from_the_one_flag_that_names_the_node() {
        // The assertion that keeps it from gaining a flag of its own.
        crate::cli::tests::assert_midnight_env_unset();

        let cfg = configured();
        let rendered = MidnightArgs::from_config(Some(cfg.clone())).into_str_args();
        assert!(
            !rendered.iter().any(|a| a.contains("publisher-node")),
            "the builder's node url must render no flag of its own: {rendered:?}"
        );

        let reparsed =
            MidnightArgs::try_parse_from(std::iter::once("test".to_string()).chain(rendered))
                .unwrap()
                .into_config()
                .expect("a valid config passes the boundary check")
                .expect("all the gating fields are set");
        assert_eq!(
            reparsed
                .publisher
                .expect("the test config responds")
                .node_ws_url,
            cfg.node_ws_url
        );
    }

    #[test]
    fn a_node_that_only_indexes_is_handed_no_endpoint_at_all() {
        // An indexer-only deployment carrying the node url alone would be four
        // values short of a builder that boots.
        crate::cli::tests::assert_midnight_env_unset();

        let mut cfg = configured();
        cfg.publisher = None;
        let reparsed = MidnightArgs::try_parse_from(
            std::iter::once("test".to_string())
                .chain(MidnightArgs::from_config(Some(cfg.clone())).into_str_args()),
        )
        .unwrap()
        .into_config()
        .expect("a node with no seed and no endpoints is a legal deployment")
        .expect("all the gating fields are set");

        assert_eq!(reparsed.publisher, None);
    }

    #[test]
    fn a_malformed_intent_gen_command_fails_at_the_config_boundary() {
        // argv arrives as one opaque clap value; the shape check has nowhere
        // else to happen.
        crate::cli::tests::assert_midnight_env_unset();

        let mut args = MidnightArgs::from_config(Some(configured()));
        args.midnight_intent_gen_command = Some("node dist/main.js".into());
        let err = args.into_config().unwrap_err().to_string();

        assert!(
            err.contains("--midnight-intent-gen-command"),
            "unexpected error: {err}"
        );
    }
}
