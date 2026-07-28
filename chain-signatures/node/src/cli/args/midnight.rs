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
        requires_all = [
            "midnight_central_address",
            "midnight_network_id",
        ]
    )]
    pub midnight_node_ws_url: Option<String>,
    /// Address of the central singleton contract: 64 hex characters, no `0x` prefix.
    #[arg(
        long,
        env("MPC_MIDNIGHT_CENTRAL_ADDRESS"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_central_address: Option<String>,
    /// Ledger network id.
    #[arg(
        long,
        env("MPC_MIDNIGHT_NETWORK_ID"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_network_id: Option<String>,
    /// Hex seed of the wallet that funds respond transactions.
    #[arg(
        long,
        env("MPC_MIDNIGHT_FUNDING_SEED"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_funding_seed: Option<String>,
    /// Directory the publisher keeps its prover artifacts and wallet state in.
    #[arg(
        long,
        env("MPC_MIDNIGHT_MANAGED_DIR"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_managed_dir: Option<String>,
    /// argv of the intent builder child process, JSON-encoded:
    /// `["node","dist/main.js"]`.
    ///
    /// A JSON array in one clap value rather than a multi-value flag: clap's
    /// multi-value forms keep consuming tokens until the next `--flag`, so an
    /// argv element that itself looks like a flag would end the list and
    /// `into_str_args` could not emit this flag ahead of another one and get
    /// the same argv back. Delimiter splitting has the matching defect one
    /// level down, making the delimiter unrepresentable inside an element;
    /// JSON escapes instead of terminating, so every argv survives.
    #[arg(
        long,
        env("MPC_MIDNIGHT_INTENT_GEN_COMMAND"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_intent_gen_command: Option<String>,
    /// Proof server URL. Required to respond: these contracts are zkir-v3 and
    /// cannot be proven in process, so there is no local-proving deployment to
    /// fall back to.
    #[arg(
        long,
        env("MPC_MIDNIGHT_PROOF_SERVER_URL"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_proof_server_url: Option<String>,
    /// Indexer GraphQL URL. Required to respond: the funding wallet's spendable
    /// DUST is only derivable by replaying every block's ledger events from
    /// genesis, and no node RPC serves them.
    #[arg(
        long,
        env("MPC_MIDNIGHT_INDEXER_URL"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_indexer_url: Option<String>,
    /// Indexer GraphQL subscription URL, the same service as above over a
    /// websocket. Both, because the wallet catches up over one and follows over
    /// the other.
    #[arg(
        long,
        env("MPC_MIDNIGHT_INDEXER_WS_URL"),
        requires = "midnight_node_ws_url"
    )]
    pub midnight_indexer_ws_url: Option<String>,
}

impl MidnightArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(16);
        if let Some(v) = self.midnight_node_ws_url {
            args.extend(["--midnight-node-ws-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_central_address {
            args.extend(["--midnight-central-address".to_string(), v]);
        }
        if let Some(v) = self.midnight_network_id {
            args.extend(["--midnight-network-id".to_string(), v]);
        }
        if let Some(v) = self.midnight_funding_seed {
            args.extend(["--midnight-funding-seed".to_string(), v]);
        }
        if let Some(v) = self.midnight_managed_dir {
            args.extend(["--midnight-managed-dir".to_string(), v]);
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

    /// Validates at the config boundary, the way `EthArgs::into_config` does.
    /// Ethereum can validate by parsing into `Url`/`Address`/`PrivateKeySigner`,
    /// which make an invalid value unrepresentable; these fields are `String`,
    /// so the boundary check is `validate()` instead. clap's `requires_all`
    /// only guarantees the flags arrive together, never that
    /// `central_address` is 64 lowercase hex.
    pub fn into_config(self) -> anyhow::Result<Option<MidnightConfig>> {
        let (Some(node_ws_url), Some(central_address), Some(network_id)) = (
            self.midnight_node_ws_url,
            self.midnight_central_address,
            self.midnight_network_id,
        ) else {
            return Ok(None);
        };
        // Start from the defaults and overwrite per supplied flag: the publisher
        // tuning without flags (timeouts, restart backoff) has to keep its
        // default, and an omitted flag must be indistinguishable from one.
        let mut publisher = PublisherConfig::default();
        // An omitted seed is legal rather than an error: Midnight runs
        // indexer-only deployments, and forcing a read-only node to invent a
        // credential it never spends puts a fake secret in a deployment. A
        // seedless publisher is simply not registered.
        if let Some(v) = self.midnight_funding_seed {
            publisher.funding_seed = v;
        }
        if let Some(v) = self.midnight_managed_dir {
            publisher.managed_dir = v;
        }
        if let Some(v) = self.midnight_intent_gen_command {
            publisher.intent_gen_command = serde_json::from_str(&v).with_context(|| {
                format!("midnight config: --midnight-intent-gen-command must be a JSON array of strings, got {v}")
            })?;
        }
        if let Some(v) = self.midnight_proof_server_url {
            publisher.proof_server_url = v;
        }
        if let Some(v) = self.midnight_indexer_url {
            publisher.indexer_url = v;
        }
        if let Some(v) = self.midnight_indexer_ws_url {
            publisher.indexer_ws_url = v;
        }
        // No flag of its own: the builder dials the same node this config already
        // names, so a second flag would only be a second spelling of one value
        // and a way for them to disagree. Copied only for a deployment that
        // responds, because the child validates its submit half all-or-none, and
        // the node URL alone would be the one value an indexer-only deployment
        // handed it out of five.
        if !publisher.funding_seed.is_empty() {
            publisher.node_ws_url = node_ws_url.clone();
        }
        let config = MidnightConfig {
            node_ws_url,
            central_address,
            network_id,
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
                // The rpc/indexer tuning sub-structs have no CLI flags;
                // into_config reinstates their defaults on the other side.
                let MidnightConfig {
                    node_ws_url,
                    central_address,
                    network_id,
                    publisher,
                    rpc: _,
                    indexer: _,
                } = c;
                let PublisherConfig {
                    funding_seed,
                    managed_dir,
                    intent_gen_command,
                    proof_server_url,
                    indexer_url,
                    indexer_ws_url,
                    // Emitted by no flag and rebuilt from `node_ws_url` above on
                    // the way back in, which is the whole reason it has none.
                    node_ws_url: _,
                    request_timeout: _,
                    restart_backoff: _,
                    submit_timeout: _,
                } = publisher;
                MidnightArgs {
                    midnight_node_ws_url: Some(node_ws_url),
                    midnight_central_address: Some(central_address),
                    midnight_network_id: Some(network_id),
                    midnight_funding_seed: Some(funding_seed),
                    midnight_managed_dir: Some(managed_dir),
                    midnight_intent_gen_command: Some(
                        serde_json::to_string(&intent_gen_command)
                            .expect("a Vec<String> always serializes"),
                    ),
                    midnight_proof_server_url: Some(proof_server_url),
                    midnight_indexer_url: Some(indexer_url),
                    midnight_indexer_ws_url: Some(indexer_ws_url),
                }
            }
            None => MidnightArgs {
                midnight_node_ws_url: None,
                midnight_central_address: None,
                midnight_network_id: None,
                midnight_funding_seed: None,
                midnight_managed_dir: None,
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

    /// A config whose publisher fields are all distinguishable from their
    /// defaults, so an assertion against it cannot pass on a dropped flag.
    fn configured() -> MidnightConfig {
        MidnightConfig {
            node_ws_url: "ws://127.0.0.1:9944".into(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".into(),
            publisher: PublisherConfig {
                funding_seed: "0f".repeat(32),
                managed_dir: "/var/lib/mpc/midnight".into(),
                // A space and a leading dash in one argv, which only a
                // structured encoding gets back out intact.
                intent_gen_command: vec![
                    "node".into(),
                    "/opt/midnight publisher/dist/main.js".into(),
                    "--managed-dir".into(),
                ],
                proof_server_url: "http://127.0.0.1:6300".into(),
                indexer_url: "http://127.0.0.1:8088/api/v3/graphql".into(),
                indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".into(),
                // Not a flag's doing: `into_config` copies it off
                // `--midnight-node-ws-url`, so a fixture without it would fail
                // the round trip on a field the CLI is right to have added.
                node_ws_url: "ws://127.0.0.1:9944".into(),
                ..Default::default()
            },
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    #[test]
    fn tuning_fields_do_not_survive_the_cli_round_trip() {
        // Known limitation, pinned deliberately: only the endpoint/identity and
        // publisher fields have flags, so `from_config` discards the tuning
        // sub-structs and `into_config` reinstates their defaults.
        // `archive_probe_window` and `require_archive_state` therefore cannot
        // traverse a process restart. Adding real flags flips this into a
        // round-trip assert.
        crate::cli::tests::assert_midnight_env_unset();

        let mut cfg = configured();
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
        .expect("all the gating fields are set");

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
        // Midnight is one config gate: supplying no `--midnight-*` flag means
        // the chain never spawns. A publisher flag clap accepts on its own
        // would let a node carry a funding seed and a proof server with no
        // chain configured to spend them on, and nothing else here would
        // notice, because `into_config` returns `None` on that path.
        crate::cli::tests::assert_midnight_env_unset();

        for flag in [
            "--midnight-funding-seed",
            "--midnight-managed-dir",
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
    fn the_builder_s_node_url_is_taken_from_the_one_flag_that_names_the_node() {
        // Not a flag of its own, and this is the assertion that keeps it from
        // becoming one: the builder dials the same node this config already
        // names, so a second flag would be a second spelling of one value and a
        // way for the two to disagree, which fails only on chain.
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
        assert_eq!(reparsed.publisher.node_ws_url, cfg.node_ws_url);
    }

    #[test]
    fn a_node_that_only_indexes_is_handed_no_endpoint_at_all() {
        // The other half of the copy above, and the reason it is conditional.
        // The child validates its submit half all-or-none and dies at boot on
        // any subset, so an indexer-only deployment carrying the node url alone
        // would be four values short of a builder that runs. It is never spawned
        // one here, so it must not be configured for one either.
        crate::cli::tests::assert_midnight_env_unset();

        let mut cfg = configured();
        cfg.publisher = Default::default();
        let reparsed = MidnightArgs::try_parse_from(
            std::iter::once("test".to_string())
                .chain(MidnightArgs::from_config(Some(cfg.clone())).into_str_args()),
        )
        .unwrap()
        .into_config()
        .expect("a node with no seed and no endpoints is a legal deployment")
        .expect("all the gating fields are set");

        assert_eq!(reparsed.publisher, PublisherConfig::default());
    }

    #[test]
    fn funding_seed_is_never_logged() {
        // `cli::log_startup` prints the chain configs with `Debug`, so a seed
        // that `Debug` renders is a seed in the node's startup log line and in
        // every `?config` that follows.
        let seed = "0123456789abcdef0123456789abcdef";
        let mut cfg = configured();
        cfg.publisher.funding_seed = seed.to_string();

        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains(seed),
            "the funding seed reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("funding_seed"),
            "the field must render redacted rather than vanish, or a later \
             derive(Debug) reinstates the leak unnoticed: {rendered}"
        );
    }

    #[test]
    fn a_malformed_intent_gen_command_fails_at_the_config_boundary() {
        // argv arrives as one opaque clap value, so the shape check has nowhere
        // to happen but here; without it a typo would surface as a child
        // process that never spawns, long after startup.
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
