use anyhow::Context as _;
use mpc_chain_midnight::{MidnightAddress, MidnightConfig, PublisherConfig};
use secrecy::{ExposeSecret as _, SecretString};
use std::time::Duration;

/// CLI arguments for the Midnight integration. The node url requires the whole
/// required publisher group. GCS output storage is optional.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_midnight_options")]
pub struct MidnightArgs {
    /// Midnight node HTTP RPC URL.
    #[arg(
        long,
        env("MPC_MIDNIGHT_NODE_URL"),
        requires_all = [
            "midnight_central_address",
            "midnight_funding_seed",
            "midnight_proof_server_url",
            "midnight_indexer_url",
            "midnight_indexer_ws_url",
        ]
    )]
    pub midnight_node_url: Option<String>,
    /// Address of the central singleton contract: 64 hex characters, no `0x` prefix.
    #[arg(
        long,
        env("MPC_MIDNIGHT_CENTRAL_ADDRESS"),
        requires = "midnight_node_url"
    )]
    pub midnight_central_address: Option<String>,
    /// Hex seed of the wallet that funds respond transactions.
    #[arg(long, env("MPC_MIDNIGHT_FUNDING_SEED"), requires = "midnight_node_url")]
    pub midnight_funding_seed: Option<SecretString>,
    /// argv of the intent builder child process, JSON-encoded:
    /// `["node","dist/main.js"]`. One clap value rather than a multi-value
    /// flag, whose forms stop at anything flag-shaped; JSON escapes instead
    /// of terminating, so every argv survives the round trip.
    #[arg(
        long,
        env("MPC_MIDNIGHT_INTENT_GEN_COMMAND"),
        requires = "midnight_node_url"
    )]
    pub midnight_intent_gen_command: Option<String>,
    /// Proof server URL. Required to respond: these contracts are zkir-v3 and
    /// cannot be proven in process.
    #[arg(
        long,
        env("MPC_MIDNIGHT_PROOF_SERVER_URL"),
        requires = "midnight_node_url"
    )]
    pub midnight_proof_server_url: Option<String>,
    /// Indexer GraphQL URL. Required to respond: the funding wallet's spendable
    /// DUST is only derivable from the ledger events the indexer serves.
    #[arg(long, env("MPC_MIDNIGHT_INDEXER_URL"), requires = "midnight_node_url")]
    pub midnight_indexer_url: Option<String>,
    /// Indexer GraphQL subscription URL: the wallet catches up over the URL
    /// above and follows over this one.
    #[arg(
        long,
        env("MPC_MIDNIGHT_INDEXER_WS_URL"),
        requires = "midnight_node_url"
    )]
    pub midnight_indexer_ws_url: Option<String>,
    /// Optional GCS bucket. When set, execution output uploads before the on-chain response.
    #[arg(
        long,
        env("MPC_MIDNIGHT_OUTPUT_STORAGE_BUCKET"),
        requires = "midnight_node_url"
    )]
    pub midnight_output_storage_bucket: Option<String>,
    /// Object prefix within the bucket (default: v1).
    #[arg(
        long,
        env("MPC_MIDNIGHT_OUTPUT_STORAGE_PREFIX"),
        requires = "midnight_node_url"
    )]
    pub midnight_output_storage_prefix: Option<String>,
    /// Maximum time for storing one output, in seconds (default: 30).
    #[arg(
        long,
        env("MPC_MIDNIGHT_OUTPUT_STORAGE_TIMEOUT_SECS"),
        requires = "midnight_node_url"
    )]
    pub midnight_output_storage_timeout_secs: Option<u64>,
    /// Local GCS emulator endpoint for integration tests; uses anonymous credentials.
    #[cfg(feature = "test-feature")]
    #[arg(long, requires = "midnight_node_url")]
    pub midnight_output_storage_emulator_endpoint: Option<String>,
}

impl MidnightArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(20);
        if let Some(v) = self.midnight_node_url {
            args.extend(["--midnight-node-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_central_address {
            args.extend(["--midnight-central-address".to_string(), v]);
        }
        if let Some(v) = self.midnight_funding_seed {
            args.extend([
                "--midnight-funding-seed".to_string(),
                v.expose_secret().to_string(),
            ]);
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
        if let Some(v) = self.midnight_output_storage_bucket {
            args.extend(["--midnight-output-storage-bucket".to_string(), v]);
        }
        if let Some(v) = self.midnight_output_storage_prefix {
            args.extend(["--midnight-output-storage-prefix".to_string(), v]);
        }
        if let Some(v) = self.midnight_output_storage_timeout_secs {
            args.extend([
                "--midnight-output-storage-timeout-secs".to_string(),
                v.to_string(),
            ]);
        }
        #[cfg(feature = "test-feature")]
        if let Some(v) = self.midnight_output_storage_emulator_endpoint {
            args.extend(["--midnight-output-storage-emulator-endpoint".to_string(), v]);
        }
        args
    }

    /// Clap's `requires_all` on the node URL makes the flags all-or-nothing before
    /// this conversion parses the central address and validates the remaining fields.
    pub fn into_config(self) -> anyhow::Result<Option<MidnightConfig>> {
        let (
            Some(node_url),
            Some(central_address),
            Some(funding_seed),
            Some(proof_server_url),
            Some(indexer_url),
            Some(indexer_ws_url),
        ) = (
            self.midnight_node_url,
            self.midnight_central_address,
            self.midnight_funding_seed,
            self.midnight_proof_server_url,
            self.midnight_indexer_url,
            self.midnight_indexer_ws_url,
        )
        else {
            return Ok(None);
        };
        let mut publisher = PublisherConfig {
            funding_seed: funding_seed.expose_secret().to_string(),
            proof_server_url,
            indexer_url,
            indexer_ws_url,
            output_storage_bucket: self.midnight_output_storage_bucket,
            #[cfg(feature = "test-feature")]
            output_storage_emulator_endpoint: self.midnight_output_storage_emulator_endpoint,
            ..Default::default()
        };
        if let Some(prefix) = self.midnight_output_storage_prefix {
            publisher.output_storage_prefix = prefix;
        }
        if let Some(timeout_secs) = self.midnight_output_storage_timeout_secs {
            publisher.output_storage_timeout = Duration::from_secs(timeout_secs);
        }
        if let Some(command) = self.midnight_intent_gen_command {
            publisher.intent_gen_command = serde_json::from_str(&command).with_context(|| {
                format!("midnight config: --midnight-intent-gen-command must be a JSON array of strings, got {command}")
            })?;
        }
        let central_address = MidnightAddress::from_hex(&central_address)
            .context("midnight config: central_address must be 32 bytes of hex")?;
        let config = MidnightConfig {
            node_url,
            central_address,
            publisher,
            rpc: Default::default(),
            indexer: Default::default(),
        };
        config.validate()?;
        config.publisher.validate_output_storage()?;
        Ok(Some(config))
    }

    pub fn from_config(config: Option<MidnightConfig>) -> Self {
        match config {
            Some(c) => {
                // Cargo can enable the dependency's sandbox without this crate's
                // test-feature, so its test-only fields may be present but not forwarded.
                let MidnightConfig {
                    node_url,
                    central_address,
                    publisher:
                        PublisherConfig {
                            intent_gen_command,
                            funding_seed,
                            proof_server_url,
                            indexer_url,
                            indexer_ws_url,
                            output_storage_bucket,
                            output_storage_prefix,
                            output_storage_timeout,
                            #[cfg(feature = "test-feature")]
                            output_storage_emulator_endpoint,
                            ..
                        },
                    rpc: _,
                    indexer: _,
                } = c;
                MidnightArgs {
                    midnight_node_url: Some(node_url),
                    midnight_central_address: Some(central_address.to_hex()),
                    midnight_funding_seed: Some(funding_seed.into()),
                    midnight_intent_gen_command: Some(
                        serde_json::to_string(&intent_gen_command)
                            .expect("a Vec<String> always serializes"),
                    ),
                    midnight_proof_server_url: Some(proof_server_url),
                    midnight_indexer_url: Some(indexer_url),
                    midnight_indexer_ws_url: Some(indexer_ws_url),
                    midnight_output_storage_bucket: output_storage_bucket,
                    midnight_output_storage_prefix: Some(output_storage_prefix),
                    midnight_output_storage_timeout_secs: Some(output_storage_timeout.as_secs()),
                    #[cfg(feature = "test-feature")]
                    midnight_output_storage_emulator_endpoint: output_storage_emulator_endpoint,
                }
            }
            None => MidnightArgs {
                midnight_node_url: None,
                midnight_central_address: None,
                midnight_funding_seed: None,
                midnight_intent_gen_command: None,
                midnight_proof_server_url: None,
                midnight_indexer_url: None,
                midnight_indexer_ws_url: None,
                midnight_output_storage_bucket: None,
                midnight_output_storage_prefix: None,
                midnight_output_storage_timeout_secs: None,
                #[cfg(feature = "test-feature")]
                midnight_output_storage_emulator_endpoint: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use mpc_chain_midnight::IndexerConfig;

    /// Publisher fields all distinguishable from their defaults, so an
    /// assertion cannot pass on a dropped flag.
    fn configured() -> MidnightConfig {
        MidnightConfig {
            node_url: "http://127.0.0.1:9944".into(),
            central_address: MidnightAddress::from_bytes([0xab; 32]),
            publisher: PublisherConfig {
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
                output_storage_bucket: Some("midnight-results".into()),
                output_storage_prefix: "staging/testnet".into(),
                output_storage_timeout: Duration::from_secs(47),
                ..Default::default()
            },
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    #[test]
    fn debug_redacts_the_funding_seed() {
        let config = configured();
        let funding_seed = config.publisher.funding_seed.clone();
        let rendered = format!("{:?}", MidnightArgs::from_config(Some(config)));

        assert!(
            !rendered.contains(&funding_seed),
            "the funding seed reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "the secret field must render as redacted: {rendered}"
        );
    }

    #[test]
    fn tuning_fields_do_not_survive_the_cli_round_trip() {
        // Indexer and submission tuning have no CLI flags and do not traverse
        // a process restart. Adding flags flips this into a round-trip assert.
        crate::cli::tests::assert_midnight_env_unset();

        let mut cfg = configured();
        cfg.indexer.poll_interval = Duration::from_millis(77);
        cfg.indexer.stall_timeout = Duration::from_secs(7);
        cfg.publisher.submit_timeout = Duration::from_secs(7);
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

        assert_eq!(reparsed.node_url, cfg.node_url);
        assert_eq!(reparsed.central_address, cfg.central_address);
        assert_eq!(
            reparsed.indexer,
            IndexerConfig::default(),
            "indexer tuning does not traverse the CLI; if this fails, flags were added and this test should become a round-trip assert"
        );
        assert_eq!(
            reparsed.publisher.submit_timeout,
            PublisherConfig::default().submit_timeout,
            "publisher submission timeout does not traverse the CLI"
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
    fn central_address_is_parsed_at_the_config_boundary() {
        for invalid in ["ab".repeat(31), format!("0x{}", "ab".repeat(31))] {
            let mut args = MidnightArgs::from_config(Some(configured()));
            args.midnight_central_address = Some(invalid);

            let error = args.into_config().unwrap_err().to_string();
            assert!(
                error.contains("central_address"),
                "unexpected address error: {error}"
            );
        }
    }

    #[cfg(feature = "test-feature")]
    #[test]
    fn storage_emulator_endpoint_survives_the_cli_round_trip() {
        crate::cli::tests::assert_midnight_env_unset();
        let mut args = MidnightArgs::from_config(Some(configured())).into_str_args();
        args.extend([
            "--midnight-output-storage-emulator-endpoint".into(),
            "http://127.0.0.1:4443".into(),
        ]);
        let config = MidnightArgs::try_parse_from(std::iter::once("test".into()).chain(args))
            .expect("test builds accept the Midnight storage emulator endpoint")
            .into_config()
            .unwrap();
        let forwarded = MidnightArgs::from_config(config).into_str_args();
        assert!(forwarded.windows(2).any(|args| args
            == [
                "--midnight-output-storage-emulator-endpoint",
                "http://127.0.0.1:4443"
            ]));
    }

    #[cfg(not(feature = "test-feature"))]
    #[test]
    fn production_cli_rejects_the_storage_emulator_endpoint() {
        let error = MidnightArgs::try_parse_from([
            "test",
            "--midnight-output-storage-emulator-endpoint",
            "http://127.0.0.1:4443",
        ])
        .expect_err("production nodes must not accept anonymous emulator configuration");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn the_midnight_flags_are_all_or_nothing() {
        // A publisher flag accepted on its own would let a node carry a funding
        // seed with no chain configured to spend it on, unnoticed.
        crate::cli::tests::assert_midnight_env_unset();

        for flag in [
            "--midnight-funding-seed",
            "--midnight-intent-gen-command",
            "--midnight-proof-server-url",
            "--midnight-indexer-url",
            "--midnight-indexer-ws-url",
            "--midnight-output-storage-bucket",
            "--midnight-output-storage-prefix",
            "--midnight-output-storage-timeout-secs",
        ] {
            let err = MidnightArgs::try_parse_from(["test", flag, "1"])
                .expect_err("clap must reject a publisher flag supplied on its own");
            assert!(
                err.to_string().contains("midnight-node-url"),
                "{flag} is not gated on the node url: {err}"
            );
        }

        let central_address = "ab".repeat(32);
        let err = MidnightArgs::try_parse_from([
            "test",
            "--midnight-node-url",
            "http://127.0.0.1:9944",
            "--midnight-central-address",
            &central_address,
        ])
        .expect_err("clap must demand the publisher group with the node url");
        for flag in [
            "--midnight-funding-seed",
            "--midnight-proof-server-url",
            "--midnight-indexer-url",
            "--midnight-indexer-ws-url",
        ] {
            assert!(
                err.to_string().contains(flag),
                "clap must name {flag} as missing: {err}"
            );
        }
    }

    #[test]
    fn midnight_output_storage_bucket_is_optional() {
        crate::cli::tests::assert_midnight_env_unset();
        let mut args = MidnightArgs::from_config(Some(configured())).into_str_args();
        let index = args
            .iter()
            .position(|arg| arg == "--midnight-output-storage-bucket")
            .expect("configured Midnight args include the storage bucket");
        args.drain(index..=index + 1);
        let parsed = MidnightArgs::try_parse_from(std::iter::once("test".to_owned()).chain(args))
            .expect("Midnight can run without GCS storage");
        assert!(parsed.midnight_output_storage_bucket.is_none());
        let config = parsed
            .into_config()
            .unwrap()
            .expect("Midnight remains enabled");
        assert_eq!(config.node_url, configured().node_url);
        let forwarded = MidnightArgs::from_config(Some(config)).into_str_args();
        assert!(!forwarded
            .iter()
            .any(|arg| arg == "--midnight-output-storage-bucket"));
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
