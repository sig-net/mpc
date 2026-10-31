use anyhow::Context as _;
use mpc_chain_midnight::{MidnightAddress, MidnightConfig, OutputStorageConfig, PublisherConfig};
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
        hide_env_values = true,
        requires_all = [
            "midnight_central_address",
            "midnight_funding_seed",
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
    #[arg(
        long,
        env("MPC_MIDNIGHT_FUNDING_SEED"),
        hide_env_values = true,
        requires = "midnight_node_url"
    )]
    pub midnight_funding_seed: Option<SecretString>,
    /// Indexer GraphQL subscription URL. Required to respond: the funding
    /// wallet's spendable DUST is only derivable from the ledger events the
    /// indexer serves.
    #[arg(
        long,
        env("MPC_MIDNIGHT_INDEXER_WS_URL"),
        hide_env_values = true,
        requires = "midnight_node_url"
    )]
    pub midnight_indexer_ws_url: Option<String>,
    /// Optional GCS output cache. Initialization retries in the background; upload failures warn
    /// and do not prevent the on-chain response.
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
    /// Maximum time for one cache initialization attempt or storing one output, in seconds (default: 30).
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
    /// The singleton's proving artifacts, for test nodes running outside the image
    /// that installs them.
    #[cfg(feature = "test-feature")]
    #[arg(long, requires = "midnight_node_url")]
    pub midnight_contract_artifacts_dir: Option<std::path::PathBuf>,
    /// The zero-knowledge parameter directory, for test nodes running outside the
    /// image that installs it.
    #[cfg(feature = "test-feature")]
    #[arg(long, requires = "midnight_node_url")]
    pub midnight_zk_params_dir: Option<std::path::PathBuf>,
}

impl MidnightArgs {
    /// Clap's `requires_all` on the node URL makes the flags all-or-nothing before
    /// this conversion parses the central address and validates the remaining fields.
    pub fn into_config(self) -> anyhow::Result<Option<MidnightConfig>> {
        let (Some(node_url), Some(central_address), Some(funding_seed), Some(indexer_ws_url)) = (
            self.midnight_node_url,
            self.midnight_central_address,
            self.midnight_funding_seed,
            self.midnight_indexer_ws_url,
        ) else {
            return Ok(None);
        };
        // Only test builds override the image's artifact directories.
        #[cfg_attr(not(feature = "test-feature"), allow(unused_mut))]
        let mut publisher = PublisherConfig {
            funding_seed: funding_seed.expose_secret().to_string(),
            indexer_ws_url,
            output_storage: self.midnight_output_storage_bucket.map(|bucket| {
                OutputStorageConfig::new(
                    bucket,
                    self.midnight_output_storage_prefix
                        .unwrap_or_else(|| "v1".to_string()),
                    Duration::from_secs(self.midnight_output_storage_timeout_secs.unwrap_or(30)),
                )
            }),
            ..Default::default()
        };
        #[cfg(feature = "test-feature")]
        {
            if let Some(storage) = &mut publisher.output_storage {
                storage.emulator_endpoint = self.midnight_output_storage_emulator_endpoint;
            }
            if let Some(dir) = self.midnight_contract_artifacts_dir {
                publisher.contract_artifacts_dir = dir;
            }
            if let Some(dir) = self.midnight_zk_params_dir {
                publisher.zk_params_dir = dir;
            }
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
        Ok(Some(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use mpc_chain_midnight::IndexerConfig;

    /// The command line for [`configured`].
    fn configured_argv() -> Vec<String> {
        [
            "test",
            "--midnight-node-url",
            "http://127.0.0.1:9944",
            "--midnight-central-address",
            &"ab".repeat(32),
            "--midnight-funding-seed",
            &"0f".repeat(32),
            "--midnight-indexer-ws-url",
            "ws://127.0.0.1:8088/api/v3/graphql/ws",
            "--midnight-output-storage-bucket",
            "midnight-results",
            "--midnight-output-storage-prefix",
            "staging/testnet",
            "--midnight-output-storage-timeout-secs",
            "47",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    fn configured_args() -> MidnightArgs {
        MidnightArgs::try_parse_from(configured_argv()).unwrap()
    }

    /// Publisher fields all distinguishable from their defaults, so an
    /// assertion cannot pass on a dropped flag.
    fn configured() -> MidnightConfig {
        MidnightConfig {
            node_url: "http://127.0.0.1:9944".into(),
            central_address: MidnightAddress::from_bytes([0xab; 32]),
            publisher: PublisherConfig {
                funding_seed: "0f".repeat(32),
                indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".into(),
                output_storage: Some(OutputStorageConfig::new(
                    "midnight-results".into(),
                    "staging/testnet".into(),
                    Duration::from_secs(47),
                )),
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
        let rendered = format!("{:?}", configured_args());

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
    fn configured_argv_parses_into_configured() {
        // A flag left out of the argv would be silently backfilled from a set
        // MPC_MIDNIGHT_* env var and still pass.
        crate::cli::tests::assert_midnight_env_unset();

        let config = configured_args().into_config().unwrap();
        assert_eq!(config, Some(configured()));
        // Indexer and submission tuning have no CLI flags.
        let config = config.unwrap();
        assert_eq!(config.indexer, IndexerConfig::default());
        assert_eq!(
            config.publisher.submit_timeout,
            PublisherConfig::default().submit_timeout
        );
    }

    #[test]
    fn central_address_is_parsed_at_the_config_boundary() {
        for invalid in ["ab".repeat(31), format!("0x{}", "ab".repeat(31))] {
            let mut args = configured_args();
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
        let mut argv = configured_argv();
        argv.extend([
            "--midnight-output-storage-emulator-endpoint".into(),
            "http://127.0.0.1:4443".into(),
        ]);
        let config = MidnightArgs::try_parse_from(argv)
            .expect("test builds accept the Midnight storage emulator endpoint")
            .into_config()
            .unwrap()
            .unwrap();
        assert_eq!(
            config.publisher.output_storage.unwrap().emulator_endpoint,
            Some("http://127.0.0.1:4443".to_string())
        );
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
        for flag in ["--midnight-funding-seed", "--midnight-indexer-ws-url"] {
            assert!(
                err.to_string().contains(flag),
                "clap must name {flag} as missing: {err}"
            );
        }
    }

    #[test]
    fn midnight_output_storage_bucket_is_optional() {
        crate::cli::tests::assert_midnight_env_unset();
        let mut argv = configured_argv();
        let index = argv
            .iter()
            .position(|arg| arg == "--midnight-output-storage-bucket")
            .expect("configured Midnight args include the storage bucket");
        argv.drain(index..=index + 1);
        let parsed =
            MidnightArgs::try_parse_from(argv).expect("Midnight can run without GCS storage");
        assert!(parsed.midnight_output_storage_bucket.is_none());
        let config = parsed
            .into_config()
            .unwrap()
            .expect("Midnight remains enabled");
        assert_eq!(config.node_url, configured().node_url);
        assert!(config.publisher.output_storage.is_none());
    }

    #[test]
    fn output_storage_defaults_are_resolved_at_the_cli_boundary() {
        crate::cli::tests::assert_midnight_env_unset();
        let mut args = configured_args();
        args.midnight_output_storage_prefix = None;
        args.midnight_output_storage_timeout_secs = None;

        let config = args.into_config().unwrap().unwrap();
        assert_eq!(
            config.publisher.output_storage,
            Some(OutputStorageConfig::new(
                "midnight-results".into(),
                "v1".into(),
                Duration::from_secs(30),
            ))
        );
    }

    #[cfg(not(feature = "test-feature"))]
    #[test]
    fn contract_assets_are_not_an_operator_input() {
        // The image installs the artifacts the node proves with; a production
        // node pointed elsewhere could prove against keys no deployment carries.
        crate::cli::tests::assert_midnight_env_unset();

        for flag in [
            "--midnight-contract-artifacts-dir",
            "--midnight-zk-params-dir",
        ] {
            let err = MidnightArgs::try_parse_from(["test", flag, "/tmp/managed"])
                .expect_err("production nodes take the artifacts the image installs");
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{flag}"
            );
        }
    }

    #[cfg(feature = "test-feature")]
    #[test]
    fn test_nodes_carry_their_artifact_directories_across_the_cli() {
        crate::cli::tests::assert_midnight_env_unset();

        let mut cfg = configured();
        cfg.publisher.contract_artifacts_dir = "/opt/signet/managed".into();
        cfg.publisher.zk_params_dir = "/opt/signet/zk-params".into();
        let mut argv = configured_argv();
        argv.extend([
            "--midnight-contract-artifacts-dir".into(),
            "/opt/signet/managed".into(),
            "--midnight-zk-params-dir".into(),
            "/opt/signet/zk-params".into(),
        ]);
        let reparsed = MidnightArgs::try_parse_from(argv).unwrap();
        assert_eq!(reparsed.into_config().unwrap(), Some(cfg));
    }
}
