use anyhow::Context as _;
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
        requires_all = ["signer_uri", "genesis_hash"]
    )]
    pub rpc_ws_url: Option<String>,
    /// Hydration signer URI
    #[arg(
        long = "hydration-signer-uri",
        env("MPC_HYDRATION_SIGNER_URI"),
        hide_env_values = true,
        requires_all = ["rpc_ws_url", "genesis_hash"]
    )]
    pub signer_uri: Option<String>,

    /// Hydration chain genesis hash
    #[arg(
        long = "hydration-genesis-hash",
        env("MPC_HYDRATION_GENESIS_HASH"),
        requires_all = ["rpc_ws_url", "signer_uri"]
    )]
    pub genesis_hash: Option<String>,
}

impl HydrationArgs {
    pub fn into_config(self) -> anyhow::Result<Option<HydrationConfig>> {
        let Some(rpc_ws_url) = self.rpc_ws_url else {
            return Ok(None);
        };

        Ok(Some(HydrationConfig {
            rpc_ws_url,
            signer_uri: self.signer_uri.context("signer_uri is required")?,
            genesis_hash: self
                .genesis_hash
                .context("genesis_hash is required")?
                .parse()
                .context("invalid genesis hash")?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    const DEFAULT_RPC_WS_URL: &str = "wss://hydration.example/ws";
    const DEFAULT_SIGNER_URI: &str = "//Alice";
    const DEFAULT_GENESIS_HASH: &str =
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    fn parse_hydration_args(
        rpc_ws_url: &str,
        signer_uri: &str,
        genesis_hash: &str,
    ) -> HydrationArgs {
        let argv = [
            "test",
            "--hydration-rpc-ws-url",
            rpc_ws_url,
            "--hydration-signer-uri",
            signer_uri,
            "--hydration-genesis-hash",
            genesis_hash,
        ];
        HydrationArgs::parse_from(argv)
    }

    #[test]
    fn unconfigured_yields_no_config() {
        assert!(HydrationArgs::parse_from(["test"])
            .into_config()
            .unwrap()
            .is_none());
    }

    #[test]
    fn into_config_parses_the_configured_fields() {
        let config =
            parse_hydration_args(DEFAULT_RPC_WS_URL, DEFAULT_SIGNER_URI, DEFAULT_GENESIS_HASH)
                .into_config()
                .unwrap()
                .expect("configured chain");
        assert_eq!(config.rpc_ws_url, DEFAULT_RPC_WS_URL);
        assert_eq!(config.signer_uri, DEFAULT_SIGNER_URI);
        assert_eq!(config.genesis_hash, DEFAULT_GENESIS_HASH.parse().unwrap());
    }

    #[test]
    fn into_config_parses_a_genesis_hash_without_the_0x_prefix() {
        let args = parse_hydration_args(
            DEFAULT_RPC_WS_URL,
            DEFAULT_SIGNER_URI,
            &DEFAULT_GENESIS_HASH[2..],
        );
        let config = args.into_config().unwrap().expect("configured chain");
        assert_eq!(config.genesis_hash, DEFAULT_GENESIS_HASH.parse().unwrap());
    }

    #[test]
    fn into_config_rejects_an_invalid_genesis_hash() {
        for hash in [
            "not a hash",
            "0x1234",
            // H256 Display truncates with an ellipsis; that form must not parse.
            "0x1234…cdef",
        ] {
            let args = parse_hydration_args(DEFAULT_RPC_WS_URL, DEFAULT_SIGNER_URI, hash);
            let err = args.into_config().unwrap_err().to_string();
            assert!(
                err.contains("invalid genesis hash"),
                "{hash:?} should be rejected, got {err}"
            );
        }
    }

    #[test]
    fn clap_rejects_a_partial_hydration_group() {
        assert!(HydrationArgs::try_parse_from([
            "test",
            "--hydration-rpc-ws-url",
            DEFAULT_RPC_WS_URL,
            "--hydration-signer-uri",
            DEFAULT_SIGNER_URI,
        ])
        .is_err());
    }
}
