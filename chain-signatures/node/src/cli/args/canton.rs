use mpc_chain_canton::{CantonAuthConfig, CantonConfig};

/// CLI arguments for the Canton indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_canton_options")]
pub struct CantonArgs {
    #[arg(
        long,
        env("MPC_CANTON_JSON_API_URL"),
        hide_env_values = true,
        requires_all = [
            "canton_json_api_ws_url",
            "canton_ledger_api_user",
            "canton_oidc_token_url",
            "canton_oidc_client_id",
            "canton_oidc_client_secret",
            "canton_oidc_audience",
            "canton_party_id",
            "canton_signer_contract_id",
            "canton_signer_template_id",
        ]
    )]
    pub canton_json_api_url: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_JSON_API_WS_URL"),
        hide_env_values = true,
        requires = "canton_json_api_url"
    )]
    pub canton_json_api_ws_url: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_LEDGER_API_USER"),
        requires = "canton_json_api_url"
    )]
    pub canton_ledger_api_user: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_OIDC_TOKEN_URL"),
        hide_env_values = true,
        requires = "canton_json_api_url"
    )]
    pub canton_oidc_token_url: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_OIDC_CLIENT_ID"),
        requires = "canton_json_api_url"
    )]
    pub canton_oidc_client_id: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_OIDC_CLIENT_SECRET"),
        hide_env_values = true,
        requires = "canton_json_api_url"
    )]
    pub canton_oidc_client_secret: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_OIDC_AUDIENCE"),
        requires = "canton_json_api_url"
    )]
    pub canton_oidc_audience: Option<String>,
    #[arg(long, env("MPC_CANTON_OIDC_SCOPE"), requires = "canton_json_api_url")]
    pub canton_oidc_scope: Option<String>,
    #[arg(long, env("MPC_CANTON_PARTY_ID"), requires = "canton_json_api_url")]
    pub canton_party_id: Option<String>,
    /// The Signer contract ID on the Canton ledger. Must be updated if the contract is re-deployed.
    #[arg(
        long,
        env("MPC_CANTON_SIGNER_CONTRACT_ID"),
        requires = "canton_json_api_url"
    )]
    pub canton_signer_contract_id: Option<String>,
    /// Template ID of the Signer contract, in package-name form
    /// (`#signet-signer-v1:Signer:Signer`).
    #[arg(
        long,
        env("MPC_CANTON_SIGNER_TEMPLATE_ID"),
        requires = "canton_json_api_url"
    )]
    pub canton_signer_template_id: Option<String>,
}

impl CantonArgs {
    pub fn into_config(self) -> Option<CantonConfig> {
        let auth = CantonAuthConfig {
            token_url: self.canton_oidc_token_url?,
            client_id: self.canton_oidc_client_id?,
            client_secret: self.canton_oidc_client_secret?,
            audience: self.canton_oidc_audience?,
            scope: self.canton_oidc_scope,
        };
        Some(CantonConfig {
            json_api_url: self.canton_json_api_url?,
            json_api_ws_url: self.canton_json_api_ws_url?,
            auth,
            ledger_api_user: self.canton_ledger_api_user?,
            party_id: self.canton_party_id?,
            signer_contract_id: self.canton_signer_contract_id?,
            signer_template_id: self.canton_signer_template_id?,
        })
    }
}
