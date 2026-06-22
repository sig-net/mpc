use crate::indexer_canton::{CantonAuthConfig, CantonConfig};

/// CLI arguments for the Canton indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_canton_options")]
pub struct CantonArgs {
    #[arg(
        long,
        env("MPC_CANTON_JSON_API_URL"),
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
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(16);
        if let Some(v) = self.canton_json_api_url {
            args.extend(["--canton-json-api-url".to_string(), v]);
        }
        if let Some(v) = self.canton_json_api_ws_url {
            args.extend(["--canton-json-api-ws-url".to_string(), v]);
        }
        if let Some(v) = self.canton_ledger_api_user {
            args.extend(["--canton-ledger-api-user".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_token_url {
            args.extend(["--canton-oidc-token-url".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_client_id {
            args.extend(["--canton-oidc-client-id".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_client_secret {
            args.extend(["--canton-oidc-client-secret".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_audience {
            args.extend(["--canton-oidc-audience".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_scope {
            args.extend(["--canton-oidc-scope".to_string(), v]);
        }
        if let Some(v) = self.canton_party_id {
            args.extend(["--canton-party-id".to_string(), v]);
        }
        if let Some(v) = self.canton_signer_contract_id {
            args.extend(["--canton-signer-contract-id".to_string(), v]);
        }
        if let Some(v) = self.canton_signer_template_id {
            args.extend(["--canton-signer-template-id".to_string(), v]);
        }
        args
    }

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

    pub fn from_config(config: Option<CantonConfig>) -> Self {
        match config {
            Some(c) => {
                let CantonAuthConfig {
                    token_url,
                    client_id,
                    client_secret,
                    audience,
                    scope,
                } = c.auth;
                CantonArgs {
                    canton_json_api_url: Some(c.json_api_url),
                    canton_json_api_ws_url: Some(c.json_api_ws_url),
                    canton_ledger_api_user: Some(c.ledger_api_user),
                    canton_oidc_token_url: Some(token_url),
                    canton_oidc_client_id: Some(client_id),
                    canton_oidc_client_secret: Some(client_secret),
                    canton_oidc_audience: Some(audience),
                    canton_oidc_scope: scope,
                    canton_party_id: Some(c.party_id),

                    canton_signer_contract_id: Some(c.signer_contract_id),
                    canton_signer_template_id: Some(c.signer_template_id),
                }
            }
            None => CantonArgs {
                canton_json_api_url: None,
                canton_json_api_ws_url: None,
                canton_ledger_api_user: None,
                canton_oidc_token_url: None,
                canton_oidc_client_id: None,
                canton_oidc_client_secret: None,
                canton_oidc_audience: None,
                canton_oidc_scope: None,
                canton_party_id: None,

                canton_signer_contract_id: None,
                canton_signer_template_id: None,
            },
        }
    }
}
