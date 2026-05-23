use anyhow::{Context as _, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::time::{sleep, Duration};

pub(crate) const LOCAL_OIDC_AUDIENCE: &str = "https://canton.network.global";
pub(crate) const LOCAL_OIDC_CLIENT_SECRET: &str = "local-canton-client-secret";
pub(crate) const LOCAL_OIDC_SCOPE: &str = "daml_ledger_api";

const MOCK_OAUTH2_SERVER_IMAGE: &str = "ghcr.io/navikt/mock-oauth2-server";
const MOCK_OAUTH2_SERVER_TAG: &str = "3.0.1";
const MOCK_OAUTH2_SERVER_PORT: u16 = 8080;
const TRUSTED_ISSUER_ID: &str = "default";
const ROGUE_ISSUER_ID: &str = "rogue";
const LOCAL_OIDC_TOKEN_TTL_SECS: u64 = 300;

pub(crate) struct OidcTestProvider {
    base_url: String,
    token_url: String,
    jwks_url: String,
    _container: ContainerAsync<GenericImage>,
}

impl OidcTestProvider {
    pub(crate) async fn run() -> Result<Self> {
        let container = GenericImage::new(MOCK_OAUTH2_SERVER_IMAGE, MOCK_OAUTH2_SERVER_TAG)
            .with_exposed_port(MOCK_OAUTH2_SERVER_PORT.tcp())
            .with_wait_for(WaitFor::seconds(1))
            .with_env_var("JSON_CONFIG", oidc_json_config())
            .start()
            .await
            .context("failed to start mock-oauth2-server container")?;
        let host_port = container
            .get_host_port_ipv4(MOCK_OAUTH2_SERVER_PORT)
            .await
            .context("mock-oauth2-server port mapping")?;
        let base_url = format!("http://127.0.0.1:{host_port}");
        wait_for_mock_oauth2_server(&base_url).await?;

        Ok(Self {
            token_url: issuer_token_url(&base_url, TRUSTED_ISSUER_ID),
            jwks_url: issuer_jwks_url(&base_url, TRUSTED_ISSUER_ID),
            base_url,
            _container: container,
        })
    }

    pub(crate) fn token_url(&self) -> &str {
        &self.token_url
    }

    pub(crate) fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    pub(crate) async fn untrusted_access_token(&self, subject: &str) -> Result<String> {
        self.issue_access_token(ROGUE_ISSUER_ID, subject).await
    }

    async fn issue_access_token(&self, issuer_id: &str, subject: &str) -> Result<String> {
        let response: TokenResponse = reqwest::Client::new()
            .post(issuer_token_url(&self.base_url, issuer_id))
            .basic_auth(subject, Some(LOCAL_OIDC_CLIENT_SECRET))
            .form(&[
                ("grant_type", "client_credentials"),
                ("audience", LOCAL_OIDC_AUDIENCE),
                ("scope", LOCAL_OIDC_SCOPE),
            ])
            .send()
            .await
            .with_context(|| format!("failed to request {issuer_id} access token"))?
            .error_for_status()
            .with_context(|| format!("mock-oauth2-server rejected {issuer_id} token request"))?
            .json()
            .await
            .with_context(|| format!("invalid {issuer_id} token response"))?;

        anyhow::ensure!(
            response.token_type.eq_ignore_ascii_case("Bearer"),
            "unsupported mock-oauth2-server token_type {}",
            response.token_type
        );
        anyhow::ensure!(
            !response.access_token.is_empty(),
            "mock-oauth2-server returned an empty access token"
        );

        Ok(response.access_token)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
}

fn oidc_json_config() -> String {
    json!({
        "interactiveLogin": false,
        "httpServer": "NettyWrapper",
        "tokenProvider": {
            "keyProvider": {
                "algorithm": "RS256"
            }
        },
        "tokenCallbacks": [
            token_callback(TRUSTED_ISSUER_ID),
            token_callback(ROGUE_ISSUER_ID)
        ]
    })
    .to_string()
}

fn token_callback(issuer_id: &str) -> Value {
    json!({
        "issuerId": issuer_id,
        "tokenExpiry": LOCAL_OIDC_TOKEN_TTL_SECS,
        "requestMappings": [
            {
                "requestParam": "grant_type",
                "match": "client_credentials",
                "claims": {
                    "sub": "${clientId}",
                    "aud": LOCAL_OIDC_AUDIENCE,
                    "scope": LOCAL_OIDC_SCOPE
                }
            }
        ]
    })
}

fn issuer_token_url(base_url: &str, issuer_id: &str) -> String {
    format!("{base_url}/{issuer_id}/token")
}

fn issuer_jwks_url(base_url: &str, issuer_id: &str) -> String {
    format!("{base_url}/{issuer_id}/jwks")
}

async fn wait_for_mock_oauth2_server(base_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let is_alive_url = format!("{base_url}/isalive");
    let mut last_error = None;

    for _ in 0..60 {
        match client.get(&is_alive_url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => last_error = Some(format!("status {}", response.status())),
            Err(err) => last_error = Some(err.to_string()),
        }
        sleep(Duration::from_millis(500)).await;
    }

    anyhow::bail!(
        "mock-oauth2-server did not become ready at {is_alive_url}: {:?}",
        last_error
    )
}
