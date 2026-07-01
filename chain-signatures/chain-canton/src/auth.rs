use anyhow::Context as _;
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::reqwest::async_http_client;
use oauth2::{AuthUrl, ClientId, ClientSecret, Scope, TokenResponse, TokenUrl};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const DEFAULT_TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(60);
const UNUSED_CLIENT_CREDENTIALS_AUTH_URL: &str = "http://localhost/unused-canton-oauth-auth-url";

#[derive(Clone)]
pub struct CantonAuthConfig {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    pub scope: Option<String>,
}

impl CantonAuthConfig {
    pub fn kind(&self) -> &'static str {
        "oidc-client-credentials"
    }
}

#[derive(Clone)]
pub struct CantonAuthProvider {
    oauth_client: BasicClient,
    audience: String,
    scope: Option<String>,
    token_request_timeout: Duration,
    cached_token: Arc<Mutex<Option<CachedToken>>>,
}

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    refresh_after: Instant,
}

impl CantonAuthProvider {
    pub fn new(config: CantonAuthConfig) -> anyhow::Result<Self> {
        let token_url =
            TokenUrl::new(config.token_url.clone()).context("invalid Canton OIDC token URL")?;
        // oauth2 4.x requires an auth URL even though the client credentials
        // flow never uses it. When migrating to oauth2 5.x with reqwest 0.12,
        // remove this dummy URL and use `set_token_uri(...)` instead.
        let unused_auth_url = AuthUrl::new(UNUSED_CLIENT_CREDENTIALS_AUTH_URL.to_string())
            .context("invalid unused Canton OIDC auth URL")?;
        let oauth_client = BasicClient::new(
            ClientId::new(config.client_id),
            Some(ClientSecret::new(config.client_secret)),
            unused_auth_url,
            Some(token_url),
        );

        Ok(Self {
            oauth_client,
            audience: config.audience,
            scope: config.scope.filter(|s| !s.trim().is_empty()),
            token_request_timeout: DEFAULT_TOKEN_REQUEST_TIMEOUT,
            cached_token: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn bearer_token(&self) -> anyhow::Result<String> {
        let mut cached_token = self.cached_token.lock().await;
        if let Some(token) = cached_token.as_ref() {
            if Instant::now() < token.refresh_after {
                return Ok(token.access_token.clone());
            }
        }

        let token = self.fetch_token().await?;
        let access_token = token.access_token.clone();
        *cached_token = Some(token);
        Ok(access_token)
    }

    async fn fetch_token(&self) -> anyhow::Result<CachedToken> {
        let mut request = self
            .oauth_client
            .exchange_client_credentials()
            .add_extra_param("audience", self.audience.clone());
        if let Some(scope) = &self.scope {
            request = request.add_scope(Scope::new(scope.clone()));
        }

        let response = tokio::time::timeout(
            self.token_request_timeout,
            request.request_async(async_http_client),
        )
        .await
        .with_context(|| {
            format!(
                "Canton OIDC token request timed out after {:?}",
                self.token_request_timeout
            )
        })?
        .context("failed to request Canton OIDC token")?;

        anyhow::ensure!(
            response.token_type() == &BasicTokenType::Bearer,
            "unsupported Canton OIDC token_type {:?}",
            response.token_type()
        );
        let access_token = response.access_token().secret();
        anyhow::ensure!(
            !access_token.is_empty(),
            "Canton OIDC token response did not include access_token"
        );

        let expires_in = response
            .expires_in()
            .context("Canton OIDC token response did not include expires_in")?;
        let refresh_after = Instant::now() + expires_in.saturating_sub(TOKEN_REFRESH_SKEW);

        Ok(CachedToken {
            access_token: access_token.to_string(),
            refresh_after,
        })
    }
}
