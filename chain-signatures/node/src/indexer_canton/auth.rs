use anyhow::Context as _;
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::{
    ClientId, ClientSecret, EndpointNotSet, EndpointSet, HttpClientError, HttpRequest,
    HttpResponse, Scope, TokenResponse, TokenUrl,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(60);

type CantonOAuthClient =
    BasicClient<EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
type OAuthHttpError = HttpClientError<reqwest::Error>;

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
    ledger_api_user: String,
    http_client: reqwest::Client,
    oauth_client: CantonOAuthClient,
    audience: String,
    scope: Option<String>,
    cached_token: Arc<Mutex<Option<CachedToken>>>,
}

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    refresh_after: Instant,
}

impl CantonAuthProvider {
    pub async fn new(
        config: CantonAuthConfig,
        ledger_api_user: String,
        http_client: reqwest::Client,
    ) -> anyhow::Result<Self> {
        let oauth_client = BasicClient::new(ClientId::new(config.client_id))
            .set_client_secret(ClientSecret::new(config.client_secret))
            .set_token_uri(
                TokenUrl::new(config.token_url).context("invalid Canton OIDC token URL")?,
            );

        Ok(Self {
            ledger_api_user,
            http_client,
            oauth_client,
            audience: config.audience,
            scope: config.scope.filter(|s| !s.trim().is_empty()),
            cached_token: Arc::new(Mutex::new(None)),
        })
    }

    pub fn ledger_api_user(&self) -> &str {
        &self.ledger_api_user
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

        let http_client = self.http_client.clone();
        let oauth_http_client = move |request| execute_oauth_request(http_client.clone(), request);
        let response = request
            .request_async(&oauth_http_client)
            .await
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

async fn execute_oauth_request(
    client: reqwest::Client,
    request: HttpRequest,
) -> Result<HttpResponse, OAuthHttpError> {
    let (parts, body) = request.into_parts();
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .map_err(|err| OAuthHttpError::Other(format!("invalid OAuth HTTP method: {err}")))?;
    let mut request_builder = client.request(method, parts.uri.to_string()).body(body);
    for (name, value) in parts.headers.iter() {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }

    let response = client
        .execute(
            request_builder
                .build()
                .map_err(|err| OAuthHttpError::Reqwest(Box::new(err)))?,
        )
        .await
        .map_err(|err| OAuthHttpError::Reqwest(Box::new(err)))?;
    let status_code = oauth2::http::StatusCode::from_u16(response.status().as_u16())
        .map_err(|err| OAuthHttpError::Other(format!("invalid OAuth HTTP status: {err}")))?;
    let headers = response.headers().to_owned();
    let body = response
        .bytes()
        .await
        .map_err(|err| OAuthHttpError::Reqwest(Box::new(err)))?
        .to_vec();

    let mut response_builder = oauth2::http::Response::builder().status(status_code);
    for (name, value) in headers.iter() {
        response_builder = response_builder.header(name.as_str(), value.as_bytes());
    }
    response_builder.body(body).map_err(OAuthHttpError::Http)
}
