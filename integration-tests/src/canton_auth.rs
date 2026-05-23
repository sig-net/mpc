use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(crate) const LOCAL_OIDC_AUDIENCE: &str = "https://canton.network.global";
pub(crate) const LOCAL_OIDC_CLIENT_SECRET: &str = "local-canton-client-secret";
pub(crate) const LOCAL_OIDC_SCOPE: &str = "daml_ledger_api";

const LOCAL_OIDC_JWKS_KEY_ID: &str = "local-canton-jwks-key";
const LOCAL_OIDC_TOKEN_TTL_SECS: u64 = 3600;

pub(crate) struct OidcTestProvider {
    token_url: String,
    jwks_url: String,
    _server: mockito::ServerGuard,
}

impl OidcTestProvider {
    pub(crate) async fn run() -> Result<Self> {
        let issuer = Arc::new(LocalJwtIssuer::new()?);
        let mut server = mockito::Server::new_async().await;

        // Keep the provider small but production-shaped: Canton fetches JWKS to
        // verify bearer tokens, while the MPC node fetches OAuth access tokens.
        let jwks_body = serde_json::to_vec(&issuer.jwks())?;
        server
            .mock("GET", "/.well-known/jwks.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(jwks_body)
            .create_async()
            .await;

        let token_issuer = Arc::clone(&issuer);
        server
            .mock("POST", "/oauth/token")
            .match_request(|request| token_request_client_id(request).is_ok())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |request| {
                build_token_response_body(request, &token_issuer)
                    .expect("valid OAuth token request should build a token response")
            })
            .create_async()
            .await;

        let base_url = server.url();

        Ok(Self {
            token_url: format!("{base_url}/oauth/token"),
            jwks_url: format!("{base_url}/.well-known/jwks.json"),
            _server: server,
        })
    }

    pub(crate) fn token_url(&self) -> &str {
        &self.token_url
    }

    pub(crate) fn jwks_url(&self) -> &str {
        &self.jwks_url
    }
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    audience: String,
    #[serde(default)]
    scope: Option<String>,
}

fn token_request_client_id(request: &mockito::Request) -> Result<String> {
    let authorization = request
        .header("authorization")
        .into_iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = request
        .body()
        .map_err(|err| anyhow::anyhow!("OAuth token request body unavailable: {err}"))?;
    let token_request: TokenRequest =
        serde_urlencoded::from_bytes(body).context("invalid OAuth token request form body")?;
    anyhow::ensure!(
        token_request.grant_type == "client_credentials",
        "unsupported grant_type"
    );
    anyhow::ensure!(
        token_request.audience == LOCAL_OIDC_AUDIENCE,
        "invalid audience"
    );
    anyhow::ensure!(
        token_request.scope.as_deref().unwrap_or(LOCAL_OIDC_SCOPE) == LOCAL_OIDC_SCOPE,
        "invalid scope"
    );

    let (client_id, client_secret) = parse_basic_client_credentials(authorization.as_deref())?;
    anyhow::ensure!(
        client_secret == LOCAL_OIDC_CLIENT_SECRET,
        "invalid client_secret"
    );
    Ok(client_id)
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
}

fn build_token_response_body(
    request: &mockito::Request,
    issuer: &LocalJwtIssuer,
) -> Result<Vec<u8>> {
    let client_id = token_request_client_id(request)?;
    Ok(serde_json::to_vec(&TokenResponse {
        access_token: issuer.generate_access_token(&client_id)?,
        token_type: "Bearer",
        expires_in: LOCAL_OIDC_TOKEN_TTL_SECS,
    })?)
}

fn parse_basic_client_credentials(authorization: Option<&str>) -> Result<(String, String)> {
    let encoded_credentials = authorization
        .context("missing authorization header")?
        .strip_prefix("Basic ")
        .context("unsupported authorization scheme")?;
    let credentials = STANDARD
        .decode(encoded_credentials)
        .context("invalid basic credentials")?;
    let credentials = String::from_utf8(credentials).context("basic credentials were not UTF-8")?;
    let (client_id, client_secret) = credentials
        .split_once(':')
        .context("malformed basic credentials")?;
    Ok((client_id.to_string(), client_secret.to_string()))
}

pub fn generate_untrusted_test_access_token(subject: &str) -> Result<String> {
    LocalJwtIssuer::new()?.generate_access_token(subject)
}

struct LocalJwtIssuer {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

impl LocalJwtIssuer {
    fn new() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let private_key_der = signing_key
            .to_pkcs8_der()
            .context("failed to encode local Canton OIDC signing key")?;
        let encoding_key = EncodingKey::from_ec_der(private_key_der.as_bytes());
        let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256)
            .context("failed to derive local Canton OIDC JWK")?;
        jwk.common.key_id = Some(LOCAL_OIDC_JWKS_KEY_ID.to_string());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);

        Ok(Self { encoding_key, jwk })
    }

    fn generate_access_token(&self, subject: &str) -> Result<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(LOCAL_OIDC_JWKS_KEY_ID.to_string());
        // Keep `iss` omitted for the sandbox default identity provider. A real
        // Auth0 issuer would require matching Canton identity-provider config.
        let claims = LocalAccessTokenClaims {
            audience: LOCAL_OIDC_AUDIENCE,
            subject,
            scope: LOCAL_OIDC_SCOPE,
            issued_at: now,
            expires_at: now + 300,
            not_before: now.saturating_sub(60),
        };
        jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .context("failed to encode local Canton OIDC access token")
    }

    fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.jwk.clone()],
        }
    }
}

#[derive(Serialize)]
struct LocalAccessTokenClaims<'a> {
    #[serde(rename = "aud")]
    audience: &'static str,
    #[serde(rename = "sub")]
    subject: &'a str,
    scope: &'static str,
    #[serde(rename = "iat")]
    issued_at: u64,
    #[serde(rename = "exp")]
    expires_at: u64,
    #[serde(rename = "nbf")]
    not_before: u64,
}
