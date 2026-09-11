pub mod error;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use google_cloud_auth::credentials::AccessTokenCredentials;
use reqwest12 as reqwest;
use serde::{Deserialize, Serialize};

use crate::storage;

pub type SecretResult<T> = std::result::Result<T, error::SecretStorageError>;

const SECRET_MANAGER_ENDPOINT: &str = "https://secretmanager.googleapis.com";
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

#[derive(Deserialize)]
struct AccessSecretVersionResponse {
    #[serde(default)]
    payload: Option<SecretPayload>,
}

#[derive(Serialize, Deserialize)]
struct SecretPayload {
    #[serde(default)]
    data: Option<String>,
}

#[derive(Serialize)]
struct AddSecretVersionRequest {
    payload: AddSecretVersionPayload,
}

#[derive(Serialize)]
struct AddSecretVersionPayload {
    data: String,
}

#[derive(Clone)]
pub struct SecretManagerService {
    http: reqwest::Client,
    credentials: AccessTokenCredentials,
    project_id: String,
}

impl SecretManagerService {
    #[tracing::instrument(level = "debug", skip_all, fields(name = name.as_ref()))]
    pub async fn load_secret<T: AsRef<str>>(&self, name: T) -> SecretResult<Option<Vec<u8>>> {
        let url = format!(
            "{SECRET_MANAGER_ENDPOINT}/v1/projects/{}/secrets/{}/versions/latest",
            self.project_id,
            name.as_ref(),
        );
        let response = self.request(reqwest::Method::GET, &url, None).await?;
        let body: AccessSecretVersionResponse = response.json().await?;
        match body.payload.and_then(|p| p.data).map(|d| BASE64.decode(d)) {
            Some(Ok(data)) if data.len() > 1 => Ok(Some(data)),
            Some(Err(err)) => Err(err.into()),
            _ => {
                tracing::error!("failed to load existing key share, presuming it is missing");
                Ok(None)
            }
        }
    }

    pub async fn store_secret<T: AsRef<str>>(&mut self, data: &[u8], name: T) -> SecretResult<()> {
        let url = format!(
            "{SECRET_MANAGER_ENDPOINT}/v1/projects/{}/secrets/{}:addVersion",
            self.project_id,
            name.as_ref(),
        );
        let body = AddSecretVersionRequest {
            payload: AddSecretVersionPayload {
                data: BASE64.encode(data),
            },
        };
        self.request(
            reqwest::Method::POST,
            &url,
            Some(serde_json::to_vec(&body)?),
        )
        .await
        .map_err(|e| {
            tracing::error!(%e, "failed to store secret");
            e
        })?;
        Ok(())
    }

    async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> SecretResult<reqwest::Response> {
        let token = self.credentials.access_token().await?;
        let mut request = self.http.request(method, url).bearer_auth(token.token);
        if let Some(body) = body {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
            request = request.body(body);
        }
        let response = request.send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            return Err(error::SecretStorageError::Api { status, message });
        }
        Ok(response)
    }
}

#[derive(Clone)]
pub struct GcpService {
    pub secret_manager: SecretManagerService,
}

impl GcpService {
    pub async fn init(storage_options: &storage::Options) -> anyhow::Result<Self> {
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_scopes([CLOUD_PLATFORM_SCOPE])
            .build_access_token_credentials()?;
        let http = reqwest::Client::builder().https_only(true).build()?;

        Ok(Self {
            secret_manager: SecretManagerService {
                http,
                credentials,
                project_id: storage_options.gcp_project_id.clone(),
            },
        })
    }
}
