use crate::error::SecretStorageError;
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub type SecretResult<T> = std::result::Result<T, SecretStorageError>;

const GCP_SECRET_MANAGER_BASE_URL: &str = "https://secretmanager.googleapis.com";
const GCP_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

#[derive(Clone)]
pub enum AuthProvider {
    Mock(String),
    Adc(Arc<dyn gcp_auth::TokenProvider>),
}

impl AuthProvider {
    pub async fn get_token(&self) -> Result<String, SecretStorageError> {
        match self {
            AuthProvider::Mock(token) => Ok(token.clone()),
            AuthProvider::Adc(auth) => {
                let token = auth
                    .token(&[GCP_OAUTH_SCOPE])
                    .await
                    .map_err(|e| SecretStorageError::AuthError(e.to_string()))?;
                Ok(token.as_str().to_string())
            }
        }
    }
}

#[derive(Deserialize)]
struct AccessSecretVersionResponse {
    payload: Option<SecretPayloadResponse>,
}

#[derive(Deserialize)]
struct SecretPayloadResponse {
    data: Option<String>,
}

#[derive(Serialize)]
struct AddSecretVersionRequest {
    payload: SecretPayloadRequest,
}

#[derive(Serialize)]
struct SecretPayloadRequest {
    data: String,
}

#[derive(Clone)]
pub struct SecretManagerService {
    client: reqwest::Client,
    auth_provider: AuthProvider,
    project_id: String,
    base_url: String,
}

impl SecretManagerService {
    pub fn new(project_id: impl Into<String>, auth_provider: AuthProvider) -> Self {
        Self {
            client: reqwest::Client::new(),
            auth_provider,
            project_id: project_id.into(),
            base_url: GCP_SECRET_MANAGER_BASE_URL.to_string(),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    #[tracing::instrument(level = "debug", skip_all, fields(name = name.as_ref()))]
    pub async fn load_secret<T: AsRef<str>>(&self, name: T) -> SecretResult<Option<Vec<u8>>> {
        let token = self.auth_provider.get_token().await?;
        let url = format!(
            "{}/v1/projects/{}/secrets/{}/versions/latest:access",
            self.base_url,
            self.project_id,
            name.as_ref()
        );

        let response = self.client.get(&url).bearer_auth(token).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::debug!("secret {} not found in GCP Secret Manager", name.as_ref());
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SecretStorageError::GcpHttpError {
                status,
                message: body,
            });
        }

        let access_response: AccessSecretVersionResponse = response.json().await?;
        match access_response.payload {
            Some(SecretPayloadResponse {
                data: Some(encoded_data),
            }) => {
                let decoded_data = BASE64_STANDARD.decode(encoded_data)?;
                // GCP does not allow uploading empty secrets, so 1-byte values are reserved as placeholders.
                if decoded_data.len() > 1 {
                    Ok(Some(decoded_data))
                } else {
                    tracing::error!("failed to load existing key share, presuming it is missing");
                    Ok(None)
                }
            }
            _ => {
                tracing::error!("failed to load existing key share, presuming it is missing");
                Ok(None)
            }
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(name = name.as_ref()))]
    pub async fn store_secret<T: AsRef<str>>(&mut self, data: &[u8], name: T) -> SecretResult<()> {
        let token = self.auth_provider.get_token().await?;
        let url = format!(
            "{}/v1/projects/{}/secrets/{}:addVersion",
            self.base_url,
            self.project_id,
            name.as_ref()
        );

        let request_body = AddSecretVersionRequest {
            payload: SecretPayloadRequest {
                data: BASE64_STANDARD.encode(data),
            },
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(token)
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::error!(%status, %body, "failed to store secret");
            return Err(SecretStorageError::GcpHttpError {
                status,
                message: body,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_secret_success() {
        let mut server = mockito::Server::new_async().await;
        let project_id = "test-proj";
        let secret_name = "test-sk";
        let secret_bytes = b"my-super-secret-data-payload";
        let encoded_bytes = BASE64_STANDARD.encode(secret_bytes);

        let mock = server
            .mock(
                "GET",
                format!("/v1/projects/{project_id}/secrets/{secret_name}/versions/latest:access")
                    .as_str(),
            )
            .match_header("authorization", "Bearer TEST_TOKEN")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "name": format!("projects/{project_id}/secrets/{secret_name}/versions/1"),
                    "payload": {
                        "data": encoded_bytes
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let service =
            SecretManagerService::new(project_id, AuthProvider::Mock("TEST_TOKEN".to_string()))
                .with_base_url(server.url());

        let result = service.load_secret(secret_name).await.unwrap();
        assert_eq!(result, Some(secret_bytes.to_vec()));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_load_secret_placeholder_returns_none() {
        let mut server = mockito::Server::new_async().await;
        let project_id = "test-proj";
        let secret_name = "empty-sk";
        let placeholder_byte = vec![0u8];
        let encoded_bytes = BASE64_STANDARD.encode(&placeholder_byte);

        let mock = server
            .mock(
                "GET",
                format!("/v1/projects/{project_id}/secrets/{secret_name}/versions/latest:access")
                    .as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "payload": {
                        "data": encoded_bytes
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let service =
            SecretManagerService::new(project_id, AuthProvider::Mock("TEST_TOKEN".to_string()))
                .with_base_url(server.url());

        let result = service.load_secret(secret_name).await.unwrap();
        assert_eq!(result, None);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_load_secret_not_found() {
        let mut server = mockito::Server::new_async().await;
        let project_id = "test-proj";
        let secret_name = "missing-sk";

        let mock = server
            .mock(
                "GET",
                format!("/v1/projects/{project_id}/secrets/{secret_name}/versions/latest:access")
                    .as_str(),
            )
            .with_status(404)
            .create_async()
            .await;

        let service =
            SecretManagerService::new(project_id, AuthProvider::Mock("TEST_TOKEN".to_string()))
                .with_base_url(server.url());

        let result = service.load_secret(secret_name).await.unwrap();
        assert_eq!(result, None);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_store_secret_success() {
        let mut server = mockito::Server::new_async().await;
        let project_id = "test-proj";
        let secret_name = "test-sk";
        let secret_bytes = b"new-secret-share";
        let encoded_bytes = BASE64_STANDARD.encode(secret_bytes);

        let mock = server
            .mock(
                "POST",
                format!("/v1/projects/{project_id}/secrets/{secret_name}:addVersion").as_str(),
            )
            .match_header("authorization", "Bearer TEST_TOKEN")
            .match_body(
                serde_json::json!({
                    "payload": {
                        "data": encoded_bytes
                    }
                })
                .to_string()
                .as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "name": format!("projects/{project_id}/secrets/{secret_name}/versions/1")
                })
                .to_string(),
            )
            .create_async()
            .await;

        let mut service =
            SecretManagerService::new(project_id, AuthProvider::Mock("TEST_TOKEN".to_string()))
                .with_base_url(server.url());

        let result = service.store_secret(secret_bytes, secret_name).await;
        assert!(result.is_ok());
        mock.assert_async().await;
    }
}
