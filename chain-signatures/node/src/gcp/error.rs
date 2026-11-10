#[derive(thiserror::Error, Debug)]
pub enum SecretStorageError {
    #[error("GCP auth error: {0}")]
    Auth(#[from] google_cloud_auth::errors::CredentialsError),
    #[error("GCP API error ({status}): {message}")]
    Api {
        status: reqwest::StatusCode,
        message: String,
    },
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("(de)serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}
