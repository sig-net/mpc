#[derive(thiserror::Error, Debug)]
pub enum SecretStorageError {
    #[error("GCP HTTP error {status}: {message}")]
    GcpHttpError {
        status: reqwest::StatusCode,
        message: String,
    },
    #[error("GCP authentication error: {0}")]
    AuthError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("(de)serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("HTTP client error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}
