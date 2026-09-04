#[derive(thiserror::Error, Debug)]
pub enum SecretStorageError {
    #[error("GCP error: {0}")]
    GcpError(Box<google_secretmanager1::Error>),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("(de)serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
}

impl From<google_secretmanager1::Error> for SecretStorageError {
    fn from(err: google_secretmanager1::Error) -> Self {
        Self::GcpError(Box::new(err))
    }
}
