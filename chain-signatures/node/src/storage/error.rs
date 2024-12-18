pub type StoreResult<T> = std::result::Result<T, StoreError>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("storage connection error: {0}")]
    Connect(#[from] anyhow::Error),
    #[error("empty: {0}")]
    Empty(&'static str),
    #[error("other: {0}")]
    Other(String),
}
