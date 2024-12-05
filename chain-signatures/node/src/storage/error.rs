use crate::protocol::presignature::PresignatureId;
use crate::protocol::triple::TripleId;

pub type StoreResult<T> = std::result::Result<T, StoreError>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("storage connection error: {0}")]
    Connect(#[from] anyhow::Error),
    #[error("missing triple: id={0}")]
    TripleIsMissing(TripleId),
    #[error("missing presignature: {0}")]
    PresignatureIsMissing(PresignatureId),
    #[error("empty: {0}")]
    Empty(&'static str),
}
