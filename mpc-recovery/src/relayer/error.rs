use near_crypto::PublicKey;
use near_primitives::types::AccountId;

#[derive(thiserror::Error, Debug)]
pub enum RelayerError {
    #[error("unknown account `{0}`")]
    UnknownAccount(AccountId),
    #[error("unknown key `{0}`")]
    UnknownAccessKey(PublicKey),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
