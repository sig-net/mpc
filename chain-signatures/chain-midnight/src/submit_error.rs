//! Why a build or submit failed, in the classes the retry logic and the logs tell
//! apart. Every class is retried by the publish loop; they differ in what the retry
//! may assume about the chain.

use crate::intent::AmbiguousSubmit;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SubmitError {
    /// The request or intent is malformed; retrying the same input cannot help.
    #[error("[bad_request] {0}")]
    BadRequest(String),
    /// The deployed contract or the packaged artifacts are not the ones this
    /// publisher proves for.
    #[error("[contract_mismatch] {0}")]
    ContractMismatch(String),
    /// The DUST replay has not caught up. Nothing was posted.
    #[error("[wallet_unsynced] {0}")]
    WalletUnsynced(String),
    /// Every spendable UTXO is held by a submit that may still land. Nothing was posted.
    #[error("[wallet_busy] {0}")]
    WalletBusy(String),
    /// The wallet cannot pay the fee. Nothing was posted.
    #[error("[wallet_unfunded] {0}")]
    WalletUnfunded(String),
    /// Proving outlasted the submit budget. Nothing was posted.
    #[error("[proving_timeout] {0}")]
    ProvingTimeout(String),
    /// The node refused the transaction, or it expired unlanded. Nothing was
    /// posted; the retry rebuilds against fresh state.
    #[error("[state_conflict] {0}")]
    StateConflict(String),
    /// The transaction may still land.
    #[error("[ambiguous_submit] {0}")]
    Ambiguous(String),
    #[error("[internal] {0}")]
    Internal(String),
}

impl SubmitError {
    /// As the publisher's error, marked when the transaction may still land.
    pub(crate) fn into_anyhow(self) -> anyhow::Error {
        let ambiguous = matches!(self, Self::Ambiguous(_));
        let error = anyhow::Error::new(self);
        if ambiguous {
            error.context(AmbiguousSubmit)
        } else {
            error
        }
    }
}
