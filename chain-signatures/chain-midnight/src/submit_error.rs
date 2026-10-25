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
    /// The node refused the transaction, it expired unlanded, or it landed with
    /// a failed segment. The retry rebuilds against fresh state.
    #[error("[state_conflict] {0}")]
    StateConflict(String),
    /// The transaction may still land.
    #[error("[ambiguous_submit] {0}")]
    Ambiguous(String),
    #[error("[internal] {0}")]
    Internal(String),
}

impl SubmitError {
    /// The class's name, as its message is prefixed with.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::ContractMismatch(_) => "contract_mismatch",
            Self::WalletUnsynced(_) => "wallet_unsynced",
            Self::WalletBusy(_) => "wallet_busy",
            Self::WalletUnfunded(_) => "wallet_unfunded",
            Self::ProvingTimeout(_) => "proving_timeout",
            Self::StateConflict(_) => "state_conflict",
            Self::Ambiguous(_) => "ambiguous_submit",
            Self::Internal(_) => "internal",
        }
    }

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

/// The class of a failed build or submit, if `error` carries one.
pub(crate) fn refusal_code(error: &anyhow::Error) -> Option<&'static str> {
    error.downcast_ref::<SubmitError>().map(SubmitError::code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_is_counted_under_the_code_its_message_carries() {
        let classes: [fn(String) -> SubmitError; 9] = [
            SubmitError::BadRequest,
            SubmitError::ContractMismatch,
            SubmitError::WalletUnsynced,
            SubmitError::WalletBusy,
            SubmitError::WalletUnfunded,
            SubmitError::ProvingTimeout,
            SubmitError::StateConflict,
            SubmitError::Ambiguous,
            SubmitError::Internal,
        ];
        for class in classes {
            let error = class("reason".to_string());
            let message = error.to_string();
            let code = error.code();
            assert_eq!(message, format!("[{code}] reason"));
            assert_eq!(
                refusal_code(&error.into_anyhow().context("publishing")),
                Some(code)
            );
        }
    }
}
