//! Why a build or submit failed, in the classes the retry logic and the logs tell
//! apart. Every class is retried by the publish loop; they differ in what the retry
//! may assume about the chain.

use mpc_chain_integration_core::utils::retry::RpcFailure;

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
    /// The fee needs UTXOs held by a submit that may still land. Nothing was posted.
    #[error("[wallet_busy] {0}")]
    WalletBusy(String),
    /// The wallet cannot pay the fee. Nothing was posted.
    #[error("[wallet_unfunded] {0}")]
    WalletUnfunded(String),
    /// Proving outlasted the submit budget. Nothing was posted.
    #[error("[proving_timeout] {0}")]
    ProvingTimeout(String),
    /// The node refused the transaction or it expired unlanded. The retry
    /// rebuilds against fresh state.
    #[error("[state_conflict] {0}")]
    StateConflict(String),
    /// The transaction may still land.
    #[error("[ambiguous_submit] {0}")]
    Ambiguous(String),
    #[error("[internal] {0}")]
    Internal(String),
    /// A read from or a send to the node failed. Counted as `internal`; its text
    /// may hold the provider's own status, which the core's checks read.
    #[error("[internal] {0}")]
    Node(String),
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
            Self::Internal(_) | Self::Node(_) => "internal",
        }
    }

    /// As the publisher's error. Every failure but the node's carries a retryable
    /// verdict, so the core's retry and throttle checks never read its message,
    /// whose event ids and amounts can include a standalone 429 or 402.
    pub(crate) fn into_publish_error(self) -> anyhow::Error {
        match self {
            Self::Node(_) => anyhow::Error::new(self),
            local => anyhow::Error::new(RpcFailure::retryable(
                "retried by the publish loop".to_string(),
            ))
            .context(local),
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
        let classes: [fn(String) -> SubmitError; 10] = [
            SubmitError::BadRequest,
            SubmitError::ContractMismatch,
            SubmitError::WalletUnsynced,
            SubmitError::WalletBusy,
            SubmitError::WalletUnfunded,
            SubmitError::ProvingTimeout,
            SubmitError::StateConflict,
            SubmitError::Ambiguous,
            SubmitError::Internal,
            SubmitError::Node,
        ];
        for class in classes {
            let error = class("reason".to_string());
            let message = error.to_string();
            let code = error.code();
            assert_eq!(message, format!("[{code}] reason"));
            assert_eq!(
                refusal_code(&error.into_publish_error().context("publishing")),
                Some(code)
            );
        }
    }

    #[test]
    fn a_classified_failure_is_retried_and_never_read_as_throttling() {
        use mpc_chain_integration_core::utils::retry::{is_provider_throttled, is_retryable};
        let error = SubmitError::WalletUnsynced(
            "DUST replay is at event Some(429) of 403 (subscription live)".to_string(),
        )
        .into_publish_error()
        .context("submitting failed after 1200ms");
        assert!(!is_provider_throttled(&error), "{error:#}");
        assert!(is_retryable(&error), "{error:#}");
        assert_eq!(refusal_code(&error), Some("wallet_unsynced"));
        assert!(
            format!("{error:#}").contains("Some(429) of 403"),
            "{error:#}"
        );

        let error = SubmitError::Internal("the fee did not settle in 429 passes".to_string())
            .into_publish_error();
        assert!(!is_provider_throttled(&error), "{error:#}");
        assert_eq!(refusal_code(&error), Some("internal"));

        // The node's failure may be the provider's own throttle, which stays visible.
        let error = SubmitError::Node("the node answered 429 Too Many Requests".to_string())
            .into_publish_error();
        assert!(is_provider_throttled(&error), "{error:#}");
        assert_eq!(refusal_code(&error), Some("internal"));
    }
}
