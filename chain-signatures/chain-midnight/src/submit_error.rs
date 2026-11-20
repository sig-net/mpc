//! Why a build or submit failed, in the classes the retry logic and the logs tell
//! apart. Terminal are malformed inputs, refused gates, and a read inside the
//! submit the transport refused with a classic client error — every retry
//! would replay them unchanged. Every other class waits on a runtime event the
//! retry may yet observe.

use mpc_chain_integration_core::utils::retry::RpcFailure;

use crate::rpc::read_verdict;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SubmitError {
    /// The request or intent is malformed; retrying the same input cannot help.
    #[error("[bad_request] {0}")]
    BadRequest(String),
    /// The deployed contract or the packaged artifacts are not the ones this
    /// publisher proves for; only a redeploy changes that.
    #[error("[contract_mismatch] {0}")]
    ContractMismatch(String),
    /// The deployed contract is not the one the packaged artifacts prove for;
    /// an on-chain upgrade may still be landing. Retry waits it out — every
    /// node runs the same artifacts against the same chain, so failover cannot
    /// help. Nothing was posted.
    #[error("[deploy_mismatch] {0}")]
    DeployMismatch(String),
    /// The action was refused before any work: wrong chain, wrong kind, or a
    /// signature or attestation no circuit answers.
    #[error("[gate_refusal] the action was refused before any work")]
    GateRefusal {
        #[source]
        source: anyhow::Error,
    },
    /// The DUST replay has not caught up. Nothing was posted.
    #[error("[wallet_unsynced] {0}")]
    WalletUnsynced(String),
    /// The fee needs UTXOs held by a submit that may still land. Nothing was posted.
    #[error("[wallet_busy] {0}")]
    WalletBusy(String),
    /// The wallet cannot pay the fee. Nothing was posted. Topping up the wallet
    /// is a runtime event, like solana's funds class
    /// (`chain-solana/src/publisher.rs`).
    #[error("[wallet_unfunded] {0}")]
    WalletUnfunded(String),
    /// Proving outlasted the submit budget. Nothing was posted.
    #[error("[proving_timeout] {0}")]
    ProvingTimeout(String),
    /// The node refused the transaction. Nothing was posted. The retry
    /// rebuilds against fresh state.
    #[error("[state_conflict] {0}")]
    StateConflict(String),
    /// The posted transaction expired unlanded: the node took it, but no
    /// finalized block held it before its TTL. Retried like `StateConflict`,
    /// and struck with it (`native::implicates_restored_state`).
    #[error("[state_conflict] {0}")]
    ExpiredUnlanded(String),
    /// The transaction may still land.
    #[error("[ambiguous_submit] {0}")]
    Ambiguous(String),
    #[error("[internal] {0}")]
    Internal(String),
    /// A read from the node failed. Counted as `internal`; the verdict reads
    /// the typed signals in its chain, never the render.
    #[error("[internal] a node read or send failed")]
    Node {
        #[source]
        source: anyhow::Error,
    },
}

impl SubmitError {
    /// The class's name, as its message is prefixed with.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::ContractMismatch(_) => "contract_mismatch",
            Self::DeployMismatch(_) => "deploy_mismatch",
            Self::GateRefusal { .. } => "gate_refusal",
            Self::WalletUnsynced(_) => "wallet_unsynced",
            Self::WalletBusy(_) => "wallet_busy",
            Self::WalletUnfunded(_) => "wallet_unfunded",
            Self::ProvingTimeout(_) => "proving_timeout",
            Self::StateConflict(_) | Self::ExpiredUnlanded(_) => "state_conflict",
            Self::Ambiguous(_) => "ambiguous_submit",
            Self::Internal(_) | Self::Node { .. } => "internal",
        }
    }

    /// Whether this class is terminal on its own — `Node` is not: its verdict
    /// comes from the HTTP status its source carries. The action's own inputs
    /// are: every retry replays them, so failover covers delivery while a fix
    /// lands.
    fn terminal(&self) -> bool {
        matches!(
            self,
            Self::BadRequest(_) | Self::ContractMismatch(_) | Self::GateRefusal { .. }
        )
    }

    /// As the publisher's error, the class's verdict riding as a carrier so the
    /// core's retry and throttle checks never read the message, whose event ids
    /// and amounts can include a standalone 429 or 402.
    pub(crate) fn into_publish_error(self) -> anyhow::Error {
        match self {
            Self::Node { source } => {
                let failure = read_verdict(&source);
                anyhow::Error::new(failure).context(Self::Node { source })
            }
            Self::GateRefusal { source } => {
                let failure = RpcFailure::terminal(format!("{source:#}"));
                anyhow::Error::new(failure).context(Self::GateRefusal { source })
            }
            local => {
                let failure = if local.terminal() {
                    RpcFailure::terminal("retrying replays the same malformed input".to_string())
                } else {
                    RpcFailure::retryable("retried by the publish loop".to_string())
                };
                anyhow::Error::new(failure).context(local)
            }
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
    use jsonrpsee::core::client::Error as JsonrpseeClientError;
    use mpc_chain_integration_core::utils::retry::{is_provider_throttled, is_retryable};
    use subxt::ext::subxt_rpcs::Error as RawRpcError;

    #[test]
    fn every_class_is_counted_with_its_code_verdict_and_strike() {
        let classes: [(fn() -> SubmitError, bool, bool); 13] = [
            (
                || SubmitError::BadRequest("reason".to_string()),
                false,
                false,
            ),
            (
                || SubmitError::ContractMismatch("reason".to_string()),
                false,
                false,
            ),
            (
                || SubmitError::DeployMismatch("reason".to_string()),
                true,
                false,
            ),
            (
                || SubmitError::GateRefusal {
                    source: anyhow::anyhow!("reason"),
                },
                false,
                false,
            ),
            (
                || SubmitError::WalletUnsynced("reason".to_string()),
                true,
                false,
            ),
            (
                || SubmitError::WalletBusy("reason".to_string()),
                true,
                false,
            ),
            (
                || SubmitError::WalletUnfunded("reason".to_string()),
                true,
                false,
            ),
            (
                || SubmitError::ProvingTimeout("reason".to_string()),
                true,
                false,
            ),
            (
                || SubmitError::StateConflict("reason".to_string()),
                true,
                true,
            ),
            (
                || SubmitError::ExpiredUnlanded("reason".to_string()),
                true,
                true,
            ),
            (|| SubmitError::Ambiguous("reason".to_string()), true, false),
            (|| SubmitError::Internal("reason".to_string()), true, false),
            (
                || SubmitError::Node {
                    source: anyhow::anyhow!("reason"),
                },
                true,
                false,
            ),
        ];
        for (class, retryable, strike) in classes {
            let error = class();
            let code = error.code();
            assert!(
                error.to_string().starts_with(&format!("[{code}]")),
                "{} does not carry its code",
                error
            );
            assert_eq!(
                crate::native::implicates_restored_state(&error),
                strike,
                "{code}'s strike verdict"
            );
            let error = error.into_publish_error().context("publishing");
            assert_eq!(refusal_code(&error), Some(code));
            assert_eq!(is_retryable(&error), retryable, "{error:#}");
            assert!(!is_provider_throttled(&error), "{error:#}");
        }
    }

    #[test]
    fn a_classified_failure_is_retried_and_never_read_as_throttling() {
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
    }

    #[test]
    fn a_statusless_node_failure_is_never_read_as_throttling() {
        // However status-like the render, no typed status means no gate.
        let error = SubmitError::Node {
            source: anyhow::anyhow!("the node answered 429 Too Many Requests"),
        }
        .into_publish_error()
        .context("submitting failed after 1200ms");
        assert!(!is_provider_throttled(&error), "{error:#}");
        assert!(is_retryable(&error), "{error:#}");
        assert_eq!(refusal_code(&error), Some("internal"));
    }

    #[test]
    fn upstream_carriers_win_over_the_derived_verdict() {
        use http::StatusCode;

        let terminal = SubmitError::Node {
            source: anyhow::Error::new(RpcFailure::terminal("upstream refused".to_string()))
                .context("upstream"),
        }
        .into_publish_error();
        assert!(!is_retryable(&terminal), "{terminal:#}");

        // The carrier's verdict wins over the send partition its status implies.
        let retryable = SubmitError::Node {
            source: anyhow::Error::new(RpcFailure::retryable_with_status(
                StatusCode::from_u16(409).unwrap(),
                "upstream retry".to_string(),
            ))
            .context("upstream"),
        }
        .into_publish_error();
        assert!(is_retryable(&retryable), "{retryable:#}");
        let carrier = retryable
            .chain()
            .find_map(|cause| cause.downcast_ref::<RpcFailure>())
            .expect("the carrier survives the boundary");
        assert_eq!(carrier.status(), StatusCode::from_u16(409).ok());
        assert!(!carrier.is_terminal());
    }

    #[test]
    fn node_statuses_classify_by_the_read_partition() {
        fn rejected(status: u16) -> anyhow::Error {
            anyhow::Error::new(RawRpcError::Client(Box::new(
                JsonrpseeClientError::Transport(Box::new(
                    jsonrpsee::http_client::transport::Error::Rejected {
                        status_code: status,
                    },
                )),
            )))
        }

        // A real throttle: retryable, and the gate engages on the typed status.
        let throttled = SubmitError::Node {
            source: rejected(429).context("reading the node's runtime"),
        }
        .into_publish_error();
        assert!(is_retryable(&throttled), "{throttled:#}");
        assert!(is_provider_throttled(&throttled), "{throttled:#}");

        // A shared provider's transient conflict retries, like midnight's other
        // reads — the send table would hand the publish to failover here.
        let conflict = SubmitError::Node {
            source: rejected(409),
        }
        .into_publish_error();
        assert!(is_retryable(&conflict), "{conflict:#}");
        assert!(!is_provider_throttled(&conflict), "{conflict:#}");

        let terminal = SubmitError::Node {
            source: rejected(404),
        }
        .into_publish_error();
        assert!(!is_retryable(&terminal), "{terminal:#}");
        assert!(!is_provider_throttled(&terminal), "{terminal:#}");
    }
}
