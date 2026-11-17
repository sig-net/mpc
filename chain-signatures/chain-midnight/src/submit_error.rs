//! Why a build or submit failed, in the classes the retry logic and the logs tell
//! apart. Terminal are malformed inputs, refused gates, and a read inside the
//! submit the transport refused with a status other than 402, 408, 429 or 5xx —
//! every retry would replay them unchanged. Every other class waits on a runtime
//! event the retry may yet observe.

use mpc_chain_integration_core::utils::retry::RpcFailure;

use crate::rpc::rejected_http_status;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SubmitError {
    /// The request or intent is malformed; retrying the same input cannot help.
    #[error("[bad_request] {0}")]
    BadRequest(String),
    /// The deployed contract or the packaged artifacts are not the ones this
    /// publisher proves for; only a redeploy changes that.
    #[error("[contract_mismatch] {0}")]
    ContractMismatch(String),
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
    /// The node refused the transaction or it expired unlanded. The retry
    /// rebuilds against fresh state.
    #[error("[state_conflict] {0}")]
    StateConflict(String),
    /// The transaction may still land.
    #[error("[ambiguous_submit] {0}")]
    Ambiguous(String),
    #[error("[internal] {0}")]
    Internal(String),
    /// A read from the node failed. Counted as `internal`; the verdict reads
    /// the typed HTTP status in its chain, never the render.
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
            Self::GateRefusal { .. } => "gate_refusal",
            Self::WalletUnsynced(_) => "wallet_unsynced",
            Self::WalletBusy(_) => "wallet_busy",
            Self::WalletUnfunded(_) => "wallet_unfunded",
            Self::ProvingTimeout(_) => "proving_timeout",
            Self::StateConflict(_) => "state_conflict",
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
            // The send partition, like ethereum's pre-broadcast nonce fetch
            // (`chain-ethereum/src/publisher.rs`):
            // nothing was posted, so a classic 4xx hands the publish to failover.
            // A carrier already inside the source rides as-is (`from_chain`) —
            // its verdict, status and retry_after win over the derivation.
            Self::Node { source } => {
                let failure = match RpcFailure::from_chain(&source) {
                    Some(failure) => failure,
                    None => match rejected_http_status(&source) {
                        Some(status) => RpcFailure::send_status(status, format!("{source:#}")),
                        None => RpcFailure::retryable(format!("{source:#}")),
                    },
                };
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
    fn every_class_is_counted_and_classified_under_its_code() {
        let classes: [(fn() -> SubmitError, bool); 11] = [
            (|| SubmitError::BadRequest("reason".to_string()), false),
            (
                || SubmitError::ContractMismatch("reason".to_string()),
                false,
            ),
            (
                || SubmitError::GateRefusal {
                    source: anyhow::anyhow!("reason"),
                },
                false,
            ),
            (|| SubmitError::WalletUnsynced("reason".to_string()), true),
            (|| SubmitError::WalletBusy("reason".to_string()), true),
            (|| SubmitError::WalletUnfunded("reason".to_string()), true),
            (|| SubmitError::ProvingTimeout("reason".to_string()), true),
            (|| SubmitError::StateConflict("reason".to_string()), true),
            (|| SubmitError::Ambiguous("reason".to_string()), true),
            (|| SubmitError::Internal("reason".to_string()), true),
            (
                || SubmitError::Node {
                    source: anyhow::anyhow!("reason"),
                },
                true,
            ),
        ];
        for (class, retryable) in classes {
            let error = class();
            let code = error.code();
            assert!(
                error.to_string().starts_with(&format!("[{code}]")),
                "{} does not carry its code",
                error
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
    fn node_statuses_classify_by_the_send_partition() {
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

        let terminal = SubmitError::Node {
            source: rejected(409),
        }
        .into_publish_error();
        assert!(!is_retryable(&terminal), "{terminal:#}");
        assert!(!is_provider_throttled(&terminal), "{terminal:#}");
    }
}
