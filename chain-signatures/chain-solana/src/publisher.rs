use std::error::Error as _;

use anchor_client::ClientError as AnchorClientError;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use mpc_chain_integration_core::{utils::retry::RpcFailure, ChainPublisher, PublishAction};
use mpc_primitives::SignKind;
use reqwest::StatusCode;
use signet_program::accounts::{
    Respond as SolanaRespondAccount, RespondBidirectional as SolanaRespondBidirectionalAccount,
};
use signet_program::instruction::{
    Respond as SolanaRespond, RespondBidirectional as SolanaRespondBidirectional,
};
use solana_client::{
    client_error::ClientErrorKind,
    rpc_custom_error::JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE,
    rpc_request::{RpcError, RpcResponseErrorData},
    rpc_response::RpcSimulateTransactionResult,
};
use solana_sdk::{pubkey::Pubkey, signature::Signer as _, transaction::TransactionError};

use crate::client::SolanaClient;
use crate::utils::mpc_to_sol_signature;

enum Verdict {
    Terminal,
    Retryable,
    /// HTTP-statused transport failure; core derives the verdict from the
    /// carried status.
    Status(StatusCode),
}

impl Verdict {
    fn carrier(self, message: String) -> Option<RpcFailure> {
        match self {
            Verdict::Terminal => Some(RpcFailure::terminal(message)),
            Verdict::Retryable => Some(RpcFailure::retryable(message)),
            Verdict::Status(status) => Some(RpcFailure::with_status(status, message)),
        }
    }
}

/// Publish verdict for an anchor error: program rejections and signer
/// failures are terminal; HTTP-statused transport errors carry their status
/// for the core classifier; the rest carry a retryable verdict.
fn publish_error(e: AnchorClientError) -> anyhow::Error {
    let verdict = verdict(&e);
    let err = anyhow::Error::new(e);
    verdict
        .carrier(format!("{err:#}"))
        .map_or(err, anyhow::Error::new)
}

/// Determine the verdict for an anchor error.
fn verdict(e: &AnchorClientError) -> Verdict {
    match e {
        AnchorClientError::ProgramError(_)
        | AnchorClientError::AnchorError(_)
        | AnchorClientError::AccountNotFound
        | AnchorClientError::LogParseError(_)
        | AnchorClientError::SignerError(_) => Verdict::Terminal,
        AnchorClientError::SolanaClientError(sol) => kind_verdict(sol.kind()),
        AnchorClientError::SolanaClientPubsubError(_) | AnchorClientError::IOError(_) => {
            Verdict::Retryable
        }
    }
}

/// Determine the verdict for a solana client error kind.
fn kind_verdict(kind: &ClientErrorKind) -> Verdict {
    match kind {
        // Read the status here: solana's `#[source] Box<ErrorKind>` nesting
        // hides the inner reqwest error from chain walks. Statusless
        // (connection) failures carry an explicit retryable verdict.
        ClientErrorKind::Reqwest(e) => e.status().map_or(Verdict::Retryable, Verdict::Status),
        ClientErrorKind::TransactionError(tx) => on_chain(tx),
        ClientErrorKind::RpcError(rpc) => rpc_verdict(rpc),
        // local key problem, matching the anchor-level SignerError verdict
        ClientErrorKind::SigningError(_) => Verdict::Terminal,
        ClientErrorKind::Io(_)
        | ClientErrorKind::Middleware(_)
        | ClientErrorKind::SerdeJson(_)
        | ClientErrorKind::Custom(_) => Verdict::Retryable,
    }
}

/// JSON-RPC 2.0 spec invalid-params (jsonrpc-core 18.0.0 error.rs).
const JSON_RPC_INVALID_PARAMS: i64 = -32602;

/// Determine the verdict for an RPC error.
fn rpc_verdict(rpc: &RpcError) -> Verdict {
    let RpcError::RpcResponseError { code, data, .. } = rpc else {
        // non-response shapes (ForUser confirm timeout, request/parse failures)
        return Verdict::Retryable;
    };
    if let RpcResponseErrorData::SendTransactionPreflightFailure(sim) = data {
        return sim_tx_error(sim).map_or(Verdict::Retryable, on_chain);
    }
    match *code {
        // Deterministic sendTransaction rejections, both with `data: Empty`:
        // Oversized transaction, signature verification failure
        JSON_RPC_INVALID_PARAMS
        | JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE => Verdict::Terminal,
        // NodeUnhealthy, undecodable preflight data, every other code
        _ => Verdict::Retryable,
    }
}

/// `UiTransactionError.source()` is the inner `TransactionError`
fn sim_tx_error(sim: &RpcSimulateTransactionResult) -> Option<&TransactionError> {
    sim.err.as_ref()?.source()?.downcast_ref()
}

/// Determine the verdict for an on-chain transaction error.
fn on_chain(tx: &TransactionError) -> Verdict {
    match tx {
        // deterministic failures a fresh attempt cannot change; everything
        // else (blockhash expiry, contention) recovers on retry
        TransactionError::InstructionError(..)
        | TransactionError::InsufficientFundsForFee
        | TransactionError::UnsupportedVersion => Verdict::Terminal,
        _ => Verdict::Retryable,
    }
}

#[async_trait::async_trait]
impl ChainPublisher for SolanaClient {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let timestamp = action.timestamp;
        let mpc_sig = &action.signature;
        let program = self
            .client
            .program(self.program_id)
            .map_err(publish_error)?;

        let sign_id = action.request.id;
        let request_ids = vec![action.request.id.request_id];
        let big_r = mpc_sig.big_r.to_encoded_point(false);
        let signature = mpc_to_sol_signature(mpc_sig, big_r);

        tracing::debug!(
            ?sign_id,
            request_type = ?action.request.kind,
            "Solana publish signature: dispatching request"
        );

        let (event_authority, _) =
            Pubkey::find_program_address(&[b"__event_authority"], &self.program_id);

        match &action.request.kind {
            SignKind::Sign | SignKind::SignBidirectional(_) => {
                let tx = program
                    .request()
                    .accounts(SolanaRespondAccount {
                        responder: self.payer.pubkey(),
                        event_authority,
                        program: self.program_id,
                    })
                    .args(SolanaRespond {
                        request_ids,
                        signatures: vec![signature.clone()],
                    })
                    .send()
                    .await
                    .map_err(publish_error)
                    .inspect_err(|err| {
                        tracing::error!(
                            sign_id = ?action.request.id,
                            error = ?err,
                            "failed to publish solana signature"
                        );
                    })?;

                tracing::info!(
                    ?sign_id,
                    tx_hash = ?tx,
                    elapsed = ?timestamp.elapsed(),
                    "published solana signature successfully"
                );
            }
            SignKind::RespondBidirectional(respond_bidirectional_tx) => {
                tracing::debug!(
                    ?sign_id,
                    request_id = ?request_ids[0],
                    serialized_output_len = respond_bidirectional_tx.output.len(),
                    "Solana publish signature: entering RespondBidirectional arm"
                );
                let respond_bidirectional_serialized_output =
                    respond_bidirectional_tx.output.clone();
                let tx = program
                    .request()
                    .accounts(SolanaRespondBidirectionalAccount {
                        responder: self.payer.pubkey(),
                        event_authority,
                        program: self.program_id,
                    })
                    .args(SolanaRespondBidirectional {
                        request_id: request_ids[0],
                        serialized_output: respond_bidirectional_serialized_output,
                        signature: signature.clone(),
                    })
                    .send()
                    .await
                    .map_err(publish_error)
                    .inspect_err(|err| {
                        tracing::error!(
                            ?sign_id,
                            error = ?err,
                            "Solana publish signature: failed to publish respond bidirectional solana signature"
                        );
                    })?;

                tracing::info!(
                    ?sign_id,
                    tx_hash = ?tx,
                    elapsed = ?timestamp.elapsed(),
                    "published respond bidirectional solana signature successfully"
                );
            }
        }

        self.telemetry.record_publish_metrics(action);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_chain_integration_core::utils::retry::{is_provider_throttled, is_retryable};
    use serde_json::json;
    use solana_client::client_error::ClientError as SolanaClientError;
    use solana_sdk::instruction::InstructionError;

    /// Wrap a `ClientErrorKind` into an `anyhow::Error` using the anchor error wrapper.
    fn anchor_wrapped(kind: ClientErrorKind) -> anyhow::Error {
        publish_error(AnchorClientError::SolanaClientError(Box::new(
            SolanaClientError::from(kind),
        )))
    }

    #[test]
    fn on_chain_instruction_failure_is_terminal() {
        let err = anchor_wrapped(ClientErrorKind::TransactionError(
            TransactionError::InstructionError(0, InstructionError::Custom(0)),
        ));
        assert!(!is_retryable(&err));
    }

    #[test]
    fn on_chain_expiry_and_contention_stay_retryable() {
        let err = anchor_wrapped(ClientErrorKind::TransactionError(
            TransactionError::BlockhashNotFound,
        ));
        assert!(is_retryable(&err));
    }

    #[test]
    fn deterministic_on_chain_failures_are_terminal() {
        for tx in [
            TransactionError::InsufficientFundsForFee,
            TransactionError::UnsupportedVersion,
        ] {
            let err = anchor_wrapped(ClientErrorKind::TransactionError(tx.clone()));
            assert!(!is_retryable(&err), "{tx:?}");
        }
    }

    #[test]
    fn confirm_timeout_for_user_stays_retryable() {
        // anchor's confirm-loop shape
        let err = anchor_wrapped(ClientErrorKind::RpcError(RpcError::ForUser(
            "unable to confirm transaction. This can happen in situations such as transaction \
             expiration and insufficient fee-payer funds"
                .to_string(),
        )));
        assert!(is_retryable(&err));
    }

    #[test]
    fn preflight_instruction_failure_is_terminal() {
        // wire shape of -32002:
        // every field is an Option, missing means None)
        let sim: RpcSimulateTransactionResult =
            serde_json::from_value(json!({"err": {"InstructionError": [0, {"Custom": 0}]}}))
                .unwrap();
        let err = anchor_wrapped(ClientErrorKind::RpcError(RpcError::RpcResponseError {
            code: -32002,
            message: "Transaction simulation failed".to_string(),
            data: RpcResponseErrorData::SendTransactionPreflightFailure(sim),
        }));
        assert!(!is_retryable(&err));
    }

    #[test]
    fn deterministic_send_rejections_are_terminal() {
        // both arrive on the wire with `data: Empty`
        let rejects = [
            (
                JSON_RPC_INVALID_PARAMS,
                "Transaction too large: 1300 bytes (max: 1232 bytes)",
            ),
            (
                JSON_RPC_SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE,
                "Transaction signature verification failure",
            ),
        ];
        for (code, message) in rejects {
            let err = anchor_wrapped(ClientErrorKind::RpcError(RpcError::RpcResponseError {
                code,
                message: message.to_string(),
                data: RpcResponseErrorData::Empty,
            }));
            assert!(!is_retryable(&err), "code {code} should be terminal");
        }
    }

    #[test]
    fn signer_errors_are_terminal() {
        let err = publish_error(AnchorClientError::SignerError(
            anchor_client::SignerError::KeypairPubkeyMismatch,
        ));
        assert!(!is_retryable(&err));
        // solana-level signing errors agree with the anchor-level verdict
        let err = anchor_wrapped(ClientErrorKind::SigningError(
            anchor_client::SignerError::KeypairPubkeyMismatch,
        ));
        assert!(!is_retryable(&err));
    }

    #[test]
    fn anchor_level_failures_are_terminal() {
        let program_error = anchor_lang::solana_program::program_error::ProgramError::Custom(0);
        let errs = [
            AnchorClientError::AccountNotFound,
            AnchorClientError::LogParseError("nope".to_string()),
            AnchorClientError::ProgramError(program_error.clone()),
            AnchorClientError::AnchorError(anchor_lang::error::Error::from(program_error)),
        ];
        for e in errs {
            let err = publish_error(e);
            assert!(!is_retryable(&err), "{err:#}");
        }
    }

    #[tokio::test]
    async fn http_status_errors_classify_by_carried_status() {
        // real reqwest status errors nested exactly as solana nests them:
        // anchor ClientError → solana ClientError → ErrorKind::Reqwest
        let mut server = mockito::Server::new_async().await;
        let client = reqwest::Client::new();

        let throttled = server
            .mock("POST", "/")
            .with_status(429)
            .create_async()
            .await;
        let reqwest_err = client
            .post(server.url())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap_err();
        throttled.assert();

        let err = anchor_wrapped(ClientErrorKind::Reqwest(reqwest_err));
        assert!(is_retryable(&err));
        assert!(is_provider_throttled(&err));

        // 409 diverges from the string fallback: terminal proves the verdict is the carried status.
        let conflict = server
            .mock("POST", "/")
            .with_status(409)
            .create_async()
            .await;
        let reqwest_err = client
            .post(server.url())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap_err();
        conflict.assert();

        let err = anchor_wrapped(ClientErrorKind::Reqwest(reqwest_err));
        assert!(!is_retryable(&err));
        assert!(!is_provider_throttled(&err));

        // no status (connection refused): the retryable carrier keeps the
        // string fallback away from the rendered ":429" port
        let reqwest_err = client
            .post("http://127.0.0.1:429")
            .send()
            .await
            .unwrap_err();
        let err = anchor_wrapped(ClientErrorKind::Reqwest(reqwest_err));
        assert!(is_retryable(&err));
        assert!(!is_provider_throttled(&err));
    }
}
