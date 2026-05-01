use std::task::Poll;
use std::time::Duration;

use backon::ConstantBuilder;
use backon::Retryable;
use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_primitives::Signature;
use near_fetch::ops::AsyncTransactionStatus;
use near_primitives::hash::CryptoHash;
use near_primitives::views::ExecutionOutcomeWithIdView;
use near_primitives::views::ExecutionStatusView;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("tx final outcome not yet available")]
    NotYetAvailable,
    #[error("tx was unsuccessful: {0}")]
    Failed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum WaitForError {
    #[error("Json RPC request error: {0}")]
    JsonRpc(String),
    #[error("signature tx error: {0}")]
    Signature(SignatureError),
    #[error("Serde json error: {0}")]
    SerdeJson(String),
}

/// Used locally for testing to circumvent retrying on all errors. This will avoid retrying
/// on failed signatures as we should abort early on those when in the retrying loop.
enum Outcome {
    Signature(FullSignature<Secp256k1>),
    Failed(String),
    Signatures(Vec<FullSignature<Secp256k1>>),
}

pub async fn signature_responded(
    status: AsyncTransactionStatus,
) -> Result<FullSignature<Secp256k1>, WaitForError> {
    let is_tx_ready = || async {
        let Poll::Ready(outcome) = status
            .status()
            .await
            .map_err(|err| WaitForError::JsonRpc(format!("{err:?}")))?
        else {
            return Err(WaitForError::Signature(SignatureError::NotYetAvailable));
        };

        if outcome.is_failure() {
            return Ok(Outcome::Failed(format!("{:?}", outcome.status())));
        }

        let result: Signature = outcome
            .json()
            .map_err(|err| WaitForError::SerdeJson(format!("{err:?}")))?;
        Ok(Outcome::Signature(cait_sith::FullSignature::<Secp256k1> {
            big_r: result.big_r,
            s: result.s,
        }))
    };

    let strategy = ConstantBuilder::default()
        .with_delay(Duration::from_millis(500))
        .with_max_times(120);

    match is_tx_ready.retry(&strategy).await? {
        Outcome::Signature(signature) => Ok(signature),
        Outcome::Failed(err) => Err(WaitForError::Signature(SignatureError::Failed(err))),
        _ => Err(WaitForError::Signature(SignatureError::Failed(
            "Should not return more than one signature".to_string(),
        ))),
    }
}

pub async fn batch_signature_responded(
    status: AsyncTransactionStatus,
) -> Result<Vec<FullSignature<Secp256k1>>, WaitForError> {
    let is_tx_ready = || async {
        let Poll::Ready(outcome) = status
            .status()
            .await
            .map_err(|err| WaitForError::JsonRpc(format!("{err:?}")))?
        else {
            return Err(WaitForError::Signature(SignatureError::NotYetAvailable));
        };

        if !outcome.is_success() {
            return Err(WaitForError::Signature(SignatureError::Failed(format!(
                "status: {:?}",
                outcome.status()
            ))));
        }

        let mut signatures: Vec<FullSignature<Secp256k1>> = vec![];
        for receipt_outcome in outcome.details.receipt_outcomes() {
            let outcome = &receipt_outcome.outcome;
            if outcome.logs.contains(&"Signature is ready.".to_string()) {
                match &outcome.status {
                    ExecutionStatusView::SuccessValue(value) => {
                        let result: Signature = serde_json::from_slice(value)
                            .map_err(|err| WaitForError::SerdeJson(format!("{err:?}")))?;
                        let signature = cait_sith::FullSignature::<Secp256k1> {
                            big_r: result.big_r,
                            s: result.s,
                        };
                        signatures.push(signature);
                    }
                    _ => {
                        return Err(WaitForError::Signature(SignatureError::Failed(
                            "one signature not done.".to_string(),
                        )))
                    }
                }
            }
        }

        Ok(Outcome::Signatures(signatures))
    };

    let strategy = ConstantBuilder::default()
        .with_delay(Duration::from_millis(500))
        .with_max_times(120);

    match is_tx_ready.retry(&strategy).await? {
        Outcome::Signature(_) => Err(WaitForError::Signature(SignatureError::Failed(
            "Should not return just 1 signature".to_string(),
        ))),
        Outcome::Failed(err) => Err(WaitForError::Signature(SignatureError::Failed(err))),
        Outcome::Signatures(signatures) => Ok(signatures),
    }
}
