use std::task::Poll;
use std::time::Duration;

use anyhow::Context;
use backon::ConstantBuilder;
use backon::Retryable;
use cait_sith::FullSignature;
use crypto_shared::SignatureResponse;
use k256::Secp256k1;
use near_fetch::ops::AsyncTransactionStatus;
use near_primitives::errors::ActionErrorKind;
use near_primitives::hash::CryptoHash;
use near_primitives::views::ExecutionOutcomeWithIdView;
use near_primitives::views::ExecutionStatusView;
use near_primitives::views::FinalExecutionStatus;
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

        let result: SignatureResponse = outcome
            .json()
            .map_err(|err| WaitForError::SerdeJson(format!("{err:?}")))?;
        Ok(Outcome::Signature(cait_sith::FullSignature::<Secp256k1> {
            big_r: result.big_r.affine_point,
            s: result.s.scalar,
        }))
    };

    let strategy = ConstantBuilder::default()
        .with_delay(Duration::from_secs(20))
        .with_max_times(10);

    match is_tx_ready.retry(&strategy).await? {
        Outcome::Signature(signature) => Ok(signature),
        Outcome::Failed(err) => Err(WaitForError::Signature(SignatureError::Failed(err))),
        _ => Err(WaitForError::Signature(SignatureError::Failed(
            "Should not return more than one signature".to_string(),
        ))),
    }
}

// Check that the rogue message failed
pub async fn rogue_message_responded(status: AsyncTransactionStatus) -> anyhow::Result<String> {
    let is_tx_ready = || async {
        let Poll::Ready(outcome) = status
            .status()
            .await
            .map_err(|err| WaitForError::JsonRpc(format!("{err:?}")))?
        else {
            return Err(WaitForError::Signature(SignatureError::NotYetAvailable));
        };

        let FinalExecutionStatus::Failure(failure) = outcome.status() else {
            return Err(WaitForError::JsonRpc(format!(
                "rogue: unexpected success {:?}",
                outcome.status()
            )));
        };

        use near_primitives::errors::TxExecutionError;
        let TxExecutionError::ActionError(action_err) = failure else {
            return Err(WaitForError::JsonRpc(format!(
                "rogue: invalid transaction {:?}",
                outcome.status(),
            )));
        };

        let ActionErrorKind::FunctionCallError(ref err) = action_err.kind else {
            return Err(WaitForError::JsonRpc(format!(
                "rogue: not a function call error {:?}",
                outcome.status(),
            )));
        };
        use near_primitives::errors::FunctionCallError;
        let FunctionCallError::ExecutionError(err_msg) = err else {
            return Err(WaitForError::JsonRpc(format!(
                "rogue: wrong execution error {:?}",
                outcome.status(),
            )));
        };
        Ok(err_msg.clone())
    };

    let strategy = ConstantBuilder::default()
        .with_delay(Duration::from_secs(20))
        .with_max_times(5);

    let signature = is_tx_ready
        .retry(&strategy)
        .await
        .with_context(|| "failed to wait for rogue message response")?;

    Ok(signature.clone())
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

        let receipt_outcomes = outcome.details.receipt_outcomes();
        let mut result_receipts: HashMap<CryptoHash, Vec<CryptoHash>> = HashMap::new();
        for receipt_outcome in receipt_outcomes {
            result_receipts
                .entry(receipt_outcome.id)
                .or_insert(receipt_outcome.outcome.receipt_ids.clone());
        }
        let mut receipt_outcomes_keyed: HashMap<CryptoHash, &ExecutionOutcomeWithIdView> =
            HashMap::new();
        for receipt_outcome in receipt_outcomes {
            receipt_outcomes_keyed
                .entry(receipt_outcome.id)
                .or_insert(receipt_outcome);
        }

        let starting_receipts = &receipt_outcomes.first().unwrap().outcome.receipt_ids;

        let mut signatures: Vec<FullSignature<Secp256k1>> = vec![];
        for receipt_id in starting_receipts {
            if !result_receipts.contains_key(receipt_id) {
                break;
            }
            let sign_receipt_id = receipt_id;
            for receipt_id in result_receipts.get(sign_receipt_id).unwrap() {
                let receipt_outcome = receipt_outcomes_keyed
                    .get(receipt_id)
                    .unwrap()
                    .outcome
                    .clone();
                if receipt_outcome
                    .logs
                    .contains(&"Signature is ready.".to_string())
                {
                    match receipt_outcome.status {
                        ExecutionStatusView::SuccessValue(value) => {
                            let result: SignatureResponse = serde_json::from_slice(&value)
                                .map_err(|err| WaitForError::SerdeJson(format!("{err:?}")))?;
                            let signature = cait_sith::FullSignature::<Secp256k1> {
                                big_r: result.big_r.affine_point,
                                s: result.s.scalar,
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
        }

        Ok(Outcome::Signatures(signatures))
    };

    let strategy = ConstantBuilder::default()
        .with_delay(Duration::from_secs(20))
        .with_max_times(5);

    match is_tx_ready.retry(&strategy).await? {
        Outcome::Signature(_) => Err(WaitForError::Signature(SignatureError::Failed(
            "Should not return just 1 signature".to_string(),
        ))),
        Outcome::Failed(err) => Err(WaitForError::Signature(SignatureError::Failed(err))),
        Outcome::Signatures(signatures) => Ok(signatures),
    }
}
