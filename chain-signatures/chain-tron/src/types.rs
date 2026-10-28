//! Response domain types returned by [`crate::client::TronHttp`].
//!
//! Receipt fields mirror java-tron's `TransactionInfo`/`ResourceReceipt`
//! JSON (protocol/core/Tron.proto@4e8389f).

use alloy::primitives::{Log, LogData, B256};

use anyhow::{bail, Context};
use mpc_primitives::ExecutionOutcome;

pub use mpc_tron_wire::NowBlock;

/// Outcome of `broadcasttransaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// Accepted into the mempool
    Accepted,
    /// `DUP_TRANSACTION_ERROR`: a transaction with this txID is already
    /// known to the node — success for a relayer that rebroadcasts.
    AlreadyKnown,
    /// Terminal rejection, retrying identical bytes cannot succeed.
    Rejected { code: String, message: String },
}

/// Receipt from the solidity router; presence means executed and final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronReceipt {
    pub id: B256,
    pub block_number: u64,
    pub block_timestamp: u64,
    /// Total fee in sun.
    pub fee: u64,
    /// Top-level `result` — `TransactionInfo.code` (SUCESS|FAILED); absent
    /// on TronGrid.
    pub result: Option<String>,
    /// `receipt.result` — `ResourceReceipt`'s contractResult.
    pub receipt_result: Option<String>,
    /// Revert reason, hex-decoded when present.
    pub res_message: Option<String>,
    pub logs: Vec<TronLog>,
}

/// What a solidified receipt attests about execution: classification
/// only, no policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TronExecutionResult {
    Succeeded,
    Failed,
}

impl TronReceipt {
    /// Verdict strings are two enums (Tron.proto@4e8389f): top-level `result`
    /// (`TransactionInfo.code`) and `receipt.result` (`contractResult`).
    /// Every non-success member attests failure; `DEFAULT` (proto3 zero)
    /// and unknown strings attest nothing — error, keep polling.
    pub fn execution_result(&self) -> anyhow::Result<TronExecutionResult> {
        let result = self
            .result
            .as_deref()
            .or(self.receipt_result.as_deref())
            .context("receipt carries no execution result field")?;
        match result {
            // `SUCESS` is code's spelling, `SUCCESS` is contractResult's.
            "SUCESS" | "SUCCESS" => Ok(TronExecutionResult::Succeeded),
            "FAILED"
            | "REVERT"
            | "BAD_JUMP_DESTINATION"
            | "OUT_OF_MEMORY"
            | "PRECOMPILED_CONTRACT"
            | "STACK_TOO_SMALL"
            | "STACK_TOO_LARGE"
            | "ILLEGAL_OPERATION"
            | "STACK_OVERFLOW"
            | "OUT_OF_ENERGY"
            | "OUT_OF_TIME"
            | "JVM_STACK_OVER_FLOW"
            | "UNKNOWN"
            | "TRANSFER_FAILED"
            | "INVALID_CODE" => Ok(TronExecutionResult::Failed),
            "DEFAULT" => bail!("unset execution result"),
            other => bail!("unclassifiable execution result {other:?}"),
        }
    }

    /// Determine the execution outcome for this receipt given the request's output schema.
    pub fn execution_outcome(&self, output_schema: &[u8]) -> anyhow::Result<ExecutionOutcome> {
        match self.execution_result()? {
            TronExecutionResult::Failed => Ok(ExecutionOutcome::Failed),
            // Schema-less requests attest an empty output until log
            // extraction is defined.
            TronExecutionResult::Succeeded if output_schema.is_empty() => {
                Ok(ExecutionOutcome::Success { output: Vec::new() })
            }
            // Tron receipts carry no extractable output; park rather than
            // attest an empty one.
            // TODO(tron): log-based output extraction for these requests.
            TronExecutionResult::Succeeded => Ok(ExecutionOutcome::ExtractionFailed),
        }
    }
}

/// Receipt logs, EVM-shaped
pub type TronLog = Log<LogData>;

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(result: Option<&str>, receipt_result: Option<&str>) -> TronReceipt {
        TronReceipt {
            id: B256::ZERO,
            block_number: 1,
            block_timestamp: 1,
            fee: 0,
            result: result.map(str::to_string),
            receipt_result: receipt_result.map(str::to_string),
            res_message: None,
            logs: vec![],
        }
    }

    /// Every member of both vendor enums (Tron.proto@4e8389f), in both
    /// carrier fields, gets a deliberate verdict.
    #[test]
    fn execution_result_classifies_every_vendor_member() {
        let cases = [
            ("SUCESS", TronExecutionResult::Succeeded),
            ("SUCCESS", TronExecutionResult::Succeeded),
            ("FAILED", TronExecutionResult::Failed),
            ("REVERT", TronExecutionResult::Failed),
            ("BAD_JUMP_DESTINATION", TronExecutionResult::Failed),
            ("OUT_OF_MEMORY", TronExecutionResult::Failed),
            ("PRECOMPILED_CONTRACT", TronExecutionResult::Failed),
            ("STACK_TOO_SMALL", TronExecutionResult::Failed),
            ("STACK_TOO_LARGE", TronExecutionResult::Failed),
            ("ILLEGAL_OPERATION", TronExecutionResult::Failed),
            ("STACK_OVERFLOW", TronExecutionResult::Failed),
            ("OUT_OF_ENERGY", TronExecutionResult::Failed),
            ("OUT_OF_TIME", TronExecutionResult::Failed),
            ("JVM_STACK_OVER_FLOW", TronExecutionResult::Failed),
            ("UNKNOWN", TronExecutionResult::Failed),
            ("TRANSFER_FAILED", TronExecutionResult::Failed),
            ("INVALID_CODE", TronExecutionResult::Failed),
        ];
        for (value, expected) in cases {
            for (carrier, receipt) in [
                ("result", receipt(Some(value), None)),
                ("receipt.result", receipt(None, Some(value))),
            ] {
                assert_eq!(
                    receipt.execution_result().unwrap(),
                    expected,
                    "{carrier}={value}"
                );
            }
        }
    }

    #[test]
    fn unset_or_unknown_result_is_an_error() {
        // contractResult's proto3 zero value attests nothing.
        assert!(receipt(None, Some("DEFAULT")).execution_result().is_err());
        let err = receipt(None, Some("WEIRD")).execution_result().unwrap_err();
        assert!(format!("{err:#}").contains("unclassifiable"), "{err:#}");
        let err = receipt(None, None).execution_result().unwrap_err();
        assert!(
            format!("{err:#}").contains("no execution result"),
            "{err:#}"
        );
    }

    /// The policy mapping every consumer of a receipt agrees on.
    #[test]
    fn execution_outcome_maps_schema_policy() {
        let failed = receipt(Some("REVERT"), None);
        assert!(matches!(
            failed.execution_outcome(&[]).unwrap(),
            ExecutionOutcome::Failed
        ));
        let succeeded = receipt(Some("SUCCESS"), None);
        assert!(matches!(
            succeeded.execution_outcome(&[]).unwrap(),
            ExecutionOutcome::Success { output } if output.is_empty()
        ));
        let schema = br#"[{"name":"output","type":"bool"}]"#;
        assert!(matches!(
            succeeded.execution_outcome(schema).unwrap(),
            ExecutionOutcome::ExtractionFailed
        ));
        assert!(receipt(None, None).execution_outcome(&[]).is_err());
    }

    /// java-tron emits both fields; the top-level `result` is canonical.
    #[test]
    fn top_level_result_outranks_receipt_result() {
        let both = receipt(Some("REVERT"), Some("SUCCESS"));
        assert_eq!(
            both.execution_result().unwrap(),
            TronExecutionResult::Failed
        );
    }
}
