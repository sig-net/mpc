//! Response domain types returned by [`crate::client::TronHttp`].
//!
//! These are the HTTP-JSON representation of messages whose protobuf-binary
//! form lives in [`mpc_tron_wire::pb`]; field names must match the vendored proto
//! (see `proto/README.md`).

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
    /// Execution result; java-tron only — absent on TronGrid.
    pub contract_ret: Option<String>,
    /// Execution result from the nested `receipt` object; TronGrid's form.
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
    /// java-tron `TransactionInfo.code` values (protocol/core/Tron.proto),
    /// carried in `contractRet` (java-tron) or `receipt.result` (TronGrid).
    /// Both success spellings — observed "SUCCESS", proto `SUCESS` —
    /// classify; anything else is an error, not an attested guess.
    pub fn execution_result(&self) -> anyhow::Result<TronExecutionResult> {
        let result = self
            .contract_ret
            .as_deref()
            .or(self.receipt_result.as_deref())
            .context("receipt carries no execution result field")?;
        match result {
            "SUCCESS" | "SUCESS" => Ok(TronExecutionResult::Succeeded),
            "FAILED" | "REVERT" | "OUT_OF_ENERGY" | "OUT_OF_TIME" => {
                Ok(TronExecutionResult::Failed)
            }
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

    fn receipt(contract_ret: Option<&str>, receipt_result: Option<&str>) -> TronReceipt {
        TronReceipt {
            id: B256::ZERO,
            block_number: 1,
            block_timestamp: 1,
            fee: 0,
            contract_ret: contract_ret.map(str::to_string),
            receipt_result: receipt_result.map(str::to_string),
            res_message: None,
            logs: vec![],
        }
    }

    /// Every member of java-tron's `TransactionInfo.code` set, in both
    /// carrier fields, gets a deliberate verdict.
    #[test]
    fn execution_result_covers_the_proto_code_set() {
        for (value, expected) in [
            // Both spellings of success: the observed "SUCCESS" and the
            // proto's own `SUCESS` member name.
            ("SUCCESS", TronExecutionResult::Succeeded),
            ("SUCESS", TronExecutionResult::Succeeded),
            ("FAILED", TronExecutionResult::Failed),
            ("REVERT", TronExecutionResult::Failed),
            ("OUT_OF_ENERGY", TronExecutionResult::Failed),
            ("OUT_OF_TIME", TronExecutionResult::Failed),
        ] {
            for (carrier, receipt) in [
                ("contractRet", receipt(Some(value), None)),
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
    fn unknown_or_missing_result_is_an_error() {
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

    /// java-tron emits both fields; `contractRet` wins, as the live gate's
    /// settle check reads them.
    #[test]
    fn contract_ret_outranks_receipt_result() {
        let both = receipt(Some("REVERT"), Some("SUCCESS"));
        assert_eq!(
            both.execution_result().unwrap(),
            TronExecutionResult::Failed
        );
    }
}
