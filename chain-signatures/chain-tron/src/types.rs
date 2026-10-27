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

impl TronReceipt {
    /// java-tron `TransactionInfo.code` values (protocol/core/Tron.proto).
    /// Both success spellings — the observed "SUCCESS" and the proto's
    /// `SUCESS` — classify: `contractRet` outranks `receipt.result`, so a
    /// build emitting the proto name must not hang the watcher. Anything
    /// else is an error rather than an attested guess.
    pub fn execution_outcome(&self) -> anyhow::Result<ExecutionOutcome> {
        let result = self
            .contract_ret
            .as_deref()
            .or(self.receipt_result.as_deref())
            .context("receipt carries no execution result field")?;
        match result {
            "SUCCESS" | "SUCESS" => Ok(ExecutionOutcome::Success { output: Vec::new() }),
            "FAILED" | "REVERT" | "OUT_OF_ENERGY" | "OUT_OF_TIME" => Ok(ExecutionOutcome::Failed),
            other => bail!("unclassifiable execution result {other:?}"),
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
    fn execution_outcome_covers_the_proto_code_set() {
        for (value, expects_failed) in [
            // Both spellings of success: the observed "SUCCESS" and the
            // proto's own `SUCESS` member name.
            ("SUCCESS", false),
            ("SUCESS", false),
            ("FAILED", true),
            ("REVERT", true),
            ("OUT_OF_ENERGY", true),
            ("OUT_OF_TIME", true),
        ] {
            for (carrier, receipt) in [
                ("contractRet", receipt(Some(value), None)),
                ("receipt.result", receipt(None, Some(value))),
            ] {
                let outcome = receipt.execution_outcome();
                if expects_failed {
                    assert!(
                        matches!(outcome, Ok(ExecutionOutcome::Failed)),
                        "{carrier}={value} must classify Failed, got {outcome:?}"
                    );
                } else {
                    assert!(
                        matches!(&outcome, Ok(ExecutionOutcome::Success { output }) if output.is_empty()),
                        "{carrier}={value} must classify Success with empty output, got {outcome:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_or_missing_result_is_an_error() {
        let err = receipt(None, Some("WEIRD"))
            .execution_outcome()
            .unwrap_err();
        assert!(format!("{err:#}").contains("unclassifiable"), "{err:#}");
        let err = receipt(None, None).execution_outcome().unwrap_err();
        assert!(
            format!("{err:#}").contains("no execution result"),
            "{err:#}"
        );
    }

    /// java-tron emits both fields; `contractRet` wins, as the live gate's
    /// settle check reads them.
    #[test]
    fn contract_ret_outranks_receipt_result() {
        let both = receipt(Some("REVERT"), Some("SUCCESS"));
        assert!(matches!(
            both.execution_outcome(),
            Ok(ExecutionOutcome::Failed)
        ));
    }
}
