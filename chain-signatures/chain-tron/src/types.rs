//! Response domain types returned by [`crate::client::TronHttp`].
//!
//! These are the HTTP-JSON representation of messages whose protobuf-binary
//! form lives in [`mpc_tron_wire::pb`]; field names must match the vendored proto
//! (see `proto/README.md`).

use alloy::primitives::{Log, LogData, B256};

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

/// Receipt logs, EVM-shaped
pub type TronLog = Log<LogData>;
