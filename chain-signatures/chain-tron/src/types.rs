//! Response domain types returned by [`crate::client::TronHttp`].
//!
//! These are the HTTP-JSON representation of messages whose protobuf-binary
//! form lives in [`crate::pb`]; field names must match the vendored proto
//! (see `proto/README.md`).

use alloy::primitives::{Log, LogData, B256};
use serde::Deserialize;

/// Head block, as needed for ref-block fields at assembly time.
#[derive(Debug, Clone, Copy)]
pub struct NowBlock {
    pub block_id: B256,
    pub number: u64,
    pub timestamp: u64,
}

impl NowBlock {
    /// Reference fields per java-tron: `ref_block_bytes` is the height's low
    /// two bytes (big-endian), `ref_block_hash` is the block ID's bytes 8..16.
    /// Pinned against recorded mainnet fixtures.
    pub fn reference_fields(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.number.to_be_bytes()[6..8].to_vec(),
            self.block_id.as_slice()[8..16].to_vec(),
        )
    }
}

/// Outcome of `broadcasttransaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// Accepted into the mempool
    Accepted,
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
    pub energy_usage: u64,
    pub net_usage: u64,
    pub logs: Vec<TronLog>,
}

/// Receipt logs, EVM-shaped
pub type TronLog = Log<LogData>;

/// Resource usage and limits for an account. Names follow java-tron's `AccountResourceMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct AccountResources {
    #[serde(default, rename = "freeNetUsed")]
    pub free_net_used: u64,
    #[serde(default, rename = "freeNetLimit")]
    pub free_net_limit: u64,
    #[serde(default, rename = "NetUsed")]
    pub net_used: u64,
    #[serde(default, rename = "NetLimit")]
    pub net_limit: u64,
    #[serde(default, rename = "EnergyUsed")]
    pub energy_used: u64,
    #[serde(default, rename = "EnergyLimit")]
    pub energy_limit: u64,
}
