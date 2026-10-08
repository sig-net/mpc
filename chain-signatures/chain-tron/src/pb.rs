//! Wire types for the protobuf-binary path (tx assembly and signing) — the
//! four `core.proto` messages we produce or consume, hand-declared with
//! `prost::Message`.
//!
//! Field tags are immutable by protobuf contract and copied from
//! [`tronprotocol/protocol`](https://github.com/tronprotocol/protocol)
//! (`core/Tron.proto`, `core/contract/smart_contract.proto`); unused fields
//! are omitted (proto3 defaults are wire-invisible, so built bytes are
//! unaffected). The golden fixtures in `tests/golden.rs` enforce byte-exact
//! behavior against recorded mainnet transactions — a wrong tag fails
//! decode/re-encode or the txID reproduction.
//!
//! The HTTP-JSON path keeps its own wire/domain types (`client.rs`,
//! `types.rs`): Tron's JSON is not proto3-JSON (hex bytes, the `SUCESS` enum
//! typo, provider-omitted fields), so these types cannot parse it.

use prost_types::Any;

pub use prost::Message;

/// `Transaction.Contract.ContractType` subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ContractType {
    TriggerSmartContract = 31,
}

/// `Transaction.Contract` — `provider` and `ContractName` are unused.
#[derive(Clone, PartialEq, Message)]
pub struct Contract {
    #[prost(int32, tag = "1")]
    pub r#type: i32,
    #[prost(message, optional, tag = "2")]
    pub parameter: Option<Any>,
    /// Multi-sig permission selector; 0 (default) is wire-invisible.
    #[prost(int32, tag = "5")]
    pub permission_id: i32,
}

/// `Transaction.raw` — `auths`, `data` and `scripts` are unused.
#[derive(Clone, PartialEq, Message)]
pub struct RawTransaction {
    #[prost(bytes = "vec", tag = "1")]
    pub ref_block_bytes: Vec<u8>,
    #[prost(int64, tag = "3")]
    pub ref_block_num: i64,
    #[prost(bytes = "vec", tag = "4")]
    pub ref_block_hash: Vec<u8>,
    #[prost(int64, tag = "8")]
    pub expiration: i64,
    #[prost(message, repeated, tag = "11")]
    pub contract: Vec<Contract>,
    #[prost(int64, tag = "14")]
    pub timestamp: i64,
    #[prost(int64, tag = "18")]
    pub fee_limit: i64,
}

/// `Transaction` — `ret` is unused (execution results, not our path).
#[derive(Clone, PartialEq, Message)]
pub struct Transaction {
    #[prost(message, optional, tag = "1")]
    pub raw_data: Option<RawTransaction>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub signature: Vec<Vec<u8>>,
}

/// `TriggerSmartContract` from `core/contract/smart_contract.proto`.
#[derive(Clone, PartialEq, Message)]
pub struct TriggerSmartContract {
    /// 21-byte `0x41 ‖ eth20` form.
    #[prost(bytes = "vec", tag = "1")]
    pub owner_address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub contract_address: Vec<u8>,
    #[prost(int64, tag = "3")]
    pub call_value: i64,
    #[prost(bytes = "vec", tag = "4")]
    pub data: Vec<u8>,
    #[prost(int64, tag = "5")]
    pub call_token_value: i64,
    #[prost(int64, tag = "6")]
    pub token_id: i64,
}
