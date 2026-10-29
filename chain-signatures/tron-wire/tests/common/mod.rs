//! Shared test assembly: raw transactions from structured parameters.

use mpc_tron_wire::pb::{Contract, ContractType, Message, RawTransaction, TriggerSmartContract};
use mpc_tron_wire::{NowBlock, TronAddress};
use prost_types::Any;

/// Validity window and energy-fee cap; observed on recorded transfers.
pub const EXPIRATION_MS: i64 = 300_000;
pub const FEE_LIMIT_SUN: i64 = 50_000_000;
const TRIGGER_SMART_CONTRACT_TYPE_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";

/// Test-local assembly of raw transactions from structured parameters.
pub fn build_raw(
    owner: &TronAddress,
    contract: &TronAddress,
    call_data: &[u8],
    reference: &NowBlock,
    now_ms: i64,
) -> RawTransaction {
    let trigger = TriggerSmartContract {
        owner_address: owner.as_bytes().to_vec(),
        contract_address: contract.as_bytes().to_vec(),
        call_value: 0,
        data: call_data.to_vec(),
        call_token_value: 0,
        token_id: 0,
    };
    let contract = Contract {
        r#type: ContractType::TriggerSmartContract as i32,
        parameter: Some(Any {
            type_url: TRIGGER_SMART_CONTRACT_TYPE_URL.to_string(),
            value: trigger.encode_to_vec(),
        }),
        permission_id: 0,
    };
    let (ref_block_bytes, ref_block_hash) = reference.reference_fields();
    RawTransaction {
        ref_block_bytes,
        ref_block_num: 0,
        ref_block_hash,
        expiration: now_ms + EXPIRATION_MS,
        timestamp: now_ms,
        fee_limit: FEE_LIMIT_SUN,
        contract: vec![contract],
    }
}
