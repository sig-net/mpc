//! Shared test assembly: raw transactions from structured parameters.

use mpc_primitives::{BidirectionalTx, BidirectionalTxId, Chain};
use mpc_tron_wire::pb::{Contract, ContractType, Message, RawTransaction, TriggerSmartContract};
use mpc_tron_wire::{NowBlock, TronAddress};
use prost_types::Any;
use std::sync::Arc;

/// Validity window and energy-fee cap; observed on recorded transfers.
pub const EXPIRATION_MS: i64 = 300_000;
pub const FEE_LIMIT_SUN: i64 = 50_000_000;
const TRIGGER_SMART_CONTRACT_TYPE_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";

/// Minimal watcher-leg backlog entry: identity and bytes, `request_id`
/// mirroring the flat id, Nile-targeted.
pub fn bidirectional_tx(
    id: [u8; 32],
    serialized_transaction: Vec<u8>,
    source_chain: Chain,
) -> Arc<BidirectionalTx> {
    Arc::new(BidirectionalTx {
        id: BidirectionalTxId(id),
        sender: [0u8; 32],
        serialized_transaction,
        source_chain,
        target_chain: Chain::Tron,
        caip2_id: "tron:nile".to_string(),
        key_version: 0,
        deposit: 0,
        path: String::new(),
        algo: "secp256k1".to_string(),
        dest: "tron:nile".to_string(),
        params: String::new(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: vec![],
        request_id: id,
        from_address: [0u8; 20],
        nonce: 0,
    })
}

/// Test-local assembly of raw transactions from structured parameters,
/// with the standard 5-minute validity window.
pub fn build_raw(
    owner: &TronAddress,
    contract: &TronAddress,
    call_data: &[u8],
    reference: &NowBlock,
    now_ms: i64,
) -> RawTransaction {
    build_raw_expiring(
        owner,
        contract,
        call_data,
        reference,
        now_ms,
        now_ms + EXPIRATION_MS,
    )
}

/// As [`build_raw`] with an explicit expiration — the live expiry gate
/// needs a window shorter than any realistic confirmation.
pub fn build_raw_expiring(
    owner: &TronAddress,
    contract: &TronAddress,
    call_data: &[u8],
    reference: &NowBlock,
    now_ms: i64,
    expiration: i64,
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
        expiration,
        timestamp: now_ms,
        fee_limit: FEE_LIMIT_SUN,
        contract: vec![contract],
    }
}
