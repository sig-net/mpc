//! Transaction assembly and signing — the protobuf-binary path: composes
//! generated `pb::*` types only, no hand-rolled binary structs.
//!
//! Derivations and constants are pinned by recorded mainnet fixtures
//! (`tests/fixtures`): txID = sha256(raw_data), ref-block fields, and the
//! 65-byte `[r ‖ s ‖ v]` signature with v ∈ {0,1}.

use crate::address::TronAddress;
use crate::pb::{
    transaction::contract::ContractType, transaction::Contract as TronContract, Message,
    RawTransaction, Transaction, TriggerSmartContract,
};
use crate::types::NowBlock;
use prost_types::Any;
use sha2::{Digest, Sha256};

pub const TRIGGER_SMART_CONTRACT_TYPE_URL: &str =
    "type.googleapis.com/protocol.TriggerSmartContract";

/// Transaction validity window; observed on recorded transfers.
pub const EXPIRATION_MS: i64 = 300_000;
/// Cap on energy fees (50 TRX in sun); observed on recorded transfers.
pub const FEE_LIMIT_SUN: i64 = 50_000_000;

/// A contract call to execute on Tron.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronIntent {
    pub owner: TronAddress,
    pub contract: TronAddress,
    pub call_data: Vec<u8>,
}

impl TronIntent {
    /// Assembles the unsigned `raw` transaction, referencing `reference` for
    /// replay protection and expiring `EXPIRATION_MS` after `now_ms`.
    pub fn raw_transaction(&self, reference: &NowBlock, now_ms: i64) -> RawTransaction {
        let trigger = TriggerSmartContract {
            owner_address: self.owner.as_bytes().to_vec(),
            contract_address: self.contract.as_bytes().to_vec(),
            call_value: 0,
            data: self.call_data.clone(),
            call_token_value: 0,
            token_id: 0,
        };
        let contract = TronContract {
            r#type: ContractType::TriggerSmartContract as i32,
            parameter: Some(Any {
                type_url: TRIGGER_SMART_CONTRACT_TYPE_URL.to_string(),
                value: trigger.encode_to_vec(),
            }),
            provider: Vec::new(),
            contract_name: Vec::new(),
            permission_id: 0,
        };
        let (ref_block_bytes, ref_block_hash) = reference.reference_fields();
        RawTransaction {
            ref_block_bytes,
            ref_block_num: 0,
            ref_block_hash,
            expiration: now_ms + EXPIRATION_MS,
            auths: Vec::new(),
            data: Vec::new(),
            scripts: Vec::new(),
            timestamp: now_ms,
            fee_limit: FEE_LIMIT_SUN,
            contract: vec![contract],
        }
    }
}

impl RawTransaction {
    /// txID as defined by java-tron: sha256 over the serialized `raw` message.
    pub fn txid(&self) -> [u8; 32] {
        Sha256::digest(self.encode_to_vec()).into()
    }
}

impl Transaction {
    /// Parses and validates a transaction we are willing to sign.
    pub fn parse_unsigned(bytes: &[u8]) -> anyhow::Result<Self> {
        let tx = Transaction::decode(bytes)?;
        anyhow::ensure!(tx.signature.is_empty(), "transaction already signed");
        anyhow::ensure!(tx.raw_data.is_some(), "transaction missing raw_data");
        let raw = tx.raw_data.as_ref().unwrap();
        anyhow::ensure!(raw.contract.len() == 1, "expected exactly one contract");
        anyhow::ensure!(!raw.ref_block_bytes.is_empty(), "missing ref_block_bytes");
        anyhow::ensure!(!raw.ref_block_hash.is_empty(), "missing ref_block_hash");
        anyhow::ensure!(raw.expiration > 0, "missing expiration");
        Ok(tx)
    }

    /// Appends the 65-byte `[r ‖ s ‖ v]` signature, returning the signed
    /// bytes and txID.
    pub fn sign_and_hash(
        self,
        r: &[u8; 32],
        s: &[u8; 32],
        v: u8,
    ) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
        anyhow::ensure!(v <= 1, "recovery id must be 0 or 1");
        let mut tx = self;
        let txid = tx.raw_data.as_ref().unwrap().txid();

        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(r);
        signature.extend_from_slice(s);
        signature.push(v);
        tx.signature = vec![signature];
        Ok((tx.encode_to_vec(), txid))
    }
}
