//! Transaction validation and signing — the protobuf-binary path: uses
//! `pb::*` types only, no hand-rolled binary structs.
//!
//! The bytes the multichain API carries are the bare `raw` message;
//! nodes assemble them from structured request parameters (§6.1 of
//! `doc/bidirectional_calls.md`), so this crate ships no assembler.
//! Derivations are pinned by recorded mainnet fixtures (`tests/fixtures`):
//! txID = sha256(raw_data), ref-block fields, and the 65-byte
//! `[r ‖ s ‖ v]` signature with v ∈ {0,1}.

use crate::pb::{ContractType, Message, RawTransaction, Transaction};
use sha2::{Digest, Sha256};

impl RawTransaction {
    /// txID as defined by java-tron: sha256 over the serialized `raw` message.
    pub fn txid(&self) -> [u8; 32] {
        Sha256::digest(self.encode_to_vec()).into()
    }

    /// Parses and validates the bytes the multichain API carries for Tron
    /// targets: the bare `raw` message, unsigned by construction. The MPC's
    /// payload is `sha256` of exactly these bytes — the same hash as txID.
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let raw = RawTransaction::decode(bytes)?;
        anyhow::ensure!(raw.contract.len() == 1, "expected exactly one contract");
        anyhow::ensure!(
            raw.contract[0].r#type == ContractType::TriggerSmartContract as i32,
            "expected a TriggerSmartContract"
        );
        anyhow::ensure!(!raw.ref_block_bytes.is_empty(), "missing ref_block_bytes");
        anyhow::ensure!(!raw.ref_block_hash.is_empty(), "missing ref_block_hash");
        anyhow::ensure!(raw.expiration > 0, "missing expiration");
        Ok(raw)
    }

    /// Wraps in a `Transaction` with the 65-byte `[r ‖ s ‖ v]` signature,
    /// returning the signed bytes and txID.
    pub fn sign_and_hash(
        self,
        r: &[u8; 32],
        s: &[u8; 32],
        v: u8,
    ) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
        anyhow::ensure!(v <= 1, "recovery id must be 0 or 1");
        let txid = self.txid();

        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(r);
        signature.extend_from_slice(s);
        signature.push(v);
        let signed = Transaction {
            raw_data: Some(self),
            signature: vec![signature],
        };
        Ok((signed.encode_to_vec(), txid))
    }
}
