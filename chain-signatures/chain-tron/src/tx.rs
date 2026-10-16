//! Transaction validation and signing — the protobuf-binary path: uses
//! `pb::*` types only, no hand-rolled binary structs.
//!
//! The bytes the multichain API carries are the bare `raw` message;
//! nodes assemble them from structured request parameters (§6.1 of
//! `doc/bidirectional_calls.md`), so this crate ships no assembler.
//! Derivations are pinned by recorded mainnet fixtures (`tests/fixtures`):
//! txID = sha256(raw_data), ref-block fields, and the 65-byte
//! `[r ‖ s ‖ v]` signature with v ∈ {0,1}.

use crate::pb::{
    Contract, ContractType, Message, RawTransaction, Transaction, TriggerSmartContract,
    TRIGGER_SMART_CONTRACT_TYPE_URL,
};
use anyhow::Context as _;
use sha2::{Digest, Sha256};

impl RawTransaction {
    /// txID as defined by java-tron: sha256 over the serialized `raw` message.
    pub fn txid(&self) -> [u8; 32] {
        Sha256::digest(self.encode_to_vec()).into()
    }

    /// Parses and validates the bytes the multichain API carries for Tron
    /// targets: the bare `raw` message, unsigned by construction. Admission
    /// accepts only what the MPC can faithfully name and sign — canonical
    /// bytes, one valid trigger contract, reference fields, expiration.
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let raw = RawTransaction::decode(bytes)?;
        // Unknown, duplicated, or non-minimal fields re-encode away, which
        // would desync the payload preimage (these bytes) from the txID
        // preimage (the re-encoded transaction).
        anyhow::ensure!(
            raw.encode_to_vec() == bytes,
            "not the canonical encoding: unknown, duplicated, or non-minimal fields"
        );
        anyhow::ensure!(raw.contract.len() == 1, "expected exactly one contract");
        raw.contract[0].validate_as_trigger()?;
        raw.validate_reference_fields()?;
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

    /// Validates that the reference fields (`ref_block_bytes`, `ref_block_hash`, and `expiration`) are present and correctly set.
    fn validate_reference_fields(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.ref_block_bytes.is_empty(), "missing ref_block_bytes");
        anyhow::ensure!(!self.ref_block_hash.is_empty(), "missing ref_block_hash");
        anyhow::ensure!(self.expiration > 0, "missing expiration");
        Ok(())
    }
}

impl Contract {
    /// Validates that the contract is a TriggerSmartContract with correctly formatted addresses.
    fn validate_as_trigger(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.r#type == ContractType::TriggerSmartContract as i32,
            "expected a TriggerSmartContract"
        );

        let parameter = self
            .parameter
            .as_ref()
            .and_then(|any| (any.type_url == TRIGGER_SMART_CONTRACT_TYPE_URL).then_some(&any.value))
            .context("expected a TriggerSmartContract parameter")?;

        let trigger = TriggerSmartContract::decode(parameter.as_slice())?;

        for (name, address) in [
            ("owner_address", &trigger.owner_address),
            ("contract_address", &trigger.contract_address),
        ] {
            anyhow::ensure!(
                address.len() == 21 && address.first() == Some(&0x41),
                "{name} must be 21 bytes with the 0x41 prefix"
            );
        }
        Ok(())
    }
}
