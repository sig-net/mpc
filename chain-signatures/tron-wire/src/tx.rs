//! Transaction validation, assembly, and signing — the protobuf-binary
//! path: uses `pb::*` types only, no hand-rolled binary structs.
//!
//! The bytes the multichain API carries are the bare `raw` message;
//! [`to_unsigned_tron_tx`] assembles them from a tron record's structured
//! request parameters (§7.4 of `doc/bidirectional-calls.md`).
//! Derivations are pinned by recorded mainnet fixtures (`tests/fixtures`):
//! txID = sha256(raw_data), ref-block fields, and the 65-byte
//! `[r ‖ s ‖ v]` signature with v ∈ {0,1}.

use crate::pb::{
    Contract, ContractType, Message, RawTransaction, Transaction, TriggerSmartContract,
    TRIGGER_SMART_CONTRACT_TYPE_URL,
};
use crate::TronAddress;
use anyhow::Context as _;
use mpc_primitives::{CompactMaybe, EvmCalldata, TronTxParams};
use prost_types::Any;
use sha2::{Digest, Sha256};

impl RawTransaction {
    /// txID as defined by java-tron: sha256 over the serialized `raw` message.
    pub fn txid(&self) -> [u8; 32] {
        Sha256::digest(self.encode_to_vec()).into()
    }

    /// The trigger's `owner_address`, for admission checks that bind the
    /// owner to the request's derived key.
    pub fn owner_address(&self) -> anyhow::Result<Vec<u8>> {
        let any = self
            .contract
            .first()
            .and_then(|contract| contract.parameter.as_ref())
            .context("missing TriggerSmartContract parameter")?;
        let trigger = TriggerSmartContract::decode(any.value.as_slice())?;
        Ok(trigger.owner_address)
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

/// Assembles the canonical `raw` bytes a tron record names (§7.4): contract
/// type fixed to `TriggerSmartContract`, `owner_address` from the derived
/// key, every other field from `params`. Re-validated through
/// [`RawTransaction::parse`], so the txID names exactly what is returned.
/// Byte-exact assembly is pinned by the golden fixtures; the
/// unrepresentable-param branches are unit-tested below.
pub fn to_unsigned_tron_tx(params: &TronTxParams, owner: TronAddress) -> anyhow::Result<Vec<u8>> {
    let trigger = TriggerSmartContract {
        owner_address: owner.as_bytes().to_vec(),
        contract_address: params.contract_address.to_vec(),
        call_value: i64_field(params.call_value, "call_value")?,
        data: calldata_bytes(&params.calldata)?,
        call_token_value: 0,
        token_id: 0,
    };
    let raw = RawTransaction {
        ref_block_bytes: params.ref_block_bytes.to_vec(),
        ref_block_num: 0,
        ref_block_hash: params.ref_block_hash.to_vec(),
        expiration: i64_field(params.expiration, "expiration")?,
        timestamp: i64_field(params.timestamp, "timestamp")?,
        fee_limit: i64_field(params.fee_limit, "fee_limit")?,
        contract: vec![Contract {
            r#type: ContractType::TriggerSmartContract as i32,
            parameter: Some(Any {
                type_url: TRIGGER_SMART_CONTRACT_TYPE_URL.to_string(),
                value: trigger.encode_to_vec(),
            }),
            permission_id: 0,
        }],
    };
    let bytes = raw.encode_to_vec();
    RawTransaction::parse(&bytes).context("assembled raw is not signable")?;
    Ok(bytes)
}

/// `data = selector ‖ words[..no_words]` when present, empty otherwise.
fn calldata_bytes(calldata: &CompactMaybe<EvmCalldata>) -> anyhow::Result<Vec<u8>> {
    if !calldata.is_some {
        return Ok(Vec::new());
    }
    let value = &calldata.value;
    let no_words = usize::from(value.no_words);
    anyhow::ensure!(
        no_words <= value.words.len(),
        "calldata no_words {no_words} overruns the record's {} stored word slots",
        value.words.len()
    );
    let mut data = Vec::with_capacity(4 + 32 * no_words);
    data.extend_from_slice(&value.selector);
    for word in &value.words[..no_words] {
        data.extend_from_slice(word);
    }
    Ok(data)
}

fn i64_field(value: u64, field: &str) -> anyhow::Result<i64> {
    i64::try_from(value)
        .map_err(|_| anyhow::anyhow!("{field} {value} exceeds the int64 wire field"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

    fn params() -> TronTxParams {
        TronTxParams {
            ref_block_bytes: [0x27, 0x10],
            ref_block_hash: [0x42; 8],
            timestamp: 1_728_000_000_000,
            expiration: 1_728_000_060_000,
            fee_limit: 50_000_000,
            contract_address: {
                let mut address = [0xcd; 21];
                address[0] = 0x41;
                address
            },
            call_value: 0,
            calldata: CompactMaybe {
                is_some: false,
                value: EvmCalldata {
                    selector: [0; 4],
                    no_words: 0,
                    words: Vec::new(),
                },
            },
        }
    }

    fn owner() -> TronAddress {
        TronAddress::from_evm(Address::from_slice(&[0xab; 20]))
    }

    fn trigger_of(bytes: &[u8]) -> TriggerSmartContract {
        let raw = RawTransaction::parse(bytes).unwrap();
        let any = raw.contract[0].parameter.as_ref().unwrap();
        TriggerSmartContract::decode(any.value.as_slice()).unwrap()
    }

    #[test]
    fn absent_calldata_assembles_a_plain_transfer() {
        let mut params = params();
        params.call_value = 1_000_000;
        let trigger = trigger_of(&to_unsigned_tron_tx(&params, owner()).unwrap());
        assert!(trigger.data.is_empty());
        assert_eq!(trigger.call_value, 1_000_000);
        assert_eq!(
            trigger.owner_address.as_slice(),
            owner().as_bytes().as_slice()
        );
    }

    #[test]
    fn assembly_rejects_unrepresentable_params() {
        let mut with_words = params();
        with_words.calldata.is_some = true;
        with_words.calldata.value.words = vec![[0x11; 32]; 2];

        let mut over_words = with_words.clone();
        over_words.calldata.value.no_words = 3;
        let err = format!(
            "{:#}",
            to_unsigned_tron_tx(&over_words, owner()).unwrap_err()
        );
        assert!(err.contains("calldata no_words"), "{err}");

        let mut overflow = with_words.clone();
        overflow.expiration = u64::MAX;
        let err = format!("{:#}", to_unsigned_tron_tx(&overflow, owner()).unwrap_err());
        assert!(err.contains("exceeds the int64 wire field"), "{err}");

        let mut zero_expiration = with_words;
        zero_expiration.expiration = 0;
        let err = format!(
            "{:#}",
            to_unsigned_tron_tx(&zero_expiration, owner()).unwrap_err()
        );
        assert!(err.contains("missing expiration"), "{err}");
    }
}
