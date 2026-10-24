//! EVM type-2 transaction assembly and the signing payload scalar.

use alloy::consensus::{SignableTransaction as _, TxEip1559};
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use k256::Scalar;
use mpc_chain_integration_core::utils::hashing::hash_payload;
use mpc_primitives::ScalarExt as _;

use crate::records::SignBidirectionalRecord;
use mpc_primitives::{CompactMaybe, EvmCalldata, EvmType2TxParams, TxParams};

fn to_eip1559(params: &EvmType2TxParams) -> anyhow::Result<TxEip1559> {
    Ok(TxEip1559 {
        chain_id: params.chain_id,
        nonce: params.nonce,
        gas_limit: params.gas_limit,
        max_fee_per_gas: params.max_fee_per_gas,
        max_priority_fee_per_gas: params.max_priority_fee_per_gas,
        to: TxKind::Call(Address::from(params.to)),
        value: U256::from(params.value),
        access_list: assemble_access_list(params),
        input: assemble_calldata(&params.calldata)?,
    })
}

/// Assembles the unsigned EIP-1559 transaction a verified record describes.
pub fn to_unsigned_tx(record: &SignBidirectionalRecord) -> anyhow::Result<TxEip1559> {
    match &record.tx_params {
        TxParams::EvmType2(params) => to_eip1559(params),
        // The protobuf raw assembly and sha256 payload dispatch for Tron land with
        // the rest of PR C; until then a Tron record cannot become a signing payload.
        TxParams::Tron(_) => anyhow::bail!(
            "tx_params is tron, which assembles a TriggerSmartContract raw, not an EVM transaction"
        ),
    }
}

/// The RLP-encoded unsigned signing payload (`0x02 ‖ rlp(fields)`): what
/// `SignBidirectionalEvent.serialized_transaction` carries, and the bytes the payload
/// scalar is hashed from.
pub fn serialized_transaction(record: &SignBidirectionalRecord) -> anyhow::Result<Vec<u8>> {
    Ok(to_unsigned_tx(record)?.encoded_for_signing())
}

/// The scalar the MPC signs: `keccak256(serialized)` as a field element, bailing when
/// the hash falls outside the curve order, as Canton does.
pub fn payload_scalar(serialized: &[u8]) -> anyhow::Result<Scalar> {
    let unsigned_tx_hash = hash_payload(serialized);
    let Some(payload) = Scalar::from_bytes(unsigned_tx_hash) else {
        anyhow::bail!("failed to convert unsigned_tx_hash to scalar: {unsigned_tx_hash:?}");
    };
    Ok(payload)
}

/// `data = selector || words[..no_words]` when present, empty otherwise.
fn assemble_calldata(calldata: &CompactMaybe<EvmCalldata>) -> anyhow::Result<Bytes> {
    if !calldata.is_some {
        return Ok(Bytes::new());
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
    Ok(Bytes::from(data))
}

/// The count-trimmed access list, per `decodeAccessList`.
fn assemble_access_list(params: &EvmType2TxParams) -> AccessList {
    AccessList(
        params
            .access_list
            .iter()
            .take(usize::from(params.access_list_entry_count))
            .map(|entry| AccessListItem {
                address: Address::from(entry.address),
                storage_keys: entry
                    .storage_keys
                    .iter()
                    .take(usize::from(entry.storage_key_count))
                    .map(|key| B256::from(*key))
                    .collect(),
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::sample_record_with_partial_access_list;

    #[test]
    fn to_unsigned_tx_rejects_tron_params() {
        let record = crate::test_utils::sample_tron_record();
        let err = to_unsigned_tx(&record)
            .expect_err("tron params must not assemble as an EVM transaction")
            .to_string();
        assert!(err.contains("tron"), "err: {err}");
    }

    #[test]
    fn assemble_calldata_errors_on_overrun_access_list_clamps() {
        // The reference is asymmetric and the port preserves it: assembleCalldata
        // indexes words[i] and throws past capacity, while decodeAccessList slices at
        // both levels, which clamps.
        let mut record = sample_record_with_partial_access_list();

        record.evm_mut().calldata.value.no_words = 3; // capacity is 2
        let err = serialized_transaction(&record)
            .expect_err("a word count past capacity must error, matching the reference throw")
            .to_string();
        assert!(err.contains("no_words"), "err: {err}");
        record.evm_mut().calldata.value.no_words = 2;

        record.evm_mut().access_list_entry_count = 9; // capacity is 2
        let tx = to_unsigned_tx(&record).expect("an entry count past capacity clamps");
        assert_eq!(
            tx.access_list.0.len(),
            2,
            "slice semantics: every present entry, no invented ones"
        );

        record.evm_mut().access_list_entry_count = 1;
        record.evm_mut().access_list[0].storage_key_count = 9; // capacity is 3
        let tx = to_unsigned_tx(&record).expect("a key count past capacity clamps");
        assert_eq!(
            tx.access_list.0[0].storage_keys.len(),
            3,
            "slice semantics one level down: every present key, no invented ones"
        );
    }

    #[test]
    fn assemble_access_list_emits_no_keys_at_zero_count() {
        // With an entry count of 0 no entry is emitted, so the key-level slice never
        // runs there.
        let mut record = sample_record_with_partial_access_list();
        record.evm_mut().access_list[0].storage_key_count = 0; // key capacity is 3
        let tx = to_unsigned_tx(&record).expect("assembles");
        assert_eq!(
            tx.access_list.0.len(),
            1,
            "the entry itself is still emitted (entry count is 1)"
        );
        assert!(
            tx.access_list.0[0].storage_keys.is_empty(),
            "zero key count means zero keys, never all keys at capacity"
        );
    }
}
