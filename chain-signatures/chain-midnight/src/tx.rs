//! EVM type-2 transaction assembly and the signing payload scalar.
//!
//! Counts decide what is real, never vector lengths: only `no_words`,
//! `access_list_entry_count` and each entry's `storage_key_count` reach the
//! transaction. The stored vectors are capacity and may be longer.

use alloy::consensus::{SignableTransaction as _, TxEip1559};
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use k256::Scalar;
use mpc_chain_integration_core::utils::hashing::hash_payload;
use mpc_primitives::ScalarExt as _;

use crate::records::{CompactMaybe, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord};

/// `TxParamType::evmType2`, the only decomposition the contract defines (the other
/// discriminant is reserved).
const TX_PARAM_TYPE_EVM_TYPE2: u8 = 0;

impl TryFrom<&EvmType2TxParams> for TxEip1559 {
    type Error = anyhow::Error;

    /// The pure params-to-transaction transform.
    fn try_from(params: &EvmType2TxParams) -> anyhow::Result<Self> {
        Ok(Self {
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
}

/// Assembles the unsigned EIP-1559 transaction a verified record describes.
pub fn to_unsigned_tx(record: &SignBidirectionalRecord) -> anyhow::Result<TxEip1559> {
    anyhow::ensure!(
        record.tx_param_type == TX_PARAM_TYPE_EVM_TYPE2,
        "unsupported tx_param_type {}: only evmType2 (0) assembles into a transaction",
        record.tx_param_type
    );
    TxEip1559::try_from(&record.tx_params)
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
    use crate::records::SignBidirectionalRecord;
    use crate::request_id::compute_request_id;
    use crate::test_fixtures::RecordFixture;
    use serde::Deserialize;

    const TX_VECTORS_JSON: &str = include_str!("../tests/tx_vectors.json");
    const RID_VECTORS_JSON: &str = include_str!("../tests/rid_vectors.json");

    #[derive(Deserialize)]
    struct TxVectorFile {
        vectors: Vec<TxVector>,
    }

    /// One oracle vector.
    #[derive(Deserialize)]
    struct TxVector {
        name: String,
        request_id_hex: String,
        assembled_calldata_hex: String,
        expected_unsigned_serialized_hex: String,
        expected_unsigned_hash_hex: String,
    }

    #[derive(Deserialize)]
    struct RidVectorFile {
        vectors: Vec<RidVector>,
    }

    #[derive(Deserialize)]
    struct RidVector {
        name: String,
        record: RecordFixture,
    }

    fn tx_vectors() -> Vec<TxVector> {
        serde_json::from_str::<TxVectorFile>(TX_VECTORS_JSON)
            .expect("tx_vectors.json parses")
            .vectors
    }

    /// The record a tx vector describes, joined by name.
    fn record_by_name(name: &str) -> SignBidirectionalRecord {
        serde_json::from_str::<RidVectorFile>(RID_VECTORS_JSON)
            .expect("rid_vectors.json parses")
            .vectors
            .into_iter()
            .find(|vector| vector.name == name)
            .unwrap_or_else(|| panic!("no rid vector named {name}"))
            .record
            .0
    }

    fn strip_0x(hex: &str) -> &str {
        hex.strip_prefix("0x").unwrap_or(hex)
    }

    #[test]
    fn to_unsigned_tx_matches_ethers_oracle() {
        let vectors = tx_vectors();
        assert_eq!(vectors.len(), 8, "the anchor names eight vectors");

        for vector in vectors {
            let name = vector.name.as_str();
            let record = record_by_name(name);

            // Join integrity: the record loaded by name IS the record the oracle
            // assembled, proven by the id rather than assumed.
            assert_eq!(
                hex::encode(compute_request_id(&record)),
                vector.request_id_hex,
                "{name}: joined record's request id"
            );

            let tx = to_unsigned_tx(&record).expect(name);
            assert_eq!(
                hex::encode(&tx.input),
                strip_0x(&vector.assembled_calldata_hex),
                "{name}: assembled calldata"
            );

            let serialized = serialized_transaction(&record).expect(name);
            assert_eq!(
                hex::encode(&serialized),
                strip_0x(&vector.expected_unsigned_serialized_hex),
                "{name}: unsigned serialized payload"
            );

            let unsigned_hash = hash_payload(&serialized);
            assert_eq!(
                hex::encode(unsigned_hash),
                strip_0x(&vector.expected_unsigned_hash_hex),
                "{name}: unsigned hash"
            );

            // The scalar the MPC signs is that hash and nothing else.
            let scalar = payload_scalar(&serialized).expect(name);
            assert_eq!(
                scalar,
                k256::Scalar::from_bytes(unsigned_hash).expect("oracle hash is in range"),
                "{name}: payload scalar"
            );
        }
    }

    #[test]
    fn to_unsigned_tx_requires_evm_type2_param_type() {
        let mut record = record_by_name("minimal-1word");
        record.tx_param_type = 1;
        let err = to_unsigned_tx(&record)
            .expect_err("the reserved tx_param_type must not assemble as evmType2")
            .to_string();
        assert!(err.contains("tx_param_type"), "err: {err}");
    }

    #[test]
    fn assemble_calldata_errors_on_overrun_access_list_clamps() {
        // The reference is asymmetric and the port preserves it: assembleCalldata
        // indexes words[i] and throws past capacity, while decodeAccessList slices at
        // both levels, which clamps.
        let mut record = record_by_name("access-list-partial");

        record.tx_params.calldata.value.no_words = 3; // capacity is 2
        let err = serialized_transaction(&record)
            .expect_err("a word count past capacity must error, matching the reference throw")
            .to_string();
        assert!(err.contains("no_words"), "err: {err}");
        record.tx_params.calldata.value.no_words = 2;

        record.tx_params.access_list_entry_count = 9; // capacity is 2
        let tx = to_unsigned_tx(&record).expect("an entry count past capacity clamps");
        assert_eq!(
            tx.access_list.0.len(),
            2,
            "slice semantics: every present entry, no invented ones"
        );

        record.tx_params.access_list_entry_count = 1;
        record.tx_params.access_list[0].storage_key_count = 9; // capacity is 3
        let tx = to_unsigned_tx(&record).expect("a key count past capacity clamps");
        assert_eq!(
            tx.access_list.0[0].storage_keys.len(),
            3,
            "slice semantics one level down: every present key, no invented ones"
        );
    }

    #[test]
    fn assemble_access_list_emits_no_keys_at_zero_count() {
        // No golden reaches this level: with an entry count of 0 no entry is emitted,
        // so the key-level slice never runs there.
        let mut record = record_by_name("access-list-partial");
        record.tx_params.access_list[0].storage_key_count = 0; // key capacity is 3
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
