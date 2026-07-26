//! EVM type-2 transaction assembly and the signing payload scalar.
//!
//! The node signs a transaction, not the record. This is the canonical
//! request-to-transaction transform, a port of
//! `signBidirectionalEventToUnsignedEvmTransaction` plus `assembleCalldata`
//! in `@sig-net/midnight`, and the step Canton performs in
//! `chain-canton/src/signing.rs`.
//!
//! The rule that matters here: counts decide what is real, never vector
//! lengths. A record with unused capacity is capacity-ambiguous on the wire, so
//! `words.len()` and friends are recovered capacity two honest readers can
//! disagree about. Only `no_words`, `access_list_entry_count` and each entry's
//! `storage_key_count` are authoritative, and only they reach the transaction.

use alloy::consensus::{SignableTransaction as _, TxEip1559};
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use k256::Scalar;
use mpc_chain_integration_core::utils::hashing::hash_payload;
use mpc_primitives::ScalarExt as _;

use crate::records::{CompactMaybe, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord};

/// `TxParamType::evmType2`, the only decomposition the contract defines
/// (the other discriminant is reserved).
const TX_PARAM_TYPE_EVM_TYPE2: u8 = 0;

impl TryFrom<&EvmType2TxParams> for TxEip1559 {
    type Error = anyhow::Error;

    /// The pure params-to-transaction transform. Envelope fields pass straight
    /// through; `to` is a fixed `Bytes<20>` in the contract, so there is no
    /// create form and the kind is always `Call`.
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
///
/// Adds two record-level gates the TS transform gets for free from its typed
/// decode: `tx_param_type` must be the evmType2 discriminant, and `caip2_id`
/// must agree with `tx_params.chain_id` when it names an eip155 chain. A record
/// that routes to one chain and signs for another is refused, not signed.
pub fn to_unsigned_tx(record: &SignBidirectionalRecord) -> anyhow::Result<TxEip1559> {
    anyhow::ensure!(
        record.tx_param_type == TX_PARAM_TYPE_EVM_TYPE2,
        "unsupported tx_param_type {}: only evmType2 (0) assembles into a transaction",
        record.tx_param_type
    );
    ensure_caip2_agrees(&record.caip2_id, record.tx_params.chain_id)?;
    TxEip1559::try_from(&record.tx_params)
}

/// The RLP-encoded unsigned signing payload (`0x02 ‖ rlp(fields)`): what
/// `SignBidirectionalEvent.serialized_transaction` carries, and the bytes
/// the payload scalar is hashed from.
pub fn serialized_transaction(record: &SignBidirectionalRecord) -> anyhow::Result<Vec<u8>> {
    Ok(to_unsigned_tx(record)?.encoded_for_signing())
}

/// The scalar the MPC signs: `keccak256(serialized)` as a field element,
/// bailing when the hash falls outside the curve order, as Canton does.
pub fn payload_scalar(serialized: &[u8]) -> anyhow::Result<Scalar> {
    let unsigned_tx_hash = hash_payload(serialized);
    let Some(payload) = Scalar::from_bytes(unsigned_tx_hash) else {
        anyhow::bail!("failed to convert unsigned_tx_hash to scalar: {unsigned_tx_hash:?}");
    };
    Ok(payload)
}

/// `data = selector || words[..no_words]` when present, empty otherwise.
///
/// Ports `assembleCalldata` including its failure mode: the reference throws
/// when the count overruns the stored slots, so `no_words > words.len()` is an
/// error here, never a clamp and never zero-fill. The vector length appears
/// only as that overrun bound, never as a word count.
///
/// An empty `Maybe` yields no bytes at all; a present calldata with
/// `no_words = 0` yields the four selector bytes. Different transactions.
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

/// The count-trimmed access list, per `decodeAccessList`. The reference slices
/// at both levels, which clamps when a count exceeds the stored slots, and
/// `take` preserves that. Deliberately asymmetric with the calldata path's
/// overrun error, because the reference is.
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

/// Rejects a record whose `caip2_id` names an eip155 chain other than
/// `tx_params.chain_id`.
///
/// The label is NUL-trimmed ASCII, the contract's `pad(32, ...)` convention. A
/// label in another namespace, or one that is not UTF-8, expresses no eip155
/// opinion and passes; routing it belongs to a later layer. One that claims the
/// namespace but does not parse as `eip155:<decimal u64>` can only be corrupt,
/// so it is rejected rather than ignored.
fn ensure_caip2_agrees(caip2_id: &[u8; 32], chain_id: u64) -> anyhow::Result<()> {
    let trimmed_len = 32 - caip2_id.iter().rev().take_while(|byte| **byte == 0).count();
    let Ok(label) = std::str::from_utf8(&caip2_id[..trimmed_len]) else {
        return Ok(());
    };
    let Some(id_text) = label.strip_prefix("eip155:") else {
        return Ok(());
    };
    let parsed: u64 = id_text.parse().map_err(|_| {
        anyhow::anyhow!("malformed eip155 caip2 label {label:?}: the id is not a decimal u64")
    })?;
    anyhow::ensure!(
        parsed == chain_id,
        "caip2 label {label:?} routes to eip155 chain {parsed} but tx_params.chain_id is \
         {chain_id}: refusing to assemble a transaction for a chain the record does not route to"
    );
    Ok(())
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

    /// One oracle vector. The `tx_fields_ethers_sees` debugging view and the
    /// file-level provenance keys are not modelled; the bytes are the
    /// assertions.
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

    /// The record a tx vector describes, joined by name. `tx_vectors.json`
    /// claims its records are byte-identical to the same-named
    /// `rid_vectors.json` entries; the golden test proves that per vector by
    /// asserting the request id before comparing any transaction bytes.
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

    fn caip2(label: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..label.len()].copy_from_slice(label);
        out
    }

    #[test]
    fn to_unsigned_tx_matches_ethers_oracle() {
        let vectors = tx_vectors();
        assert_eq!(vectors.len(), 8, "the anchor names eight vectors");

        for vector in vectors {
            let name = vector.name.as_str();
            let record = record_by_name(name);

            // Join integrity: the record loaded by name IS the record the
            // oracle assembled, proven by the id rather than assumed.
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
    fn to_unsigned_tx_requires_caip2_to_agree_with_chain_id() {
        // The routing label and the transaction's chain id must agree; a
        // record that routes to one chain and signs for another is refused.
        let mut record = record_by_name("minimal-1word");

        record.caip2_id = caip2(b"eip155:1");
        let err = to_unsigned_tx(&record)
            .expect_err("an eip155 label naming another chain must be rejected")
            .to_string();
        assert!(err.contains('1') && err.contains("31337"), "err: {err}");

        // A label in another namespace expresses no eip155 opinion.
        record.caip2_id = caip2(b"midnight:testnet");
        to_unsigned_tx(&record).expect("a non-eip155 label passes the agreement gate");

        // Non-UTF-8 bytes cannot be an eip155 label either.
        record.caip2_id = [0xff; 32];
        to_unsigned_tx(&record).expect("non-utf8 label bytes pass the agreement gate");

        // But a label that CLAIMS the eip155 namespace and fails to parse is
        // a corrupt routing label, rejected rather than ignored.
        record.caip2_id = caip2(b"eip155:banana");
        let err = to_unsigned_tx(&record)
            .expect_err("a malformed eip155 label must be rejected")
            .to_string();
        assert!(err.contains("malformed"), "err: {err}");
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
        // The reference is asymmetric and the port preserves it:
        // assembleCalldata indexes words[i] and throws past capacity, while
        // decodeAccessList slices at both levels, which clamps.
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
        // No golden reaches this level: with an entry count of 0 no entry is
        // emitted, so the key-level slice never runs there. On an emitted
        // entry a storage_key_count of 0 slices to zero keys, where a
        // "0 means all" sentinel would emit every slot at capacity.
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
