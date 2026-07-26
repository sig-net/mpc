//! EVM type-2 transaction assembly and the signing payload scalar.
//!
//! The node does not sign the record; it signs a transaction. This module
//! is the canonical request-to-transaction transform, a port of
//! `signBidirectionalEventToUnsignedEvmTransaction` plus `assembleCalldata`
//! (`signet-evtype2tx-requests.ts:343-412` in `@sig-net/midnight`), the same
//! step Canton performs in `chain-canton/src/signing.rs`.
//!
//! The one rule that matters here: the COUNT fields decide what is real,
//! never the vector lengths. A record whose capacity is entirely unused is
//! provably capacity-ambiguous on the wire (several splits share one
//! request id), so `words.len()`, `access_list.len()` and
//! `storage_keys.len()` are recovered capacity that two honest readers can
//! legitimately disagree about; `no_words`, `access_list_entry_count` and
//! each entry's `storage_key_count` are the only authoritative quantities,
//! and only they reach the transaction.

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

    /// The pure params-to-transaction transform, mirroring both
    /// `signBidirectionalEventToUnsignedEvmTransaction`
    /// (`signet-evtype2tx-requests.ts:390-412`) and Canton's `TryFrom` in
    /// `chain-canton/src/signing.rs`. Envelope fields pass straight
    /// through; the contract's `to` is a fixed `Bytes<20>`, so there is no
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
/// Beyond the pure `TryFrom` transform this enforces two record-level
/// consistency gates the TS transform does not need, because it dispatches
/// through typed decode: `tx_param_type` must be the evmType2 discriminant,
/// and `caip2_id`, the routing label, must agree with `tx_params.chain_id`
/// whenever it names an eip155 chain. A record that routes to one chain
/// and signs for another is refused here rather than signed.
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

/// The scalar the MPC signs: `keccak256(serialized)` read as a field
/// element, bailing when the hash falls outside the curve order, exactly
/// as Canton does (`chain-canton/src/signing.rs:117-121`).
pub fn payload_scalar(serialized: &[u8]) -> anyhow::Result<Scalar> {
    let unsigned_tx_hash = hash_payload(serialized);
    let Some(payload) = Scalar::from_bytes(unsigned_tx_hash) else {
        anyhow::bail!("failed to convert unsigned_tx_hash to scalar: {unsigned_tx_hash:?}");
    };
    Ok(payload)
}

/// `data = selector ‖ words[..no_words]` when present, empty otherwise.
///
/// Ports `assembleCalldata` (`signet-evtype2tx-requests.ts:343-353`)
/// including its failure mode: the reference indexes `words[i]` for
/// `i < noWords` and THROWS when the count overruns the stored slots, so a
/// record with `no_words > words.len()` is an error here, never a clamp
/// and never zero-fill. `no_words` alone decides how many words are real;
/// the vector length appears only as the overrun bound the reference also
/// has, never as a word count.
///
/// D8's distinction holds: an empty `Maybe` yields NO bytes at all, while
/// a present calldata with `no_words = 0` yields the four selector bytes
/// alone. The two are different transactions with different hashes.
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

/// The count-trimmed access list, per `decodeAccessList`
/// (`signet-evtype2tx-requests.ts:361-380`). The reference uses
/// `.slice(0, count)` at both levels, which CLAMPS when a count exceeds
/// the stored slots; `take` preserves that, deliberately asymmetric with
/// the calldata path's overrun error, because that is what the reference
/// does. `access_list_entry_count` and each entry's `storage_key_count`
/// decide what is real; the vector lengths never do.
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
/// The label is NUL-trimmed ASCII (the contract's `pad(32, ...)`
/// convention). A label in another namespace, or one that is not UTF-8 at
/// all, expresses no eip155 opinion and passes: routing it is a later
/// layer's concern. A label that CLAIMS the eip155 namespace but does not
/// parse as `eip155:<decimal u64>` can only be corrupt and is rejected
/// rather than ignored, keeping this gate fail-closed within the namespace
/// it covers.
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
    use crate::compute_request_id;
    use crate::records::SignBidirectionalRecord;
    use crate::test_fixtures::RecordFixture;
    use serde::Deserialize;

    const TX_VECTORS_JSON: &str = include_str!("../tests/tx_vectors.json");
    const RID_VECTORS_JSON: &str = include_str!("../tests/rid_vectors.json");

    #[derive(Deserialize)]
    struct TxVectorFile {
        vectors: Vec<TxVector>,
    }

    /// One oracle vector. The `tx_fields_ethers_sees` debugging view and the
    /// file-level provenance keys are deliberately not modelled: the byte
    /// expectations are the assertions.
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

    /// The record a tx vector describes, joined by name: the anchor
    /// guarantees the records are byte-identical to the same-named
    /// `rid_vectors.json` entries, and the request-id assertion in the
    /// golden test proves the join per vector.
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
    fn golden_assembly_matches_the_ethers_oracle() {
        let vectors = tx_vectors();
        assert_eq!(vectors.len(), 7, "the anchor names seven vectors");

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
    fn counts_not_capacity_is_the_assembled_truth() {
        // The anchor's central fact: minimal-1word, unused-word-slot and
        // wide-schemas differ only in word CAPACITY (1 vs 3) and schema
        // widths, and must assemble to one identical transaction, because
        // only the counts reach the transaction and the schemas never do.
        let base = serialized_transaction(&record_by_name("minimal-1word"))
            .expect("minimal-1word assembles");
        for name in ["unused-word-slot", "wide-schemas"] {
            assert_eq!(
                serialized_transaction(&record_by_name(name)).expect(name),
                base,
                "{name}: capacity and schema widths must not reach the transaction"
            );
        }

        // Non-vacuity: the three RECORDS are distinct (their ids differ),
        // so the equality above is three records collapsing to one
        // transaction, not one record loaded three times.
        let ids: Vec<[u8; 32]> = ["minimal-1word", "unused-word-slot", "wide-schemas"]
            .into_iter()
            .map(|name| compute_request_id(&record_by_name(name)))
            .collect();
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[0], ids[2]);
        assert_ne!(ids[1], ids[2]);
    }

    #[test]
    fn an_empty_maybe_and_zero_words_are_distinct() {
        // D8's easy conflation, separated: is_some = false yields NO bytes
        // at all, while is_some = true with no_words = 0 yields exactly the
        // four selector bytes.
        let absent = to_unsigned_tx(&record_by_name("no-calldata")).expect("no-calldata");
        assert!(
            absent.input.is_empty(),
            "an empty Maybe must produce empty calldata with no selector"
        );

        let selector_only =
            to_unsigned_tx(&record_by_name("zero-words-capacity")).expect("zero-words-capacity");
        assert_eq!(
            selector_only.input.len(),
            4,
            "a present calldata with no_words = 0 is the selector alone"
        );
    }

    #[test]
    fn caip2_must_agree_with_chain_id_when_it_names_an_eip155_chain() {
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
    fn tx_param_type_must_be_evm_type2() {
        let mut record = record_by_name("minimal-1word");
        record.tx_param_type = 1;
        let err = to_unsigned_tx(&record)
            .expect_err("the reserved tx_param_type must not assemble as evmType2")
            .to_string();
        assert!(err.contains("tx_param_type"), "err: {err}");
    }

    #[test]
    fn count_overrun_errors_for_calldata_and_clamps_for_the_access_list() {
        // The reference is deliberately asymmetric and the port preserves
        // it: assembleCalldata INDEXES words[i] for i < noWords and throws
        // past capacity (signet-evtype2tx-requests.ts:349-351), while
        // decodeAccessList SLICES at both levels, which clamps
        // (signet-evtype2tx-requests.ts:371-377).
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
}
