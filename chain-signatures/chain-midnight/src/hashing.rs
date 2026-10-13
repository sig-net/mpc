//! Compact-compatible request hashing for decoded Midnight records.

use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};
use midnight_transient_crypto::repr::FieldRepr as _;
use mpc_compact_hashing::HashDomain;

use crate::records::{EvmType2TxParams, SignBidirectionalRecord};
use crate::tx::TX_PARAM_TYPE_EVM_TYPE2;

/// Hash `RequestIdPreimageV1`, after its domain tag, from an already decoded
/// EVM type-2 record.
///
/// Reserved signature destination/params and serialization schemas are excluded.
/// The transaction enters as a digest of its used entries, independent of capacity.
pub(crate) fn compute_request_id(record: &SignBidirectionalRecord) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        record.tx_param_type == TX_PARAM_TYPE_EVM_TYPE2,
        "unsupported tx_param_type {}: request identity requires evmType2 (0)",
        record.tx_param_type
    );
    let preimage = (
        HashDomain::RequestId as u8,
        record.key_version,
        record.sender,
        record.path,
        record.algo,
        record.tx_param_type,
        compute_evm_type2_tx_params_digest_v1(&record.tx_params)?,
        record.execution_dest,
    )
        .field_vec();
    Ok(upgrade_from_transient(transient_hash(&preimage)).0)
}

/// Mirror `calculateEvmType2TxParamsDigestV1`: hash the scalar/count head, then
/// fold used words and access-list entries. Inner storage-key folds start at zero.
/// Every hash input starts with its domain tag. Running hashes stay Fields until
/// the final upgrade to Bytes<32>.
fn compute_evm_type2_tx_params_digest_v1(tx: &EvmType2TxParams) -> anyhow::Result<[u8; 32]> {
    let no_words = if tx.calldata.is_some {
        tx.calldata.value.no_words
    } else {
        0
    };
    let selector = if tx.calldata.is_some {
        tx.calldata.value.selector
    } else {
        [0; 4]
    };
    // Compact increments the fold counters across the entire declared vector,
    // including unused slots. Reject capacities that overflow those counters.
    anyhow::ensure!(
        tx.calldata.value.words.len() <= usize::from(u16::MAX),
        "calldata capacity exceeds the Compact Uint<16> fold counter"
    );
    anyhow::ensure!(
        tx.access_list.len() <= usize::from(u8::MAX),
        "access-list capacity exceeds the Compact Uint<8> fold counter"
    );
    anyhow::ensure!(
        usize::from(no_words) <= tx.calldata.value.words.len(),
        "calldata no_words exceeds capacity"
    );
    anyhow::ensure!(
        usize::from(tx.access_list_entry_count) <= tx.access_list.len(),
        "access_list_entry_count exceeds capacity"
    );
    let entries = &tx.access_list[..usize::from(tx.access_list_entry_count)];
    for entry in entries {
        // The inner fold runs only for used entries, even at zero used keys.
        anyhow::ensure!(
            entry.storage_keys.len() <= usize::from(u8::MAX),
            "a used entry's storage-key capacity exceeds the Compact Uint<8> fold counter"
        );
        anyhow::ensure!(
            usize::from(entry.storage_key_count) <= entry.storage_keys.len(),
            "a used entry's storage_key_count exceeds capacity"
        );
    }

    let mut hash = transient_hash(
        &(
            HashDomain::EvmType2TxHeader as u8,
            tx.chain_id,
            tx.nonce,
            tx.max_priority_fee_per_gas,
            tx.max_fee_per_gas,
            tx.gas_limit,
            tx.to,
            tx.value,
            tx.calldata.is_some,
            selector,
            no_words,
            tx.access_list_entry_count,
        )
            .field_vec(),
    );
    for word in &tx.calldata.value.words[..usize::from(no_words)] {
        hash = transient_hash(&(HashDomain::EvmType2TxWord as u8, hash, *word).field_vec());
    }
    for entry in entries {
        let mut keys_hash = Fr::from(0u64);
        for key in &entry.storage_keys[..usize::from(entry.storage_key_count)] {
            keys_hash = transient_hash(
                &(HashDomain::EvmType2TxStorageKey as u8, keys_hash, *key).field_vec(),
            );
        }
        hash = transient_hash(
            &(
                HashDomain::EvmType2TxAccessEntry as u8,
                hash,
                entry.address,
                entry.storage_key_count,
                keys_hash,
            )
                .field_vec(),
        );
    }
    Ok(upgrade_from_transient(hash).0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{sample_record, sample_record_with_partial_access_list};

    #[test]
    fn request_id_matches_compact_golden() {
        let (cell, expected) = crate::test_utils::api_reference_cell();
        let record =
            crate::reader::decode_record(&midnight_onchain_state::state::StateValue::from(cell))
                .expect("compiled Compact record decodes");
        assert_eq!(compute_request_id(&record).unwrap(), expected);
        assert_eq!(compute_request_id(&sample_record()).unwrap(), expected);
    }

    // The SDK's RECORD_2_1_2 vector from tests/circuits.test.ts at
    // @sig-net/midnight 0.24.0-rc.4. Every capacity is used, so every
    // request-side domain tag enters a hash.
    #[test]
    fn request_id_and_transaction_digest_match_sdk_domain_vector() {
        let mut record = sample_record();
        record.sender = [0x01; 32];
        record.path = [0x03; 32];
        record.execution_dest = [0x02; 32];
        record.output_deserialization_schema = vec![0x07; 34];
        record.respond_serialization_schema = vec![0x08; 34];
        let tx = &mut record.tx_params;
        tx.nonce = 1;
        tx.max_priority_fee_per_gas = 1_000_000_000;
        tx.max_fee_per_gas = 30_000_000_000;
        tx.gas_limit = 100_000;
        tx.to = [0xaa; 20];
        tx.value = 0;
        tx.calldata.value.selector = [0xab; 4];
        tx.calldata.value.no_words = 2;
        tx.calldata.value.words = vec![[0x11; 32], [0x12; 32]];
        tx.access_list_entry_count = 1;
        tx.access_list = vec![crate::records::EvmAccessListEntry {
            address: [0xcc; 20],
            storage_key_count: 2,
            storage_keys: vec![[0x22; 32], [0x23; 32]],
        }];
        assert_eq!(
            hex::encode(compute_evm_type2_tx_params_digest_v1(tx).unwrap()),
            "e5e11cd48153d16da6d9ec69b471848bafa6c1258a234b30359d383e3fba0b00"
        );
        assert_eq!(
            hex::encode(compute_request_id(&record).unwrap()),
            "4c4e839b3257b4d73de4a362aabf435de1a4a137c0b220479d874c6b6b80fd00"
        );
    }

    #[test]
    fn request_identity_excludes_reserved_fields_and_schema_bytes_and_widths() {
        let mut record = sample_record();
        let original = compute_request_id(&record).unwrap();
        record.signature_dest = 1;
        record.params = [0x73; 64];
        record.output_deserialization_schema = b"different-output-schema".to_vec();
        record.respond_serialization_schema = b"[]".to_vec();
        assert_eq!(compute_request_id(&record).unwrap(), original);
    }

    #[test]
    fn request_identity_binds_transaction_key_sender_and_destination() {
        let record = sample_record_with_partial_access_list();
        let original = compute_request_id(&record).unwrap();
        let mut changes = vec![record.clone(); 15];
        changes[0].tx_params.nonce += 1;
        changes[1].tx_params.max_fee_per_gas += 1;
        changes[2].key_version += 1;
        changes[3].path[0] ^= 1;
        changes[4].sender[0] ^= 1;
        changes[5].execution_dest[0] ^= 1;
        changes[6].algo = 1;
        changes[7].tx_params.calldata.value.selector[0] ^= 1;
        changes[8].tx_params.calldata.value.words[1][31] ^= 1;
        changes[9].tx_params.access_list[0].address[0] ^= 1;
        changes[10].tx_params.access_list[0].storage_keys[2][31] ^= 1;
        changes[11].tx_params.calldata.value.no_words -= 1;
        changes[12].tx_params.access_list_entry_count = 0;
        changes[13].tx_params.access_list[0].storage_key_count -= 1;
        changes[14].tx_params.calldata.is_some = false;
        for (index, changed) in changes.iter().enumerate() {
            assert_ne!(
                compute_request_id(changed).unwrap(),
                original,
                "case {index}"
            );
        }
        let mut unsupported = record;
        unsupported.tx_param_type = 1;
        assert!(compute_request_id(&unsupported)
            .unwrap_err()
            .to_string()
            .contains("tx_param_type"));
    }

    #[test]
    fn request_identity_ignores_unused_capacity_and_absent_calldata_body() {
        let mut record = sample_record_with_partial_access_list();
        record.tx_params.calldata.value.no_words = 1;
        record.tx_params.access_list[0].storage_key_count = 1;
        let mut changes = vec![record.clone(); 7];
        changes[0].tx_params.calldata.value.words[1][31] ^= 1;
        changes[1].tx_params.access_list[1].address[0] = 1;
        changes[2].tx_params.access_list[1].storage_key_count = u8::MAX;
        changes[3].tx_params.access_list[1].storage_keys[1][31] = 1;
        changes[4].tx_params.access_list[0].storage_keys[2][31] = 1;
        changes[5].tx_params.calldata.value.words.push([0xa5; 32]);
        changes[6]
            .tx_params
            .access_list
            .push(record.tx_params.access_list[0].clone());
        let original = compute_request_id(&record).unwrap();
        let transaction = crate::tx::serialized_transaction(&record).unwrap();
        for (index, changed) in changes.iter().enumerate() {
            assert_eq!(
                compute_request_id(changed).unwrap(),
                original,
                "case {index}"
            );
            assert_eq!(
                crate::tx::serialized_transaction(changed).unwrap(),
                transaction
            );
        }
        let mut compact = record.clone();
        compact.tx_params.calldata.value.words.truncate(1);
        compact.tx_params.access_list.truncate(1);
        compact.tx_params.access_list[0].storage_keys.truncate(1);
        assert_eq!(compute_request_id(&compact).unwrap(), original);
        assert_eq!(
            crate::tx::serialized_transaction(&compact).unwrap(),
            transaction
        );

        record.tx_params.calldata.is_some = false;
        let original = compute_request_id(&record).unwrap();
        let transaction = crate::tx::serialized_transaction(&record).unwrap();
        record.tx_params.calldata.value.selector = [0xff; 4];
        record.tx_params.calldata.value.no_words = u16::MAX;
        record.tx_params.calldata.value.words.clear();
        assert_eq!(compute_request_id(&record).unwrap(), original);
        assert_eq!(
            crate::tx::serialized_transaction(&record).unwrap(),
            transaction
        );
    }

    #[test]
    fn request_identity_rejects_used_counts_beyond_capacity() {
        let record = sample_record_with_partial_access_list();
        let mut changes = vec![record; 3];
        changes[0].tx_params.calldata.value.no_words = 3;
        changes[1].tx_params.access_list_entry_count = 3;
        changes[2].tx_params.access_list[0].storage_key_count = 4;
        for (changed, expected) in changes.iter().zip([
            "calldata no_words",
            "access_list_entry_count",
            "storage_key_count",
        ]) {
            assert!(compute_request_id(changed)
                .unwrap_err()
                .to_string()
                .contains(expected));
        }
    }

    // Boundary digests come from Compact 0.33.0-rc.2 compiling the unmodified
    // @sig-net/midnight 0.24.0-rc.4 Signet.compact, published from
    // f3c3e3906d193db903430f101bdf56aea9713dcf, with the capacities exercised
    // below. The folds increment their counters even for unused slots, but skip
    // the key fold for an unused access entry.
    #[test]
    fn calldata_capacity_matches_compact_counter_boundaries() {
        for (is_some, no_words, expected) in [
            (
                false,
                0,
                "236eb84cf68556327107473b32c37c130c61ba97a1e83b851474462da098ce00",
            ),
            (
                true,
                0,
                "8c4dfa0baf04ba0904f359020156ad4d5d63f39eea74104b82bc2c17e39a5000",
            ),
            (
                true,
                1,
                "2e2f17aed8b2b6618dd3219fe2904343964140b0681d73cf5c1494884379db00",
            ),
        ] {
            let mut tx = sample_record().tx_params;
            tx.calldata.is_some = is_some;
            tx.calldata.value.no_words = no_words;
            tx.calldata.value.words = vec![[0x11; 32]; usize::from(u16::MAX)];
            assert_eq!(
                hex::encode(compute_evm_type2_tx_params_digest_v1(&tx).unwrap()),
                expected
            );
            tx.calldata.value.words.push([0x11; 32]);
            assert!(compute_evm_type2_tx_params_digest_v1(&tx)
                .unwrap_err()
                .to_string()
                .contains("calldata capacity"));
        }
    }

    #[test]
    fn access_list_capacity_matches_compact_counter_boundaries() {
        for (used, expected) in [
            (
                0,
                "8c4dfa0baf04ba0904f359020156ad4d5d63f39eea74104b82bc2c17e39a5000",
            ),
            (
                1,
                "6c422c71b692207849e9dd1a0884dd5156df03ee40eaee964696966b41e1a600",
            ),
            (
                u8::MAX,
                "47664bbc1405de0d88af438901c6161ad88d246db61fe72c7ef1288164427000",
            ),
        ] {
            let mut tx = sample_record().tx_params;
            tx.calldata.value.no_words = 0;
            tx.calldata.value.words.clear();
            tx.access_list_entry_count = used;
            let entry = crate::records::EvmAccessListEntry {
                address: [0xef; 20],
                storage_key_count: 0,
                storage_keys: Vec::new(),
            };
            tx.access_list = vec![entry.clone(); usize::from(u8::MAX)];
            assert_eq!(
                hex::encode(compute_evm_type2_tx_params_digest_v1(&tx).unwrap()),
                expected
            );
            tx.access_list.push(entry);
            assert!(compute_evm_type2_tx_params_digest_v1(&tx)
                .unwrap_err()
                .to_string()
                .contains("access-list capacity"));
        }
    }

    #[test]
    fn storage_key_capacity_matches_compact_counter_boundaries() {
        for (used_keys, expected) in [
            (
                0,
                "6c422c71b692207849e9dd1a0884dd5156df03ee40eaee964696966b41e1a600",
            ),
            (
                1,
                "653423539b015d0adbb73c5d2b269798bef56a38f403a67684fec1e557d76f00",
            ),
            (
                u8::MAX,
                "1a3c3cc6eb756cb0beb291facb7c5704a6fc0731c854e231af4323a8555d9900",
            ),
        ] {
            let mut tx = sample_record().tx_params;
            tx.calldata.value.no_words = 0;
            tx.calldata.value.words.clear();
            tx.access_list_entry_count = 1;
            tx.access_list = vec![crate::records::EvmAccessListEntry {
                address: [0xef; 20],
                storage_key_count: used_keys,
                storage_keys: vec![[0x22; 32]; usize::from(u8::MAX)],
            }];
            assert_eq!(
                hex::encode(compute_evm_type2_tx_params_digest_v1(&tx).unwrap()),
                expected
            );
            tx.access_list[0].storage_keys.push([0x22; 32]);
            assert!(compute_evm_type2_tx_params_digest_v1(&tx)
                .unwrap_err()
                .to_string()
                .contains("storage-key capacity"));
            tx.access_list_entry_count = 0;
            assert_eq!(
                hex::encode(compute_evm_type2_tx_params_digest_v1(&tx).unwrap()),
                "8c4dfa0baf04ba0904f359020156ad4d5d63f39eea74104b82bc2c17e39a5000",
                "unused entries do not evaluate the storage-key fold",
            );
        }
    }

    #[test]
    fn request_id_and_transaction_digest_match_compact_capacity_vectors() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/api-parity-vectors.json")).unwrap();
        let vectors = fixture["requestVectors"].as_array().unwrap();
        assert!(
            vectors.len() >= 5,
            "cover zero, unused, partial and maximum-value inputs"
        );
        for vector in vectors {
            let atoms: Vec<Vec<u8>> = vector["atoms"]
                .as_array()
                .unwrap()
                .iter()
                .map(|atom| hex::decode(atom.as_str().unwrap()).unwrap())
                .collect();
            let widths: Vec<u32> = vector["widths"]
                .as_array()
                .unwrap()
                .iter()
                .map(|width| width.as_u64().unwrap().try_into().unwrap())
                .collect();
            let cell = crate::test_utils::cell_from_atoms(&atoms, &widths);
            let record = crate::reader::decode_record(&cell).unwrap();
            assert_eq!(
                hex::encode(compute_request_id(&record).unwrap()),
                vector["requestId"].as_str().unwrap(),
                "{}",
                vector["name"]
            );
            assert_eq!(
                hex::encode(compute_evm_type2_tx_params_digest_v1(&record.tx_params).unwrap()),
                vector["txParamsDigest"].as_str().unwrap(),
                "{}",
                vector["name"]
            );
        }
    }
}
