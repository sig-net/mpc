//! Compact-compatible request hashing for decoded Midnight records.

use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};
use midnight_transient_crypto::repr::FieldRepr as _;

use crate::records::SignBidirectionalRecord;

/// Hash the SDK's `RequestIdPreimage` fields from an already decoded record.
///
/// Reserved signature destination/params and serialization schemas are excluded.
/// Compact vectors contribute every capacity slot, and `Maybe` contributes its
/// entire body even when absent; neither is an execution-time collection here.
pub(crate) fn compute_request_id(record: &SignBidirectionalRecord) -> [u8; 32] {
    let mut preimage = Vec::new();
    record.sender.field_repr(&mut preimage);
    record.key_version.field_repr(&mut preimage);
    record.path.field_repr(&mut preimage);
    record.algo.field_repr(&mut preimage);
    record.tx_param_type.field_repr(&mut preimage);

    let tx = &record.tx_params;
    tx.chain_id.field_repr(&mut preimage);
    tx.nonce.field_repr(&mut preimage);
    tx.max_priority_fee_per_gas.field_repr(&mut preimage);
    tx.max_fee_per_gas.field_repr(&mut preimage);
    tx.gas_limit.field_repr(&mut preimage);
    tx.to.field_repr(&mut preimage);
    tx.value.field_repr(&mut preimage);
    tx.calldata.is_some.field_repr(&mut preimage);
    tx.calldata.value.selector.field_repr(&mut preimage);
    tx.calldata.value.no_words.field_repr(&mut preimage);
    tx.calldata.value.words.field_repr(&mut preimage);
    tx.access_list_entry_count.field_repr(&mut preimage);
    for entry in &tx.access_list {
        entry.address.field_repr(&mut preimage);
        entry.storage_key_count.field_repr(&mut preimage);
        entry.storage_keys.field_repr(&mut preimage);
    }

    record.execution_dest.field_repr(&mut preimage);
    upgrade_from_transient(transient_hash(&preimage)).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_matches_compact_golden() {
        let (cell, expected) = crate::test_utils::api_reference_cell();
        let record =
            crate::reader::decode_record(&midnight_onchain_state::state::StateValue::from(cell))
                .expect("compiled Compact record decodes");
        assert_eq!(compute_request_id(&record), expected);
        assert_eq!(
            compute_request_id(&crate::test_utils::sample_record()),
            expected
        );
    }

    #[test]
    fn request_identity_excludes_reserved_fields_and_schema_bytes_and_widths() {
        let mut record = crate::test_utils::sample_record();
        let original = compute_request_id(&record);
        record.signature_dest = 1;
        record.params = [0x73; 64];
        record.output_deserialization_schema = b"different-output-schema".to_vec();
        record.respond_serialization_schema = b"[]".to_vec();
        assert_eq!(compute_request_id(&record), original);
    }

    #[test]
    fn request_identity_binds_transaction_key_sender_and_destination() {
        let record = crate::test_utils::sample_record();
        let original = compute_request_id(&record);
        let mut changes = vec![record.clone(); 8];
        changes[0].tx_params.nonce += 1;
        changes[1].tx_params.max_fee_per_gas += 1;
        changes[2].key_version += 1;
        changes[3].path[0] ^= 1;
        changes[4].sender[0] ^= 1;
        changes[5].execution_dest[0] ^= 1;
        changes[6].algo = 1;
        changes[7].tx_param_type = 1;
        for changed in changes {
            assert_ne!(compute_request_id(&changed), original);
        }
    }

    #[test]
    fn request_identity_keeps_unused_capacity_and_absent_calldata_body() {
        let mut record = crate::test_utils::sample_record_with_unused_access_list();
        record.tx_params.calldata.is_some = false;
        record.tx_params.calldata.value.no_words = 0;
        record.tx_params.calldata.value.selector = [0; 4];
        record.tx_params.calldata.value.words = vec![[0; 32]; 2];
        let original = compute_request_id(&record);
        let mut changes = vec![record.clone(); 7];
        changes[0].tx_params.calldata.value.selector[0] = 1;
        changes[1].tx_params.calldata.value.words[1][31] = 1;
        changes[2].tx_params.access_list[1].address[0] = 1;
        changes[3].tx_params.access_list[1].storage_key_count = 1;
        changes[4].tx_params.access_list[1].storage_keys[1][31] = 1;
        changes[5].tx_params.calldata.value.words.push([0; 32]);
        changes[6]
            .tx_params
            .access_list
            .push(record.tx_params.access_list[0].clone());
        for changed in changes {
            assert_ne!(compute_request_id(&changed), original);
        }
    }

    #[test]
    fn request_id_matches_sdk_capacity_and_integer_boundary_vectors() {
        use crate::test_utils::{
            minimal_record, sample_record_with_partial_access_list,
            sample_record_with_unused_access_list,
        };
        let mut high = sample_record_with_partial_access_list();
        high.key_version = u8::MAX;
        high.tx_params.chain_id = u64::MAX;
        high.tx_params.nonce = u64::MAX;
        high.tx_params.gas_limit = u64::MAX;
        high.tx_params.max_priority_fee_per_gas = u128::MAX;
        high.tx_params.max_fee_per_gas = u128::MAX;
        high.tx_params.value = u128::MAX;
        // Generated with @sig-net/midnight 0.24.0-rc.2 calculateRequestId.
        for (record, expected) in [
            (
                minimal_record(),
                "b1ded02c69aabe2d5e022461d46b7a7eb65f0ef8f1ff34c62087ed7d8fb9cb00",
            ),
            (
                sample_record_with_unused_access_list(),
                "a2a6eddc8c52b01d1c811b56d695396c779d1d6204a5070129006074c5bc4400",
            ),
            (
                sample_record_with_partial_access_list(),
                "7fbf3d873d0d633e3f3d3f1c9badf5ff66aec497db0999d1d3bc65ab79429800",
            ),
            (
                high,
                "31f682e792c0cbb8c1adb80a0c509b73a24a6fc7738962f88d72be132b7f3200",
            ),
        ] {
            assert_eq!(hex::encode(compute_request_id(&record)), expected);
        }
    }
}
