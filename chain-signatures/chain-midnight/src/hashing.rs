//! Compact-compatible request hashing for decoded Midnight records.

use midnight_base_crypto::fab::AlignedValue;
use midnight_transient_crypto::fab::AlignedValueExt as _;
use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};

/// Compute the canonical identity of a fully decoded nonce-free request cell.
///
/// The caller must first validate the complete record layout. The last two atoms
/// are schemas and atoms 4 and 5 are reserved signature destination and params.
/// Excluding those fields preserves the `RequestIdPreimage` order from the SDK;
/// unused transaction capacity slots remain part of the identity.
pub(crate) fn compute_request_id(cell: &AlignedValue) -> [u8; 32] {
    let mut identity = cell.clone();
    let identity_atoms = identity.value.0.len() - 2;
    identity.value.0.truncate(identity_atoms);
    identity.alignment.0.truncate(identity_atoms);
    identity.value.0.drain(4..6);
    identity.alignment.0.drain(4..6);
    let mut preimage = Vec::with_capacity(identity.value_only_field_size());
    identity.value_only_field_repr(&mut preimage);
    upgrade_from_transient(transient_hash(&preimage)).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_matches_compact_golden() {
        let (cell, expected) = crate::test_utils::api_reference_cell();
        assert_eq!(compute_request_id(&cell), expected);
        let sample =
            crate::test_utils::aligned_value_from_record(&crate::test_utils::sample_record());
        assert_eq!(compute_request_id(&sample), expected);
    }

    #[test]
    fn request_identity_excludes_reserved_fields_and_schema_bytes_and_widths() {
        let mut record = crate::test_utils::sample_record();
        let original = compute_request_id(&crate::test_utils::aligned_value_from_record(&record));
        record.signature_dest = 1;
        record.params = [0x73; 64];
        record.output_deserialization_schema = b"different-output-schema".to_vec();
        record.respond_serialization_schema = b"[]".to_vec();
        assert_eq!(
            compute_request_id(&crate::test_utils::aligned_value_from_record(&record)),
            original
        );
    }

    #[test]
    fn request_identity_binds_transaction_key_sender_and_destination() {
        let record = crate::test_utils::sample_record();
        let original = compute_request_id(&crate::test_utils::aligned_value_from_record(&record));
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
            assert_ne!(
                compute_request_id(&crate::test_utils::aligned_value_from_record(&changed)),
                original
            );
        }
    }
}
