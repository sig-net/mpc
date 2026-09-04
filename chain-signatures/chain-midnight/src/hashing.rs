//! Compact-compatible request hashing for decoded Midnight records.

use midnight_base_crypto::fab::AlignedValue;
use midnight_transient_crypto::fab::AlignedValueExt as _;
use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};

/// Compute the request ID Compact assigns to an aligned request-record cell.
pub(crate) fn compute_request_id(cell: &AlignedValue) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(cell.value_only_field_size());
    cell.value_only_field_repr(&mut preimage);
    upgrade_from_transient(transient_hash(&preimage)).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_matches_compact_golden() {
        let record = crate::test_utils::sample_record();
        let cell = crate::test_utils::aligned_value_from_record(&record);

        assert_eq!(
            hex::encode(compute_request_id(&cell)),
            "db879820adcaca1d5e38c36a3d8de6cc0918273268fdde87b8258ac77ca11e00"
        );
    }
}
