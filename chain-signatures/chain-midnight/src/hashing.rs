//! Compact-compatible request hashing for decoded Midnight records.

use midnight_base_crypto::fab::AlignedValue;
use midnight_transient_crypto::fab::AlignedValueExt as _;
use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};
use mpc_primitives::RequestId;

/// The Midnight derivation of a [`RequestId`], as an extension so the transient-hash
/// dependency stays in this crate.
pub trait MidnightRequestId {
    /// Midnight `sign_bidirectional`: the Compact transient hash of the aligned
    /// request-record cell, as the central contract assigns it.
    fn from_midnight_record(cell: &AlignedValue) -> RequestId;
}

impl MidnightRequestId for RequestId {
    fn from_midnight_record(cell: &AlignedValue) -> RequestId {
        let mut preimage = Vec::with_capacity(cell.value_only_field_size());
        cell.value_only_field_repr(&mut preimage);
        RequestId::new(upgrade_from_transient(transient_hash(&preimage)).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_matches_compact_golden() {
        let record = crate::test_utils::sample_record();
        let cell = crate::test_utils::aligned_value_from_record(&record);

        assert_eq!(
            hex::encode(RequestId::from_midnight_record(&cell).as_bytes()),
            "db879820adcaca1d5e38c36a3d8de6cc0918273268fdde87b8258ac77ca11e00"
        );
    }
}
