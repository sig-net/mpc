//! Compact-compatible hashing for protocol values represented as FAB fields.

use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};
use midnight_transient_crypto::repr::FieldRepr as _;

/// Computes the Compact response hash for a request ID and its serialized output.
pub fn compute_response_hash(request_id: &[u8; 32], serialized_output: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(request_id.field_size() + serialized_output.field_size());
    request_id.field_repr(&mut preimage);
    serialized_output.field_repr(&mut preimage);
    upgrade_from_transient(transient_hash(&preimage)).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_hash_matches_compact_golden() {
        // Thirty-two bytes cross the FAB 31-byte field-packing boundary.
        let serialized_output = (1..=32).collect::<Vec<_>>();

        assert_eq!(
            hex::encode(compute_response_hash(&[0x2f; 32], &serialized_output)),
            "61c48f724b114d830caafcb9722b07c5428e2b906b5a61afa26c063735722700"
        );
    }
}
