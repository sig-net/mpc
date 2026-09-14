//! Compact-compatible hashing for protocol values represented as FAB fields.

use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};
use midnight_transient_crypto::repr::FieldRepr as _;

/// Hashes the Compact tuple `[RequestId, Uint<64>, Bytes<N>]`, with `N` as the length.
/// The separate length field prevents zero padding from aliasing different outputs.
pub fn compute_response_hash(request_id: &[u8; 32], serialized_output: &[u8]) -> [u8; 32] {
    let mut preimage =
        Vec::with_capacity(request_id.field_size() + 1 + serialized_output.field_size());
    request_id.field_repr(&mut preimage);
    (serialized_output.len() as u64).field_repr(&mut preimage);
    serialized_output.field_repr(&mut preimage);
    upgrade_from_transient(transient_hash(&preimage)).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_hash_matches_compact_goldens() {
        // Generated with Compact 0.33.0 / compact-runtime 0.18.0-rc.1 from
        // upgradeFromTransient(transientHash<[RequestId, Uint<64>, Bytes<N>]>(
        //   [requestId, N as Uint<64>, output])). Cover the 31-byte packing boundary.
        for (length, expected) in [
            (
                0,
                "06acdfb74d1ed81990d627014e36ef32f941b9285c82b2ca982cc911947a2300",
            ),
            (
                1,
                "07ff0ee9b445e83960c7d98854056defc5e45eb46e13851f2a0e3487692ab200",
            ),
            (
                5,
                "51deb9974a65aa4a5c5ae084e32fbd5ea29b0b26194dd2a277f598167bf74000",
            ),
            (
                8,
                "3c55d6ee9366d5ff926a8d94e16c79ca0c9602672fa67899f3dcbf651bb6a500",
            ),
            (
                30,
                "a0d07b736bedce3f3e2132c21eba40fe9d77ee2c26720a52cdcb0f63cc3bcc00",
            ),
            (
                31,
                "f5437e7679994b04af9a221aea2ca590a72346104d9a4429682a8325e3639800",
            ),
            (
                32,
                "48755c01b13d35977c80da4ec29a61995d7f48d45357891cf783de38f1337600",
            ),
            (
                62,
                "a61658efd482ae392a7e05a29e40bc680a85726d7ed81c39c25d137dcff3f100",
            ),
            (
                63,
                "4642529504c3255a70b5720aac78de7c15075a73619806e25ee4d080f11c1d00",
            ),
        ] {
            let serialized_output = (1..=length).collect::<Vec<u8>>();
            assert_eq!(
                hex::encode(compute_response_hash(&[0x2f; 32], &serialized_output)),
                expected,
                "output length {length}"
            );
        }
    }

    #[test]
    fn response_hash_binds_output_length() {
        for (output, padded_length) in [
            (vec![0xde, 0xad, 0xbe, 0xef, 1], 8),
            (vec![0xde, 0xad, 0xbe, 0xef, 1], 9),
            (vec![], 1),
            (vec![0], 2),
            (vec![1; 30], 31),
            (vec![1; 31], 32),
            (vec![1; 32], 33),
            (vec![1; 62], 63),
        ] {
            let mut padded = output.clone();
            padded.resize(padded_length, 0);
            assert_ne!(
                compute_response_hash(&[0x2f; 32], &output),
                compute_response_hash(&[0x2f; 32], &padded),
                "output {output:?} padded to {padded_length} bytes"
            );
        }
    }
}
