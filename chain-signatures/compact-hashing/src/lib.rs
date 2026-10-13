//! Compact-compatible hashing for protocol values represented as FAB fields.

use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};
use midnight_transient_crypto::repr::FieldRepr as _;

/// Variant indices of the SDK Compact `HashDomain` enum, the tag each protocol
/// hash input starts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HashDomain {
    RequestId = 0,
    AttestationDigest = 1,
    EvmType2TxHeader = 2,
    EvmType2TxWord = 3,
    EvmType2TxAccessEntry = 4,
    EvmType2TxStorageKey = 5,
}

/// Matches the SDK's `calculateSignetAttestationDigest` tuple:
/// `[HashDomain, RequestId, Uint<64>, OutputKind, Uint<64>, Bytes<N>]`.
/// The separate length field prevents zero padding from aliasing different outputs.
pub fn compute_attestation_hash(
    request_id: &[u8; 32],
    metadata: &mpc_primitives::AttestationMetadata,
    output: &[u8],
) -> Result<[u8; 32], mpc_primitives::AttestationError> {
    metadata.validate_output(output)?;
    let mut preimage = Vec::with_capacity(1 + request_id.field_size() + 3 + output.field_size());
    (HashDomain::AttestationDigest as u8).field_repr(&mut preimage);
    request_id.field_repr(&mut preimage);
    metadata.block_height.field_repr(&mut preimage);
    (metadata.outcome_kind as u8).field_repr(&mut preimage);
    (output.len() as u64).field_repr(&mut preimage);
    output.field_repr(&mut preimage);
    Ok(upgrade_from_transient(transient_hash(&preimage)).0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_hash_matches_compiled_compact_oracle() {
        use mpc_primitives::{AttestationMetadata, AttestationOutcomeKind};
        // Produced by compiled Compact circuits; no Rust hash implementation
        // participates in generating these expected bytes.
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../chain-midnight/fixtures/api-parity-vectors.json"
        ))
        .unwrap();
        for vector in fixtures["attestations"].as_array().unwrap() {
            let metadata = AttestationMetadata {
                key_version: vector["keyVersion"].as_u64().unwrap().try_into().unwrap(),
                block_height: vector["blockHeight"].as_str().unwrap().parse().unwrap(),
                outcome_kind: AttestationOutcomeKind::try_from(
                    u8::try_from(vector["kind"].as_u64().unwrap()).unwrap(),
                )
                .unwrap(),
            };
            let rid: [u8; 32] = hex::decode(vector["requestId"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let output = hex::decode(vector["data"].as_str().unwrap()).unwrap();
            assert_eq!(
                hex::encode(compute_attestation_hash(&rid, &metadata, &output).unwrap()),
                vector["digest"].as_str().unwrap(),
            );
            assert_eq!(hex::encode(&output), vector["cache"].as_str().unwrap());
        }
    }

    #[test]
    fn attestation_hash_matches_sdk_domain_vector() {
        use mpc_primitives::{AttestationMetadata, AttestationOutcomeKind};
        // The SDK pins this digest in tests/circuits.test.ts at
        // @sig-net/midnight 0.24.0-rc.4, over its RECORD_2_1_2 request id.
        let request_id: [u8; 32] =
            hex::decode("4c4e839b3257b4d73de4a362aabf435de1a4a137c0b220479d874c6b6b80fd00")
                .unwrap()
                .try_into()
                .unwrap();
        let metadata = AttestationMetadata {
            key_version: 1,
            block_height: 42,
            outcome_kind: AttestationOutcomeKind::Executed,
        };
        assert_eq!(
            hex::encode(compute_attestation_hash(&request_id, &metadata, &[0xab; 32]).unwrap()),
            "41a1845ae55860bc1d9bf08d2581cbc5f2a34005e99ea51743db252040165400"
        );
    }

    #[test]
    fn attestation_hash_binds_every_field_and_output_length() {
        use mpc_primitives::{AttestationMetadata, AttestationOutcomeKind};
        let metadata = AttestationMetadata {
            key_version: 1,
            block_height: 42,
            outcome_kind: AttestationOutcomeKind::Executed,
        };
        let rid = [0x2f; 32];
        let baseline = compute_attestation_hash(&rid, &metadata, &[]).unwrap();
        for (request_id, metadata, output) in [
            ([0x30; 32], metadata, vec![]),
            (
                rid,
                AttestationMetadata {
                    block_height: 43,
                    ..metadata
                },
                vec![],
            ),
            (
                rid,
                AttestationMetadata {
                    outcome_kind: AttestationOutcomeKind::Failed,
                    ..metadata
                },
                vec![],
            ),
            (
                rid,
                AttestationMetadata {
                    outcome_kind: AttestationOutcomeKind::Unviable,
                    ..metadata
                },
                vec![],
            ),
            (rid, metadata, vec![0]),
            (rid, metadata, vec![1]),
        ] {
            assert_ne!(
                compute_attestation_hash(&request_id, &metadata, &output).unwrap(),
                baseline
            );
        }
        assert_ne!(
            compute_attestation_hash(&rid, &metadata, &[0]).unwrap(),
            compute_attestation_hash(&rid, &metadata, &[1]).unwrap(),
        );
        assert_ne!(
            compute_attestation_hash(
                &rid,
                &AttestationMetadata {
                    outcome_kind: AttestationOutcomeKind::Failed,
                    ..metadata
                },
                &[]
            )
            .unwrap(),
            compute_attestation_hash(
                &rid,
                &AttestationMetadata {
                    outcome_kind: AttestationOutcomeKind::Unviable,
                    ..metadata
                },
                &[]
            )
            .unwrap(),
        );
        for length in [0, 1, 5, 30, 31, 32, 62, 63] {
            let output = vec![1; length];
            let mut padded = output.clone();
            padded.push(0);
            assert_ne!(
                compute_attestation_hash(&rid, &metadata, &output).unwrap(),
                compute_attestation_hash(&rid, &metadata, &padded).unwrap()
            );
        }
        for outcome in [
            AttestationOutcomeKind::Failed,
            AttestationOutcomeKind::Unviable,
        ] {
            assert!(compute_attestation_hash(
                &rid,
                &AttestationMetadata {
                    outcome_kind: outcome,
                    ..metadata
                },
                &[1]
            )
            .is_err());
        }
    }
}
