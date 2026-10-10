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
    AttestedOutput = 6,
}

/// Matches the SDK's `calculateAttestedOutputHashV1` tuple:
/// `[HashDomain, Bytes<N>]`. The bytes pack into field elements without their
/// width, so outputs that differ only in trailing zero bytes hash alike; the
/// attestation digest commits to the width beside this hash.
pub fn compute_attested_output_hash(output: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(1 + output.field_size());
    (HashDomain::AttestedOutput as u8).field_repr(&mut preimage);
    output.field_repr(&mut preimage);
    upgrade_from_transient(transient_hash(&preimage)).0
}

/// Matches the SDK's `calculateSignetAttestationDigestV1` tuple:
/// `[HashDomain, RequestId, Uint<64>, OutputKind, Uint<64>, Bytes<32>]`, over the
/// output's length and [`compute_attested_output_hash`]. Every input is carried
/// by the `RespondBidirectionalEvent`, so a node checks an event without the output.
pub fn compute_attestation_digest(
    request_id: &[u8; 32],
    metadata: &mpc_primitives::AttestationMetadata,
    serialized_output_length: u64,
    output_hash: &[u8; 32],
) -> [u8; 32] {
    let mut preimage =
        Vec::with_capacity(1 + request_id.field_size() + 3 + output_hash.field_size());
    (HashDomain::AttestationDigest as u8).field_repr(&mut preimage);
    request_id.field_repr(&mut preimage);
    metadata.block_height.field_repr(&mut preimage);
    (metadata.outcome_kind as u8).field_repr(&mut preimage);
    serialized_output_length.field_repr(&mut preimage);
    output_hash.field_repr(&mut preimage);
    upgrade_from_transient(transient_hash(&preimage)).0
}

/// The attestation digest of an output in hand: [`compute_attestation_digest`]
/// over its length and hash, after checking that only Executed carries output.
pub fn compute_attestation_hash(
    request_id: &[u8; 32],
    metadata: &mpc_primitives::AttestationMetadata,
    output: &[u8],
) -> Result<[u8; 32], mpc_primitives::AttestationError> {
    metadata.validate_output(output)?;
    Ok(compute_attestation_digest(
        request_id,
        metadata,
        output.len() as u64,
        &compute_attested_output_hash(output),
    ))
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
                hex::encode(compute_attested_output_hash(&output)),
                vector["outputHash"].as_str().unwrap(),
            );
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
        // The SDK pins this output hash and digest in tests/circuits.test.ts, over its
        // RECORD_2_1_2 request id.
        let request_id: [u8; 32] =
            hex::decode("2985be91d1a1191749abaee288eed371d19607e69cec0b43468cb750a9dc8d00")
                .unwrap()
                .try_into()
                .unwrap();
        let metadata = AttestationMetadata {
            key_version: 1,
            block_height: 42,
            outcome_kind: AttestationOutcomeKind::Executed,
        };
        assert_eq!(
            hex::encode(compute_attested_output_hash(&[0xab; 32])),
            "ebb2798826150dd6a814821b318928f517888e8978ca5207a35b3fc5253d1f00"
        );
        assert_eq!(
            hex::encode(compute_attestation_hash(&request_id, &metadata, &[0xab; 32]).unwrap()),
            "174ac56d23e49f26fc8dff9b72d76f3abaaae5867f03c8594122640585042300"
        );
    }

    #[test]
    fn attested_output_hash_leaves_the_width_to_the_digest() {
        use mpc_primitives::{AttestationMetadata, AttestationOutcomeKind};
        // Trailing zero bytes pack into the same field elements, so only the digest's
        // length field tells these outputs apart.
        assert_eq!(
            compute_attested_output_hash(&[1]),
            compute_attested_output_hash(&[1, 0])
        );
        let metadata = AttestationMetadata {
            key_version: 1,
            block_height: 42,
            outcome_kind: AttestationOutcomeKind::Executed,
        };
        assert_ne!(
            compute_attestation_hash(&[0x2f; 32], &metadata, &[1]).unwrap(),
            compute_attestation_hash(&[0x2f; 32], &metadata, &[1, 0]).unwrap()
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
