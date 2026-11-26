use crate::KeyVersion;
use k256::{
    ecdsa::{RecoveryId, VerifyingKey},
    elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, CurveArithmetic},
    AffinePoint, Scalar, Secp256k1,
};
use sha3::{Digest, Keccak256, Sha3_256};
use signet_primitives::{Chain, PublicKey, ScalarExt, Signature, LATEST_MPC_KEY_VERSION};

/// Prefix of a derivation path at key version 0.
const DERIVATION_PREFIX_V0: &str = "sig.network v1.0.0 epsilon derivation";
/// Prefix of a derivation path at key version 1.
const DERIVATION_PREFIX_V1: &str = "sig.network v2.0.0 epsilon derivation";
/// Prefix of a derivation path from key version 2, which names the version itself.
const DERIVATION_PREFIX_V2: &str = "sig.network derivation";

/// The sender a system account derives with below key version 2.
const SYSTEM_SENDER: &str = "%admin#";

/// Why no key is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// Above `LATEST_MPC_KEY_VERSION`, or a version with no derivation format.
    #[error("key version {0} is not supported")]
    UnsupportedKeyVersion(KeyVersion),
    /// The key version does not have this key.
    #[error("key version {key_version}: {reason}")]
    Refused {
        key_version: KeyVersion,
        reason: &'static str,
    },
}

/// What a key signs, with the fields its derivation path holds
/// (doc/account-derivation.md). From key version 2 the derivation path names the
/// purpose, so two purposes never derive the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose<'a> {
    /// A plain sign request's key.
    Plain { sender: &'a str, path: &'a str },
    /// A bidirectional request's key.
    Bidirectional { sender: &'a str, path: &'a str },
    /// The key the MPC attests a bidirectional request's outcome to `sender` with.
    Attestation { sender: &'a str },
    /// A system account's key.
    System { path: &'a str },
}

/// The purpose's name in the derivation path.
impl std::fmt::Display for KeyPurpose<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyPurpose::Plain { .. } => "plain",
            KeyPurpose::Bidirectional { .. } => "bidirectional",
            KeyPurpose::Attestation { .. } => "attestation",
            KeyPurpose::System { .. } => "system",
        })
    }
}

/// The path that holds `chain`'s attestation key at `key_version`, which no request
/// may name. Only below key version 2, where the attestation key is a plain key;
/// `None` on chains that are not bidirectional sources.
pub const fn reserved_path(key_version: KeyVersion, chain: Chain) -> Option<&'static str> {
    if key_version >= 2 {
        return None;
    }
    match chain {
        Chain::Solana => Some("solana response key"),
        Chain::Canton => Some("canton response key"),
        Chain::Midnight => Some("midnight response key"),
        _ => None,
    }
}

/// The epsilon of the key for `purpose` on `chain` at `key_version`.
pub fn derive_epsilon(
    key_version: KeyVersion,
    chain: Chain,
    purpose: KeyPurpose<'_>,
) -> Result<Scalar, DeriveError> {
    if key_version > LATEST_MPC_KEY_VERSION {
        return Err(DeriveError::UnsupportedKeyVersion(key_version));
    }
    let derivation_path = versioned_derivation_path(key_version, chain, purpose)?;
    Ok(hash_derivation_path(chain, derivation_path))
}

/// Each key version is pinned to one format; unknown versions are rejected.
/// Ignores `LATEST_MPC_KEY_VERSION`, so formats are testable before they are served.
fn versioned_derivation_path(
    key_version: KeyVersion,
    chain: Chain,
    purpose: KeyPurpose<'_>,
) -> Result<String, DeriveError> {
    match key_version {
        0 | 1 => legacy_derivation_path(key_version, chain, purpose),
        2 => Ok(derivation_path_v2(chain, purpose)),
        other => Err(DeriveError::UnsupportedKeyVersion(other)),
    }
}

/// Key versions 0 and 1 name no purpose in the path, so each refuses the keys it does not have.
fn legacy_derivation_path(
    key_version: KeyVersion,
    chain: Chain,
    purpose: KeyPurpose<'_>,
) -> Result<String, DeriveError> {
    let refused = |reason| DeriveError::Refused {
        key_version,
        reason,
    };
    let format = if key_version == 0 {
        derivation_path_v0
    } else {
        derivation_path_v1
    };
    match purpose {
        KeyPurpose::Bidirectional { .. } | KeyPurpose::Attestation { .. } if key_version == 0 => {
            Err(refused("predates bidirectional signing"))
        }
        KeyPurpose::Plain { path, .. } | KeyPurpose::Bidirectional { path, .. }
            if reserved_path(key_version, chain) == Some(path) =>
        {
            Err(refused("the path holds the attestation key"))
        }
        KeyPurpose::Plain { sender, path } | KeyPurpose::Bidirectional { sender, path } => {
            Ok(format(chain, sender, path))
        }
        // The attestation key is a plain key under the reserved path.
        KeyPurpose::Attestation { sender } => reserved_path(key_version, chain)
            .map(|path| format(chain, sender, path))
            .ok_or_else(|| refused("the chain has no attestation key")),
        KeyPurpose::System { path } => Ok(format(chain, SYSTEM_SENDER, path)),
    }
}

/// Key version 0: `sig.network v1.0.0 epsilon derivation,{deprecated chain id},{sender},{path}`.
fn derivation_path_v0(chain: Chain, sender: &str, path: &str) -> String {
    let chain_id = chain.deprecated_chain_id();
    format!("{DERIVATION_PREFIX_V0},{chain_id},{sender},{path}")
}

/// Key version 1: `sig.network v2.0.0 epsilon derivation:{caip2 chain id}:{sender}:{path}`.
fn derivation_path_v1(chain: Chain, sender: &str, path: &str) -> String {
    let chain_id = chain.caip2_chain_id();
    format!("{DERIVATION_PREFIX_V1}:{chain_id}:{sender}:{path}")
}

/// Key version 2: `sig.network derivation:2:{purpose}:{caip2 chain id}:{fields}`, where the
/// fields depend on the purpose.
fn derivation_path_v2(chain: Chain, purpose: KeyPurpose<'_>) -> String {
    let head = format!(
        "{DERIVATION_PREFIX_V2}:2:{purpose}:{}",
        chain.caip2_chain_id()
    );
    match purpose {
        KeyPurpose::Plain { sender, path } | KeyPurpose::Bidirectional { sender, path } => {
            format!("{head}:{sender}:{path}")
        }
        KeyPurpose::Attestation { sender } => format!("{head}:{sender}"),
        KeyPurpose::System { path } => format!("{head}:{path}"),
    }
}

fn sha3(derivation_path: impl AsRef<[u8]>) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_non_biased(hash)
}

fn keccak(derivation_path: impl AsRef<[u8]>) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_non_biased(hash)
}

fn hash_derivation_path(chain: Chain, derivation_path: String) -> Scalar {
    match chain {
        Chain::NEAR => sha3(derivation_path),
        _ => keccak(derivation_path),
    }
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

/// x coordinate of `point`, reduced to a scalar.
pub fn x_coordinate(point: &AffinePoint) -> Scalar {
    <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes(&point.x())
}

/// Reconstructs a signature from its components, returning `None` unless it
/// verifies against `public_key` for one of the two recovery ids.
pub fn reconstruct_signature(
    public_key: &PublicKey,
    big_r: &AffinePoint,
    s: &Scalar,
    msg_hash: Scalar,
) -> Option<Signature> {
    let public_key = public_key.to_encoded_point(false);
    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(big_r), s).ok()?;
    for recovery_id in [0, 1] {
        let recovery_id = RecoveryId::try_from(recovery_id).ok()?;
        let recovered =
            VerifyingKey::recover_from_prehash(&msg_hash.to_bytes()[..], &signature, recovery_id)
                .ok()?
                .to_encoded_point(false);
        if public_key == recovered {
            return Some(Signature::new(*big_r, *s, recovery_id.to_byte()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::elliptic_curve::point::DecompressPoint;
    use k256::{AffinePoint, SecretKey};

    fn sign_with(sk: &SecretKey, msg_hash: &Scalar) -> (AffinePoint, Scalar, u8) {
        let (ecdsa_sig, rec_id): (k256::ecdsa::Signature, _) = k256::ecdsa::SigningKey::from(sk)
            .sign_prehash(&msg_hash.to_bytes())
            .unwrap();
        let (r_bytes, _) = ecdsa_sig.split_bytes();
        let big_r =
            AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0))
                .unwrap();
        (big_r, *ecdsa_sig.s().as_ref(), rec_id.to_byte())
    }

    #[test]
    fn test_reconstruct_signature_success() {
        let sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let public_key: PublicKey = sk.public_key().into();
        let msg_hash = Scalar::from_bytes([0x22; 32]).unwrap();
        let (big_r, s, expected_rec_id) = sign_with(&sk, &msg_hash);

        let sig = reconstruct_signature(&public_key, &big_r, &s, msg_hash).unwrap();
        assert_eq!(sig.big_r, big_r);
        assert_eq!(sig.s, s);
        assert_eq!(sig.recovery_id, expected_rec_id);
    }

    #[test]
    fn test_reconstruct_signature_wrong_public_key() {
        let sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let wrong_sk = SecretKey::from_bytes((&[0x99; 32]).into()).unwrap();
        let wrong_public_key: PublicKey = wrong_sk.public_key().into();
        let msg_hash = Scalar::from_bytes([0x22; 32]).unwrap();
        let (big_r, s, _) = sign_with(&sk, &msg_hash);

        assert!(reconstruct_signature(&wrong_public_key, &big_r, &s, msg_hash).is_none());
    }

    #[test]
    fn test_reconstruct_signature_wrong_payload() {
        let sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let public_key: PublicKey = sk.public_key().into();
        let msg_hash = Scalar::from_bytes([0x22; 32]).unwrap();
        let wrong_msg_hash = Scalar::from_bytes([0x33; 32]).unwrap();
        let (big_r, s, _) = sign_with(&sk, &msg_hash);

        assert!(reconstruct_signature(&public_key, &big_r, &s, wrong_msg_hash).is_none());
    }

    #[test]
    fn test_reconstruct_signature_invalid_s_scalar() {
        let sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let public_key: PublicKey = sk.public_key().into();
        let msg_hash = Scalar::from_bytes([0x22; 32]).unwrap();

        assert!(reconstruct_signature(&public_key, &public_key, &Scalar::ZERO, msg_hash).is_none());
    }

    #[test]
    fn test_x_coordinate_of_generator() {
        let expected = Scalar::from_bytes(
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(x_coordinate(&PublicKey::GENERATOR), expected);
    }

    fn derivation_path(key_version: KeyVersion, chain: Chain, purpose: KeyPurpose<'_>) -> String {
        versioned_derivation_path(key_version, chain, purpose).unwrap()
    }

    const PLAIN: KeyPurpose<'static> = KeyPurpose::Plain {
        sender: "sender",
        path: "path",
    };

    #[test]
    fn test_derivation_path_stays_the_same() {
        assert_eq!(
            derivation_path(0, Chain::Ethereum, PLAIN),
            "sig.network v1.0.0 epsilon derivation,0x1,sender,path"
        );
        assert_eq!(
            derivation_path(1, Chain::Ethereum, PLAIN),
            "sig.network v2.0.0 epsilon derivation:eip155:1:sender:path"
        );
        assert_eq!(
            derivation_path(0, Chain::Solana, PLAIN),
            "sig.network v1.0.0 epsilon derivation,0x800001f5,sender,path"
        );
        assert_eq!(
            derivation_path(1, Chain::Solana, PLAIN),
            "sig.network v2.0.0 epsilon derivation:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:sender:path"
        );
        assert_eq!(
            derivation_path(0, Chain::NEAR, PLAIN),
            "sig.network v1.0.0 epsilon derivation,0x18d,sender,path"
        );
        assert_eq!(
            derivation_path(1, Chain::NEAR, PLAIN),
            "sig.network v2.0.0 epsilon derivation:near:mainnet:sender:path"
        );
        assert_eq!(
            derivation_path(0, Chain::Bitcoin, PLAIN),
            "sig.network v1.0.0 epsilon derivation,bip122:000000000019d6689c085ae165831e93,sender,path"
        );
        assert_eq!(
            derivation_path(1, Chain::Bitcoin, PLAIN),
            "sig.network v2.0.0 epsilon derivation:bip122:000000000019d6689c085ae165831e93:sender:path"
        );
        assert_eq!(
            derivation_path(0, Chain::Canton, PLAIN),
            "sig.network v1.0.0 epsilon derivation,canton:global,sender,path"
        );
        assert_eq!(
            derivation_path(1, Chain::Canton, PLAIN),
            "sig.network v2.0.0 epsilon derivation:canton:global:sender:path"
        );
        assert_eq!(
            derivation_path(1, Chain::Ethereum, KeyPurpose::System { path: "path" }),
            "sig.network v2.0.0 epsilon derivation:eip155:1:%admin#:path"
        );
    }

    #[test]
    fn test_derive_epsilon_stays_the_same() {
        // Expected scalar values for Ethereum epsilon derivation
        let expected_eth_v0 = Scalar::from_bytes([
            0x8F, 0x2A, 0x2D, 0xCC, 0x32, 0xB3, 0x35, 0xE1, 0x21, 0x40, 0x4D, 0xE8, 0x43, 0x6E,
            0xD8, 0x95, 0x83, 0xD5, 0xA6, 0x39, 0x70, 0xA6, 0x1A, 0x23, 0xD9, 0x78, 0xAC, 0x12,
            0x5B, 0xF2, 0x00, 0x69,
        ])
        .unwrap();

        let expected_eth_v1 = Scalar::from_bytes([
            0x51, 0x8D, 0x99, 0xF3, 0x4A, 0x18, 0x27, 0xA5, 0x9E, 0xD2, 0xA8, 0xC6, 0xB7, 0x00,
            0x3C, 0xF4, 0x24, 0x6C, 0x6E, 0xCA, 0x82, 0xE8, 0x4B, 0xFB, 0x40, 0xC4, 0x7D, 0xD8,
            0xD1, 0xA1, 0xD4, 0x2F,
        ])
        .unwrap();

        assert_eq!(
            derive_epsilon(0, Chain::Ethereum, PLAIN),
            Ok(expected_eth_v0)
        );
        assert_eq!(
            derive_epsilon(1, Chain::Ethereum, PLAIN),
            Ok(expected_eth_v1)
        );

        // Expected scalar values for Solana epsilon derivation
        let expected_sol_v0 = Scalar::from_bytes([
            0x61, 0xDD, 0xCA, 0xFF, 0x12, 0xF1, 0x29, 0xBB, 0x47, 0x3C, 0xFB, 0x26, 0x8A, 0x01,
            0x9C, 0x7D, 0x2F, 0xDD, 0xF2, 0x65, 0xF1, 0xD9, 0x5A, 0xC5, 0xAD, 0x65, 0x4E, 0x27,
            0x9B, 0xA3, 0x39, 0x92,
        ])
        .unwrap();

        let expected_sol_v1 = Scalar::from_bytes([
            0xF1, 0x83, 0x50, 0x69, 0xD5, 0x52, 0x22, 0xD0, 0x08, 0xB3, 0x07, 0x39, 0x81, 0x98,
            0x85, 0x00, 0xAB, 0x7C, 0xE2, 0x96, 0x88, 0x43, 0xE7, 0x1A, 0xD9, 0x38, 0x8B, 0xF8,
            0xFA, 0x93, 0xFF, 0x9E,
        ])
        .unwrap();

        assert_eq!(derive_epsilon(0, Chain::Solana, PLAIN), Ok(expected_sol_v0));
        assert_eq!(derive_epsilon(1, Chain::Solana, PLAIN), Ok(expected_sol_v1));

        // Expected scalar values for NEAR epsilon derivation
        let expected_near_v0 = Scalar::from_bytes([
            0x0E, 0x32, 0x6D, 0x79, 0x76, 0x3A, 0xEE, 0xC1, 0x9F, 0x16, 0x6A, 0xE1, 0xC4, 0x6B,
            0x08, 0x65, 0x29, 0xC9, 0x40, 0x21, 0xC3, 0x6E, 0xD6, 0xFF, 0x4C, 0xF2, 0x2C, 0xD7,
            0xF4, 0xE6, 0x5A, 0x97,
        ])
        .unwrap();

        let expected_near_v1 = Scalar::from_bytes([
            0xFD, 0xFD, 0xB2, 0x01, 0x7F, 0x43, 0xB6, 0x8B, 0x2C, 0xC9, 0x8F, 0x6B, 0x4F, 0x87,
            0x55, 0x4C, 0xE3, 0x2C, 0xC7, 0x13, 0xE5, 0xC3, 0xFF, 0x33, 0x70, 0x34, 0x93, 0x94,
            0xD9, 0xF7, 0x1E, 0x4B,
        ])
        .unwrap();

        let near = KeyPurpose::Plain {
            sender: "sender.near",
            path: "path",
        };
        assert_eq!(derive_epsilon(0, Chain::NEAR, near), Ok(expected_near_v0));
        assert_eq!(derive_epsilon(1, Chain::NEAR, near), Ok(expected_near_v1));
    }

    #[test]
    fn test_derive_epsilon_canton_stays_the_same() {
        let expected_canton_v0 = Scalar::from_bytes([
            0xA4, 0xCF, 0xD1, 0x98, 0x07, 0xD1, 0x96, 0x8D, 0xAA, 0xDA, 0x88, 0xB5, 0xB8, 0x12,
            0xAD, 0x61, 0xC6, 0x24, 0x08, 0xB4, 0x84, 0xB5, 0x51, 0xFC, 0x37, 0x30, 0x34, 0x51,
            0x03, 0x14, 0x61, 0x4C,
        ])
        .unwrap();

        let expected_canton_v1 = Scalar::from_bytes([
            0x49, 0x05, 0x93, 0xA1, 0x00, 0xEA, 0xE1, 0x26, 0x98, 0x8F, 0x3B, 0xA4, 0xEC, 0x3A,
            0xBD, 0x75, 0x4C, 0xD2, 0x4C, 0xD9, 0xA6, 0x6B, 0x14, 0x71, 0x27, 0x6A, 0x1B, 0xC3,
            0xE3, 0x10, 0xCA, 0xBD,
        ])
        .unwrap();

        assert_eq!(
            derive_epsilon(0, Chain::Canton, PLAIN),
            Ok(expected_canton_v0)
        );
        assert_eq!(
            derive_epsilon(1, Chain::Canton, PLAIN),
            Ok(expected_canton_v1)
        );
    }

    /// Golden: `@sig-net/midnight` is what integrators derive their expected
    /// keys with, so agreeing with it is the property that matters. Every
    /// expected value comes from that package (see the fixture's provenance);
    /// nothing here is computed by the code under test.
    #[test]
    fn midnight_epsilon_matches_the_reference_implementation() {
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/midnight-epsilon.json")).unwrap();

        assert_eq!(
            golden["constants"]["epsilon_derivation_prefix"],
            DERIVATION_PREFIX_V1
        );
        assert_eq!(
            golden["constants"]["midnight_chain_id"],
            Chain::Midnight.caip2_chain_id()
        );

        for vector in golden["vectors"].as_array().unwrap() {
            let (sender, path) = (
                vector["requester"].as_str().unwrap(),
                vector["path"].as_str().unwrap(),
            );
            let mut expected = [0u8; 32];
            hex::decode_to_slice(vector["epsilon"].as_str().unwrap(), &mut expected).unwrap();
            // The reference derives the response key as a request under its path.
            let purpose = if path == "midnight response key" {
                KeyPurpose::Attestation { sender }
            } else {
                KeyPurpose::Bidirectional { sender, path }
            };
            assert_eq!(
                derive_epsilon(1, Chain::Midnight, purpose)
                    .unwrap()
                    .to_bytes()
                    .as_slice(),
                expected,
                "requester {sender}, path {path:?}"
            );
        }
    }

    /// `versioned_derivation_path` pins each version to a format by hand, so a
    /// bump of `LATEST_MPC_KEY_VERSION` without a new match arm would reject every
    /// request at the new version.
    #[test]
    fn the_latest_key_version_has_a_format() {
        let (sender, path) = ("sender", "path");
        for (chain, purpose) in [
            (Chain::Ethereum, KeyPurpose::Plain { sender, path }),
            (Chain::Solana, KeyPurpose::Bidirectional { sender, path }),
            (Chain::Solana, KeyPurpose::Attestation { sender }),
            (Chain::Ethereum, KeyPurpose::System { path }),
        ] {
            assert!(
                derive_epsilon(LATEST_MPC_KEY_VERSION, chain, purpose).is_ok(),
                "{purpose:?}"
            );
        }
    }

    /// The key version 2 table of doc/account-derivation.md.
    #[test]
    fn key_version_2_derivation_paths() {
        let (sender, path) = ("sender", "path");
        assert_eq!(
            derivation_path(2, Chain::Ethereum, KeyPurpose::Plain { sender, path }),
            "sig.network derivation:2:plain:eip155:1:sender:path"
        );
        assert_eq!(
            derivation_path(
                2,
                Chain::Ethereum,
                KeyPurpose::Bidirectional { sender, path }
            ),
            "sig.network derivation:2:bidirectional:eip155:1:sender:path"
        );
        assert_eq!(
            derivation_path(2, Chain::Solana, KeyPurpose::Attestation { sender }),
            "sig.network derivation:2:attestation:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:sender"
        );
        assert_eq!(
            derivation_path(2, Chain::Ethereum, KeyPurpose::System { path }),
            "sig.network derivation:2:system:eip155:1:path"
        );
    }

    fn scalar(hex_bytes: &str) -> Scalar {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_bytes, &mut bytes).unwrap();
        Scalar::from_bytes(bytes).unwrap()
    }

    fn v2_epsilon(chain: Chain, purpose: KeyPurpose<'_>) -> Scalar {
        hash_derivation_path(chain, derivation_path(2, chain, purpose))
    }

    /// Expected values are keccak-256 (sha3-256 on NEAR) of the derivation paths
    /// above, computed outside this crate (`cast keccak`, Python's `hashlib`).
    #[test]
    fn key_version_2_epsilons() {
        let (sender, path) = ("sender", "path");
        assert_eq!(
            v2_epsilon(Chain::Ethereum, KeyPurpose::Plain { sender, path }),
            scalar("5268a12d5cf592cc5f3b668ee66e8d10d29c39553c3dd2ea61da748af4b324fb")
        );
        assert_eq!(
            v2_epsilon(Chain::Ethereum, KeyPurpose::Bidirectional { sender, path }),
            scalar("99d9614ae3b4d545344e51e68885fdc92d64160275892278b282889baa6ab479")
        );
        assert_eq!(
            v2_epsilon(Chain::Solana, KeyPurpose::Attestation { sender }),
            scalar("fb5f74e32c045f3beadd6a6cd8dc5bd68feeed174bd7ae80ea36f8d7c5d0dd8b")
        );
        assert_eq!(
            v2_epsilon(Chain::Ethereum, KeyPurpose::System { path }),
            scalar("e2a9df0418ef5628fecd7ff9f2d5ed4a2775ac2a63d961be23cca6ae82bee0e8")
        );
        assert_eq!(
            v2_epsilon(
                Chain::NEAR,
                KeyPurpose::Plain {
                    sender: "sender.near",
                    path
                }
            ),
            scalar("eb990bf8724ef278657009900b06489c2d87155ffdd061921f1f9ba060015614")
        );
    }

    /// Key version 1 names no purpose in the path: a bidirectional key is the plain key.
    #[test]
    fn key_version_1_bidirectional_key_is_the_plain_key() {
        let (sender, path) = ("sender", "path");
        assert_eq!(
            derive_epsilon(1, Chain::Solana, KeyPurpose::Bidirectional { sender, path }),
            derive_epsilon(1, Chain::Solana, KeyPurpose::Plain { sender, path }),
        );
    }

    /// At key version 1 the attestation key is the plain key under the reserved path.
    #[test]
    fn key_version_1_attestation_key_is_the_reserved_path_key() {
        let attestation = KeyPurpose::Attestation { sender: "sender" };
        assert_eq!(
            derivation_path(1, Chain::Solana, attestation),
            "sig.network v2.0.0 epsilon derivation:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:sender:solana response key"
        );
        assert_eq!(
            derive_epsilon(1, Chain::Solana, attestation),
            Ok(scalar(
                "1a4bfe456b826af8269cb3adef1489e4ada6c79817faa8f7b17fad6239353282"
            ))
        );
    }

    fn refused(key_version: KeyVersion, reason: &'static str) -> Result<Scalar, DeriveError> {
        Err(DeriveError::Refused {
            key_version,
            reason,
        })
    }

    /// Key version 0 predates bidirectional signing; plain and system keys stay.
    #[test]
    fn key_version_0_has_no_bidirectional_or_attestation_key() {
        let (sender, path) = ("sender", "path");
        assert_eq!(
            derive_epsilon(0, Chain::Solana, KeyPurpose::Bidirectional { sender, path }),
            refused(0, "predates bidirectional signing")
        );
        assert_eq!(
            derive_epsilon(0, Chain::Solana, KeyPurpose::Attestation { sender }),
            refused(0, "predates bidirectional signing")
        );
        assert!(derive_epsilon(0, Chain::Solana, KeyPurpose::Plain { sender, path }).is_ok());
        assert!(derive_epsilon(0, Chain::Ethereum, KeyPurpose::System { path }).is_ok());
    }

    /// A chain that is not a bidirectional source has an attestation key only from
    /// key version 2.
    #[test]
    fn attestation_keys_below_key_version_2_need_a_reserved_path() {
        let attestation = KeyPurpose::Attestation { sender: "sender" };
        assert_eq!(
            derive_epsilon(1, Chain::Ethereum, attestation),
            refused(1, "the chain has no attestation key")
        );
        assert!(versioned_derivation_path(2, Chain::Ethereum, attestation).is_ok());
    }

    /// Below key version 2 a request naming the reserved path would derive the
    /// attestation key, so it is refused; from key version 2 the path is ordinary.
    #[test]
    fn requests_below_key_version_2_cannot_name_the_reserved_path() {
        for (chain, path) in [
            (Chain::Solana, "solana response key"),
            (Chain::Canton, "canton response key"),
            (Chain::Midnight, "midnight response key"),
        ] {
            let plain = KeyPurpose::Plain {
                sender: "sender",
                path,
            };
            let bidirectional = KeyPurpose::Bidirectional {
                sender: "sender",
                path,
            };
            let reserved = "the path holds the attestation key";
            assert_eq!(derive_epsilon(0, chain, plain), refused(0, reserved));
            assert_eq!(derive_epsilon(1, chain, plain), refused(1, reserved));
            assert_eq!(
                derive_epsilon(1, chain, bidirectional),
                refused(1, reserved)
            );
            assert!(versioned_derivation_path(2, chain, plain).is_ok());
            assert!(versioned_derivation_path(2, chain, bidirectional).is_ok());
        }
        // Only the chain's own reserved path.
        let other_chains = KeyPurpose::Plain {
            sender: "sender",
            path: "solana response key",
        };
        assert!(derive_epsilon(1, Chain::Ethereum, other_chains).is_ok());
        assert!(derive_epsilon(1, Chain::Canton, other_chains).is_ok());
    }

    #[test]
    fn reserved_paths_are_reserved_below_key_version_2() {
        assert_eq!(reserved_path(0, Chain::Solana), Some("solana response key"));
        assert_eq!(reserved_path(1, Chain::Canton), Some("canton response key"));
        assert_eq!(
            reserved_path(1, Chain::Midnight),
            Some("midnight response key")
        );
        assert_eq!(reserved_path(2, Chain::Solana), None);
        assert_eq!(reserved_path(1, Chain::Ethereum), None);
    }

    /// A key version is not served until `LATEST_MPC_KEY_VERSION` reaches it.
    #[test]
    fn versions_above_the_latest_are_refused() {
        let unsupported = LATEST_MPC_KEY_VERSION + 1;
        for (chain, purpose) in [
            (Chain::Ethereum, PLAIN),
            (Chain::Solana, KeyPurpose::Attestation { sender: "sender" }),
        ] {
            assert_eq!(
                derive_epsilon(unsupported, chain, purpose),
                Err(DeriveError::UnsupportedKeyVersion(unsupported))
            );
        }
    }
}
