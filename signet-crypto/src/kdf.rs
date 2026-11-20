use crate::KeyVersion;
use k256::{
    ecdsa::{RecoveryId, VerifyingKey},
    elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, CurveArithmetic},
    AffinePoint, Scalar, Secp256k1,
};
use sha3::{Digest, Keccak256, Sha3_256};
use signet_primitives::{Chain, PublicKey, ScalarExt, Signature, MAX_SUPPORTED_MPC_KEY_VERSION};

// Constant prefix that ensures epsilon derivation values are used specifically for
// Sig.Network with key derivation protocol vX.Y.Z.
pub const EPSILON_DERIVATION_PREFIX_V1: &str = "sig.network v1.0.0 epsilon derivation";
pub const EPSILON_DERIVATION_PREFIX_V2: &str = "sig.network v2.0.0 epsilon derivation";
/// Prefix of every derivation path from key version 2, which names the version itself.
pub const SIGNET_DERIVATION_PREFIX: &str = "sig.network derivation";

/// The key version is not one this derivation scheme knows how to route, or
/// has no such key on the chain.
///
/// Every version maps to exactly one derivation format; an unknown one is
/// rejected rather than silently coerced to the latest format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedKeyVersion(pub KeyVersion);

impl std::fmt::Display for UnsupportedKeyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported key_version {}", self.0)
    }
}

impl std::error::Error for UnsupportedKeyVersion {}

/// What a key signs (doc/account-derivation.md). From key version 2 the
/// derivation path names it, so two purposes never derive the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyPurpose {
    Plain,
    Bidirectional,
    Attestation,
    System,
}

impl KeyPurpose {
    const fn as_str(self) -> &'static str {
        match self {
            KeyPurpose::Plain => "plain",
            KeyPurpose::Bidirectional => "bidirectional",
            KeyPurpose::Attestation => "attestation",
            KeyPurpose::System => "system",
        }
    }
}

impl std::fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The purpose of a key a request names, set by the signing API the request came on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPurpose {
    Plain,
    Bidirectional,
}

impl From<RequestPurpose> for KeyPurpose {
    fn from(purpose: RequestPurpose) -> Self {
        match purpose {
            RequestPurpose::Plain => KeyPurpose::Plain,
            RequestPurpose::Bidirectional => KeyPurpose::Bidirectional,
        }
    }
}

/// The path that holds a chain's attestation key at key version 1, which no request
/// at that version may name. `None` on chains that are not bidirectional sources.
pub const fn reserved_attestation_path_v1(chain: Chain) -> Option<&'static str> {
    match chain {
        Chain::Solana => Some("solana response key"),
        Chain::Hydration => Some("hydration response key"),
        Chain::Canton => Some("canton response key"),
        Chain::Midnight => Some("midnight response key"),
        _ => None,
    }
}

/// The key to derive an epsilon for, at any key version.
#[derive(Debug, Clone, Copy)]
pub enum DerivationParams<'a> {
    /// Key a request names, owned by its sender on a specific chain.
    Request {
        chain: Chain,
        purpose: RequestPurpose,
        sender: &'a str,
        path: &'a str,
    },
    /// Key the MPC attests bidirectional outcomes to a contract with.
    Attestation { chain: Chain, sender: &'a str },
    /// Account owned by MPC system on a specific chain.
    SystemAccount { chain: Chain, path: &'a str },
}

impl DerivationParams<'_> {
    /// The derivation path at `key_version`; refuses versions above
    /// `MAX_SUPPORTED_MPC_KEY_VERSION`.
    pub fn derivation_path(
        &self,
        key_version: KeyVersion,
    ) -> Result<String, UnsupportedKeyVersion> {
        if key_version > MAX_SUPPORTED_MPC_KEY_VERSION {
            return Err(UnsupportedKeyVersion(key_version));
        }
        self.versioned_derivation_path(key_version)
    }

    fn chain(&self) -> Chain {
        match *self {
            DerivationParams::Request { chain, .. }
            | DerivationParams::Attestation { chain, .. }
            | DerivationParams::SystemAccount { chain, .. } => chain,
        }
    }

    /// Each key version is pinned to one format; unknown versions are rejected.
    /// Ignores `MAX_SUPPORTED_MPC_KEY_VERSION`, so formats are testable before they are served.
    fn versioned_derivation_path(
        &self,
        key_version: KeyVersion,
    ) -> Result<String, UnsupportedKeyVersion> {
        match *self {
            DerivationParams::Request {
                chain,
                purpose,
                sender,
                path,
            } => match key_version {
                0 => Ok(derivation_path_v0(chain, sender, path)),
                1 => Ok(derivation_path_v1(chain, sender, path)),
                2 => Ok(derivation_path_v2(chain, purpose.into(), &[sender, path])),
                other => Err(UnsupportedKeyVersion(other)),
            },
            // Key version 0 predates bidirectional signing, so it has no attestation key.
            // At key version 1 the attestation key is a plain key under a reserved path.
            DerivationParams::Attestation { chain, sender } => match key_version {
                1 => reserved_attestation_path_v1(chain)
                    .map(|path| derivation_path_v1(chain, sender, path))
                    .ok_or(UnsupportedKeyVersion(key_version)),
                2 => Ok(derivation_path_v2(
                    chain,
                    KeyPurpose::Attestation,
                    &[sender],
                )),
                other => Err(UnsupportedKeyVersion(other)),
            },
            DerivationParams::SystemAccount { chain, path } => match key_version {
                0 => Ok(derivation_path_v0(chain, "%admin#", path)),
                1 => Ok(derivation_path_v1(chain, "%admin#", path)),
                2 => Ok(derivation_path_v2(chain, KeyPurpose::System, &[path])),
                other => Err(UnsupportedKeyVersion(other)),
            },
        }
    }
}

/// Key version 0: `sig.network v1.0.0 epsilon derivation,{deprecated chain id},{sender},{path}`.
fn derivation_path_v0(chain: Chain, sender: &str, path: &str) -> String {
    let chain_id = chain.deprecated_chain_id();
    format!("{EPSILON_DERIVATION_PREFIX_V1},{chain_id},{sender},{path}")
}

/// Key version 1: `sig.network v2.0.0 epsilon derivation:{caip2 chain id}:{sender}:{path}`.
fn derivation_path_v1(chain: Chain, sender: &str, path: &str) -> String {
    let chain_id = chain.caip2_chain_id();
    format!("{EPSILON_DERIVATION_PREFIX_V2}:{chain_id}:{sender}:{path}")
}

/// Key version 2: `sig.network derivation:2:{purpose}:{caip2 chain id}:{fields}`, where the
/// fields depend on the purpose.
fn derivation_path_v2(chain: Chain, purpose: KeyPurpose, fields: &[&str]) -> String {
    let chain_id = chain.caip2_chain_id();
    let mut path = format!("{SIGNET_DERIVATION_PREFIX}:2:{purpose}:{chain_id}");
    for field in fields {
        path.push(':');
        path.push_str(field);
    }
    path
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

pub fn derive_epsilon(
    key_version: KeyVersion,
    params: DerivationParams<'_>,
) -> Result<Scalar, UnsupportedKeyVersion> {
    Ok(hash_derivation_path(
        params.chain(),
        params.derivation_path(key_version)?,
    ))
}

/// Epsilon of `sender`'s attestation key on `chain`.
pub fn derive_attestation_epsilon(
    key_version: KeyVersion,
    chain: Chain,
    sender: &str,
) -> Result<Scalar, UnsupportedKeyVersion> {
    derive_epsilon(key_version, DerivationParams::Attestation { chain, sender })
}

fn derive_request_epsilon(
    key_version: KeyVersion,
    chain: Chain,
    purpose: RequestPurpose,
    sender: &str,
    path: &str,
) -> Result<Scalar, UnsupportedKeyVersion> {
    derive_epsilon(
        key_version,
        DerivationParams::Request {
            chain,
            purpose,
            sender,
            path,
        },
    )
}

pub fn derive_epsilon_eth(
    key_version: KeyVersion,
    purpose: RequestPurpose,
    address: &str,
    path: &str,
) -> Result<Scalar, UnsupportedKeyVersion> {
    derive_request_epsilon(key_version, Chain::Ethereum, purpose, address, path)
}

pub fn derive_epsilon_sol(
    key_version: KeyVersion,
    purpose: RequestPurpose,
    address: &str,
    path: &str,
) -> Result<Scalar, UnsupportedKeyVersion> {
    derive_request_epsilon(key_version, Chain::Solana, purpose, address, path)
}

pub fn derive_epsilon_canton(
    key_version: KeyVersion,
    purpose: RequestPurpose,
    address: &str,
    path: &str,
) -> Result<Scalar, UnsupportedKeyVersion> {
    derive_request_epsilon(key_version, Chain::Canton, purpose, address, path)
}

pub fn derive_epsilon_hydration(
    key_version: KeyVersion,
    purpose: RequestPurpose,
    address: &str,
    path: &str,
) -> Result<Scalar, UnsupportedKeyVersion> {
    derive_request_epsilon(key_version, Chain::Hydration, purpose, address, path)
}

pub fn derive_epsilon_bitcoin(
    key_version: KeyVersion,
    purpose: RequestPurpose,
    address: &str,
    path: &str,
) -> Result<Scalar, UnsupportedKeyVersion> {
    derive_request_epsilon(key_version, Chain::Bitcoin, purpose, address, path)
}

pub fn derive_epsilon_midnight(
    key_version: KeyVersion,
    purpose: RequestPurpose,
    address: &str,
    path: &str,
) -> Result<Scalar, UnsupportedKeyVersion> {
    derive_request_epsilon(key_version, Chain::Midnight, purpose, address, path)
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

    #[test]
    fn test_derivation_path_stays_the_same() {
        assert_eq!(
            DerivationParams::Request {
                chain: Chain::Ethereum,
                purpose: RequestPurpose::Plain,
                sender: "sender",
                path: "path"
            }
            .derivation_path(0)
            .unwrap(),
            "sig.network v1.0.0 epsilon derivation,0x1,sender,path"
        );
        assert_eq!(
            DerivationParams::Request {
                chain: Chain::Ethereum,
                purpose: RequestPurpose::Plain,
                sender: "sender",
                path: "path"
            }
            .derivation_path(1)
            .unwrap(),
            "sig.network v2.0.0 epsilon derivation:eip155:1:sender:path"
        );

        assert_eq!(
            DerivationParams::Request {
                chain: Chain::Solana,
                purpose: RequestPurpose::Plain,
                sender: "sender",
                path: "path"
            }
            .derivation_path(0)
            .unwrap(),
            "sig.network v1.0.0 epsilon derivation,0x800001f5,sender,path"
        );
        assert_eq!(
            DerivationParams::Request { chain: Chain::Solana, purpose: RequestPurpose::Plain, sender: "sender", path: "path" }
                .derivation_path(1).unwrap(),
            "sig.network v2.0.0 epsilon derivation:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:sender:path"
        );

        assert_eq!(
            DerivationParams::Request {
                chain: Chain::NEAR,
                purpose: RequestPurpose::Plain,
                sender: "sender",
                path: "path"
            }
            .derivation_path(0)
            .unwrap(),
            "sig.network v1.0.0 epsilon derivation,0x18d,sender,path"
        );

        assert_eq!(
            DerivationParams::Request {
                chain: Chain::NEAR,
                purpose: RequestPurpose::Plain,
                sender: "sender",
                path: "path"
            }
            .derivation_path(1)
            .unwrap(),
            "sig.network v2.0.0 epsilon derivation:near:mainnet:sender:path"
        );

        assert_eq!(
            DerivationParams::Request { chain: Chain::Bitcoin, purpose: RequestPurpose::Plain, sender: "sender", path: "path" }
                .derivation_path(0).unwrap(),
            "sig.network v1.0.0 epsilon derivation,bip122:000000000019d6689c085ae165831e93,sender,path"
        );
        assert_eq!(
            DerivationParams::Request { chain: Chain::Bitcoin, purpose: RequestPurpose::Plain, sender: "sender", path: "path" }
                .derivation_path(1).unwrap(),
            "sig.network v2.0.0 epsilon derivation:bip122:000000000019d6689c085ae165831e93:sender:path"
        );

        assert_eq!(
            DerivationParams::Request {
                chain: Chain::Canton,
                purpose: RequestPurpose::Plain,
                sender: "sender",
                path: "path"
            }
            .derivation_path(0)
            .unwrap(),
            "sig.network v1.0.0 epsilon derivation,canton:global,sender,path"
        );
        assert_eq!(
            DerivationParams::Request {
                chain: Chain::Canton,
                purpose: RequestPurpose::Plain,
                sender: "sender",
                path: "path"
            }
            .derivation_path(1)
            .unwrap(),
            "sig.network v2.0.0 epsilon derivation:canton:global:sender:path"
        );

        assert_eq!(
            DerivationParams::SystemAccount {
                chain: Chain::Ethereum,
                path: "path"
            }
            .derivation_path(1)
            .unwrap(),
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
            derive_epsilon(
                0,
                DerivationParams::Request {
                    chain: Chain::Ethereum,
                    purpose: RequestPurpose::Plain,
                    sender: "sender",
                    path: "path"
                }
            ),
            Ok(expected_eth_v0)
        );
        assert_eq!(
            derive_epsilon(
                1,
                DerivationParams::Request {
                    chain: Chain::Ethereum,
                    purpose: RequestPurpose::Plain,
                    sender: "sender",
                    path: "path"
                }
            ),
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

        assert_eq!(
            derive_epsilon(
                0,
                DerivationParams::Request {
                    chain: Chain::Solana,
                    purpose: RequestPurpose::Plain,
                    sender: "sender",
                    path: "path"
                }
            ),
            Ok(expected_sol_v0)
        );
        assert_eq!(
            derive_epsilon(
                1,
                DerivationParams::Request {
                    chain: Chain::Solana,
                    purpose: RequestPurpose::Plain,
                    sender: "sender",
                    path: "path"
                }
            ),
            Ok(expected_sol_v1)
        );

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

        // Test NEAR epsilon derivation
        assert_eq!(
            derive_epsilon(
                0,
                DerivationParams::Request {
                    chain: Chain::NEAR,
                    purpose: RequestPurpose::Plain,
                    sender: "sender.near",
                    path: "path"
                }
            ),
            Ok(expected_near_v0)
        );
        assert_eq!(
            derive_epsilon(
                1,
                DerivationParams::Request {
                    chain: Chain::NEAR,
                    purpose: RequestPurpose::Plain,
                    sender: "sender.near",
                    path: "path"
                }
            ),
            Ok(expected_near_v1)
        );
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
            derive_epsilon(
                0,
                DerivationParams::Request {
                    chain: Chain::Canton,
                    purpose: RequestPurpose::Plain,
                    sender: "sender",
                    path: "path"
                }
            ),
            Ok(expected_canton_v0)
        );
        assert_eq!(
            derive_epsilon(
                1,
                DerivationParams::Request {
                    chain: Chain::Canton,
                    purpose: RequestPurpose::Plain,
                    sender: "sender",
                    path: "path"
                }
            ),
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
            EPSILON_DERIVATION_PREFIX_V2
        );
        assert_eq!(
            golden["constants"]["midnight_chain_id"],
            Chain::Midnight.caip2_chain_id()
        );

        for vector in golden["vectors"].as_array().unwrap() {
            let (requester, path) = (
                vector["requester"].as_str().unwrap(),
                vector["path"].as_str().unwrap(),
            );
            let mut expected = [0u8; 32];
            hex::decode_to_slice(vector["epsilon"].as_str().unwrap(), &mut expected).unwrap();
            assert_eq!(
                derive_epsilon_midnight(1, RequestPurpose::Bidirectional, requester, path)
                    .unwrap()
                    .to_bytes()
                    .as_slice(),
                expected,
                "requester {requester}, path {path:?}"
            );
        }
    }

    // Key version 0 has the comma format, which the reference implementation cannot
    // produce, so no golden reaches it. Versions above the highest supported are
    // rejected rather than coerced to another format.
    #[test]
    fn test_derive_epsilon_midnight_key_version_routing() {
        let (sender, path) = ("ab".repeat(32), "caller-path");
        assert_ne!(
            derive_epsilon_midnight(0, RequestPurpose::Bidirectional, &sender, path),
            derive_epsilon_midnight(1, RequestPurpose::Bidirectional, &sender, path),
        );
        let unsupported = MAX_SUPPORTED_MPC_KEY_VERSION + 1;
        assert_eq!(
            derive_epsilon_midnight(unsupported, RequestPurpose::Bidirectional, &sender, path),
            Err(UnsupportedKeyVersion(unsupported)),
        );
    }

    /// `versioned_derivation_path` pins each version to a format by hand, so a
    /// bump of `MAX_SUPPORTED_MPC_KEY_VERSION` without a new match arm would
    /// reject every request at the new version.
    #[test]
    fn supported_key_versions_have_a_format() {
        for purpose in [RequestPurpose::Plain, RequestPurpose::Bidirectional] {
            assert!(
                derive_epsilon_eth(MAX_SUPPORTED_MPC_KEY_VERSION, purpose, "sender", "path")
                    .is_ok()
            );
        }
        assert!(
            derive_attestation_epsilon(MAX_SUPPORTED_MPC_KEY_VERSION, Chain::Solana, "sender")
                .is_ok()
        );
        assert!(derive_epsilon(
            MAX_SUPPORTED_MPC_KEY_VERSION,
            DerivationParams::SystemAccount {
                chain: Chain::Ethereum,
                path: "path"
            }
        )
        .is_ok());
    }

    fn v2(params: DerivationParams<'_>) -> String {
        params.versioned_derivation_path(2).unwrap()
    }

    /// The key version 2 table of doc/account-derivation.md.
    #[test]
    fn key_version_2_derivation_paths() {
        let (sender, path) = ("sender", "path");
        assert_eq!(
            v2(DerivationParams::Request {
                chain: Chain::Ethereum,
                purpose: RequestPurpose::Plain,
                sender,
                path
            }),
            "sig.network derivation:2:plain:eip155:1:sender:path"
        );
        assert_eq!(
            v2(DerivationParams::Request {
                chain: Chain::Ethereum,
                purpose: RequestPurpose::Bidirectional,
                sender,
                path
            }),
            "sig.network derivation:2:bidirectional:eip155:1:sender:path"
        );
        assert_eq!(
            v2(DerivationParams::Attestation {
                chain: Chain::Solana,
                sender
            }),
            "sig.network derivation:2:attestation:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:sender"
        );
        assert_eq!(
            v2(DerivationParams::SystemAccount {
                chain: Chain::Ethereum,
                path
            }),
            "sig.network derivation:2:system:eip155:1:path"
        );
    }

    fn scalar(hex_bytes: &str) -> Scalar {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_bytes, &mut bytes).unwrap();
        Scalar::from_bytes(bytes).unwrap()
    }

    fn v2_epsilon(params: DerivationParams<'_>) -> Scalar {
        let path = params.versioned_derivation_path(2).unwrap();
        hash_derivation_path(params.chain(), path)
    }

    /// Expected values are keccak-256 (sha3-256 on NEAR) of the derivation paths
    /// above, computed outside this crate (`cast keccak`, Python's `hashlib`).
    #[test]
    fn key_version_2_epsilons() {
        let (sender, path) = ("sender", "path");
        assert_eq!(
            v2_epsilon(DerivationParams::Request {
                chain: Chain::Ethereum,
                purpose: RequestPurpose::Plain,
                sender,
                path
            }),
            scalar("5268a12d5cf592cc5f3b668ee66e8d10d29c39553c3dd2ea61da748af4b324fb")
        );
        assert_eq!(
            v2_epsilon(DerivationParams::Request {
                chain: Chain::Ethereum,
                purpose: RequestPurpose::Bidirectional,
                sender,
                path
            }),
            scalar("99d9614ae3b4d545344e51e68885fdc92d64160275892278b282889baa6ab479")
        );
        assert_eq!(
            v2_epsilon(DerivationParams::Attestation {
                chain: Chain::Solana,
                sender
            }),
            scalar("fb5f74e32c045f3beadd6a6cd8dc5bd68feeed174bd7ae80ea36f8d7c5d0dd8b")
        );
        assert_eq!(
            v2_epsilon(DerivationParams::SystemAccount {
                chain: Chain::Ethereum,
                path
            }),
            scalar("e2a9df0418ef5628fecd7ff9f2d5ed4a2775ac2a63d961be23cca6ae82bee0e8")
        );
        assert_eq!(
            v2_epsilon(DerivationParams::Request {
                chain: Chain::NEAR,
                purpose: RequestPurpose::Plain,
                sender: "sender.near",
                path
            }),
            scalar("eb990bf8724ef278657009900b06489c2d87155ffdd061921f1f9ba060015614")
        );
    }

    /// Key versions 0 and 1 have no purposes: a bidirectional key is the plain key.
    #[test]
    fn earlier_key_versions_ignore_the_purpose() {
        for key_version in [0, 1] {
            assert_eq!(
                derive_epsilon_sol(key_version, RequestPurpose::Bidirectional, "sender", "path"),
                derive_epsilon_sol(key_version, RequestPurpose::Plain, "sender", "path"),
            );
        }
    }

    /// At key version 1 the attestation key is the plain key under the reserved path.
    #[test]
    fn key_version_1_attestation_key_is_the_reserved_path_key() {
        assert_eq!(
            derive_attestation_epsilon(1, Chain::Solana, "sender"),
            derive_epsilon_sol(1, RequestPurpose::Plain, "sender", "solana response key"),
        );
        assert_eq!(
            derive_attestation_epsilon(1, Chain::Solana, "sender"),
            Ok(scalar(
                "1a4bfe456b826af8269cb3adef1489e4ada6c79817faa8f7b17fad6239353282"
            ))
        );
    }

    /// Key version 0 predates bidirectional signing, and a chain that is not a
    /// bidirectional source has no attestation key before key version 2.
    #[test]
    fn attestation_key_versions() {
        assert_eq!(
            derive_attestation_epsilon(0, Chain::Solana, "sender"),
            Err(UnsupportedKeyVersion(0))
        );
        assert_eq!(
            derive_attestation_epsilon(1, Chain::Ethereum, "sender"),
            Err(UnsupportedKeyVersion(1))
        );
        assert!(DerivationParams::Attestation {
            chain: Chain::Ethereum,
            sender: "sender"
        }
        .versioned_derivation_path(2)
        .is_ok());
    }

    /// A key version is not served until `MAX_SUPPORTED_MPC_KEY_VERSION` reaches it.
    #[test]
    fn versions_above_max_supported_are_refused() {
        let unsupported = MAX_SUPPORTED_MPC_KEY_VERSION + 1;
        assert_eq!(
            derive_epsilon_eth(unsupported, RequestPurpose::Plain, "sender", "path"),
            Err(UnsupportedKeyVersion(unsupported))
        );
        assert_eq!(
            derive_attestation_epsilon(unsupported, Chain::Solana, "sender"),
            Err(UnsupportedKeyVersion(unsupported))
        );
    }
}
