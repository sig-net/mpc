use crate::types::{Address, KeyVersion, Path, Purpose};
use crate::{PublicKey, ScalarExt};
use anyhow::Context;
use k256::{
    ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, VerifyingKey},
    elliptic_curve::{
        point::{AffineCoordinates, DecompressPoint},
        sec1::ToEncodedPoint,
        CurveArithmetic,
    },
    Scalar, Secp256k1, SecretKey,
};
use mpc_primitives::{Chain, Signature as MpcSignature};
use near_account_id::AccountId;
use sha3::{Digest, Keccak256, Sha3_256};

// Constant prefix that ensures epsilon derivation values are used specifically for
// Sig.Network with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX_V1: &str = "sig.network v1.0.0 epsilon derivation";
const EPSILON_DERIVATION_PREFIX_V2: &str = "sig.network v2.0.0 epsilon derivation";

const CHECKPOINT_SENDER: &str = "checkpoint|sender";

pub enum DerivationParams {
    /// Account owned by a user on a specific chain.
    UserAccount(KeyVersion, Chain, Address, Path),
    /// Account owned by MPC system on a specific chain.
    SystemAccount(KeyVersion, Chain, Path),
    /// Key used for system purposes.
    SystemKey(Purpose),
    /// Checkpoint for consensus of a given chain and block height.
    ConsensusCheckpoint(Chain, u64),
}

impl DerivationParams {
    pub fn derivation_path(&self) -> String {
        match self {
            DerivationParams::UserAccount(key_version, chain, owner, path) => match key_version {
                0 => deprecated_derivation_path(*chain, owner, path),
                _ => caip2_derivation_path(*chain, owner, path),
            },
            DerivationParams::SystemAccount(key_version, chain, path) => {
                let sender = "%admin#";
                match key_version {
                    0 => deprecated_derivation_path(*chain, sender, path),
                    _ => caip2_derivation_path(*chain, sender, path),
                }
            }
            DerivationParams::SystemKey(purpose) => {
                // key version and other parameters are not relevant for system keys
                format!("{EPSILON_DERIVATION_PREFIX_V2}:system_key:{purpose}")
            }
            DerivationParams::ConsensusCheckpoint(chain, height) => {
                caip2_derivation_path(*chain, CHECKPOINT_SENDER, &height.to_string())
            }
        }
    }
}

/// Creates a derivation path string using the legacy format
fn deprecated_derivation_path(chain: Chain, sender: &str, path: &str) -> String {
    let chain_id = chain.deprecated_chain_id();
    format!("{EPSILON_DERIVATION_PREFIX_V1},{chain_id},{sender},{path}")
}

/// Creates a derivation path string using the extended with prefix CAIP-2 format
fn caip2_derivation_path(chain: Chain, sender: &str, derivation_path: &str) -> String {
    let chain_id = chain.caip2_chain_id();
    format!("{EPSILON_DERIVATION_PREFIX_V2}:{chain_id}:{sender}:{derivation_path}")
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

pub fn derive_epsilon(params: &DerivationParams) -> Scalar {
    let derivation_path = params.derivation_path();
    match params {
        DerivationParams::UserAccount(_, Chain::NEAR, _, _)
        | DerivationParams::SystemAccount(_, Chain::NEAR, _)
        | DerivationParams::ConsensusCheckpoint(_, _) => sha3(derivation_path),
        _ => keccak(derivation_path),
    }
}

pub fn derive_epsilon_checkpoint(chain: Chain, height: u64) -> Scalar {
    derive_epsilon(&DerivationParams::ConsensusCheckpoint(chain, height))
}

pub fn derive_epsilon_near(key_version: KeyVersion, account_id: &AccountId, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::NEAR,
        account_id.to_string(),
        path.to_string(),
    ))
}

pub fn derive_epsilon_eth(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Ethereum,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_epsilon_sol(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Solana,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_epsilon_canton(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Canton,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_epsilon_hydration(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Hydration,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_epsilon_bitcoin(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Bitcoin,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

pub fn derive_secret_key(secret_key: &SecretKey, epsilon: Scalar) -> SecretKey {
    SecretKey::new((epsilon + secret_key.to_nonzero_scalar().as_ref()).into())
}

/// Get the x coordinate of a point, as a scalar
pub fn x_coordinate(
    point: &<Secp256k1 as CurveArithmetic>::AffinePoint,
) -> <Secp256k1 as CurveArithmetic>::Scalar {
    <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes(&point.x())
}

pub fn check_ec_signature(
    expected_pk: &k256::AffinePoint,
    big_r: &k256::AffinePoint,
    s: &k256::Scalar,
    msg_hash: Scalar,
    recovery_id: u8,
) -> anyhow::Result<()> {
    let public_key = expected_pk.to_encoded_point(false);
    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(big_r), s)
        .context("cannot create signature from cait_sith signature")?;
    let found_pk = recover(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(recovery_id).context("invalid recovery ID")?,
    )?
    .to_encoded_point(false);
    if public_key == found_pk {
        return Ok(());
    }

    anyhow::bail!("cannot use either recovery id={recovery_id} to recover pubic key")
}

pub fn verify_signature(
    root_public_key: PublicKey,
    epsilon: Scalar,
    payload: Scalar,
    signature: &mpc_primitives::Signature,
) -> anyhow::Result<()> {
    let expected_public_key = derive_key(root_public_key, epsilon);
    check_ec_signature(
        &expected_public_key,
        &signature.big_r,
        &signature.s,
        payload,
        signature.recovery_id,
    )
}

#[cfg(not(target_arch = "wasm32"))]
pub fn recover(
    prehash: &[u8],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> anyhow::Result<VerifyingKey> {
    VerifyingKey::recover_from_prehash(prehash, signature, recovery_id)
        .context("Unable to recover public key")
}

#[cfg(target_arch = "wasm32")]
pub fn recover(
    prehash: &[u8],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> anyhow::Result<VerifyingKey> {
    use k256::EncodedPoint;
    use near_sdk::env;
    // While this function also works on native code, it's a bit weird and unsafe.
    // I'm more comfortable using an existing library instead.
    let recovered_key_bytes =
        env::ecrecover(prehash, &signature.to_bytes(), recovery_id.to_byte(), true)
            .context("Unable to recover public key")?;
    VerifyingKey::from_encoded_point(&EncodedPoint::from_untagged_bytes(
        &recovered_key_bytes.into(),
    ))
    .context("Failed to parse returned key")
}

/// Reconstructs a signature from its components and verifies that it matches the expected public key.
pub fn reconstruct_signature(
    public_key: &k256::AffinePoint,
    big_r: &k256::AffinePoint,
    s: &k256::Scalar,
    msg_hash: Scalar,
) -> anyhow::Result<MpcSignature> {
    let public_key = public_key.to_encoded_point(false);
    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(big_r), s)
        .context("cannot create signature from cait_sith signature")?;
    let pk0 = recover(
        &msg_hash.to_bytes()[..],
        &signature,
        RecoveryId::try_from(0).context("cannot create recovery_id=0")?,
    )
    .context("unable to use 0 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk0 {
        return Ok(MpcSignature::new(*big_r, *s, 0));
    }

    let pk1 = recover(
        &msg_hash.to_bytes()[..],
        &signature,
        RecoveryId::try_from(1).context("cannot create recovery_id=1")?,
    )
    .context("unable to use 1 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk1 {
        return Ok(MpcSignature::new(*big_r, *s, 1));
    }

    anyhow::bail!("cannot use either recovery id (0 or 1) to recover pubic key")
}

/// Generates a signature for the given payload using the provided root secret key and sign arguments.
pub fn generate_signature(
    root_sk: &k256::SecretKey,
    args: &mpc_primitives::SignArgs,
) -> MpcSignature {
    let derived_secret_key = derive_secret_key(root_sk, args.epsilon);
    let signing_key = k256::ecdsa::SigningKey::from(&derived_secret_key);
    let (ecdsa_sig, _): (k256::ecdsa::Signature, _) = signing_key
        .sign_prehash(&args.payload.to_bytes())
        .expect("signing should succeed");
    let (r_bytes, _) = ecdsa_sig.split_bytes();
    let big_r =
        k256::AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0))
            .unwrap();
    let s = *ecdsa_sig.s().as_ref();
    let expected_public_key = derive_key(root_sk.public_key().into(), args.epsilon);

    reconstruct_signature(&expected_public_key, &big_r, &s, args.payload)
        .expect("signature should validate")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::near_public_key_to_affine_point;
    use std::str::FromStr;

    #[test]
    fn test_derivation_path_stays_the_same() {
        assert_eq!(
            DerivationParams::UserAccount(
                0,
                Chain::Ethereum,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,0x1,sender,path"
        );
        assert_eq!(
            DerivationParams::UserAccount(
                1,
                Chain::Ethereum,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:eip155:1:sender:path"
        );

        assert_eq!(
            DerivationParams::UserAccount(
                0,
                Chain::Solana,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,0x800001f5,sender,path"
        );
        assert_eq!(
            DerivationParams::UserAccount(1, Chain::Solana, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:sender:path"
        );

        assert_eq!(
            DerivationParams::UserAccount(0, Chain::NEAR, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,0x18d,sender,path"
        );

        assert_eq!(
            DerivationParams::UserAccount(1, Chain::NEAR, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:near:mainnet:sender:path"
        );

        assert_eq!(
            DerivationParams::UserAccount(0, Chain::Bitcoin, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,bip122:000000000019d6689c085ae165831e93,sender,path"
        );
        assert_eq!(
            DerivationParams::UserAccount(1, Chain::Bitcoin, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:bip122:000000000019d6689c085ae165831e93:sender:path"
        );

        assert_eq!(
            DerivationParams::UserAccount(
                0,
                Chain::Canton,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,canton:global,sender,path"
        );
        assert_eq!(
            DerivationParams::UserAccount(
                1,
                Chain::Canton,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:canton:global:sender:path"
        );

        assert_eq!(
            DerivationParams::SystemAccount(1, Chain::Ethereum, "path".to_string())
                .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:eip155:1:%admin#:path"
        );
    }

    #[test]
    fn test_derive_epsilon_stays_the_same() {
        use crate::ScalarExt;

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
            derive_epsilon(&DerivationParams::UserAccount(
                0,
                Chain::Ethereum,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_eth_v0
        );
        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                1,
                Chain::Ethereum,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_eth_v1
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
            derive_epsilon(&DerivationParams::UserAccount(
                0,
                Chain::Solana,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_sol_v0
        );
        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                1,
                Chain::Solana,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_sol_v1
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
            derive_epsilon(&DerivationParams::UserAccount(
                0,
                Chain::NEAR,
                "sender.near".to_string(),
                "path".to_string()
            )),
            expected_near_v0
        );
        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                1,
                Chain::NEAR,
                "sender.near".to_string(),
                "path".to_string()
            )),
            expected_near_v1
        );
    }

    #[test]
    fn test_derive_key_stays_the_same() {
        let root_pk = "secp256k1:4tY4qMzusmgX5wYdG35663Y3Qar3CTbpApotwk9ZKLoF79XA4DjG8XoByaKdNHKQX9Lz5hd7iJqsWdTKyA7dKa6Z";
        let root_pk = near_sdk::PublicKey::from_str(root_pk).unwrap();
        let root_pk = near_public_key_to_affine_point(root_pk);

        let epsilon = Scalar::from_bytes([
            0x51, 0x8D, 0x99, 0xF3, 0x4A, 0x18, 0x27, 0xA5, 0x9E, 0xD2, 0xA8, 0xC6, 0xB7, 0x00,
            0x3C, 0xF4, 0x24, 0x6C, 0x6E, 0xCA, 0x82, 0xE8, 0x4B, 0xFB, 0x40, 0xC4, 0x7D, 0xD8,
            0xD1, 0xA1, 0xD4, 0x2F,
        ])
        .unwrap();

        let derived_pk = derive_key(root_pk, epsilon);

        let expected_bytes = [
            0x04, 0xE3, 0x19, 0x91, 0x03, 0x7B, 0x08, 0x23, 0x27, 0x39, 0xBB, 0x84, 0x2E, 0x35,
            0x89, 0xB4, 0x81, 0x02, 0x39, 0xEE, 0x5D, 0xE4, 0xF1, 0x53, 0x4D, 0x6F, 0x78, 0x93,
            0xE4, 0x75, 0x1F, 0x0E, 0x54, 0x53, 0x4B, 0x65, 0x21, 0x74, 0x5B, 0xFA, 0x39, 0xDE,
            0x5E, 0xD8, 0xB2, 0x6D, 0x54, 0x3F, 0x94, 0x7C, 0x84, 0x11, 0x0C, 0x67, 0x41, 0x70,
            0x6B, 0x5D, 0xEA, 0x30, 0x98, 0x8E, 0x3F, 0x47, 0xF5,
        ];

        let derived_encoded = derived_pk.to_encoded_point(false);
        assert_eq!(derived_encoded.as_bytes(), &expected_bytes);
    }

    #[test]
    fn test_derive_secret_key_stays_the_same() {
        let root_secret_key_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let root_secret_key = SecretKey::from_bytes((&root_secret_key_bytes).into()).unwrap();

        let epsilon = Scalar::from_bytes([
            0x51, 0x8D, 0x99, 0xF3, 0x4A, 0x18, 0x27, 0xA5, 0x9E, 0xD2, 0xA8, 0xC6, 0xB7, 0x00,
            0x3C, 0xF4, 0x24, 0x6C, 0x6E, 0xCA, 0x82, 0xE8, 0x4B, 0xFB, 0x40, 0xC4, 0x7D, 0xD8,
            0xD1, 0xA1, 0xD4, 0x2F,
        ])
        .unwrap();

        let derived_secret_key = derive_secret_key(&root_secret_key, epsilon);

        let expected_bytes = [
            82, 143, 156, 247, 79, 30, 46, 173, 167, 220, 179, 210, 196, 14, 76, 4, 53, 126, 129,
            222, 151, 254, 99, 19, 89, 222, 152, 244, 238, 191, 243, 79,
        ];

        assert_eq!(derived_secret_key.to_bytes().as_slice(), &expected_bytes);
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
            derive_epsilon(&DerivationParams::UserAccount(
                0,
                Chain::Canton,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_canton_v0
        );
        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                1,
                Chain::Canton,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_canton_v1
        );
    }

    #[test]
    fn test_derive_epsilon_checkpoint() {
        let p = DerivationParams::SystemKey("checkpoint".to_string()).derivation_path();
        assert_eq!(
            p,
            "sig.network v2.0.0 epsilon derivation:system_key:checkpoint"
        );
    }

    // This logic is used to determine MPC PK (address) that is set as admin in Ethereum contract
    #[test]
    fn derive_ethereum_admin_key() {
        // Define epsilon
        let epsilon = derive_epsilon(&DerivationParams::SystemAccount(
            0,
            Chain::Ethereum,
            "signing_contract_control".to_string(),
        ));

        // Mainnet root PK
        let root_pk = "secp256k1:4tY4qMzusmgX5wYdG35663Y3Qar3CTbpApotwk9ZKLoF79XA4DjG8XoByaKdNHKQX9Lz5hd7iJqsWdTKyA7dKa6Z";
        let root_pk = near_sdk::PublicKey::from_str(root_pk).unwrap();
        let root_pk = near_public_key_to_affine_point(root_pk);

        // Derive admin PK
        let admin_ap = derive_key(root_pk, epsilon);
        let admin_pk = k256::PublicKey::from_affine(admin_ap).unwrap();
        let admin_pk = admin_pk.to_encoded_point(false);

        // Calculate admin Ethereum address
        let hash: [u8; 32] = *alloy::primitives::keccak256(&admin_pk.as_bytes()[1..]);
        let address = alloy::primitives::Address::from_slice(&hash[12..]);

        println!("Admin Ethereum address: {address}");

        let expected_address =
            alloy::primitives::Address::from_str("0x3c0f802d66ac9fe56fa90afb0714dbc65b05a445")
                .unwrap();

        assert_eq!(address, expected_address);
    }

    #[test]
    fn test_reconstruct_signature_success() {
        let sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let public_key: k256::AffinePoint = sk.public_key().into();
        let msg_hash = Scalar::from_bytes([0x22; 32]).unwrap();

        // Generate a valid signature
        let (ecdsa_sig, expected_rec_id): (k256::ecdsa::Signature, _) =
            k256::ecdsa::SigningKey::from(&sk)
                .sign_prehash(&msg_hash.to_bytes())
                .unwrap();

        // Extract components
        let (r_bytes, _) = ecdsa_sig.split_bytes();
        let big_r =
            k256::AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0))
                .unwrap();
        let s = *ecdsa_sig.s().as_ref();

        let mpc_sig = reconstruct_signature(&public_key, &big_r, &s, msg_hash).unwrap();
        assert_eq!(mpc_sig.big_r, big_r);
        assert_eq!(mpc_sig.s, s);
        assert_eq!(mpc_sig.recovery_id, expected_rec_id.to_byte());
    }

    #[test]
    fn test_reconstruct_signature_wrong_public_key() {
        let sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        // Generate a different secret key to simulate a wrong public key
        let wrong_sk = SecretKey::from_bytes((&[0x99; 32]).into()).unwrap();
        let wrong_public_key: k256::AffinePoint = wrong_sk.public_key().into();

        let msg_hash = Scalar::from_bytes([0x22; 32]).unwrap();

        // Generate a valid signature with the original secret key
        let (ecdsa_sig, _): (k256::ecdsa::Signature, _) = k256::ecdsa::SigningKey::from(&sk)
            .sign_prehash(&msg_hash.to_bytes())
            .unwrap();

        let (r_bytes, _) = ecdsa_sig.split_bytes();
        let big_r =
            k256::AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0))
                .unwrap();
        let s = *ecdsa_sig.s().as_ref();

        // Attempt to create an MPC signature with the wrong public key
        let err = reconstruct_signature(&wrong_public_key, &big_r, &s, msg_hash).unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot use either recovery id (0 or 1) to recover pubic key"
        );
    }

    #[test]
    fn test_reconstruct_signature_wrong_payload() {
        let sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let public_key: k256::AffinePoint = sk.public_key().into();

        let msg_hash = Scalar::from_bytes([0x22; 32]).unwrap();
        // Use a different message hash to simulate a wrong payload
        let wrong_msg_hash = Scalar::from_bytes([0x33; 32]).unwrap();

        let (ecdsa_sig, _): (k256::ecdsa::Signature, _) = k256::ecdsa::SigningKey::from(&sk)
            .sign_prehash(&msg_hash.to_bytes())
            .unwrap();

        let (r_bytes, _) = ecdsa_sig.split_bytes();
        let big_r =
            k256::AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0))
                .unwrap();
        let s = *ecdsa_sig.s().as_ref();

        // Attempt to create an MPC signature with the wrong message hash
        let err = reconstruct_signature(&public_key, &big_r, &s, wrong_msg_hash).unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot use either recovery id (0 or 1) to recover pubic key"
        );
    }

    #[test]
    fn test_reconstruct_signature_invalid_s_scalar() {
        let sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let public_key: k256::AffinePoint = sk.public_key().into();
        let msg_hash = Scalar::from_bytes([0x22; 32]).unwrap();

        // use the public key as a dummy point for big_r
        let dummy_big_r = public_key;
        let invalid_s = Scalar::ZERO; // 0 is always an invalid 's' in ECDSA

        // Attempt to create an MPC signature with an invalid 's' scalar
        let err =
            reconstruct_signature(&public_key, &dummy_big_r, &invalid_s, msg_hash).unwrap_err();
        assert!(err
            .to_string()
            .contains("cannot create signature from cait_sith signature"));
    }

    #[test]
    fn test_generate_signature_produces_verifiable_signature() {
        let root_sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let root_public_key: PublicKey = root_sk.public_key().into();

        let epsilon = Scalar::from_bytes([0x22; 32]).unwrap();
        let payload = Scalar::from_bytes([0x33; 32]).unwrap();

        let args = mpc_primitives::SignArgs {
            entropy: [0x44; 32],
            epsilon,
            payload,
            path: "test/path".to_string(),
            key_version: 0,
        };

        let mpc_sig = generate_signature(&root_sk, &args);

        // Verify the produced signature is mathematically correct against the derived public key
        let is_valid = verify_signature(root_public_key, epsilon, payload, &mpc_sig);
        assert!(
            is_valid.is_ok(),
            "generate_signature should produce a mathematically valid signature"
        );
    }

    #[test]
    fn test_generate_signature_is_deterministic() {
        let root_sk = SecretKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let epsilon = Scalar::from_bytes([0x22; 32]).unwrap();
        let payload = Scalar::from_bytes([0x33; 32]).unwrap();

        let args = mpc_primitives::SignArgs {
            entropy: [0x44; 32],
            epsilon,
            payload,
            path: "test/path".to_string(),
            key_version: 0,
        };

        // ECDSA signatures with the same key and payload should be completely deterministic.
        let sig1 = generate_signature(&root_sk, &args);
        let sig2 = generate_signature(&root_sk, &args);

        assert_eq!(sig1.big_r, sig2.big_r);
        assert_eq!(sig1.s, sig2.s);
        assert_eq!(sig1.recovery_id, sig2.recovery_id);
    }
}
