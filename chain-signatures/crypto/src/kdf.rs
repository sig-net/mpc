use crate::types::{PublicKey, ScalarExt};
use anyhow::Context;
use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, CurveArithmetic},
    Scalar, Secp256k1, SecretKey,
};
use near_account_id::AccountId;
use sha3::{Digest, Keccak256};

// Constant prefix that ensures epsilon derivation values are used specifically for
// Sig.Network with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX: &str = "sig.network v1.0.0 epsilon derivation";

fn full_derivation_path(chain_id: &str, requester: &str, path: &str) -> String {
    format!("{EPSILON_DERIVATION_PREFIX},{chain_id},{requester},{path}")
}

fn hash_derivation_path(derivation_path: impl AsRef<[u8]>) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_non_biased(hash)
}

const CHAIN_ID_NEAR: &str = "0x18d";
pub fn derive_epsilon_near(predecessor_id: &AccountId, path: &str) -> Scalar {
    let derivation_path = full_derivation_path(CHAIN_ID_NEAR, &predecessor_id.to_string(), path);
    hash_derivation_path(derivation_path)
}

const CHAIN_ID_ETHEREUM: &str = "0x1";
pub fn derive_epsilon_eth(requester: String, path: &str) -> Scalar {
    let derivation_path = full_derivation_path(CHAIN_ID_ETHEREUM, &requester, path);
    hash_derivation_path(derivation_path)
}

const CHAIN_ID_SOLANA: &str = "0x800001f5";
pub fn derive_epsilon_sol(requester: &str, path: &str) -> Scalar {
    let derivation_path = full_derivation_path(CHAIN_ID_SOLANA, requester, path);
    hash_derivation_path(derivation_path.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::near_public_key_to_affine_point;
    use std::str::FromStr;

    // This logic is used to determine MPC PK (address) that is set as admin in Ethereum contract
    #[test]
    fn derive_ethereum_admin_key() {
        // Define epsilon
        let requester = "%admin#".to_string();
        let path = "signing_contract_control".to_string();
        let derivation_path =
            format!("{EPSILON_DERIVATION_PREFIX},{CHAIN_ID_ETHEREUM},{requester},{path}");

        let mut hasher = Keccak256::new();
        hasher.update(derivation_path);
        let hash: [u8; 32] = hasher.finalize().into();
        let epsilon = Scalar::from_non_biased(hash);

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
}
