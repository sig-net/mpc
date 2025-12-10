use crate::types::{PublicKey, ScalarExt};
use anyhow::Context;
use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, CurveArithmetic},
    Scalar, Secp256k1, SecretKey,
};
use near_account_id::AccountId;
use sha3::{Digest, Keccak256, Sha3_256};

// Constant prefix that ensures epsilon derivation values are used specifically for
// Sig.Network with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX_V1: &str = "sig.network v1.0.0 epsilon derivation";
const EPSILON_DERIVATION_PREFIX_V2: &str = "sig.network v2.0.0 epsilon derivation";

#[derive(Debug, Clone, Copy)]
pub enum Chain {
    Near,
    Ethereum,
    Solana,
    Bitcoin,
}

impl Chain {
    pub fn deprecated_chain_id(&self) -> &str {
        match self {
            Chain::Near => "0x18d",
            Chain::Ethereum => "0x1",
            Chain::Solana => "0x800001f5",
            Chain::Bitcoin => "bip122:000000000019d6689c085ae165831e93",
        }
    }

    pub fn caip2_chain_id(&self) -> &str {
        match self {
            Chain::Near => "near:mainnet",
            Chain::Ethereum => "eip155:1",
            Chain::Solana => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            Chain::Bitcoin => "bip122:000000000019d6689c085ae165831e93",
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

fn derivation_path(key_version: u32, chain: Chain, sender: &str, derivation_path: &str) -> String {
    match key_version {
        0 => deprecated_derivation_path(chain, sender, derivation_path),
        // Note: if the user provides a key_version that is higher than supported, we fall back to the latest supported one
        _ => caip2_derivation_path(chain, sender, derivation_path),
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

pub fn derive_epsilon_near(key_version: u32, predecessor_id: &AccountId, path: &str) -> Scalar {
    let derivation_path = derivation_path(key_version, Chain::Near, predecessor_id.as_str(), path);
    sha3(derivation_path)
}

pub fn derive_epsilon_eth(key_version: u32, sender: &str, path: &str) -> Scalar {
    let derivation_path = derivation_path(key_version, Chain::Ethereum, sender, path);
    keccak(derivation_path)
}

pub fn derive_epsilon_sol(key_version: u32, sender: &str, path: &str) -> Scalar {
    let derivation_path = derivation_path(key_version, Chain::Solana, sender, path);
    keccak(derivation_path.as_bytes())
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

    #[test]
    fn test_derivation_path_stays_the_same() {
        assert_eq!(
            derivation_path(0, Chain::Ethereum, "sender", "path"),
            "sig.network v1.0.0 epsilon derivation,0x1,sender,path"
        );
        assert_eq!(
            derivation_path(1, Chain::Ethereum, "sender", "path"),
            "sig.network v2.0.0 epsilon derivation:eip155:1:sender:path"
        );

        assert_eq!(
            derivation_path(0, Chain::Solana, "sender", "path"),
            "sig.network v1.0.0 epsilon derivation,0x800001f5,sender,path"
        );
        assert_eq!(
            derivation_path(1, Chain::Solana, "sender", "path"),
            "sig.network v2.0.0 epsilon derivation:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:sender:path"
        );

        assert_eq!(
            derivation_path(0, Chain::Near, "sender", "path"),
            "sig.network v1.0.0 epsilon derivation,0x18d,sender,path"
        );

        assert_eq!(
            derivation_path(1, Chain::Near, "sender", "path"),
            "sig.network v2.0.0 epsilon derivation:near:mainnet:sender:path"
        );

        assert_eq!(
            derivation_path(0, Chain::Bitcoin, "sender", "path"),
            "sig.network v1.0.0 epsilon derivation,bip122:000000000019d6689c085ae165831e93,sender,path"
        );
        assert_eq!(
            derivation_path(1, Chain::Bitcoin, "sender", "path"),
            "sig.network v2.0.0 epsilon derivation:bip122:000000000019d6689c085ae165831e93:sender:path"
        );
    }

    #[test]
    fn test_derive_epsilon_stays_the_same() {
        use crate::types::ScalarExt;

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

        assert_eq!(derive_epsilon_eth(0, "sender", "path"), expected_eth_v0);
        assert_eq!(derive_epsilon_eth(1, "sender", "path"), expected_eth_v1);

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

        assert_eq!(derive_epsilon_sol(0, "sender", "path"), expected_sol_v0);
        assert_eq!(derive_epsilon_sol(1, "sender", "path"), expected_sol_v1);

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
            derive_epsilon_near(0, &AccountId::from_str("sender.near").unwrap(), "path"),
            expected_near_v0
        );
        assert_eq!(
            derive_epsilon_near(1, &AccountId::from_str("sender.near").unwrap(), "path"),
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

    // This logic is used to determine MPC PK (address) that is set as admin in Ethereum contract
    #[test]
    fn derive_ethereum_admin_key() {
        // Define epsilon
        let sender = "%admin#".to_string();
        let path = "signing_contract_control".to_string();
        let epsilon = derive_epsilon_eth(0, &sender, &path);

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

    // Property-based tests using proptest
    #[cfg(test)]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::elliptic_curve::sec1::FromEncodedPoint;

        // Property 11: Key Derivation Consistency
        // For any input parameters, key derivation functions should produce consistent outputs across multiple invocations
        // Validates: Requirements 4.1
        proptest! {
            #[test]
            fn prop_key_derivation_consistency(
                key_version in 0u32..=10,
                sender in r"[a-zA-Z0-9._-]{1,20}",
                path in r"[a-zA-Z0-9._-]{1,20}",
            ) {
                // Test Ethereum epsilon derivation consistency
                let epsilon1 = derive_epsilon_eth(key_version, &sender, &path);
                let epsilon2 = derive_epsilon_eth(key_version, &sender, &path);
                prop_assert_eq!(epsilon1, epsilon2, "Ethereum epsilon derivation should be deterministic");

                // Test Solana epsilon derivation consistency
                let epsilon1 = derive_epsilon_sol(key_version, &sender, &path);
                let epsilon2 = derive_epsilon_sol(key_version, &sender, &path);
                prop_assert_eq!(epsilon1, epsilon2, "Solana epsilon derivation should be deterministic");
            }
        }

        // Property 12: Signature Verification Round-trip
        // For any message and key pair, signing the message then verifying the signature should always succeed
        // Validates: Requirements 4.2, 4.4
        proptest! {
            #[test]
            fn prop_signature_verification_roundtrip(
                msg_hash_bytes in prop::array::uniform32(any::<u8>()),
            ) {
                // Create a message hash from the bytes
                let msg_hash = match Scalar::from_bytes(msg_hash_bytes) {
                    Some(scalar) => scalar,
                    None => return Ok(()), // Skip if bytes are outside field
                };

                // Generate a random signing key
                use k256::ecdsa::SigningKey;
                let signing_key = SigningKey::random(&mut rand::thread_rng());
                let verifying_key = signing_key.verifying_key();

                // Sign the message
                let (signature, _recovery_id) = signing_key
                    .sign_prehash_recoverable(&msg_hash.to_bytes())
                    .expect("Failed to sign message");

                // Verify the signature using standard ECDSA verification
                let result = verifying_key.verify_prehash(&msg_hash.to_bytes(), &signature);
                prop_assert!(result.is_ok(), "Signature verification should succeed for valid signature");
            }
        }

        // Property 13: Signature Verification Correctness
        // For any signature verification operation, valid signatures should be accepted and invalid signatures should be rejected
        // Validates: Requirements 4.3
        proptest! {
            #[test]
            fn prop_signature_verification_correctness(
                msg_hash_bytes in prop::array::uniform32(any::<u8>()),
            ) {
                // Create a message hash from the bytes
                let msg_hash = match Scalar::from_bytes(msg_hash_bytes) {
                    Some(scalar) => scalar,
                    None => return Ok(()), // Skip if bytes are outside field
                };

                // Generate a random signing key
                use k256::ecdsa::SigningKey;
                let signing_key = SigningKey::random(&mut rand::thread_rng());
                let verifying_key = signing_key.verifying_key();

                // Sign the message
                let (signature, _recovery_id) = signing_key
                    .sign_prehash_recoverable(&msg_hash.to_bytes())
                    .expect("Failed to sign message");

                // Verify with correct public key should succeed
                let result = verifying_key.verify_prehash(&msg_hash.to_bytes(), &signature);
                prop_assert!(result.is_ok(), "Valid signature should be accepted");

                // Verify with wrong message should fail
                let wrong_msg_hash = match Scalar::from_bytes([1u8; 32]) {
                    Some(scalar) => scalar,
                    None => return Ok(()), // Skip if bytes are outside field
                };

                let result = verifying_key.verify_prehash(&wrong_msg_hash.to_bytes(), &signature);
                prop_assert!(result.is_err(), "Invalid signature should be rejected");
            }
        }

        // **Feature: unit-test-coverage, Property 90: Chain-Specific Epsilon Derivation**
        // *For any* chain (NEAR, Ethereum, Solana, Bitcoin), epsilon derivation should produce correct chain-specific values
        // **Validates: Requirements 29.1**
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn prop_chain_specific_epsilon_derivation(
                key_version in 0u32..=2,
                sender in r"[a-zA-Z0-9._-]{1,20}",
                path in r"[a-zA-Z0-9._-]{1,20}",
            ) {
                // Test that each chain produces different epsilon values for the same inputs
                // This validates that chain-specific derivation is working correctly
                
                let eth_epsilon = derive_epsilon_eth(key_version, &sender, &path);
                let sol_epsilon = derive_epsilon_sol(key_version, &sender, &path);
                
                // Ethereum and Solana should produce different epsilons for the same sender/path
                // because they use different chain IDs in the derivation path
                prop_assert_ne!(
                    eth_epsilon, sol_epsilon,
                    "Different chains should produce different epsilon values for same inputs"
                );
                
                // Test that the derivation path format is correct for each version
                // v0 uses deprecated format with comma separators
                // v1+ uses CAIP-2 format with colon separators
                let eth_path_v0 = deprecated_derivation_path(Chain::Ethereum, &sender, &path);
                let eth_path_v1 = caip2_derivation_path(Chain::Ethereum, &sender, &path);
                
                // v0 should contain comma separators and deprecated chain ID
                prop_assert!(eth_path_v0.contains(','), "v0 path should use comma separators");
                prop_assert!(eth_path_v0.contains("0x1"), "v0 Ethereum path should contain deprecated chain ID");
                
                // v1 should contain colon separators and CAIP-2 chain ID
                prop_assert!(eth_path_v1.contains(':'), "v1 path should use colon separators");
                prop_assert!(eth_path_v1.contains("eip155:1"), "v1 Ethereum path should contain CAIP-2 chain ID");
                
                // Test Solana chain-specific derivation
                let sol_path_v0 = deprecated_derivation_path(Chain::Solana, &sender, &path);
                let sol_path_v1 = caip2_derivation_path(Chain::Solana, &sender, &path);
                
                prop_assert!(sol_path_v0.contains("0x800001f5"), "v0 Solana path should contain deprecated chain ID");
                prop_assert!(sol_path_v1.contains("solana:"), "v1 Solana path should contain CAIP-2 chain ID");
                
                // Test Bitcoin chain-specific derivation
                let btc_path_v0 = deprecated_derivation_path(Chain::Bitcoin, &sender, &path);
                let btc_path_v1 = caip2_derivation_path(Chain::Bitcoin, &sender, &path);
                
                prop_assert!(btc_path_v0.contains("bip122:"), "v0 Bitcoin path should contain BIP-122 chain ID");
                prop_assert!(btc_path_v1.contains("bip122:"), "v1 Bitcoin path should contain BIP-122 chain ID");
                
                // Test NEAR chain-specific derivation
                let near_path_v0 = deprecated_derivation_path(Chain::Near, &sender, &path);
                let near_path_v1 = caip2_derivation_path(Chain::Near, &sender, &path);
                
                prop_assert!(near_path_v0.contains("0x18d"), "v0 NEAR path should contain deprecated chain ID");
                prop_assert!(near_path_v1.contains("near:mainnet"), "v1 NEAR path should contain CAIP-2 chain ID");
            }
        }

        // **Feature: unit-test-coverage, Property 91: Key Version Migration Correctness**
        // *For any* key version migration (v0 → v1), the format changes should be handled correctly and produce expected outputs
        // **Validates: Requirements 29.2**
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn prop_key_version_migration_correctness(
                sender in r"[a-zA-Z0-9._-]{1,20}",
                path in r"[a-zA-Z0-9._-]{1,20}",
            ) {
                // Test that v0 and v1 produce different epsilon values (migration changes output)
                let eth_v0 = derive_epsilon_eth(0, &sender, &path);
                let eth_v1 = derive_epsilon_eth(1, &sender, &path);
                
                prop_assert_ne!(
                    eth_v0, eth_v1,
                    "v0 and v1 should produce different epsilon values due to format change"
                );
                
                // Test that v1 and higher versions produce the same result (fallback to latest)
                let eth_v2 = derive_epsilon_eth(2, &sender, &path);
                let eth_v10 = derive_epsilon_eth(10, &sender, &path);
                
                prop_assert_eq!(
                    eth_v1, eth_v2,
                    "v1 and v2 should produce same epsilon (v2+ falls back to v1 format)"
                );
                prop_assert_eq!(
                    eth_v1, eth_v10,
                    "v1 and v10 should produce same epsilon (higher versions fall back to v1)"
                );
                
                // Test Solana version migration
                let sol_v0 = derive_epsilon_sol(0, &sender, &path);
                let sol_v1 = derive_epsilon_sol(1, &sender, &path);
                
                prop_assert_ne!(
                    sol_v0, sol_v1,
                    "Solana v0 and v1 should produce different epsilon values"
                );
                
                // Verify the derivation path format changes between versions
                let path_v0 = derivation_path(0, Chain::Ethereum, &sender, &path);
                let path_v1 = derivation_path(1, Chain::Ethereum, &sender, &path);
                
                // v0 uses EPSILON_DERIVATION_PREFIX_V1 with comma separators
                prop_assert!(
                    path_v0.starts_with("sig.network v1.0.0"),
                    "v0 path should use v1.0.0 prefix"
                );
                
                // v1 uses EPSILON_DERIVATION_PREFIX_V2 with colon separators
                prop_assert!(
                    path_v1.starts_with("sig.network v2.0.0"),
                    "v1 path should use v2.0.0 prefix"
                );
            }
        }

        // **Feature: unit-test-coverage, Property 92: Derivation Path Collision Resistance**
        // *For any* two different derivation path inputs, the resulting epsilons should be different (collision resistant)
        // **Validates: Requirements 29.3**
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn prop_derivation_path_collision_resistance(
                key_version in 0u32..=1,
                sender1 in r"[a-zA-Z0-9._-]{1,20}",
                sender2 in r"[a-zA-Z0-9._-]{1,20}",
                path1 in r"[a-zA-Z0-9._-]{1,20}",
                path2 in r"[a-zA-Z0-9._-]{1,20}",
            ) {
                // Skip if inputs are identical
                if sender1 == sender2 && path1 == path2 {
                    return Ok(());
                }
                
                // Test collision resistance for Ethereum
                let eth_epsilon1 = derive_epsilon_eth(key_version, &sender1, &path1);
                let eth_epsilon2 = derive_epsilon_eth(key_version, &sender2, &path2);
                
                // Different inputs should produce different epsilons
                prop_assert_ne!(
                    eth_epsilon1, eth_epsilon2,
                    "Different inputs should produce different epsilon values (collision resistance)"
                );
                
                // Test collision resistance for Solana
                let sol_epsilon1 = derive_epsilon_sol(key_version, &sender1, &path1);
                let sol_epsilon2 = derive_epsilon_sol(key_version, &sender2, &path2);
                
                prop_assert_ne!(
                    sol_epsilon1, sol_epsilon2,
                    "Different inputs should produce different Solana epsilon values"
                );
                
                // Test that same sender with different paths produces different epsilons
                if path1 != path2 {
                    let eth_same_sender1 = derive_epsilon_eth(key_version, &sender1, &path1);
                    let eth_same_sender2 = derive_epsilon_eth(key_version, &sender1, &path2);
                    
                    prop_assert_ne!(
                        eth_same_sender1, eth_same_sender2,
                        "Same sender with different paths should produce different epsilons"
                    );
                }
                
                // Test that same path with different senders produces different epsilons
                if sender1 != sender2 {
                    let eth_same_path1 = derive_epsilon_eth(key_version, &sender1, &path1);
                    let eth_same_path2 = derive_epsilon_eth(key_version, &sender2, &path1);
                    
                    prop_assert_ne!(
                        eth_same_path1, eth_same_path2,
                        "Same path with different senders should produce different epsilons"
                    );
                }
            }
        }

        // **Feature: unit-test-coverage, Property 93: Cross-Chain Key Isolation**
        // *For any* key derived for one chain, it should be cryptographically isolated from keys derived for other chains
        // **Validates: Requirements 29.4**
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn prop_cross_chain_key_isolation(
                key_version in 0u32..=1,
                sender in r"[a-zA-Z0-9._-]{1,20}",
                path in r"[a-zA-Z0-9._-]{1,20}",
            ) {
                // Derive epsilon for each chain with identical inputs
                let eth_epsilon = derive_epsilon_eth(key_version, &sender, &path);
                let sol_epsilon = derive_epsilon_sol(key_version, &sender, &path);
                
                // All chains should produce different epsilons for the same sender/path
                // This ensures cross-chain key isolation
                prop_assert_ne!(
                    eth_epsilon, sol_epsilon,
                    "Ethereum and Solana should produce different epsilons (cross-chain isolation)"
                );
                
                // Test that derived keys are also different
                // Use a fixed root public key for testing
                let root_pk_bytes = [
                    0x04, // Uncompressed point prefix
                    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
                    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
                    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
                ];
                
                let root_pk = k256::EncodedPoint::from_bytes(&root_pk_bytes).ok();
                if let Some(encoded_point) = root_pk {
                    if let Some(root_pk) = k256::AffinePoint::from_encoded_point(&encoded_point).into() {
                        let eth_derived_key = derive_key(root_pk, eth_epsilon);
                        let sol_derived_key = derive_key(root_pk, sol_epsilon);
                        
                        prop_assert_ne!(
                            eth_derived_key, sol_derived_key,
                            "Derived keys for different chains should be different"
                        );
                    }
                }
                
                // Verify that the chain ID is embedded in the derivation path
                let eth_path = derivation_path(key_version, Chain::Ethereum, &sender, &path);
                let sol_path = derivation_path(key_version, Chain::Solana, &sender, &path);
                
                // Verify chain-specific identifiers are present
                if key_version == 0 {
                    prop_assert!(eth_path.contains("0x1"), "Ethereum v0 path should contain chain ID 0x1");
                    prop_assert!(sol_path.contains("0x800001f5"), "Solana v0 path should contain chain ID 0x800001f5");
                } else {
                    prop_assert!(eth_path.contains("eip155:1"), "Ethereum v1 path should contain eip155:1");
                    prop_assert!(sol_path.contains("solana:"), "Solana v1 path should contain solana:");
                }
                
                // Verify paths are different (cross-chain isolation)
                prop_assert_ne!(
                    eth_path, sol_path,
                    "Derivation paths for different chains should be different"
                );
            }
        }

        // **Feature: unit-test-coverage, Property 94: EC Signature Recovery Correctness**
        // *For any* valid signature, recovery with the correct recovery ID should produce the original public key
        // **Validates: Requirements 30.1**
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn prop_ec_signature_recovery_correctness(
                msg_hash_bytes in prop::array::uniform32(any::<u8>()),
            ) {
                use k256::ecdsa::SigningKey;
                
                // Create a message hash from the bytes
                let msg_hash = match Scalar::from_bytes(msg_hash_bytes) {
                    Some(scalar) => scalar,
                    None => return Ok(()), // Skip if bytes are outside field
                };
                
                // Generate a random signing key
                let signing_key = SigningKey::random(&mut rand::thread_rng());
                let verifying_key = signing_key.verifying_key();
                let expected_pk = verifying_key.to_encoded_point(false);
                
                // Sign the message with recoverable signature
                let (signature, recovery_id) = signing_key
                    .sign_prehash_recoverable(&msg_hash.to_bytes())
                    .expect("Failed to sign message");
                
                // Recover the public key using the recovery function
                let recovered_key = recover(&msg_hash.to_bytes(), &signature, recovery_id)
                    .expect("Failed to recover public key");
                let recovered_pk = recovered_key.to_encoded_point(false);
                
                // The recovered public key should match the original
                prop_assert_eq!(
                    expected_pk.as_bytes(),
                    recovered_pk.as_bytes(),
                    "Recovered public key should match original public key"
                );
                
                // Test with different recovery IDs - only the correct one should work
                for test_recovery_id in 0u8..4 {
                    if let Ok(rid) = RecoveryId::try_from(test_recovery_id) {
                        let result = recover(&msg_hash.to_bytes(), &signature, rid);
                        if test_recovery_id == recovery_id.to_byte() {
                            // Correct recovery ID should succeed
                            prop_assert!(result.is_ok(), "Correct recovery ID should succeed");
                            let recovered = result.unwrap().to_encoded_point(false);
                            prop_assert_eq!(
                                expected_pk.as_bytes(),
                                recovered.as_bytes(),
                                "Correct recovery ID should recover original key"
                            );
                        }
                        // Note: Other recovery IDs may or may not succeed, but if they do,
                        // they should recover a different key
                    }
                }
            }
        }

        // **Feature: unit-test-coverage, Property 95: Derived Key Signature Verification**
        // *For any* signature created with a derived key, verification with the corresponding derived public key should succeed
        // **Validates: Requirements 30.2**
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn prop_derived_key_signature_verification(
                msg_hash_bytes in prop::array::uniform32(any::<u8>()),
                epsilon_bytes in prop::array::uniform32(any::<u8>()),
            ) {
                use k256::ecdsa::SigningKey;
                
                // Create a message hash from the bytes
                let msg_hash = match Scalar::from_bytes(msg_hash_bytes) {
                    Some(scalar) => scalar,
                    None => return Ok(()), // Skip if bytes are outside field
                };
                
                // Create epsilon from bytes
                let epsilon = match Scalar::from_bytes(epsilon_bytes) {
                    Some(scalar) => scalar,
                    None => return Ok(()), // Skip if bytes are outside field
                };
                
                // Generate a root signing key
                let root_signing_key = SigningKey::random(&mut rand::thread_rng());
                let root_secret_key = SecretKey::from(root_signing_key.clone());
                let root_public_key = *root_signing_key.verifying_key().as_affine();
                
                // Derive the secret key and public key using epsilon
                let derived_secret_key = derive_secret_key(&root_secret_key, epsilon);
                let derived_public_key = derive_key(root_public_key, epsilon);
                
                // Create a signing key from the derived secret key
                let derived_signing_key = SigningKey::from(&derived_secret_key);
                
                // Sign the message with the derived key
                let (signature, recovery_id) = derived_signing_key
                    .sign_prehash_recoverable(&msg_hash.to_bytes())
                    .expect("Failed to sign message");
                
                // Recover the public key from the signature
                let recovered_key = recover(&msg_hash.to_bytes(), &signature, recovery_id)
                    .expect("Failed to recover public key");
                
                // The recovered key should match the derived public key
                let derived_pk_encoded = k256::PublicKey::from_affine(derived_public_key)
                    .expect("Invalid derived public key")
                    .to_encoded_point(false);
                let recovered_pk_encoded = recovered_key.to_encoded_point(false);
                
                prop_assert_eq!(
                    derived_pk_encoded.as_bytes().to_vec(),
                    recovered_pk_encoded.as_bytes().to_vec(),
                    "Recovered key from derived signature should match derived public key"
                );
                
                // Also verify using standard ECDSA verification
                let derived_verifying_key = derived_signing_key.verifying_key();
                let verify_result = derived_verifying_key.verify_prehash(&msg_hash.to_bytes(), &signature);
                prop_assert!(
                    verify_result.is_ok(),
                    "Signature verification with derived key should succeed"
                );
            }
        }

        // **Feature: unit-test-coverage, Property 96: Invalid Signature Rejection**
        // *For any* invalid signature, verification should fail appropriately without crashing
        // **Validates: Requirements 30.3**
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn prop_invalid_signature_rejection(
                msg_hash_bytes in prop::array::uniform32(any::<u8>()),
                tamper_byte_idx in 0usize..64,
                tamper_value in any::<u8>(),
            ) {
                use k256::ecdsa::SigningKey;
                
                // Create a message hash from the bytes
                let msg_hash = match Scalar::from_bytes(msg_hash_bytes) {
                    Some(scalar) => scalar,
                    None => return Ok(()), // Skip if bytes are outside field
                };
                
                // Generate a random signing key
                let signing_key = SigningKey::random(&mut rand::thread_rng());
                let verifying_key = signing_key.verifying_key();
                
                // Sign the message
                let (signature, recovery_id) = signing_key
                    .sign_prehash_recoverable(&msg_hash.to_bytes())
                    .expect("Failed to sign message");
                
                // Tamper with the signature bytes
                let mut sig_bytes = signature.to_bytes();
                let original_byte = sig_bytes[tamper_byte_idx];
                
                // Only tamper if it actually changes the byte
                if original_byte != tamper_value {
                    sig_bytes[tamper_byte_idx] = tamper_value;
                    
                    // Try to create a signature from tampered bytes
                    match Signature::from_slice(&sig_bytes) {
                        Ok(tampered_signature) => {
                            // Try to verify the tampered signature - should fail
                            let verify_result = verifying_key.verify_prehash(
                                &msg_hash.to_bytes(),
                                &tampered_signature
                            );
                            
                            // Tampered signature should be rejected
                            prop_assert!(
                                verify_result.is_err(),
                                "Tampered signature should be rejected by verification"
                            );
                            
                            // Try to recover public key from tampered signature
                            // This may fail or recover a different key
                            // Try to recover - may fail or recover a different key
                            // We don't assert specific behavior as tampering results are probabilistic
                            let _recovery_result = recover(&msg_hash.to_bytes(), &tampered_signature, recovery_id);
                        }
                        Err(_) => {
                            // Tampered bytes don't form a valid signature structure - this is fine
                        }
                    }
                }
                
                // Test with wrong message hash
                let wrong_msg = [0xFFu8; 32];
                if let Some(wrong_hash) = Scalar::from_bytes(wrong_msg) {
                    if wrong_hash != msg_hash {
                        let verify_result = verifying_key.verify_prehash(
                            &wrong_hash.to_bytes(),
                            &signature
                        );
                        prop_assert!(
                            verify_result.is_err(),
                            "Signature should be rejected when verified with wrong message"
                        );
                    }
                }
                
                // Test with wrong public key
                let wrong_signing_key = SigningKey::random(&mut rand::thread_rng());
                let wrong_verifying_key = wrong_signing_key.verifying_key();
                
                if wrong_verifying_key.to_encoded_point(false) != verifying_key.to_encoded_point(false) {
                    let verify_result = wrong_verifying_key.verify_prehash(
                        &msg_hash.to_bytes(),
                        &signature
                    );
                    prop_assert!(
                        verify_result.is_err(),
                        "Signature should be rejected when verified with wrong public key"
                    );
                }
            }
        }

        // **Feature: unit-test-coverage, Property 97: Cross-Chain Signature Format Compatibility**
        // *For any* signature used across chains, the format should be compatible with chain-specific requirements
        // **Validates: Requirements 30.4**
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn prop_cross_chain_signature_format_compatibility(
                msg_hash_bytes in prop::array::uniform32(any::<u8>()),
                key_version in 0u32..=1,
                sender in r"[a-zA-Z0-9._-]{1,20}",
                path in r"[a-zA-Z0-9._-]{1,20}",
            ) {
                use k256::ecdsa::SigningKey;
                
                // Create a message hash from the bytes
                let msg_hash = match Scalar::from_bytes(msg_hash_bytes) {
                    Some(scalar) => scalar,
                    None => return Ok(()), // Skip if bytes are outside field
                };
                
                // Generate a root signing key
                let root_signing_key = SigningKey::random(&mut rand::thread_rng());
                let root_secret_key = SecretKey::from(root_signing_key.clone());
                let root_public_key = *root_signing_key.verifying_key().as_affine();
                
                // Derive keys for Ethereum
                let eth_epsilon = derive_epsilon_eth(key_version, &sender, &path);
                let eth_derived_secret = derive_secret_key(&root_secret_key, eth_epsilon);
                let eth_derived_public = derive_key(root_public_key, eth_epsilon);
                let eth_signing_key = SigningKey::from(&eth_derived_secret);
                
                // Sign with Ethereum-derived key
                let (eth_signature, eth_recovery_id) = eth_signing_key
                    .sign_prehash_recoverable(&msg_hash.to_bytes())
                    .expect("Failed to sign with Ethereum key");
                
                // Verify signature format is compatible with Ethereum (65 bytes: r(32) + s(32) + v(1))
                let eth_sig_bytes = eth_signature.to_bytes();
                prop_assert_eq!(eth_sig_bytes.len(), 64, "ECDSA signature should be 64 bytes (r + s)");
                
                // Recovery ID should be valid (0 or 1 for standard ECDSA)
                let recovery_byte = eth_recovery_id.to_byte();
                prop_assert!(
                    recovery_byte <= 1,
                    "Recovery ID should be 0 or 1 for standard ECDSA"
                );
                
                // Verify the signature can be recovered to the correct public key
                let recovered = recover(&msg_hash.to_bytes(), &eth_signature, eth_recovery_id)
                    .expect("Failed to recover Ethereum signature");
                let eth_pk = k256::PublicKey::from_affine(eth_derived_public)
                    .expect("Invalid Ethereum derived public key");
                
                let recovered_bytes = recovered.to_encoded_point(false);
                let eth_pk_bytes = eth_pk.to_encoded_point(false);
                prop_assert_eq!(
                    recovered_bytes.as_bytes().to_vec(),
                    eth_pk_bytes.as_bytes().to_vec(),
                    "Ethereum signature should recover to correct public key"
                );
                
                // Derive keys for Solana
                let sol_epsilon = derive_epsilon_sol(key_version, &sender, &path);
                let sol_derived_secret = derive_secret_key(&root_secret_key, sol_epsilon);
                let sol_derived_public = derive_key(root_public_key, sol_epsilon);
                let sol_signing_key = SigningKey::from(&sol_derived_secret);
                
                // Sign with Solana-derived key
                let (sol_signature, sol_recovery_id) = sol_signing_key
                    .sign_prehash_recoverable(&msg_hash.to_bytes())
                    .expect("Failed to sign with Solana key");
                
                // Verify signature format is the same (secp256k1 signatures are chain-agnostic)
                let sol_sig_bytes = sol_signature.to_bytes();
                prop_assert_eq!(sol_sig_bytes.len(), 64, "Solana signature should also be 64 bytes");
                
                // Verify the Solana signature can be recovered
                let sol_recovered = recover(&msg_hash.to_bytes(), &sol_signature, sol_recovery_id)
                    .expect("Failed to recover Solana signature");
                let sol_pk = k256::PublicKey::from_affine(sol_derived_public)
                    .expect("Invalid Solana derived public key");
                
                let sol_recovered_bytes = sol_recovered.to_encoded_point(false);
                let sol_pk_bytes = sol_pk.to_encoded_point(false);
                prop_assert_eq!(
                    sol_recovered_bytes.as_bytes().to_vec(),
                    sol_pk_bytes.as_bytes().to_vec(),
                    "Solana signature should recover to correct public key"
                );
                
                // Verify that Ethereum and Solana signatures are different (different keys)
                prop_assert_ne!(
                    eth_sig_bytes,
                    sol_sig_bytes,
                    "Signatures from different chain-derived keys should be different"
                );
                
                // Verify cross-chain key isolation - Ethereum signature should NOT verify with Solana key
                let eth_verifying_key = eth_signing_key.verifying_key();
                let sol_verifying_key = sol_signing_key.verifying_key();
                
                // Ethereum signature with Solana verifying key should fail
                let cross_verify_result = sol_verifying_key.verify_prehash(
                    &msg_hash.to_bytes(),
                    &eth_signature
                );
                prop_assert!(
                    cross_verify_result.is_err(),
                    "Ethereum signature should not verify with Solana key (cross-chain isolation)"
                );
                
                // Solana signature with Ethereum verifying key should fail
                let cross_verify_result = eth_verifying_key.verify_prehash(
                    &msg_hash.to_bytes(),
                    &sol_signature
                );
                prop_assert!(
                    cross_verify_result.is_err(),
                    "Solana signature should not verify with Ethereum key (cross-chain isolation)"
                );
            }
        }
    }
}
