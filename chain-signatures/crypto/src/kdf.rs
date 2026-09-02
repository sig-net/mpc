use crate::types::KeyVersion;
use crate::PublicKey;
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

// `ScalarExt` and `Sha3_256` are used only by `derive_delta`, which is
// excluded from the wasm contract build; gate the imports to match so the
// wasm build has no unused imports (CI compiles with `-D warnings`).
#[cfg(not(target_arch = "wasm32"))]
use crate::ScalarExt;
#[cfg(not(target_arch = "wasm32"))]
use sha3::Sha3_256;

// Epsilon derivation and derived-key computation now live in the publishable
// `signet-crypto` kernel; re-exported here so node paths (`mpc_crypto::kdf::…`,
// `mpc_crypto::…`) keep resolving unchanged.
pub use signet_crypto::{
    derive_epsilon, derive_epsilon_bitcoin, derive_epsilon_canton, derive_epsilon_eth,
    derive_epsilon_hydration, derive_epsilon_midnight, derive_epsilon_sol, derive_key,
    DerivationParams, EPSILON_DERIVATION_PREFIX_V1, EPSILON_DERIVATION_PREFIX_V2,
};

pub fn derive_epsilon_near(key_version: KeyVersion, account_id: &AccountId, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::NEAR,
        account_id.to_string(),
        path.to_string(),
    ))
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

/// Derives the delta tweak used to randomize a presignature for a specific request.
///
/// Only used off-chain by the node, so it (and its `hkdf`/`near-primitives`
/// dependencies) is excluded from the wasm contract build.
///
/// In case there are multiple requests in the same block (hence same entropy), we need to ensure
/// that we generate different random scalars as delta tweaks.
/// Receipt ID should be unique inside of a block, so it serves us as the request identifier.
#[cfg(not(target_arch = "wasm32"))]
pub fn derive_delta(
    request_id: [u8; 32],
    entropy: [u8; 32],
    presignature_big_r: k256::AffinePoint,
) -> Scalar {
    use hkdf::Hkdf;
    use near_primitives::hash::CryptoHash;

    // Constant prefix that ensures delta derivation values are used specifically for
    // near-mpc-recovery with key derivation protocol vX.Y.Z.
    const DELTA_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 delta derivation:";

    let hk = Hkdf::<Sha3_256>::new(None, &entropy);
    let info = format!("{DELTA_DERIVATION_PREFIX}:{}", CryptoHash(request_id));
    let mut okm = [0u8; 32];
    // Both the request identifier (`info`) and the presignature's `big_r` must feed the
    // derivation. A single `expand` per input would overwrite the buffer each time, so we
    // pass them together via `expand_multi_info`, which concatenates them into one HKDF call.
    hk.expand_multi_info(
        &[
            info.as_bytes(),
            presignature_big_r.to_encoded_point(true).as_bytes(),
        ],
        &mut okm,
    )
    .unwrap();
    Scalar::from_non_biased(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::near_public_key_to_affine_point;
    use std::str::FromStr;

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

    // Within a single block every request shares the same entropy, so `derive_delta`
    // must rely on the unique per-request `request_id` to produce distinct deltas.
    // Otherwise all presignatures in that block would be tweaked identically.
    #[test]
    fn test_derive_delta_differs_by_request_id_within_same_block() {
        let big_r: k256::AffinePoint = SecretKey::from_bytes((&[0x11; 32]).into())
            .unwrap()
            .public_key()
            .into();

        // Same block => same entropy and same presignature `big_r`.
        let entropy = [0x44; 32];

        let delta_a = derive_delta([0x01; 32], entropy, big_r);
        let delta_b = derive_delta([0x02; 32], entropy, big_r);

        assert_ne!(
            delta_a, delta_b,
            "distinct request_ids must yield distinct deltas even with identical entropy and big_r"
        );

        // Sanity: derivation is deterministic for identical inputs.
        assert_eq!(delta_a, derive_delta([0x01; 32], entropy, big_r));
    }

    #[test]
    fn test_derive_delta_stays_the_same() {
        let big_r: k256::AffinePoint = SecretKey::from_bytes((&[0x11; 32]).into())
            .unwrap()
            .public_key()
            .into();

        let delta = derive_delta([0x01; 32], [0x44; 32], big_r);

        let expected = [
            201, 189, 221, 160, 229, 175, 219, 17, 168, 142, 248, 183, 27, 177, 126, 76, 212, 79,
            213, 149, 121, 44, 193, 110, 192, 228, 97, 9, 64, 180, 196, 28,
        ];
        assert_eq!(delta.to_bytes().as_slice(), &expected);
    }

    #[test]
    fn test_derive_delta_differs_by_big_r() {
        let big_r_a: k256::AffinePoint = SecretKey::from_bytes((&[0x11; 32]).into())
            .unwrap()
            .public_key()
            .into();
        let big_r_b: k256::AffinePoint = SecretKey::from_bytes((&[0x22; 32]).into())
            .unwrap()
            .public_key()
            .into();

        let request_id = [0x01; 32];
        let entropy = [0x44; 32];

        assert_ne!(
            derive_delta(request_id, entropy, big_r_a),
            derive_delta(request_id, entropy, big_r_b),
            "distinct presignature big_r must yield distinct deltas"
        );
    }

    #[test]
    fn test_derive_delta_differs_by_entropy() {
        let big_r: k256::AffinePoint = SecretKey::from_bytes((&[0x11; 32]).into())
            .unwrap()
            .public_key()
            .into();

        let request_id = [0x01; 32];

        assert_ne!(
            derive_delta(request_id, [0x44; 32], big_r),
            derive_delta(request_id, [0x55; 32], big_r),
            "distinct entropy must yield distinct deltas"
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
