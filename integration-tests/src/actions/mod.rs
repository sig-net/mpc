pub mod sign;
pub mod wait;
pub mod wait_for;

use crate::cluster::Cluster;

use alloy::primitives::Address;
use anyhow::Context as _;
use cait_sith::FullSignature;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, Scalar, Secp256k1};
use mpc_contract::errors::SignError;
use mpc_contract::primitives::SignRequest;
use mpc_crypto::ScalarExt;
use mpc_crypto::{derive_epsilon_near, derive_key};
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use near_crypto::InMemorySigner;
use near_fetch::ops::AsyncTransactionStatus;
use near_fetch::ops::Function;
use near_workspaces::types::Gas;
use near_workspaces::types::NearToken;
use near_workspaces::Account;
use rand::Rng;
use wait_for::{SignatureError, WaitForError};

use std::time::Duration;

pub async fn request_batch_random_sign(
    nodes: &Cluster,
) -> anyhow::Result<(Vec<([u8; 32], [u8; 32])>, Account, AsyncTransactionStatus)> {
    let account = nodes.worker().dev_create_account().await?;
    let signer = InMemorySigner {
        account_id: account.id().clone(),
        public_key: account.secret_key().public_key().to_string().parse()?,
        secret_key: account.secret_key().to_string().parse()?,
    };

    let mut payloads: Vec<([u8; 32], [u8; 32])> = vec![];
    let mut tx = nodes.rpc_client.batch(&signer, nodes.contract().id());
    for _ in 0..3 {
        let payload: [u8; 32] = rand::thread_rng().gen();
        let payload_hashed: [u8; 32] = *alloy::primitives::keccak256(payload);
        payloads.push((payload, payload_hashed));
        let request = SignRequest {
            payload: payload_hashed,
            path: "test".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
        };
        let function = Function::new("sign")
            .args_json(serde_json::json!({
                "request": request,
            }))
            .gas(Gas::from_tgas(50))
            .deposit(NearToken::from_yoctonear(1));
        tx = tx.call(function);
    }

    let status = tx.transact_async().await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    Ok((payloads, account, status))
}

pub async fn request_batch_duplicate_sign(
    nodes: &Cluster,
) -> anyhow::Result<([u8; 32], u32, Account, AsyncTransactionStatus)> {
    let account = nodes.worker().dev_create_account().await?;
    let signer = InMemorySigner {
        account_id: account.id().clone(),
        public_key: account.secret_key().public_key().to_string().parse()?,
        secret_key: account.secret_key().to_string().parse()?,
    };

    let mut tx = nodes.rpc_client.batch(&signer, nodes.contract().id());
    let payload: [u8; 32] = rand::thread_rng().gen();
    let payload_hashed: [u8; 32] = *alloy::primitives::keccak256(payload);
    let sign_call_cnt = 2;
    for _ in 0..sign_call_cnt {
        let request = SignRequest {
            payload: payload_hashed,
            path: "test".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
        };
        let function = Function::new("sign")
            .args_json(serde_json::json!({
                "request": request,
            }))
            .gas(Gas::from_tgas(50))
            .deposit(NearToken::from_yoctonear(1));
        tx = tx.call(function);
    }

    let status = tx.transact_async().await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    Ok((payload_hashed, sign_call_cnt, account, status))
}

pub async fn validate_signature(
    account_id: &near_workspaces::AccountId,
    mpc_pk_bytes: &[u8],
    payload: [u8; 32],
    signature: &FullSignature<Secp256k1>,
) -> anyhow::Result<()> {
    let mpc_point = EncodedPoint::from_bytes(mpc_pk_bytes).unwrap();
    let mpc_pk = AffinePoint::from_encoded_point(&mpc_point).unwrap();
    let epsilon = derive_epsilon_near(LATEST_MPC_KEY_VERSION, account_id, "test");
    let user_pk = derive_key(mpc_pk, epsilon);
    signature
        .verify(
            &user_pk,
            &Scalar::from_bytes(payload).context("failed to convert payload to scalar")?, // .ok_or_else(|| anyhow::anyhow!("failed to convert payload to scalar"))?,
        )
        .then(|| Ok(()))
        .ok_or_else(|| anyhow::anyhow!("failed to validate signature"))?
}

pub async fn batch_random_signature_production(nodes: &Cluster) -> anyhow::Result<()> {
    let (payloads, account, status) = request_batch_random_sign(nodes).await?;
    let signatures = wait_for::batch_signature_responded(status).await?;

    let mpc_pk = nodes.root_public_key().await?;
    let mut mpc_pk_bytes = vec![0x04];
    mpc_pk_bytes.extend_from_slice(&mpc_pk.as_bytes()[1..]);
    assert_eq!(payloads.len(), signatures.len());
    for i in 0..payloads.len() {
        let (_, payload_hash) = payloads.get(i).unwrap();
        let signature = signatures.get(i).unwrap();
        validate_signature(account.id(), &mpc_pk_bytes, *payload_hash, signature)
            .await
            .unwrap();
    }

    Ok(())
}

pub async fn batch_duplicate_signature_production(nodes: &Cluster) -> anyhow::Result<()> {
    let (_, _, _, status) = request_batch_duplicate_sign(nodes).await?;
    let result = wait_for::batch_signature_responded(status).await;
    match result {
        Err(WaitForError::Signature(SignatureError::Failed(err_msg))) => {
            assert!(err_msg.contains(&SignError::RequestCollision.to_string()));
        }
        _ => panic!("Should have failed with PayloadCollision"),
    }
    Ok(())
}

/// Get the x coordinate of a point, as a scalar
pub fn x_coordinate<C: cait_sith::CSCurve>(point: &C::AffinePoint) -> C::Scalar {
    <C::Scalar as k256::elliptic_curve::ops::Reduce<<C as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(&point.x())
}

pub fn public_key_to_address(public_key: &secp256k1::PublicKey) -> Address {
    let public_key = public_key.serialize_uncompressed();

    debug_assert_eq!(public_key[0], 0x04);
    let hash: [u8; 32] = *alloy::primitives::keccak256(&public_key[1..]);

    Address::from_slice(&hash[12..])
}

pub fn recover_eth_address(
    msg_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
    recovery_id: u8,
) -> Address {
    let r = k256::Scalar::from_bytes(signature_bytes[..32].try_into().unwrap()).unwrap();
    let s = k256::Scalar::from_bytes(signature_bytes[32..].try_into().unwrap()).unwrap();
    let signature = k256::ecdsa::Signature::from_scalars(r, s).expect("valid r,s");

    let recid = k256::ecdsa::RecoveryId::from_byte(recovery_id).expect("invalid recovery id");
    let verifying_key = VerifyingKey::recover_from_prehash(msg_hash, &signature, recid)
        .expect("failed to recover pubkey");

    let encoded = verifying_key.to_encoded_point(false);
    let public_key =
        secp256k1::PublicKey::from_slice(encoded.as_bytes()).expect("valid secp256k1 pubkey");

    public_key_to_address(&public_key)
}

#[cfg(test)]
mod tests {
    use elliptic_curve::sec1::FromEncodedPoint as _;
    use k256::ecdsa::VerifyingKey;
    use k256::elliptic_curve::ops::{Invert, Reduce};
    use k256::elliptic_curve::point::AffineCoordinates;
    use k256::elliptic_curve::ProjectivePoint;
    use k256::{AffinePoint, EncodedPoint, Scalar};
    use mpc_crypto::{derive_epsilon_near, derive_key, ScalarExt as _};
    use mpc_primitives::LEGACY_MPC_KEY_VERSION_0;

    use super::{public_key_to_address, recover_eth_address, x_coordinate};

    // This test hardcodes the output of the signing process and checks that everything verifies as expected
    // If you find yourself changing the constants in this test you are likely breaking backwards compatibility
    #[test]
    fn signatures_havent_changed() {
        let big_r = "029b1b94bf4511b1a25986ba858cfa0fbdd5e4077c02e1d1102a194389b1f72df7";
        let s = "25f3494bb7e7b3349a4b4d939d3e5ae1787a0863e4f698fb8ed2d3e11c195035";
        let mpc_key = "045b4fa179e005361fd858f8a6f896d7afc23a53d3f95d6566a88cde954e7b2f1cb77c554705c35d4ffced67aeafbcda46d9d89d6f200c3a3d109f92872863b3dc";
        let account_id = "dev-20250212213501-93636560094065.test.near";
        let payload_hash: [u8; 32] =
            hex::decode("835b9f469b36126284df2e06ecab9482cf495413ab9275faaafb2d40d79cf7bb")
                .unwrap()
                .try_into()
                .unwrap();

        let payload_hash_scalar = Scalar::from_bytes(payload_hash).unwrap();

        // Derive and convert user pk
        let mpc_pk = hex::decode(mpc_key).unwrap();
        let mpc_pk = EncodedPoint::from_bytes(mpc_pk).unwrap();
        let mpc_pk = AffinePoint::from_encoded_point(&mpc_pk).unwrap();

        let account_id = account_id.parse().unwrap();
        let derivation_epsilon: k256::Scalar =
            derive_epsilon_near(LEGACY_MPC_KEY_VERSION_0, &account_id, "test");
        let user_pk: AffinePoint = derive_key(mpc_pk, derivation_epsilon);
        let user_pk_y_parity = match user_pk.y_is_odd().unwrap_u8() {
            0 => secp256k1::Parity::Even,
            1 => secp256k1::Parity::Odd,
            _ => unreachable!(),
        };
        let user_pk_x = x_coordinate::<k256::Secp256k1>(&user_pk);
        let user_pk_x = secp256k1::XOnlyPublicKey::from_slice(&user_pk_x.to_bytes()).unwrap();
        let user_secp_pk: secp256k1::PublicKey =
            secp256k1::PublicKey::from_x_only_public_key(user_pk_x, user_pk_y_parity);
        let user_address_from_pk = public_key_to_address(&user_secp_pk);

        // Prepare R ans s signature values
        let big_r = hex::decode(big_r).unwrap();
        let big_r = EncodedPoint::from_bytes(big_r).unwrap();
        let big_r = AffinePoint::from_encoded_point(&big_r).unwrap();
        let big_r_y_parity = big_r.y_is_odd().unwrap_u8() as i32;
        assert!(big_r_y_parity == 0 || big_r_y_parity == 1);

        let s = hex::decode(s).unwrap().try_into().unwrap();
        let s = k256::Scalar::from_bytes(s).unwrap();
        let r = x_coordinate::<k256::Secp256k1>(&big_r);

        let signature = cait_sith::FullSignature::<k256::Secp256k1> { big_r, s };

        let multichain_sig = mpc_node::kdf::into_signature(
            &user_pk,
            &signature.big_r,
            &signature.s,
            payload_hash_scalar,
        )
        .unwrap();

        // Check signature using cait-sith tooling
        let is_signature_valid_for_user_pk = signature.verify(&user_pk, &payload_hash_scalar);
        let is_signature_valid_for_mpc_pk = signature.verify(&mpc_pk, &payload_hash_scalar);
        let another_user_pk = derive_key(mpc_pk, derivation_epsilon + k256::Scalar::ONE);
        let is_signature_valid_for_another_user_pk =
            signature.verify(&another_user_pk, &payload_hash_scalar);
        assert!(is_signature_valid_for_user_pk);
        assert!(!is_signature_valid_for_mpc_pk);
        assert!(!is_signature_valid_for_another_user_pk);

        // Check signature using ecdsa tooling
        let k256_sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();
        let user_pk_k256: k256::elliptic_curve::PublicKey<k256::Secp256k1> =
            k256::PublicKey::from_affine(user_pk).unwrap();

        let ecdsa_local_verify_result = verify(
            &k256::ecdsa::VerifyingKey::from(&user_pk_k256),
            &payload_hash,
            &k256_sig,
        );
        assert!(ecdsa_local_verify_result.is_ok());

        // TODO: fix
        // let ecdsa_signature: ecdsa::Signature<Secp256k1> =
        //     ecdsa::Signature::from_scalars(r, s).unwrap();
        // let ecdsa_verify_result = ecdsa::signature::Verifier::verify(
        //     &k256::ecdsa::VerifyingKey::from(&user_pk_k256),
        //     &payload_hash_reversed,
        //     &ecdsa_signature,
        // );
        // assert!(ecdsa_verify_result.is_ok());
        // let k256_verify_key = k256::ecdsa::VerifyingKey::from(&user_pk_k256);
        // let k256_verify_result = k256_verify_key.verify(&payload_hash_reversed, &k256_sig);
        // assert!(k256_verify_result.is_ok());

        // Check if recovered address is the same as the user address
        let signature_for_recovery: [u8; 64] = {
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&r.to_bytes());
            signature[32..].copy_from_slice(&s.to_bytes());
            signature
        };

        let recovered_from_signature_address_web3 = recover_eth_address(
            &payload_hash,
            &signature_for_recovery,
            multichain_sig.recovery_id,
        );
        assert_eq!(user_address_from_pk, recovered_from_signature_address_web3);
    }

    fn verify(
        key: &VerifyingKey,
        msg: &[u8],
        sig: &k256::ecdsa::Signature,
    ) -> Result<(), &'static str> {
        let q = ProjectivePoint::<k256::Secp256k1>::from(key.as_affine());
        let z = ecdsa::hazmat::bits2field::<k256::Secp256k1>(msg).unwrap();

        // &k256::FieldBytes::from_slice(&k256::Scalar::from_bytes(msg).to_bytes()),
        verify_prehashed(&q, &z, sig)
    }

    fn verify_prehashed(
        q: &ProjectivePoint<k256::Secp256k1>,
        z: &k256::FieldBytes,
        sig: &k256::ecdsa::Signature,
    ) -> Result<(), &'static str> {
        // let z: Scalar = Scalar::reduce_bytes(z);
        let z =
    <Scalar as Reduce<<k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(z);
        let (r, s) = sig.split_scalars();
        let s_inv = *s.invert_vartime();
        let u1 = z * s_inv;
        let u2 = *r * s_inv;
        let reproduced =
            lincomb(&ProjectivePoint::<k256::Secp256k1>::GENERATOR, &u1, q, &u2).to_affine();
        let x = reproduced.x();

        // println!("------------- verify_prehashed[beg] -------------");
        // println!("z: {z:#?}");
        // // println!("r: {r:#?}");
        // // println!("s: {s:#?}");
        // println!("s_inv {s_inv:#?}");
        // println!("u1 {u1:#?}");
        // println!("u2 {u2:#?}");
        // println!("reproduced {reproduced:#?}");
        // println!("reproduced_x {x:?}");
        // println!("------------- verify_prehashed[end] -------------");

        let reduced =
    <Scalar as Reduce<<k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
        &x,
    );

        //println!("reduced {reduced:#?}");

        if *r == reduced {
            Ok(())
        } else {
            Err("error")
        }
    }

    fn lincomb(
        x: &ProjectivePoint<k256::Secp256k1>,
        k: &Scalar,
        y: &ProjectivePoint<k256::Secp256k1>,
        l: &Scalar,
    ) -> ProjectivePoint<k256::Secp256k1> {
        (*x * k) + (*y * l)
    }
}
