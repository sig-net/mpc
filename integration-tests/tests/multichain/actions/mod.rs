pub mod wait_for;

use crate::MultichainTestContext;

use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, Scalar, Secp256k1};
use mpc_contract::RunningContractState;
use mpc_recovery_node::kdf;
use mpc_recovery_node::util::ScalarExt;
use near_crypto::{InMemorySigner, Secp256K1Signature};
use near_jsonrpc_client::methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest;
use near_lake_primitives::CryptoHash;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction};
use near_workspaces::Account;
use rand::Rng;

use std::time::Duration;

pub async fn request_sign(
    ctx: &MultichainTestContext<'_>,
) -> anyhow::Result<([u8; 32], Account, CryptoHash)> {
    let worker = &ctx.nodes.ctx().worker;
    let account = worker.dev_create_account().await?;
    let payload: [u8; 32] = rand::thread_rng().gen();
    let signer = InMemorySigner {
        account_id: account.id().clone(),
        public_key: account.secret_key().public_key().clone().into(),
        secret_key: account.secret_key().to_string().parse()?,
    };
    let (nonce, block_hash, _) = ctx
        .rpc_client
        .fetch_nonce(&signer.account_id, &signer.public_key)
        .await?;
    let tx_hash = ctx
        .jsonrpc_client
        .call(&RpcBroadcastTxAsyncRequest {
            signed_transaction: Transaction {
                nonce,
                block_hash,
                signer_id: signer.account_id.clone(),
                public_key: signer.public_key.clone(),
                receiver_id: ctx.nodes.ctx().mpc_contract.id().clone(),
                actions: vec![Action::FunctionCall(FunctionCallAction {
                    method_name: "sign".to_string(),
                    args: serde_json::to_vec(&serde_json::json!({
                        "payload": payload,
                        "path": "test",
                    }))?,
                    gas: 300_000_000_000_000,
                    deposit: 0,
                })],
            }
            .sign(&signer),
        })
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok((payload, account, tx_hash))
}

pub async fn single_signature_production(
    ctx: &MultichainTestContext<'_>,
    state: &RunningContractState,
) -> anyhow::Result<()> {
    let (payload, account, tx_hash) = request_sign(ctx).await?;
    let (signature_big_r, signature_s) = wait_for::signature_responded(ctx, tx_hash).await?;

    let mpc_pk = state.public_key.clone();

    let derivation_epsilon = kdf::derive_epsilon(account.id(), "test");

    check_signature_cait_sith(
        &signature_big_r,
        &signature_s,
        &payload,
        &derivation_epsilon,
        &mpc_pk,
    );
    check_signature_near(
        &signature_big_r,
        &signature_s,
        &payload,
        &derivation_epsilon,
        &mpc_pk,
    );

    Ok(())
}

fn check_signature_cait_sith(
    signature_big_r: &AffinePoint,
    signature_s: &Scalar,
    payload: &[u8; 32],
    derivation_epsilon: &Scalar,
    mpc_pk: &near_sdk::PublicKey,
) {
    let signature = cait_sith::FullSignature::<Secp256k1> {
        big_r: *signature_big_r,
        s: *signature_s,
    };

    let mpc_pk = near_sdk_pk_to_affine_point(mpc_pk);

    let user_pk = kdf::derive_key(mpc_pk, *derivation_epsilon);

    assert!(signature.verify(&user_pk, &Scalar::from_bytes(payload),));
}

fn check_signature_near(
    signature_big_r: &AffinePoint,
    signature_s: &Scalar,
    payload: &[u8; 32],
    derivation_epsilon: &Scalar,
    mpc_pk: &near_sdk::PublicKey,
) {
    let signature = reconstruct_near_signature(signature_big_r, signature_s);

    // Reconstract user PublicKey
    let mpc_pk = near_sdk_pk_to_affine_point(mpc_pk);
    let user_pk = kdf::derive_key(mpc_pk, *derivation_epsilon);
    let user_pk = affine_point_to_near_pk(&user_pk);

    assert!(signature.verify(payload, &user_pk));
}

fn near_sdk_pk_to_affine_point(pk: &near_sdk::PublicKey) -> AffinePoint {
    let mut pk_bytes = vec![0x04];
    pk_bytes.extend_from_slice(&pk.as_bytes()[1..]);
    let point = EncodedPoint::from_bytes(pk_bytes).unwrap();
    AffinePoint::from_encoded_point(&point).unwrap()
}

// TODO: fix
fn reconstruct_near_signature(
    signature_big_r: &AffinePoint,
    signature_s: &Scalar,
) -> near_crypto::Signature {
    let signature_bytes: [u8; 65] = {
        let mut signature_bytes = [0u8; 65];
        signature_bytes[0] = signature_big_r.y_is_odd().unwrap_u8();
        signature_bytes[1..33].copy_from_slice(&signature_big_r.x());
        signature_bytes[33..65].copy_from_slice(&signature_s.to_bytes());
        signature_bytes
    };
    near_crypto::Signature::SECP256K1(Secp256K1Signature::try_from(signature_bytes).unwrap())
}

// TODO: fix
fn affine_point_to_near_pk(point: &AffinePoint) -> near_crypto::PublicKey {
    let point_bytes = {
        let mut point_bytes = [0u8; 64];
        point_bytes[0..32].copy_from_slice(&point.x());
        point_bytes[32..64].copy_from_slice(&point.x()); // TODO: definetelly not what we need
        point_bytes
    };
    near_crypto::PublicKey::SECP256K1(
        near_crypto::Secp256K1PublicKey::try_from(point_bytes).unwrap(),
    )
}
