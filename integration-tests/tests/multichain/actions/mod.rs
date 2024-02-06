pub mod wait_for;

use crate::MultichainTestContext;

use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_contract::RunningContractState;
use mpc_recovery_node::kdf;
use mpc_recovery_node::util::{NearPublicKeyExt, ScalarExt};
use near_crypto::InMemorySigner;
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

    let mpc_pk: AffinePoint = state.public_key.clone().into_affine_point();

    let derivation_epsilon = kdf::derive_epsilon(account.id(), "test");

    check_signature_cait_sith(
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
    mpc_pk: &AffinePoint,
) {
    let signature = cait_sith::FullSignature::<Secp256k1> {
        big_r: *signature_big_r,
        s: *signature_s,
    };

    let user_pk = kdf::derive_key(*mpc_pk, *derivation_epsilon);

    let payload2: [u8; 32] = rand::thread_rng().gen();

    assert!(signature.verify(&user_pk, &Scalar::from_bytes(payload)));
    assert_eq!(signature.verify(&user_pk, &Scalar::from_bytes(&payload2)), false);
}
