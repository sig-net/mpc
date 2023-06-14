use crate::{account, check, key, token, with_nodes};
use anyhow::anyhow;
use ed25519_dalek::{Signature, Verifier};
use hyper::StatusCode;
use mpc_recovery::{
    msg::{
        AddKeyRequest, AddKeyResponse, ClaimOidcRequest, ClaimOidcResponse, NewAccountRequest,
        NewAccountResponse,
    },
    oauth::get_test_claims,
    sign_node::check_signatures::{
        claim_id_token_request_digest, claim_id_token_response_digest, oidc_digest,
    },
    transaction::{
        call_all_nodes, sign_payload_with_mpc, to_dalek_combined_public_key, CreateAccountOptions,
        LimitedAccessKey,
    },
};
use rand::{distributions::Alphanumeric, Rng};
use std::time::Duration;
use workspaces::types::AccessKeyPermission;

#[tokio::test]
async fn test_basic_action_with_sig() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;

            let user_private_key =
                near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
            let user_public_key = user_private_key.public_key().to_string();
            let oidc_token = token::valid();
            let id_token_hash = oidc_digest(&oidc_token);

            let mut oidc_request = ClaimOidcRequest {
                id_token_hash,
                public_key: user_public_key.clone(),
                // Dummy signature
                signature: Signature::from_bytes(&[0; 32]).unwrap(),
            };

            let digest = claim_id_token_request_digest(&oidc_request).unwrap();

            let sig = match user_private_key.sign(&digest) {
                near_crypto::Signature::ED25519(k) => k,
                _ => return Err(anyhow::anyhow!("Wrong signature type")),
            };

            oidc_request.signature = sig;

            let (status_code, oidc_response) =
                ctx.leader_node.claim_id_token(oidc_request.clone()).await?;
            assert_eq!(status_code, StatusCode::OK);

            let res_signature = match oidc_response {
                ClaimOidcResponse::Ok { mpc_signature } => mpc_signature,
                ClaimOidcResponse::Err { msg } => return Err(anyhow::anyhow!(msg)),
            };

            // Get the node public key
            let client = reqwest::Client::new();
            let signer_urls: Vec<_> = ctx
                .signer_nodes
                .iter()
                .map(|s| s.local_address.clone())
                .collect();
            let res = call(&client, &signer_urls, "public_key", "").await?;
            let combined_pub = to_dalek_combined_public_key(&res).unwrap();

            let res_digest = claim_id_token_response_digest(oidc_request.signature).unwrap();
            combined_pub.verify(&res_digest, &res_signature)?;

            let signature = sign_payload_with_mpc(
                &client,
                &signer_urls,
                "validToken:test-subject".to_string(),
                payload.clone().into(),
            )
            .await?;
            // Create account
            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    oidc_token: oidc_token.clone(),
                    public_key: user_public_key.clone(),
                })
                .await?;

            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(new_acc_response, NewAccountResponse::Ok {
                    user_public_key: user_pk,
                    user_recovery_public_key: _,
                    near_account_id: acc_id,
                } if user_pk == user_public_key && acc_id == account_id.to_string()
            ));

            let account_id = get_test_claims("test-subject".to_string()).get_internal_account_id();
            let res = call_all_nodes(&client, &signer_urls, "public_key", account_id).await?;

            check::access_key_exists(&ctx, &account_id, &user_public_key).await?;

            // Add key
            let new_user_public_key = key::random();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token: oidc_token.clone(),
                    public_key: new_user_public_key.clone(),
                    signature: None,
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(
                add_key_response,
                AddKeyResponse::Ok {
                    user_public_key: new_pk,
                    near_account_id: acc_id,
                } if new_pk == new_user_public_key && acc_id == account_id.to_string()
            ));

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            let digest = claim_id_token_request_digest(&oidc_request).unwrap();

            let signature = match user_private_key.sign(&digest) {
                near_crypto::Signature::ED25519(k) => k,
                _ => return Err(anyhow::anyhow!("Wrong signature type")),
            };

            // Adding the same key should now fail
            let (status_code, _add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token,
                    public_key: new_user_public_key.clone(),
                    signature: Some(signature),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            Ok(())
        })
    })
    .await
}

#[tokio::test]
async fn test_basic_action() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_public_key = key::random();
            let oidc_token = token::valid_random();

            let create_account_options = CreateAccountOptions {
                full_access_keys: Some(vec![user_public_key.clone().parse().unwrap()]),
                limited_access_keys: None,
                contract_bytes: None,
            };

            // Create account
            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    create_account_options,
                    oidc_token: oidc_token.clone(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            assert!(matches!(new_acc_response, NewAccountResponse::Ok {
                    create_account_options: _,
                    user_recovery_public_key: _,
                    near_account_id: acc_id,
                } if acc_id == account_id.to_string()
            ));

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &user_public_key).await?;

            // Add key
            let new_user_public_key = key::random();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token: oidc_token.clone(),
                    create_account_options: CreateAccountOptions {
                        full_access_keys: Some(vec![new_user_public_key.parse()?]),
                        limited_access_keys: None,
                        contract_bytes: None,
                    },
                    signature: None,
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);
            let AddKeyResponse::Ok {
                full_access_keys,
                limited_access_keys,
                near_account_id,
            } = add_key_response else {
                anyhow::bail!("unexpected pattern");
            };
            assert_eq!(full_access_keys, vec![new_user_public_key.clone()]);
            assert_eq!(limited_access_keys, Vec::<String>::new());
            assert_eq!(near_account_id, account_id.to_string());

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            // Adding the same key should now fail
            let (status_code, _add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    near_account_id: Some(account_id.to_string()),
                    oidc_token,
                    create_account_options: CreateAccountOptions {
                        full_access_keys: Some(vec![new_user_public_key.clone().parse()?]),
                        limited_access_keys: None,
                        contract_bytes: None,
                    },
                    signature: None,
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

            tokio::time::sleep(Duration::from_millis(2000)).await;

            check::access_key_exists(&ctx, &account_id, &new_user_public_key).await?;

            Ok(())
        })
    })
    .await
}

#[tokio::test]
async fn test_random_recovery_keys() -> anyhow::Result<()> {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            let account_id = account::random(ctx.worker)?;
            let user_full_access_key = key::random();

            let user_limited_access_key = LimitedAccessKey {
                public_key: key::random().parse().unwrap(),
                allowance: "100".to_string(),
                receiver_id: account::random(ctx.worker)?.to_string().parse().unwrap(), // TODO: type issues here
                method_names: "method_names".to_string(),
            };

            let create_account_options = CreateAccountOptions {
                full_access_keys: Some(vec![user_full_access_key.clone().parse().unwrap()]),
                limited_access_keys: Some(vec![user_limited_access_key.clone()]),
                contract_bytes: None,
            };

            let (status_code, _) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    create_account_options,
                    oidc_token: token::valid_random(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

            tokio::time::sleep(Duration::from_millis(2000)).await;

            let access_keys = ctx.worker.view_access_keys(&account_id).await?;

            let recovery_full_access_key1 = access_keys
                .clone()
                .into_iter()
                .find(|ak| {
                    ak.public_key.to_string() != user_full_access_key
                        && ak.public_key.to_string()
                            != user_limited_access_key.public_key.to_string()
                })
                .ok_or_else(|| anyhow::anyhow!("missing recovery access key"))?;

            match recovery_full_access_key1.access_key.permission {
                AccessKeyPermission::FullAccess => (),
                AccessKeyPermission::FunctionCall(_) => {
                    return Err(anyhow!(
                        "Got a limited access key when we expected a full access key"
                    ))
                }
            };

            let la_key = access_keys
                .into_iter()
                .find(|ak| {
                    ak.public_key.to_string() == user_limited_access_key.public_key.to_string()
                })
                .ok_or_else(|| anyhow::anyhow!("missing limited access key"))?;

            match la_key.access_key.permission {
                AccessKeyPermission::FullAccess => {
                    return Err(anyhow!(
                        "Got a full access key when we expected a limited access key"
                    ))
                }
                AccessKeyPermission::FunctionCall(fc) => {
                    assert_eq!(
                        fc.receiver_id,
                        user_limited_access_key.receiver_id.to_string()
                    );
                    assert_eq!(
                        fc.method_names.first().unwrap(),
                        &user_limited_access_key.method_names.to_string()
                    );
                }
            };

            // Generate another user
            let account_id = account::random(ctx.worker)?;
            let user_public_key = key::random();

            let create_account_options = CreateAccountOptions {
                full_access_keys: Some(vec![user_public_key.clone().parse().unwrap()]),
                limited_access_keys: None,
                contract_bytes: None,
            };

            let (status_code, _) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    near_account_id: account_id.to_string(),
                    create_account_options,
                    oidc_token: token::valid_random(),
                })
                .await?;
            assert_eq!(status_code, StatusCode::OK);

            tokio::time::sleep(Duration::from_millis(2000)).await;

            let access_keys = ctx.worker.view_access_keys(&account_id).await?;
            let recovery_full_access_key2 = access_keys
                .into_iter()
                .find(|ak| ak.public_key.to_string() != user_public_key)
                .ok_or_else(|| anyhow::anyhow!("missing recovery access key"))?;

            assert_ne!(
                recovery_full_access_key1.public_key, recovery_full_access_key2.public_key,
                "MPC recovery should generate random recovery keys for each user"
            );

            Ok(())
        })
    })
    .await
}
