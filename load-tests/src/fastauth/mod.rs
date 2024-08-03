pub mod constants;
pub mod primitives;
pub mod utils;

use core::panic;
use near_workspaces::{types::NearToken, Account};
use reqwest::{header::CONTENT_TYPE, Body};
use std::{str::FromStr, time::Duration, vec};

use constants::VALID_OIDC_PROVIDER_KEY;
use goose::prelude::*;
use mpc_recovery::{
    msg::{
        ClaimOidcRequest, MpcPkRequest, NewAccountRequest, SignRequest, UserCredentialsRequest,
        UserCredentialsResponse,
    },
    sign_node::oidc::OidcToken,
    transaction::CreateAccountOptions,
    utils::{
        claim_oidc_request_digest, sign_digest, sign_request_digest,
        user_credentials_request_digest,
    },
};
use near_crypto::SecretKey;
use near_primitives::{
    account::{AccessKey, AccessKeyPermission},
    borsh::BorshSerialize,
    delegate_action::DelegateAction,
    transaction::{Action, AddKeyAction},
    types::AccountId,
};
use primitives::UserSession;
use utils::build_send_and_check_request;

pub async fn prepare_user_credentials(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("prepare_user_credentials");

    // Config
    let account_creator = "dev-1660670387515-45063246810397".to_string();
    let sk = "ed25519:4hc3qA3nTE8M63DB8jEZx9ZbHVUPdkMjUAoa11m4xtET7F6w4bk51TwQ3RzEcFhBtXvF6NYzFdiJduaGdJUvynAi";
    let sub_account_init_balance = NearToken::from_near(1);

    let worker = near_workspaces::testnet().await.unwrap();

    let root_account = Account::from_secret_key(
        near_workspaces::types::AccountId::try_from(account_creator).unwrap(),
        near_workspaces::types::SecretKey::from_str(sk).unwrap(),
        &worker,
    );

    let subaccount = root_account
        .create_subaccount(&format!("user-{}", rand::random::<u64>()))
        // Balance this values depending on how many users you want to create and available balance
        .initial_balance(sub_account_init_balance)
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();

    tracing::info!(
        "Created user accountId: {}, pk: {}",
        subaccount.id(),
        subaccount.secret_key().public_key()
    );

    // Create JWT with random sub (usually done by OIDC Provider)
    let oidc_token = OidcToken::new(&utils::create_jwt_token(
        VALID_OIDC_PROVIDER_KEY,
        constants::VALID_OIDC_AUD,
        constants::VALID_OIDC_ISS,
        None,
    ));

    let session = UserSession {
        jwt_token: oidc_token,
        account: subaccount.clone(),
        root_account,
        near_account_id: AccountId::try_from(subaccount.id().to_string()).unwrap(),
        fa_sk: SecretKey::from_str(&subaccount.secret_key().to_string()).unwrap(),
        la_sk: SecretKey::from_random(near_crypto::KeyType::ED25519), // no need to actually add it ATM
        recovery_pk: None,
    };

    user.set_session_data(session);

    Ok(())
}

pub async fn delete_user_account(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("delete_user_accounts");

    let session = user
        .get_session_data::<UserSession>()
        .expect("Session Data must be set");

    let _ = session
        .account
        .clone()
        .delete_account(session.root_account.id())
        .await
        .expect("Failed to delete subaccount");

    Ok(())
}

pub async fn user_credentials(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("user_credentials");
    let session = user
        .get_session_data::<UserSession>()
        .expect("Session Data must be set");

    let oidc_token = session.jwt_token.clone();
    let fa_sk = session.fa_sk.clone();
    let fa_pk = fa_sk.public_key();
    let la_sk = session.la_sk.clone();
    let near_account_id = session.near_account_id.clone();
    let account = session.account.clone();
    let root_account = session.root_account.clone();

    let user_credentials_request_digest =
        user_credentials_request_digest(&oidc_token, &fa_pk).expect("Failed to create digest");

    let user_credentials_frp_signature =
        sign_digest(&user_credentials_request_digest, &fa_sk).expect("Failed to sign digest");

    let user_credentials_request = UserCredentialsRequest {
        oidc_token: oidc_token.clone(),
        frp_public_key: fa_pk,
        frp_signature: user_credentials_frp_signature,
    };

    let body_json =
        serde_json::to_string(&user_credentials_request).expect("json serialization failed");

    let body = Body::from(body_json.to_owned());
    let request_builder = user
        .get_request_builder(&GooseMethod::Post, "user_credentials")?
        .body(body)
        .header(CONTENT_TYPE, "application/json")
        .timeout(Duration::from_secs(10));

    let goose_request = GooseRequest::builder()
        .set_request_builder(request_builder)
        .build();

    let goose_responce = user.request(goose_request).await?;

    let response = goose_responce.response.expect("Expected response ... .");

    let user_credentials_response = response
        .json::<UserCredentialsResponse>()
        .await
        .expect("Failed to parse user credentials response");

    if let UserCredentialsResponse::Ok { recovery_pk } = user_credentials_response {
        tracing::info!("UserCredentialsResponce has Ok, setting session data");
        let session = UserSession {
            jwt_token: oidc_token,
            account,
            root_account,
            near_account_id,
            fa_sk,
            la_sk,
            recovery_pk: Some(recovery_pk),
        };
        user.set_session_data(session);
    } else {
        panic!(
            "UserCredentialsResponce has Error: {:?}",
            user_credentials_response
        );
    }

    Ok(())
}

pub async fn mpc_public_key(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("mpc_public_key");
    let body_json = serde_json::to_string(&MpcPkRequest {}).expect("json serialization failed");
    build_send_and_check_request(user, "mpc_public_key", &body_json).await
}

pub async fn claim_oidc(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("claim_oidc");
    let session = user
        .get_session_data::<UserSession>()
        .expect("Session Data must be set");
    let oidc_token_hash = session.jwt_token.digest_hash();
    let frp_secret_key = session.fa_sk.clone();
    let frp_public_key = frp_secret_key.public_key();

    let request_digest = claim_oidc_request_digest(&oidc_token_hash, &frp_public_key)
        .expect("Failed to create digest");
    let frp_signature =
        sign_digest(&request_digest, &frp_secret_key).expect("Failed to sign digest");

    let claim_oidc_request = ClaimOidcRequest {
        oidc_token_hash: oidc_token_hash.to_owned(),
        frp_public_key,
        frp_signature,
    };

    let body_json = serde_json::to_string(&claim_oidc_request).expect("json serialization failed");

    build_send_and_check_request(user, "claim_oidc", &body_json).await
}

pub async fn new_account(user: &mut GooseUser) -> TransactionResult {
    let session = user
        .get_session_data::<UserSession>()
        .expect("Session Data must be set");
    let oidc_token = session.jwt_token.clone();
    let fa_secret_key = session.fa_sk.clone();
    let fa_public_key = fa_secret_key.public_key();
    let user_account_id = session.near_account_id.clone();

    let create_account_options = CreateAccountOptions {
        full_access_keys: Some(vec![fa_public_key.clone()]),
        limited_access_keys: None,
        contract_bytes: None,
    };

    let user_credentials_request_digest =
        user_credentials_request_digest(&oidc_token, &fa_public_key)
            .expect("Failed to create digest");

    let user_credentials_frp_signature =
        sign_digest(&user_credentials_request_digest, &fa_secret_key)
            .expect("Failed to sign digest");

    let new_account_request = NewAccountRequest {
        near_account_id: user_account_id,
        create_account_options,
        oidc_token: session.jwt_token.clone(),
        user_credentials_frp_signature,
        frp_public_key: fa_public_key,
    };

    let body_json = serde_json::to_string(&new_account_request).expect("json serialization failed");
    build_send_and_check_request(user, "new_account", &body_json).await
}

pub async fn sign(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("sign");
    let session = user
        .get_session_data::<UserSession>()
        .expect("Session Data must be set");
    let oidc_token = session.jwt_token.clone();
    let fa_secret_key = session.fa_sk.clone();
    let fa_public_key = fa_secret_key.public_key();
    let account_id = session.near_account_id.clone();
    let recovery_pk = session
        .recovery_pk
        .clone()
        .expect("Recovery PK must be set before calling /sign");

    let new_secret_key = SecretKey::from_random(near_crypto::KeyType::ED25519);
    let new_public_key = new_secret_key.public_key();

    let nonce = 0; // Set real nonce in case transaction is entend to be executed
    let block_height = 0; // Set real block height in case transaction is entend to be executed

    let add_key_delegate_action = DelegateAction {
        sender_id: account_id.clone(),
        receiver_id: account_id.clone(),
        actions: vec![Action::AddKey(AddKeyAction {
            public_key: new_public_key.clone(),
            access_key: AccessKey {
                nonce: 0,
                permission: AccessKeyPermission::FullAccess,
            },
        })
        .try_into()
        .unwrap()],
        nonce,
        max_block_height: block_height + 100,
        public_key: recovery_pk,
    };

    let sign_request_digest =
        sign_request_digest(&add_key_delegate_action, &oidc_token, &fa_public_key)
            .expect("Failed to create digest");
    let sign_request_frp_signature =
        sign_digest(&sign_request_digest, &fa_secret_key).expect("Failed to sign digest");

    let user_credentials_request_digest =
        user_credentials_request_digest(&oidc_token, &fa_public_key)
            .expect("Failed to create digest");
    let user_credentials_frp_signature =
        sign_digest(&user_credentials_request_digest, &fa_secret_key)
            .expect("Failed to sign digest");

    let sign_request = SignRequest {
        delegate_action: add_key_delegate_action
            .try_to_vec()
            .expect("Failed to serialize delegate action"),
        oidc_token,
        frp_signature: sign_request_frp_signature,
        user_credentials_frp_signature,
        frp_public_key: fa_public_key,
    };

    let body_json = serde_json::to_string(&sign_request).expect("json serialization failed");
    build_send_and_check_request(user, "sign", &body_json).await
}
