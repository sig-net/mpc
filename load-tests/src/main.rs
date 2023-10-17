mod constants;
mod primitives;
pub mod utils;

use constants::VALID_OIDC_PROVIDER_KEY;
use goose::prelude::*;
use mpc_recovery::{
    msg::{ClaimOidcRequest, MpcPkRequest},
    sign_node::oidc::OidcToken,
    utils::{claim_oidc_request_digest, sign_digest},
};
use near_crypto::SecretKey;
use primitives::UserSession;
use utils::build_send_and_check_request;

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("registration")
                .register_transaction(transaction!(prepare_user_credentials))
                .register_transaction(transaction!(claim_oidc))
                .register_transaction(transaction!(new_account)),
        )
        .register_scenario(
            scenario!("simpleMpcPublicKey").register_transaction(transaction!(mpc_public_key)),
        )
        .execute()
        .await?;

    Ok(())
}

async fn prepare_user_credentials(user: &mut GooseUser) -> TransactionResult {
    // Generate 2 key pairs
    let fa_sk = SecretKey::from_random(near_crypto::KeyType::ED25519);
    let la_sk = SecretKey::from_random(near_crypto::KeyType::ED25519);

    // Create JWT with random sub (usually done by OIDC Provider)
    let jwt_token = utils::create_jwt_token(
        VALID_OIDC_PROVIDER_KEY,
        constants::VALID_OIDC_AUD,
        constants::VALID_OIDC_ISS,
        None,
    );

    let session = UserSession {
        jwt_token: OidcToken::new(&jwt_token),
        fa_sk,
        la_sk,
    };

    // Save JWT to session
    user.set_session_data(session);

    Ok(())
}

async fn mpc_public_key(user: &mut GooseUser) -> TransactionResult {
    let body_json = serde_json::to_string(&MpcPkRequest {}).expect("json serialization failed");
    build_send_and_check_request(user, "mpc_public_key", &body_json).await
}

async fn claim_oidc(user: &mut GooseUser) -> TransactionResult {
    let sesion = user.get_session_data::<UserSession>().unwrap();
    let oidc_token_hash = sesion.jwt_token.digest_hash();
    let frp_secret_key = sesion.fa_sk.clone();
    let frp_public_key = frp_secret_key.public_key();

    let request_digest = claim_oidc_request_digest(&oidc_token_hash, &frp_public_key).unwrap();
    let frp_signature = sign_digest(&request_digest, &frp_secret_key).unwrap();

    let claim_oidc_request = ClaimOidcRequest {
        oidc_token_hash: oidc_token_hash.to_owned(),
        frp_public_key,
        frp_signature,
    };

    let body_json = serde_json::to_string(&claim_oidc_request).expect("json serialization failed");

    build_send_and_check_request(user, "claim_oidc", &body_json).await
}

async fn _user_credentials(_user: &mut GooseUser) -> TransactionResult {
    Ok(())
}

async fn new_account(_user: &mut GooseUser) -> TransactionResult {
    Ok(())
}

async fn _sign(_user: &mut GooseUser) -> TransactionResult {
    Ok(())
}
