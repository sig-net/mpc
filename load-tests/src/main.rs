mod constants;
mod primitives;
pub mod utils;

use std::time::Duration;

use constants::VALID_OIDC_PROVIDER_KEY;
use goose::prelude::*;
use goose_eggs::{validate_and_load_static_assets, Validate};
use near_crypto::SecretKey;
use primitives::UserSession;
use reqwest::{header::CONTENT_TYPE, Body};

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
        .register_scenario(scenario!("simpleMetrics").register_transaction(transaction!(metrics)))
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
        jwt_token,
        fa_sk,
        la_sk,
    };

    // Save JWT to session
    user.set_session_data(session);

    Ok(())
}

async fn mpc_public_key(user: &mut GooseUser) -> TransactionResult {
    let request_builder = user
        .get_request_builder(&GooseMethod::Post, "mpc_public_key")?
        .body(Body::from("{}"))
        .header(CONTENT_TYPE, "application/json")
        .timeout(Duration::from_secs(10));

    let goose_request = GooseRequest::builder()
        .set_request_builder(request_builder)
        .build();

    let goose_responce = user.request(goose_request).await?;

    let validate = &Validate::builder().status(200).build();
    validate_and_load_static_assets(user, goose_responce, validate).await?;

    Ok(())
}

async fn claim_oidc(_user: &mut GooseUser) -> TransactionResult {
    Ok(())
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

async fn metrics(_user: &mut GooseUser) -> TransactionResult {
    Ok(())
}
