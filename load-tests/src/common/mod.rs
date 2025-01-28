pub mod primitives;

use std::str::FromStr;

use goose::prelude::*;
use near_crypto::SecretKey;
use near_primitives::types::AccountId;
use primitives::UserSession;

pub async fn prepare_user_credentials(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("prepare_user_credentials");

    let worker = near_workspaces::testnet().await.unwrap();

    let account = worker.dev_create_account().await.unwrap();

    tracing::info!(
        "Created user accountId: {}, pk: {}",
        account.id(),
        account.secret_key().public_key()
    );

    let session = UserSession {
        account: account.clone(),
        near_account_id: AccountId::try_from(account.id().to_string()).unwrap(),
        fa_sk: SecretKey::from_str(&account.secret_key().to_string()).unwrap(),
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
        .delete_account(&AccountId::from_str("serhii.testnet").unwrap())
        .await
        .expect("Failed to delete account");
    Ok(())
}
