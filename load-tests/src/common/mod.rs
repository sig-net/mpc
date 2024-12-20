pub mod primitives;

use near_workspaces::{types::NearToken, Account};

use std::str::FromStr;

use goose::prelude::*;
use near_crypto::SecretKey;
use near_primitives::types::AccountId;
use primitives::UserSession;

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

    let session = UserSession {
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
