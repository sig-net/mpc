use near_crypto::{PublicKey, SecretKey};
use near_primitives::types::AccountId;
use near_workspaces::Account;

pub struct UserSession {
    pub account: Account,
    // account to create other account
    pub root_account: Account,
    pub near_account_id: AccountId,
    pub fa_sk: SecretKey,
    pub la_sk: SecretKey,
    pub recovery_pk: Option<PublicKey>,
}
