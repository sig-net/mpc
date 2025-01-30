use near_crypto::{PublicKey, SecretKey};
use near_primitives::types::AccountId;
use near_workspaces::Account;

pub struct UserSession {
    pub account: Account,
    pub near_account_id: AccountId,
    pub fa_sk: SecretKey,
    pub recovery_pk: Option<PublicKey>,
}
