use near_crypto::{InMemorySigner, PublicKey, SecretKey};
use near_primitives::account::{AccessKey, AccessKeyPermission};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{
    Action, AddKeyAction, FunctionCallAction, SignedTransaction, Transaction,
};
use near_primitives::types::{AccountId, Nonce};

use serde_json::json;

pub enum NetworkType {
    _Mainnet,
    Testnet,
}

pub fn new_create_account_transaction(
    new_account_id: AccountId,
    user_pk: PublicKey,
    signer_id: AccountId,
    signer_pk: PublicKey,
    nonce: Nonce,
    block_hash: CryptoHash,
    network_type: NetworkType,
) -> Transaction {
    Transaction {
        signer_id,
        public_key: signer_pk,
        nonce,
        receiver_id: match network_type {
            NetworkType::_Mainnet => "near".parse().unwrap(),
            NetworkType::Testnet => "testnet".parse().unwrap(),
        },
        block_hash,
        actions: vec![Action::FunctionCall(FunctionCallAction {
            method_name: "create_account".to_string(),
            args: json!({
                "new_account_id": new_account_id,
                "new_public_key": user_pk.to_string(),
            })
            .to_string()
            .into_bytes(),
            gas: 300_000_000_000_000,
            deposit: 0,
        })],
    }
}

pub fn new_add_fa_key_transaction(
    account_id: AccountId,
    existing_pk: PublicKey,
    new_pk: PublicKey,
    nonce: Nonce,
    block_hash: CryptoHash,
) -> Transaction {
    Transaction {
        signer_id: account_id.clone(),
        public_key: existing_pk,
        nonce,
        receiver_id: account_id,
        block_hash,
        actions: vec![Action::AddKey(AddKeyAction {
            public_key: new_pk,
            access_key: AccessKey {
                nonce: 0,
                permission: AccessKeyPermission::FullAccess,
            },
        })],
    }
}

pub fn sign_transaction(
    transaction: Transaction,
    signer_id: AccountId,
    signer_sk: SecretKey,
) -> SignedTransaction {
    let signer = InMemorySigner::from_secret_key(signer_id, signer_sk);
    transaction.sign(&signer)
}
