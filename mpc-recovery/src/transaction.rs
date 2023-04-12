use near_crypto::{InMemorySigner, PublicKey, SecretKey};
use near_primitives::account::{AccessKey, AccessKeyPermission};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{
    Action, AddKeyAction, FunctionCallAction, SignedTransaction, Transaction,
};
use near_primitives::types::{AccountId, Nonce};

use serde_json::json;

pub fn new_signed_create_account_transaction(
    new_account_id: AccountId,
    user_pk: PublicKey,
    mpc_pk: PublicKey,
    signer_account_id: AccountId, // This is the account that signs and pays for the transaction
    signer_secret_key: SecretKey,
    nonce: Nonce,
    block_hash: CryptoHash,
) -> SignedTransaction {
    let signer = InMemorySigner::from_secret_key(signer_account_id.clone(), signer_secret_key);

    // In order to create top-level NEAR account we need to use "near" contract.
    let contract_id: AccountId = "near".parse().unwrap();

    let transaction = Transaction {
        signer_id: signer.account_id.clone(),
        public_key: signer.public_key.clone(),
        nonce: nonce,
        receiver_id: contract_id,
        block_hash,
        actions: vec![
            Action::FunctionCall(FunctionCallAction {
                method_name: "create_account".to_string(),
                args: json!({
                    "new_account_id": new_account_id,
                    "new_public_key": user_pk.to_string(),
                })
                .to_string()
                .into_bytes(),
                gas: 300_000_000_000_000,
                deposit: 0,
            }),
            Action::AddKey(AddKeyAction { // <---- This key will be added to the wrong account
                public_key: mpc_pk,
                access_key: AccessKey {
                    nonce: 0,
                    permission: AccessKeyPermission::FullAccess,
                },
            }),
        ],
    };

    return transaction.sign(&signer);
}
