use near_crypto::{InMemorySigner, PublicKey, SecretKey};
use near_primitives::account::{AccessKey, AccessKeyPermission};
use near_primitives::transaction::{Action, AddKeyAction, FunctionCallAction};
use near_primitives::types::{AccountId, Nonce};

use near_primitives::delegate_action::{DelegateAction, NonDelegateAction, SignedDelegateAction};
use near_primitives::signable_message::{SignableMessage, SignableMessageType};

use serde::{Deserialize, Serialize};
use serde_json::json;

pub enum NetworkType {
    _Mainnet,
    Testnet,
}

#[derive(Serialize, Deserialize)]
pub struct CreateAccountOptions {
    // Note: original structure contains other unrelated fields
    pub full_access_keys: Option<Vec<PublicKey>>,
}

#[allow(clippy::too_many_arguments)]
pub fn get_create_account_delegate_action(
    signer_id: AccountId,
    signer_pk: PublicKey,
    new_account_id: AccountId,
    new_account_recovery_pk: PublicKey,
    new_account_user_pk: PublicKey,
    network_type: NetworkType,
    nonce: Nonce,
    max_block_height: u64,
) -> DelegateAction {
    let create_acc_options = CreateAccountOptions {
        full_access_keys: Some(vec![new_account_user_pk, new_account_recovery_pk]),
    };
    let create_acc_action = Action::FunctionCall(FunctionCallAction {
        method_name: "create_account".to_string(),
        args: json!({
            "new_account_id": new_account_id,
            "options": create_acc_options,
        })
        .to_string()
        .into_bytes(),
        gas: 300_000_000_000_000,
        deposit: 0,
    });

    let delegate_create_acc_action = NonDelegateAction::try_from(create_acc_action).unwrap();

    DelegateAction {
        sender_id: signer_id,
        receiver_id: match network_type {
            NetworkType::_Mainnet => "near".parse().unwrap(),
            NetworkType::Testnet => "testnet".parse().unwrap(),
        },
        actions: vec![delegate_create_acc_action],
        nonce,
        max_block_height,
        public_key: signer_pk,
    }
}

pub fn get_add_key_delegate_action(
    account_id: AccountId,
    signer_pk: PublicKey,
    new_public_key: PublicKey,
    nonce: Nonce,
    max_block_height: u64,
) -> DelegateAction {
    let add_key_action = Action::AddKey(AddKeyAction {
        public_key: new_public_key,
        access_key: AccessKey {
            nonce: 0,
            permission: AccessKeyPermission::FullAccess,
        },
    });

    let delegate_add_key_action = NonDelegateAction::try_from(add_key_action).unwrap();

    DelegateAction {
        sender_id: account_id.clone(),
        receiver_id: account_id,
        actions: vec![delegate_add_key_action],
        nonce,
        max_block_height,
        public_key: signer_pk,
    }
}

pub fn get_signed_delegated_action(
    delegate_action: DelegateAction,
    signer_id: AccountId,
    signer_sk: SecretKey,
) -> SignedDelegateAction {
    let signer = InMemorySigner::from_secret_key(signer_id, signer_sk);
    let signable_message =
        SignableMessage::new(&delegate_action, SignableMessageType::DelegateAction);
    let signature = signable_message.sign(&signer);

    SignedDelegateAction {
        delegate_action,
        signature,
    }
}
