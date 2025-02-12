use k256::Scalar;
use mpc_crypto::types::borsh_scalar;
use near_account_id::AccountId;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct SignRequestPending {
    #[borsh(
        serialize_with = "borsh_scalar::serialize",
        deserialize_with = "borsh_scalar::deserialize_reader"
    )]
    pub epsilon: Scalar,
    #[borsh(
        serialize_with = "borsh_scalar::serialize",
        deserialize_with = "borsh_scalar::deserialize_reader"
    )]
    pub payload: Scalar,
}

impl SignRequestPending {
    pub fn new(payload: Scalar, predecessor_id: &AccountId, path: &str) -> Self {
        let epsilon = mpc_crypto::derive_epsilon(predecessor_id, path);
        SignRequestPending { epsilon, payload }
    }
}
