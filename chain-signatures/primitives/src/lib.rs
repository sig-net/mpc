pub mod bytes;

use k256::Scalar;
use mpc_crypto::types::borsh_scalar;
use near_account_id::AccountId;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

use crate::bytes::cbor_scalar;

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

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct SignId {
    #[serde(with = "serde_bytes")]
    pub request_id: [u8; 32],
}

impl std::fmt::Debug for SignId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SignId")
            .field(&hex::encode(&self.request_id))
            .finish()
    }
}

impl SignId {
    pub fn new(request_id: [u8; 32]) -> Self {
        Self { request_id }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SignArgs {
    #[serde(with = "serde_bytes")]
    pub entropy: [u8; 32],
    #[serde(with = "cbor_scalar")]
    pub epsilon: Scalar,
    #[serde(with = "cbor_scalar")]
    pub payload: Scalar,
    pub path: String,
    pub key_version: u32,
}

impl std::fmt::Debug for SignArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignArgs")
            .field("entropy", &hex::encode(&self.entropy))
            .field("epsilon", &self.epsilon)
            .field("payload", &self.payload)
            .field("path", &self.path)
            .field("key_version", &self.key_version)
            .finish()
    }
}
