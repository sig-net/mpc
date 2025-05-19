use mpc_primitives::{bytes::borsh_scalar, SignId, Signature};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, BorshStorageKey, CryptoHash, NearToken, PublicKey};
use std::collections::{btree_map, BTreeMap, HashMap, HashSet};

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey, Hash, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    PendingRequests,
    ProposedUpdatesEntries,
}

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct PendingRequest {
    pub index: Option<YieldIndex>,
    #[borsh(
        serialize_with = "borsh_scalar::serialize",
        deserialize_with = "borsh_scalar::deserialize_reader"
    )]
    pub payload: k256::Scalar,
    #[borsh(
        serialize_with = "borsh_scalar::serialize",
        deserialize_with = "borsh_scalar::deserialize_reader"
    )]
    pub epsilon: k256::Scalar,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct Votes {
    pub votes: BTreeMap<AccountId, HashSet<AccountId>>,
}

impl Default for Votes {
    fn default() -> Self {
        Self::new()
    }
}

impl Votes {
    pub fn new() -> Self {
        Votes {
            votes: BTreeMap::new(),
        }
    }

    pub fn entry(&mut self, account_id: AccountId) -> &mut HashSet<AccountId> {
        self.votes.entry(account_id).or_default()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct PkVotes {
    pub votes: BTreeMap<PublicKey, HashSet<AccountId>>,
}

impl Default for PkVotes {
    fn default() -> Self {
        Self::new()
    }
}

impl PkVotes {
    pub fn new() -> Self {
        PkVotes {
            votes: BTreeMap::new(),
        }
    }

    pub fn entry(&mut self, public_key: PublicKey) -> &mut HashSet<AccountId> {
        self.votes.entry(public_key).or_default()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct InternalSignRequest {
    pub id: SignId,
    pub requester: AccountId,
    pub deposit: NearToken,
    pub required_deposit: NearToken,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub enum SignPoll {
    Ready(Signature),
    Timeout,
}
