use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, PublicKey};
use std::collections::{BTreeMap, HashSet};

pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[derive(Serialize, Deserialize, Debug, BorshDeserialize, BorshSerialize, Clone)]
pub struct Participants {
    pub participants: BTreeMap<AccountId, ParticipantInfo>,
}

impl Participants {
    pub fn new() -> Self {
        Participants {
            participants: BTreeMap::new(),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = (AccountId, ParticipantInfo)> {
        self.participants.into_iter()
    }

    pub fn get(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants.get(account_id)
    }

    pub fn contains_key(&self, account_id: &AccountId) -> bool {
        self.participants.contains_key(account_id)
    }

    pub fn insert(&mut self, account_id: AccountId, participant: ParticipantInfo) {
        self.participants.insert(account_id, participant);
    }

    pub fn remove(&mut self, account_id: &AccountId) {
        self.participants.remove(account_id);
    }
}

#[derive(
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
)]
pub struct ParticipantInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct Votes {
    votes: BTreeMap<AccountId, HashSet<AccountId>>,
}

impl Votes {
    pub fn new() -> Self {
        Votes {
            votes: BTreeMap::new(),
        }
    }

    pub fn get(&self, participant: &AccountId) -> Option<&HashSet<AccountId>> {
        self.votes.get(participant)
    }

    pub fn insert(&mut self, participant: AccountId, voted: AccountId) {
        self.votes.entry(participant).or_default().insert(voted);
    }

    pub fn len(&self) -> usize {
        self.votes.len()
    }

    pub fn entry(&mut self, participant: AccountId) -> &mut HashSet<AccountId> {
        self.votes.entry(participant).or_default()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct PkVotes {
    votes: BTreeMap<PublicKey, HashSet<AccountId>>,
}

impl PkVotes {
    pub fn new() -> Self {
        PkVotes {
            votes: BTreeMap::new(),
        }
    }

    pub fn get(&self, public_key: &PublicKey) -> Option<&HashSet<AccountId>> {
        self.votes.get(public_key)
    }

    pub fn insert(&mut self, public_key: PublicKey, voted: AccountId) {
        self.votes.entry(public_key).or_default().insert(voted);
    }

    pub fn len(&self) -> usize {
        self.votes.len()
    }

    pub fn entry(&mut self, public_key: PublicKey) -> &mut HashSet<AccountId> {
        self.votes.entry(public_key).or_default()
    }
}