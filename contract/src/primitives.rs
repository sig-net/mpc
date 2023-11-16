use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, PublicKey};
use std::collections::{HashMap, HashSet};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Participants {
    map: HashMap<AccountId, String>,
}

impl Participants {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, key: &AccountId) -> Option<&String> {
        self.map.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &String)> {
        self.map.iter()
    }

    pub fn contains_key(&self, key: &AccountId) -> bool {
        self.map.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &AccountId> {
        self.map.keys()
    }

    pub fn insert(&mut self, key: AccountId, value: String) -> Option<String> {
        self.map.insert(key, value)
    }

    pub fn remove(&mut self, key: &AccountId) -> Option<String> {
        self.map.remove(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, Default)]
pub struct ParticipantSet {
    set: HashSet<AccountId>,
}

impl ParticipantSet {
    pub fn new() -> Self {
        Self {
            set: HashSet::new(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &AccountId> {
        self.set.iter()
    }

    pub fn insert(&mut self, key: AccountId) -> bool {
        self.set.insert(key)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Votes {
    map: HashMap<AccountId, ParticipantSet>,
}

impl Votes {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn entry(&mut self, key: AccountId) -> &mut ParticipantSet {
        self.map.entry(key).or_default()
    }

    pub fn into_iter(self) -> impl Iterator<Item = (AccountId, ParticipantSet)> {
        self.map.into_iter()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct PkVotes {
    map: HashMap<PublicKey, ParticipantSet>,
}

impl PkVotes {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn entry(&mut self, key: PublicKey) -> &mut ParticipantSet {
        self.map.entry(key).or_default()
    }

    pub fn into_iter(self) -> impl Iterator<Item = (PublicKey, ParticipantSet)> {
        self.map.into_iter()
    }
}
