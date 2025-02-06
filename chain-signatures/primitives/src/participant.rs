use near_account_id::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::{btree_map, BTreeMap, HashMap, HashSet};

use crate::{Candidates, CandidateInfo};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Participants {
    pub next_id: u32,
    pub participants: BTreeMap<AccountId, ParticipantInfo>,
    pub account_to_participant_id: HashMap<AccountId, u32>,
}

impl Default for Participants {
    fn default() -> Self {
        Self {
            next_id: 0u32,
            participants: BTreeMap::new(),
            account_to_participant_id: HashMap::new(),
        }
    }
}

impl From<Candidates> for Participants {
    fn from(candidates: Candidates) -> Self {
        let mut participants = Participants::new();
        for (account_id, candidate_info) in candidates.into_iter() {
            participants.insert(account_id, candidate_info.into());
        }
        participants
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

impl From<CandidateInfo> for ParticipantInfo {
    fn from(candidate_info: CandidateInfo) -> Self {
        ParticipantInfo {
            account_id: candidate_info.account_id,
            url: candidate_info.url,
            cipher_pk: candidate_info.cipher_pk,
            sign_pk: candidate_info.sign_pk,
        }
    }
}

impl Participants {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains_key(&self, account_id: &AccountId) -> bool {
        self.participants.contains_key(account_id)
    }

    pub fn insert(&mut self, account_id: AccountId, participant_info: ParticipantInfo) {
        if !self.account_to_participant_id.contains_key(&account_id) {
            self.account_to_participant_id
                .insert(account_id.clone(), self.next_id);
            self.next_id += 1;
        }
        self.participants.insert(account_id, participant_info);
    }

    pub fn remove(&mut self, account_id: &AccountId) {
        self.participants.remove(account_id);
    }

    pub fn get(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants.get(account_id)
    }

    pub fn iter(&self) -> btree_map::Iter<'_, AccountId, ParticipantInfo> {
        self.participants.iter()
    }

    pub fn iter_mut(&mut self) -> btree_map::IterMut<'_, AccountId, ParticipantInfo> {
        self.participants.iter_mut()
    }

    pub fn keys(&self) -> impl Iterator<Item = &AccountId> {
        self.participants.keys()
    }

    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }
}

impl<'a> IntoIterator for &'a Participants {
    type Item = (&'a AccountId, &'a ParticipantInfo);
    type IntoIter = btree_map::Iter<'a, AccountId, ParticipantInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.participants.iter()
    }
}

impl<'a> IntoIterator for &'a mut Participants {
    type Item = (&'a AccountId, &'a mut ParticipantInfo);
    type IntoIter = btree_map::IterMut<'a, AccountId, ParticipantInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.participants.iter_mut()
    }
}

impl IntoIterator for Participants {
    type Item = (AccountId, ParticipantInfo);
    type IntoIter = btree_map::IntoIter<AccountId, ParticipantInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.participants.into_iter()
    }
}
