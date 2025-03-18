use cait_sith::protocol::Participant;
use mpc_keys::hpke;
use near_primitives::{borsh::BorshDeserialize, types::AccountId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    hash::Hash,
    str::FromStr,
};

type ParticipantId = u32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantInfo {
    pub id: ParticipantId,
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: near_crypto::PublicKey,
}

impl ParticipantInfo {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            account_id: format!("p-{id}").parse().unwrap(),
            url: String::default(),
            cipher_pk: hpke::PublicKey::from_bytes(&[0; 32]),
            sign_pk: near_crypto::PublicKey::empty(near_crypto::KeyType::ED25519),
        }
    }
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Participants {
    pub participants: BTreeMap<Participant, ParticipantInfo>,
}

impl From<mpc_contract::primitives::Participants> for Participants {
    fn from(contract_participants: mpc_contract::primitives::Participants) -> Self {
        Participants {
            participants: contract_participants
                .participants
                .into_iter()
                .map(|(account_id, contract_participant_info)| {
                    let participant_id = *contract_participants
                        .account_to_participant_id
                        .get(&account_id)
                        .unwrap();
                    (
                        Participant::from(participant_id),
                        ParticipantInfo {
                            id: participant_id,
                            account_id: AccountId::from_str(
                                contract_participant_info.account_id.as_ref(),
                            )
                            .unwrap(),
                            url: contract_participant_info.url,
                            cipher_pk: hpke::PublicKey::from_bytes(
                                &contract_participant_info.cipher_pk,
                            ),
                            sign_pk: BorshDeserialize::try_from_slice(
                                contract_participant_info.sign_pk.as_bytes(),
                            )
                            .unwrap(),
                        },
                    )
                })
                .collect(),
        }
    }
}

impl From<Candidates> for Participants {
    fn from(candidates: Candidates) -> Self {
        Participants {
            participants: candidates
                .candidates
                .into_iter()
                .enumerate()
                .map(|(participant_id, (account_id, candidate_info))| {
                    (
                        Participant::from(participant_id as ParticipantId),
                        ParticipantInfo {
                            id: participant_id as ParticipantId,
                            account_id,
                            url: candidate_info.url,
                            cipher_pk: candidate_info.cipher_pk,
                            sign_pk: candidate_info.sign_pk,
                        },
                    )
                })
                .collect(),
        }
    }
}

impl IntoIterator for Participants {
    type Item = (Participant, ParticipantInfo);
    type IntoIter = std::collections::btree_map::IntoIter<Participant, ParticipantInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.participants.into_iter()
    }
}

impl Participants {
    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    pub fn insert(&mut self, id: &Participant, info: ParticipantInfo) {
        self.participants.insert(*id, info);
    }

    pub fn remove(&mut self, id: &Participant) -> Option<ParticipantInfo> {
        self.participants.remove(id)
    }

    pub fn get(&self, id: &Participant) -> Option<&ParticipantInfo> {
        self.participants.get(id)
    }

    pub fn contains_key(&self, id: &Participant) -> bool {
        self.participants.contains_key(id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &Participant> {
        self.participants.keys()
    }

    pub fn keys_vec(&self) -> Vec<Participant> {
        self.participants.keys().cloned().collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Participant, &ParticipantInfo)> {
        self.participants.iter()
    }

    pub fn find(&self, account_id: &AccountId) -> Option<(&Participant, &ParticipantInfo)> {
        self.participants
            .iter()
            .find(|(_, participant_info)| participant_info.account_id == *account_id)
    }

    pub fn find_participant(&self, account_id: &AccountId) -> Option<&Participant> {
        self.find(account_id).map(|(participant, _)| participant)
    }

    pub fn find_participant_info(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.find(account_id).map(|(_, info)| info)
    }

    pub fn contains_account_id(&self, account_id: &AccountId) -> bool {
        self.participants
            .values()
            .any(|participant_info| participant_info.account_id == *account_id)
    }

    pub fn account_ids(&self) -> Vec<&AccountId> {
        self.participants
            .values()
            .map(|participant_info| &participant_info.account_id)
            .collect()
    }

    pub fn and(&self, other: &Self) -> Self {
        let mut participants = self.participants.clone();
        for (participant, info) in &other.participants {
            participants.insert(*participant, info.clone());
        }
        Participants { participants }
    }

    pub fn intersection(&self, other: &[&[Participant]]) -> Self {
        let mut intersect = BTreeMap::new();
        let other = other
            .iter()
            .map(|participants| participants.iter().cloned().collect::<HashSet<_>>())
            .collect::<Vec<_>>();

        'outer: for (participant, info) in &self.participants {
            for participants in &other {
                if !participants.contains(participant) {
                    continue 'outer;
                }
            }
            intersect.insert(*participant, info.clone());
        }
        Participants {
            participants: intersect,
        }
    }
}

/// ParticipantMap used to find a participant by specific amount of participants.
#[derive(Clone, Debug)]
pub enum ParticipantMap {
    Zero,
    One(Participants),
    Two(Participants, Participants),
}

impl ParticipantMap {
    pub fn get(&self, p: &Participant) -> Option<&ParticipantInfo> {
        match self {
            ParticipantMap::Zero => None,
            ParticipantMap::One(participants) => participants.get(p),
            ParticipantMap::Two(participants1, participants2) => {
                participants1.get(p).or_else(|| participants2.get(p))
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: near_crypto::PublicKey,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Candidates {
    pub candidates: BTreeMap<AccountId, CandidateInfo>,
}

impl Candidates {
    pub fn get(&self, id: &AccountId) -> Option<&CandidateInfo> {
        self.candidates.get(id)
    }

    pub fn contains_key(&self, id: &AccountId) -> bool {
        self.candidates.contains_key(id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &AccountId> {
        self.candidates.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &CandidateInfo)> {
        self.candidates.iter()
    }

    pub fn find_candidate(&self, account_id: &AccountId) -> Option<&CandidateInfo> {
        self.candidates.get(account_id)
    }
}

impl From<mpc_contract::primitives::Candidates> for Candidates {
    fn from(contract_candidates: mpc_contract::primitives::Candidates) -> Self {
        Candidates {
            candidates: contract_candidates
                .candidates
                .into_iter()
                .map(|(account_id, candidate_info)| {
                    (
                        AccountId::from_str(account_id.as_ref()).unwrap(),
                        CandidateInfo {
                            account_id: AccountId::from_str(candidate_info.account_id.as_ref())
                                .unwrap(),
                            url: candidate_info.url,
                            cipher_pk: hpke::PublicKey::from_bytes(&candidate_info.cipher_pk),
                            sign_pk: BorshDeserialize::try_from_slice(
                                candidate_info.sign_pk.as_bytes(),
                            )
                            .unwrap(),
                        },
                    )
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PkVotes {
    pub pk_votes: BTreeMap<near_crypto::PublicKey, HashSet<AccountId>>,
}

impl PkVotes {
    pub fn get(&self, id: &near_crypto::PublicKey) -> Option<&HashSet<AccountId>> {
        self.pk_votes.get(id)
    }
}

impl From<mpc_contract::primitives::PkVotes> for PkVotes {
    fn from(contract_votes: mpc_contract::primitives::PkVotes) -> Self {
        PkVotes {
            pk_votes: contract_votes
                .votes
                .into_iter()
                .map(|(pk, participants)| {
                    (
                        near_crypto::PublicKey::SECP256K1(
                            near_crypto::Secp256K1PublicKey::try_from(&pk.as_bytes()[1..]).unwrap(),
                        ),
                        participants
                            .into_iter()
                            .map(|acc_id: near_sdk::AccountId| {
                                AccountId::from_str(acc_id.as_ref()).unwrap()
                            })
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Votes {
    pub votes: BTreeMap<AccountId, HashSet<AccountId>>,
}

impl Votes {
    pub fn get(&self, id: &AccountId) -> Option<&HashSet<AccountId>> {
        self.votes.get(id)
    }
}

impl From<mpc_contract::primitives::Votes> for Votes {
    fn from(contract_votes: mpc_contract::primitives::Votes) -> Self {
        Votes {
            votes: contract_votes
                .votes
                .into_iter()
                .map(|(account_id, participants)| {
                    (
                        AccountId::from_str(account_id.as_ref()).unwrap(),
                        participants
                            .into_iter()
                            .map(|acc_id: near_sdk::AccountId| {
                                AccountId::from_str(acc_id.as_ref()).unwrap()
                            })
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

pub fn intersect<T: Copy + Hash + Eq>(sets: &[&[T]]) -> HashSet<T> {
    if let Some((first, rest)) = sets.split_first() {
        let mut intersection = first.iter().copied().collect::<HashSet<_>>();
        for set in rest {
            let set = set.iter().copied().collect::<HashSet<_>>();
            intersection.retain(|item| set.contains(item));
        }
        intersection
    } else {
        HashSet::new()
    }
}

pub fn intersect_hash<T: Clone + Hash + Eq>(sets: &[&HashSet<T>]) -> HashSet<T> {
    let mut sets = sets.iter();
    let Some(&first) = sets.next() else {
        return HashSet::new();
    };
    let mut intersection = first.clone();
    for set in sets {
        intersection.retain(|item| set.contains(item));
    }

    intersection
}

pub fn intersect_vec<T: Copy + Hash + Eq>(sets: &[&[T]]) -> Vec<T> {
    intersect(sets).into_iter().collect()
}
