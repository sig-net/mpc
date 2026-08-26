pub use mpc_primitives::ConsensusCheckpointDigest;
pub use signet_primitives::{Chain, SignRequest};

use crate::config::Config;
use crate::state::ProtocolContractStateView;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::IterableMap;
use near_sdk::{AccountId, BorshStorageKey, CryptoHash, NearToken, PublicKey};
use signet_primitives::{borsh_scalar, SignId, Signature};
use std::collections::{btree_map, BTreeMap, HashMap, HashSet};

pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey, Hash, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    PendingRequests,
    ProposedUpdatesEntries,
    LatestCheckpoints,
    LatestCheckpointDigests,
    Candidates,
}

/// One chain's entry in a checkpoint reset.
///
/// `height` is inclusive: indexing resumes at `height` itself.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct CheckpointReset {
    pub chain: Chain,
    pub height: u64,
}

#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[borsh(crate = "near_sdk::borsh")]
pub enum Read {
    State,
    Config,
    Checkpoints,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub enum View {
    State(ProtocolContractStateView),
    Config(Config),
    Checkpoints(HashMap<Chain, ConsensusCheckpointDigest>),
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
pub struct CandidateInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

/// A candidate and the participants that voted to admit it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CandidateEntry {
    pub info: CandidateInfo,
    pub join_votes: HashSet<AccountId>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Participants {
    pub next_id: u32,
    pub participants: BTreeMap<AccountId, ParticipantInfo>,
    pub account_to_participant_id: HashMap<AccountId, u32>,
}

impl Default for Participants {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&Candidates> for Participants {
    fn from(candidates: &Candidates) -> Self {
        let mut participants = Participants::new();
        for (account_id, candidate_info) in candidates.iter() {
            participants.insert(account_id.clone(), candidate_info.clone().into());
        }
        participants
    }
}

impl From<CandidatesView> for Participants {
    fn from(candidates: CandidatesView) -> Self {
        let mut participants = Participants::new();
        for (account_id, candidate_info) in candidates.candidates {
            participants.insert(account_id, candidate_info.into());
        }
        participants
    }
}

impl Participants {
    pub fn new() -> Self {
        Participants {
            next_id: 0u32,
            participants: BTreeMap::new(),
            account_to_participant_id: HashMap::new(),
        }
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
        self.account_to_participant_id.remove(account_id);
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

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct Candidates {
    /// Must be cleared before replacing its owning protocol state.
    pub candidates: IterableMap<AccountId, CandidateInfo>,
}

impl Default for Candidates {
    fn default() -> Self {
        Self::new()
    }
}

impl Candidates {
    pub fn new() -> Self {
        Candidates {
            candidates: IterableMap::new(StorageKey::Candidates),
        }
    }

    pub fn contains_key(&self, account_id: &AccountId) -> bool {
        self.candidates.contains_key(account_id)
    }

    pub fn insert(&mut self, account_id: AccountId, candidate: CandidateInfo) {
        self.candidates.insert(account_id, candidate);
    }

    pub fn remove(&mut self, account_id: &AccountId) {
        self.candidates.remove(account_id);
    }

    pub fn clear(&mut self) {
        self.candidates.clear();
    }

    pub fn get(&self, account_id: &AccountId) -> Option<&CandidateInfo> {
        self.candidates.get(account_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &CandidateInfo)> {
        self.candidates.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&AccountId, &mut CandidateInfo)> {
        self.candidates.iter_mut()
    }

    pub fn len(&self) -> usize {
        self.candidates.len() as usize
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, Default)]
pub struct CandidatesView {
    pub candidates: BTreeMap<AccountId, CandidateInfo>,
}

impl From<&Candidates> for CandidatesView {
    fn from(candidates: &Candidates) -> Self {
        Self {
            candidates: candidates
                .iter()
                .map(|(account_id, info)| (account_id.clone(), info.clone()))
                .collect(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
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

    pub fn len(&self) -> usize {
        self.votes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    pub fn remove(&mut self, account_id: &AccountId) {
        self.votes.remove(account_id);
    }

    pub fn contains_key(&self, account_id: &AccountId) -> bool {
        self.votes.contains_key(account_id)
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct PkVotes {
    pub votes: BTreeMap<PublicKey, HashSet<AccountId>>,
}

pub type Threshold = usize;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ThresholdVotes {
    /// Maps each participant AccountId to the proposed threshold value they voted for.
    pub votes: BTreeMap<AccountId, Threshold>,
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

impl Default for ThresholdVotes {
    fn default() -> Self {
        Self::new()
    }
}

impl ThresholdVotes {
    pub fn new() -> Self {
        ThresholdVotes {
            votes: BTreeMap::new(),
        }
    }

    /// Record `voter`'s support for `threshold`, replacing any vote they had
    /// previously cast, and return the resulting number of voters backing `threshold`.
    pub fn vote(&mut self, threshold: Threshold, voter: AccountId) -> usize {
        self.votes.insert(voter, threshold);
        self.tally(threshold)
    }

    /// Remove `voter`'s vote for any proposed threshold.
    pub fn remove(&mut self, voter: &AccountId) {
        self.votes.remove(voter);
    }

    /// Count the number of voters currently backing `threshold`.
    pub fn tally(&self, threshold: Threshold) -> usize {
        self.votes.values().filter(|&&t| t == threshold).count()
    }

    /// Get the threshold value voted for by `voter`, if any.
    pub fn get(&self, voter: &AccountId) -> Option<Threshold> {
        self.votes.get(voter).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
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

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub enum SignPoll {
    Ready(Signature),
    Timeout,
}

/// Manages votes for checkpoints
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct CheckpointVotes {
    pub votes: HashMap<ConsensusCheckpointDigest, HashSet<AccountId>>,
}

impl Default for CheckpointVotes {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckpointVotes {
    pub fn new() -> Self {
        CheckpointVotes {
            votes: HashMap::new(),
        }
    }

    pub fn entry(&mut self, checkpoint: ConsensusCheckpointDigest) -> &mut HashSet<AccountId> {
        self.votes.entry(checkpoint).or_default()
    }

    pub fn get(&self, checkpoint: &ConsensusCheckpointDigest) -> Option<&HashSet<AccountId>> {
        self.votes.get(checkpoint)
    }

    pub fn len(&self) -> usize {
        self.votes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }
}
