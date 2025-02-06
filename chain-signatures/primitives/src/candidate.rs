#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Candidates {
    pub candidates: BTreeMap<AccountId, CandidateInfo>,
}

impl Default for Candidates {
    fn default() -> Self {
        Self::new()
    }
}

impl Candidates {
    pub fn new() -> Self {
        Candidates {
            candidates: BTreeMap::new(),
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

    pub fn get(&self, account_id: &AccountId) -> Option<&CandidateInfo> {
        self.candidates.get(account_id)
    }

    pub fn iter(&self) -> btree_map::Iter<'_, AccountId, CandidateInfo> {
        self.candidates.iter()
    }

    pub fn iter_mut(&mut self) -> btree_map::IterMut<'_, AccountId, CandidateInfo> {
        self.candidates.iter_mut()
    }
}

impl<'a> IntoIterator for &'a Candidates {
    type Item = (&'a AccountId, &'a CandidateInfo);
    type IntoIter = btree_map::Iter<'a, AccountId, CandidateInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.candidates.iter()
    }
}

impl<'a> IntoIterator for &'a mut Candidates {
    type Item = (&'a AccountId, &'a mut CandidateInfo);
    type IntoIter = btree_map::IterMut<'a, AccountId, CandidateInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.candidates.iter_mut()
    }
}

impl IntoIterator for Candidates {
    type Item = (AccountId, CandidateInfo);
    type IntoIter = btree_map::IntoIter<AccountId, CandidateInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.candidates.into_iter()
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
