use crate::gcp::error;
use crate::protocol::triple::{Triple, TripleId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::RwLock;

use near_account_id::AccountId;

pub type LockMemoryTripleStorage = Arc<RwLock<TripleMemoryStorage>>;

pub fn init(account_id: &AccountId) -> TripleMemoryStorage {
    TripleMemoryStorage {
        triples: HashMap::new(),
        mine: HashSet::new(),
        account_id: account_id.clone(),
    }
}

// TODO: do we need this stuct?
#[derive(Clone, Debug)]
pub struct TripleData {
    pub account_id: AccountId,
    pub triple: Triple,
    pub mine: bool,
}

// TODO: remove or refactor use of DatastoreStorageError
type TripleResult<T> = std::result::Result<T, error::DatastoreStorageError>;

#[derive(Clone)]
pub struct TripleMemoryStorage {
    triples: HashMap<TripleId, Triple>,
    mine: HashSet<TripleId>,
    account_id: AccountId,
}

impl TripleMemoryStorage {
    pub async fn insert(&mut self, triple: Triple, mine: bool) -> TripleResult<()> {
        if mine {
            self.mine.insert(triple.id);
        }
        self.triples.insert(triple.id, triple);
        Ok(())
    }

    pub async fn delete(&mut self, id: TripleId) -> TripleResult<()> {
        self.triples.remove(&id);
        self.mine.remove(&id);
        Ok(())
    }

    pub async fn clear(&mut self) -> TripleResult<Vec<TripleData>> {
        let res = self.load().await?;
        self.triples.clear();
        self.mine.clear();
        Ok(res)
    }

    pub async fn load(&self) -> TripleResult<Vec<TripleData>> {
        let mut res: Vec<TripleData> = vec![];
        for (triple_id, triple) in self.triples.clone() {
            let mine = self.mine.contains(&triple_id);
            res.push(TripleData {
                account_id: self.account_id().clone(),
                triple,
                mine,
            });
        }
        Ok(res)
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}
