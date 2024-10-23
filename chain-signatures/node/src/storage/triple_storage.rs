use crate::protocol::triple::{Triple, TripleId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rand::seq::IteratorRandom;
use rand::thread_rng;
use tokio::sync::RwLock;

use near_account_id::AccountId;

pub type LockTripleMemoryStorage = Arc<RwLock<TripleMemoryStorage>>;
type TripleResult<T> = std::result::Result<T, anyhow::Error>;

pub fn init(account_id: &AccountId) -> TripleMemoryStorage {
    TripleMemoryStorage {
        triples: HashMap::new(),
        mine: HashSet::new(),
        _account_id: account_id.clone(),
    }
}

#[derive(Clone)]
pub struct TripleMemoryStorage {
    triples: HashMap<TripleId, Triple>,
    mine: HashSet<TripleId>,
    _account_id: AccountId, // TODO: will be used after migratio to Redis
}

impl TripleMemoryStorage {
    pub fn insert(&mut self, triple: Triple) -> TripleResult<()> {
        self.triples.insert(triple.id, triple);
        Ok(())
    }

    pub fn insert_mine(&mut self, triple: Triple) -> TripleResult<()> {
        self.mine.insert(triple.id);
        self.triples.insert(triple.id, triple);
        Ok(())
    }

    pub fn contains(&mut self, id: &TripleId) -> TripleResult<bool> {
        Ok(self.triples.contains_key(id))
    }

    pub fn contains_mine(&mut self, id: &TripleId) -> TripleResult<bool> {
        Ok(self.mine.contains(id))
    }

    pub fn take(&mut self, id: &TripleId) -> TripleResult<Option<Triple>> {
        if self.contains_mine(id)? {
            tracing::error!("Can not take mine triple as foreign: {:?}", id);
            return Ok(None);
        }
        Ok(self.triples.remove(&id))
    }

    pub fn take_mine(&mut self) -> TripleResult<Option<Triple>> {
        let mut rng = thread_rng();
        match self.mine.iter().choose(&mut rng) {
            Some(id) => Ok(self.triples.remove(id)),
            None => Ok(None),
        }
    }

    pub fn count_all(&mut self) -> TripleResult<usize> {
        Ok(self.triples.len())
    }

    pub fn count_mine(&mut self) -> TripleResult<usize> {
        Ok(self.mine.len())
    }

    pub fn clear(&mut self) -> TripleResult<()> {
        self.triples.clear();
        self.mine.clear();
        Ok(())
    }
}
