use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::protocol::Chain;
use crate::sign_respond_tx::{SignRespondTx, SignRespondTxId};

#[derive(Clone)]
pub struct PendingRequests {
    map: Arc<RwLock<HashMap<Chain, HashMap<SignRespondTxId, SignRespondTx>>>>,
}

impl PendingRequests {
    pub fn new() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(
        &self,
        chain: Chain,
        id: SignRespondTxId,
        tx: SignRespondTx,
    ) -> Option<SignRespondTx> {
        let mut map = self.map.write().await;
        let chain_map = map.entry(chain).or_insert_with(HashMap::new);
        chain_map.insert(id, tx)
    }

    pub async fn remove(&self, chain: Chain, id: &SignRespondTxId) -> Option<SignRespondTx> {
        let mut map = self.map.write().await;
        if let Some(chain_map) = map.get_mut(&chain) {
            chain_map.remove(id)
        } else {
            None
        }
    }

    pub async fn get(&self, chain: Chain, id: &SignRespondTxId) -> Option<SignRespondTx> {
        let map = self.map.read().await;
        map.get(&chain)
            .and_then(|chain_map| chain_map.get(id).cloned())
    }

    pub async fn get_pending_txs(&self, chain: Chain) -> HashMap<SignRespondTxId, SignRespondTx> {
        let map = self.map.read().await;
        if let Some(chain_map) = map.get(&chain) {
            chain_map
                .iter()
                .filter(|(_, tx)| tx.status == crate::sign_respond_tx::SignRespondTxStatus::Pending)
                .map(|(id, tx)| (*id, tx.clone()))
                .collect()
        } else {
            HashMap::new()
        }
    }
}
