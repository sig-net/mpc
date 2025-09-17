use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::sign_respond_tx::{SignRespondTx, SignRespondTxId};

#[derive(Clone)]
pub struct PendingRequests {
    map: Arc<RwLock<HashMap<SignRespondTxId, SignRespondTx>>>,
}

impl PendingRequests {
    pub fn new() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, id: SignRespondTxId, tx: SignRespondTx) -> Option<SignRespondTx> {
        self.map.write().await.insert(id, tx)
    }

    pub async fn remove(&self, id: &SignRespondTxId) -> Option<SignRespondTx> {
        self.map.write().await.remove(id)
    }

    pub async fn get(&self, id: &SignRespondTxId) -> Option<SignRespondTx> {
        self.map.read().await.get(id).cloned()
    }

    pub async fn get_pending_txs(&self) -> HashMap<SignRespondTxId, SignRespondTx> {
        self.map
            .read()
            .await
            .iter()
            .filter(|(_, tx)| tx.status == crate::sign_respond_tx::SignRespondTxStatus::Pending)
            .map(|(id, tx)| (*id, tx.clone()))
            .collect()
    }
}
