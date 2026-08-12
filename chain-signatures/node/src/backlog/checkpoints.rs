use super::{PendingRequests, MAX_PENDING_CHECKPOINTS};
use crate::storage::checkpoint_storage::CheckpointStorage;

use mpc_primitives::{Chain, Checkpoint};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub(super) struct Checkpoints {
    storage: CheckpointStorage,
    pending: Arc<HashMap<Chain, RwLock<BTreeMap<u64, Checkpoint>>>>,
}

impl Checkpoints {
    pub(super) fn new(storage: CheckpointStorage) -> Self {
        let pending = Chain::iter()
            .into_iter()
            .map(|chain| (chain, RwLock::new(BTreeMap::new())))
            .collect();
        Self {
            storage,
            pending: Arc::new(pending),
        }
    }

    fn pending(&self, chain: Chain) -> &RwLock<BTreeMap<u64, Checkpoint>> {
        self.pending
            .get(&chain)
            .expect("chain should be initialized within `Checkpoints::new`")
    }

    fn observe(&self, chain: Chain, len: usize) {
        crate::metrics::requests::PENDING_CHECKPOINTS
            .with_label_values(&[chain.as_str()])
            .set(len as i64);
    }

    pub(super) async fn create(
        &self,
        requests: &RwLock<PendingRequests>,
        chain: Chain,
    ) -> Option<Checkpoint> {
        let pending = self.pending(chain).read().await;
        if pending.len() >= MAX_PENDING_CHECKPOINTS {
            tracing::warn!(
                ?chain,
                count = pending.len(),
                "pending checkpoint cap reached; stalling checkpoint creation"
            );
            return None;
        }
        drop(pending);

        let checkpoint = requests.read().await.checkpoint(chain);

        if let Err(err) = self.storage.persist_pending(&checkpoint).await {
            tracing::warn!(?chain, %err, "failed to persist pending checkpoint");
            return None;
        }

        let len = {
            let mut pending = self.pending(checkpoint.chain).write().await;
            pending.insert(checkpoint.block_height, checkpoint.clone());
            pending.len()
        };
        self.observe(checkpoint.chain, len);
        Some(checkpoint)
    }

    async fn update_pending(&self, chain: Chain, height: u64) {
        let len = {
            let mut pending = self.pending(chain).write().await;
            pending.retain(|&pending_height, _| pending_height > height);
            pending.len()
        };
        self.observe(chain, len);
    }

    pub(super) async fn confirm(&self, chain: Chain, digest: [u8; 32]) -> bool {
        let Some(checkpoint) = self.find(chain, digest).await else {
            return false;
        };
        let is_pending = self
            .pending(chain)
            .read()
            .await
            .get(&checkpoint.block_height)
            .is_some_and(|pending| pending.digest() == digest);

        if !is_pending {
            self.update_pending(chain, checkpoint.block_height).await;
            return true;
        }

        match self
            .storage
            .promote_pending(chain, checkpoint.block_height, digest)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    ?chain,
                    ?digest,
                    "pending checkpoint disappeared before promotion"
                );
                return false;
            }
            Err(err) => {
                tracing::warn!(?chain, %err, "failed to promote consensus checkpoint");
                return false;
            }
        }
        self.update_pending(chain, checkpoint.block_height).await;
        tracing::info!(
            ?chain,
            height = checkpoint.block_height,
            "consensus checkpoint confirmed"
        );
        true
    }

    pub(super) async fn load_local(&self, chain: Chain) -> anyhow::Result<Option<Checkpoint>> {
        let latest = self.storage.load_latest(chain).await?;
        let latest_height = latest.as_ref().map(|checkpoint| checkpoint.block_height);
        let pending = self
            .storage
            .load_pending(chain)
            .await?
            .into_iter()
            .filter(|checkpoint| {
                latest_height.is_none_or(|height| checkpoint.block_height > height)
            })
            .collect::<Vec<_>>();

        let len = {
            let mut local = self.pending(chain).write().await;
            local.clear();
            local.extend(
                pending
                    .iter()
                    .cloned()
                    .map(|checkpoint| (checkpoint.block_height, checkpoint)),
            );
            local.len()
        };
        self.observe(chain, len);
        Ok(pending.into_iter().next_back().or(latest))
    }

    pub(super) async fn regress(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        self.storage.reset_to_latest(checkpoint).await?;
        self.pending(checkpoint.chain).write().await.clear();
        self.observe(checkpoint.chain, 0);
        Ok(())
    }

    pub(super) async fn latest(&self, chain: Chain) -> Option<Checkpoint> {
        if let Some(checkpoint) = self
            .pending(chain)
            .read()
            .await
            .values()
            .next_back()
            .cloned()
        {
            return Some(checkpoint);
        }
        self.storage.load_latest(chain).await.ok().flatten()
    }

    pub(super) async fn has_slot(&self, chain: Chain) -> bool {
        self.pending(chain).read().await.len() < MAX_PENDING_CHECKPOINTS
    }

    pub(super) async fn count(&self, chain: Chain) -> usize {
        self.pending(chain).read().await.len()
    }

    pub(super) async fn find(&self, chain: Chain, digest: [u8; 32]) -> Option<Checkpoint> {
        if let Some(checkpoint) = self
            .pending(chain)
            .read()
            .await
            .values()
            .find(|checkpoint| checkpoint.digest() == digest)
            .cloned()
        {
            return Some(checkpoint);
        }
        self.storage
            .load_latest(chain)
            .await
            .ok()
            .flatten()
            .filter(|checkpoint| checkpoint.digest() == digest)
    }

    #[cfg(test)]
    pub(super) fn storage(&self) -> &CheckpointStorage {
        &self.storage
    }
}
