use super::{PendingRequests, MAX_PENDING_CHECKPOINTS};
use crate::storage::checkpoint_storage::CheckpointStorage;

use enum_map::EnumMap;
use mpc_primitives::{Chain, Checkpoint, PendingTx};
use sha3::Digest;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub(super) struct Checkpoints {
    storage: CheckpointStorage,
    pending: Arc<EnumMap<Chain, RwLock<BTreeMap<u64, Checkpoint>>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("pending checkpoint cap reached for {chain}")]
    PendingCap { chain: Chain },
    #[error("failed to persist checkpoint for {chain}")]
    Storage {
        chain: Chain,
        #[source]
        source: anyhow::Error,
    },
}

enum CheckpointKind {
    Pending(Checkpoint),
    Latest(Checkpoint),
}

impl From<CheckpointKind> for Checkpoint {
    fn from(checkpoint_kind: CheckpointKind) -> Self {
        match checkpoint_kind {
            CheckpointKind::Pending(checkpoint) | CheckpointKind::Latest(checkpoint) => checkpoint,
        }
    }
}

impl Checkpoints {
    /// Creates an empty local pending-checkpoint cache backed by `storage`.
    pub(super) fn new(storage: CheckpointStorage) -> Self {
        Self {
            storage,
            pending: Arc::default(),
        }
    }

    /// Returns the pending-checkpoint map for `chain`.
    fn pending(&self, chain: Chain) -> &RwLock<BTreeMap<u64, Checkpoint>> {
        &self.pending[chain]
    }

    /// Updates the pending-checkpoint metric for `chain`.
    fn observe(&self, chain: Chain, len: usize) {
        crate::metrics::requests::PENDING_CHECKPOINTS
            .with_label_values(&[chain.as_str()])
            .set(len as i64);
    }

    /// Durably records an unconfirmed checkpoint and adds it to the local cache.
    pub(super) async fn persist_pending(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<(), CheckpointError> {
        let chain = checkpoint.chain;
        let height = checkpoint.block_height;
        let mut pending = self.pending(chain).write().await;
        if let Some(existing) = pending.get(&height) {
            if existing == checkpoint {
                return Ok(());
            }

            return Err(CheckpointError::Storage {
                chain,
                source: anyhow::anyhow!("conflicting pending checkpoint at height {height}"),
            });
        }

        if pending.len() >= MAX_PENDING_CHECKPOINTS {
            tracing::warn!(
                ?chain,
                count = pending.len(),
                "pending checkpoint cap reached; stalling checkpoint creation"
            );
            return Err(CheckpointError::PendingCap { chain });
        }

        self.storage
            .persist_pending(checkpoint)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?;

        pending.insert(height, checkpoint.clone());
        let len = pending.len();
        drop(pending);
        self.observe(chain, len);
        Ok(())
    }

    /// Captures the current request state as a deterministic checkpoint.
    pub(super) fn snapshot(requests: &PendingRequests, chain: Chain) -> Checkpoint {
        let mut encoded = requests
            .requests
            .iter()
            .map(|(&sign_id, entry)| {
                let mut transaction = Vec::new();
                ciborium::ser::into_writer(entry, &mut transaction)
                    .expect("serialize backlog entry for checkpoint");
                let consensus_tag = entry.status().consensus_tag();
                (
                    PendingTx {
                        sign_id,
                        transaction,
                    },
                    consensus_tag,
                )
            })
            .collect::<Vec<_>>();
        encoded.sort_by_key(|(pending, _)| pending.sign_id);

        let mut cumulative = sha3::Sha3_256::new();
        for (_, consensus_tag) in &encoded {
            cumulative.update([*consensus_tag]);
        }

        Checkpoint {
            chain,
            block_height: requests.processed_block_height.unwrap_or(0),
            pending_requests: encoded.into_iter().map(|(pending, _)| pending).collect(),
            cumulative_digest: cumulative.finalize().into(),
        }
    }

    /// Removes pending checkpoints through `height` after a confirmed checkpoint advances state.
    async fn update_pending(&self, chain: Chain, height: u64) {
        let len = {
            let mut pending = self.pending(chain).write().await;
            pending.retain(|&pending_height, _| pending_height > height);
            pending.len()
        };
        self.observe(chain, len);
    }

    /// Promotes a locally pending checkpoint when its digest reaches consensus.
    pub(super) async fn confirm(&self, chain: Chain, digest: [u8; 32]) -> bool {
        let Some(checkpoint_kind) = self.find_kind(chain, digest).await else {
            return false;
        };
        let is_pending = matches!(&checkpoint_kind, CheckpointKind::Pending(_));
        let checkpoint = Checkpoint::from(checkpoint_kind);

        if !is_pending {
            self.update_pending(chain, checkpoint.block_height).await;
            return true;
        }

        match self
            .storage
            .promote_pending(chain, checkpoint.block_height)
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

    /// Hydrates local pending checkpoints and returns the newest known checkpoint.
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

    /// Replaces durable checkpoint state with a consensus checkpoint after regression.
    pub(super) async fn regress(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        self.storage.reset_to_latest(checkpoint).await?;
        self.pending(checkpoint.chain).write().await.clear();
        self.observe(checkpoint.chain, 0);
        Ok(())
    }

    /// Returns the newest pending checkpoint or the latest confirmed checkpoint.
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

    /// Reports whether `chain` can create another pending checkpoint.
    pub(super) async fn has_slot(&self, chain: Chain) -> bool {
        self.pending(chain).read().await.len() < MAX_PENDING_CHECKPOINTS
    }

    /// Returns the number of locally pending checkpoints for `chain`.
    pub(super) async fn count(&self, chain: Chain) -> usize {
        self.pending(chain).read().await.len()
    }

    /// Finds a checkpoint by digest, searching pending checkpoints before durable latest state.
    pub(super) async fn find(&self, chain: Chain, digest: [u8; 32]) -> Option<Checkpoint> {
        self.find_kind(chain, digest).await.map(Checkpoint::from)
    }

    /// Finds a checkpoint by digest and identifies whether it is pending or confirmed.
    async fn find_kind(&self, chain: Chain, digest: [u8; 32]) -> Option<CheckpointKind> {
        if let Some(checkpoint) = self
            .pending(chain)
            .read()
            .await
            .values()
            .find(|checkpoint| checkpoint.digest() == digest)
            .cloned()
        {
            return Some(CheckpointKind::Pending(checkpoint));
        }
        self.storage
            .load_latest(chain)
            .await
            .ok()
            .flatten()
            .filter(|checkpoint| checkpoint.digest() == digest)
            .map(CheckpointKind::Latest)
    }

    #[cfg(test)]
    /// Returns the backing storage for tests that need to seed checkpoint state.
    pub(super) fn storage(&self) -> &CheckpointStorage {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Barrier;

    fn checkpoint(height: u64) -> Checkpoint {
        Checkpoint {
            chain: Chain::Ethereum,
            block_height: height,
            pending_requests: vec![],
            cumulative_digest: Checkpoint::empty_cumulative_digest(),
        }
    }

    #[tokio::test]
    async fn concurrent_persistence_respects_pending_checkpoint_cap() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        for height in 0..MAX_PENDING_CHECKPOINTS as u64 - 1 {
            assert!(checkpoints
                .persist_pending(&checkpoint(height))
                .await
                .is_ok());
        }

        let barrier = Arc::new(Barrier::new(2));
        let first = {
            let checkpoints = checkpoints.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                checkpoints
                    .persist_pending(&checkpoint(MAX_PENDING_CHECKPOINTS as u64))
                    .await
            })
        };
        let second = {
            let checkpoints = checkpoints.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                checkpoints
                    .persist_pending(&checkpoint(MAX_PENDING_CHECKPOINTS as u64 + 1))
                    .await
            })
        };

        let first = first.await.unwrap();
        let second = second.await.unwrap();
        assert!(
            matches!(first, Ok(())) && matches!(second, Err(CheckpointError::PendingCap { .. }))
                || matches!(second, Ok(()))
                    && matches!(first, Err(CheckpointError::PendingCap { .. }))
        );
        assert_eq!(
            checkpoints.count(Chain::Ethereum).await,
            MAX_PENDING_CHECKPOINTS
        );
    }

    #[tokio::test]
    async fn persist_stalls_at_cap() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        for height in 0..MAX_PENDING_CHECKPOINTS as u64 {
            checkpoints
                .persist_pending(&checkpoint(height))
                .await
                .unwrap();
        }

        assert!(matches!(
            checkpoints
                .persist_pending(&checkpoint(MAX_PENDING_CHECKPOINTS as u64))
                .await,
            Err(CheckpointError::PendingCap { .. })
        ));
    }

    #[tokio::test]
    async fn persist_is_idempotent_for_identical_checkpoint() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let checkpoint = checkpoint(1);

        checkpoints.persist_pending(&checkpoint).await.unwrap();
        checkpoints.persist_pending(&checkpoint).await.unwrap();

        assert_eq!(checkpoints.count(checkpoint.chain).await, 1);
    }

    #[tokio::test]
    async fn confirmation_frees_pending_slot() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        for height in 0..MAX_PENDING_CHECKPOINTS as u64 {
            checkpoints
                .persist_pending(&checkpoint(height))
                .await
                .unwrap();
        }

        let latest = checkpoint(MAX_PENDING_CHECKPOINTS as u64 - 1);
        assert!(checkpoints.confirm(latest.chain, latest.digest()).await);
        assert!(checkpoints
            .persist_pending(&checkpoint(MAX_PENDING_CHECKPOINTS as u64))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn confirmation_removes_pending_checkpoints_through_confirmed_height() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let first = checkpoint(1);
        let second = checkpoint(2);
        let third = checkpoint(3);
        checkpoints.persist_pending(&first).await.unwrap();
        checkpoints.persist_pending(&second).await.unwrap();
        checkpoints.persist_pending(&third).await.unwrap();

        assert!(checkpoints.confirm(second.chain, second.digest()).await);
        assert_eq!(checkpoints.count(first.chain).await, 1);
        assert_eq!(checkpoints.latest(first.chain).await, Some(third));
    }

    #[tokio::test]
    async fn unknown_consensus_digest_preserves_checkpoint_state() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let checkpoint = checkpoint(1);
        checkpoints.persist_pending(&checkpoint).await.unwrap();

        assert!(!checkpoints.confirm(checkpoint.chain, [1; 32]).await);
        assert_eq!(checkpoints.count(checkpoint.chain).await, 1);
        assert_eq!(checkpoints.latest(checkpoint.chain).await, Some(checkpoint));
    }

    #[tokio::test]
    async fn load_local_hydrates_pending_checkpoints_after_restart() {
        let storage = CheckpointStorage::in_memory();
        let first = checkpoint(1);
        let second = checkpoint(2);
        let checkpoints = Checkpoints::new(storage.clone());
        checkpoints.persist_pending(&first).await.unwrap();
        checkpoints.persist_pending(&second).await.unwrap();

        let restarted = Checkpoints::new(storage);
        assert_eq!(
            restarted.load_local(first.chain).await.unwrap(),
            Some(second.clone())
        );
        assert_eq!(restarted.count(first.chain).await, 2);
        assert_eq!(
            restarted.find(first.chain, first.digest()).await,
            Some(first)
        );
    }

    #[tokio::test]
    async fn load_local_ignores_pending_checkpoints_at_confirmed_height() {
        let storage = CheckpointStorage::in_memory();
        let confirmed = checkpoint(2);
        let stale_pending = checkpoint(1);
        let fresh_pending = checkpoint(3);
        storage.persist(&confirmed).await.unwrap();
        storage.persist_pending(&stale_pending).await.unwrap();
        storage.persist_pending(&fresh_pending).await.unwrap();

        let checkpoints = Checkpoints::new(storage);
        assert_eq!(
            checkpoints.load_local(confirmed.chain).await.unwrap(),
            Some(fresh_pending.clone())
        );
        assert_eq!(checkpoints.count(confirmed.chain).await, 1);
        assert_eq!(
            checkpoints
                .find(stale_pending.chain, stale_pending.digest())
                .await,
            None
        );
    }

    #[tokio::test]
    async fn regression_resets_checkpoint_state() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        checkpoints.persist_pending(&checkpoint(1)).await.unwrap();
        checkpoints.persist_pending(&checkpoint(2)).await.unwrap();
        let consensus = checkpoint(0);

        checkpoints.regress(&consensus).await.unwrap();

        assert_eq!(checkpoints.count(consensus.chain).await, 0);
        assert_eq!(
            checkpoints
                .storage()
                .load_latest(consensus.chain)
                .await
                .unwrap(),
            Some(consensus)
        );
    }

    #[tokio::test]
    async fn find_falls_back_to_confirmed_checkpoint() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let checkpoint = checkpoint(1);
        checkpoints.persist_pending(&checkpoint).await.unwrap();
        assert!(
            checkpoints
                .confirm(checkpoint.chain, checkpoint.digest())
                .await
        );

        assert_eq!(
            checkpoints
                .find(checkpoint.chain, checkpoint.digest())
                .await,
            Some(checkpoint)
        );
    }
}
