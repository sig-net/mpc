use super::{BacklogEntry, PendingRequests, MAX_PENDING_CHECKPOINTS};
use crate::storage::checkpoint_storage::CheckpointStorage;

use enum_map::EnumMap;
use mpc_primitives::Chain;
use sha3::Digest;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A checkpoint represents the backlog state at a specific block height.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub chain: Chain,
    pub block_height: u64,
    pub pending_requests: Vec<BacklogEntry>,
    /// Commitment to each pending request's checkpoint-consensus phase.
    #[serde(default, with = "serde_bytes")]
    pub cumulative_digest: [u8; 32],
}

impl fmt::Debug for Checkpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct DebugPendingRequests<'a>(&'a [BacklogEntry]);
        impl<'a> fmt::Debug for DebugPendingRequests<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut list = f.debug_list();
                for entry in self.0 {
                    list.entry(&entry.sign_id());
                }
                list.finish()
            }
        }

        f.debug_struct("Checkpoint")
            .field("chain", &self.chain)
            .field("block_height", &self.block_height)
            .field(
                "pending_requests",
                &DebugPendingRequests(&self.pending_requests),
            )
            .field("cumulative_digest", &self.cumulative_digest)
            .finish()
    }
}

impl Checkpoint {
    pub fn empty(chain: Chain) -> Self {
        Self::reset(chain, 0)
    }

    /// The canonical *reset* checkpoint for `(chain, block_height)`: an empty
    /// backlog at that height, digesting to
    /// [`mpc_primitives::reset_checkpoint_digest`].
    pub fn reset(chain: Chain, block_height: u64) -> Self {
        Self {
            chain,
            block_height,
            pending_requests: Vec::new(),
            cumulative_digest: Self::empty_cumulative_digest(),
        }
    }

    pub fn empty_cumulative_digest() -> [u8; 32] {
        mpc_primitives::empty_cumulative_digest()
    }

    pub fn digest(&self) -> [u8; 32] {
        mpc_primitives::checkpoint_digest(
            self.chain,
            self.block_height,
            self.pending_requests
                .iter()
                .map(|entry| entry.sign_id().request_id),
            self.cumulative_digest,
        )
    }
}

#[derive(Debug, Clone)]
pub(super) struct Checkpoints {
    storage: CheckpointStorage,
    pending_counts: Arc<EnumMap<Chain, AtomicUsize>>,
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

impl Checkpoints {
    /// Creates a checkpoint tracker backed by `storage`.
    pub(super) fn new(storage: CheckpointStorage) -> Self {
        Self {
            storage,
            pending_counts: Arc::default(),
        }
    }

    /// Updates the pending-checkpoint metric for `chain`.
    fn observe(&self, chain: Chain, len: usize) {
        crate::metrics::requests::PENDING_CHECKPOINTS
            .with_label_values(&[chain.as_str()])
            .set(len as i64);
    }

    /// Durably records an unconfirmed checkpoint.
    pub(super) async fn persist_pending(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<(), CheckpointError> {
        let chain = checkpoint.chain;
        let count = self.count(chain);
        if count >= MAX_PENDING_CHECKPOINTS {
            tracing::warn!(
                ?chain,
                count,
                "pending checkpoint cap reached; stalling checkpoint creation"
            );
            return Err(CheckpointError::PendingCap { chain });
        }

        let inserted = self
            .storage
            .persist_pending(checkpoint)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?;

        if inserted {
            let new_count = self.pending_counts[chain].fetch_add(1, Ordering::AcqRel) + 1;
            self.observe(chain, new_count);
        }
        Ok(())
    }

    /// Captures the current request state as a deterministic checkpoint.
    pub(super) fn snapshot(requests: &PendingRequests, chain: Chain) -> Checkpoint {
        let mut pending_requests = requests.requests.values().cloned().collect::<Vec<_>>();
        pending_requests.sort_by_key(|entry| entry.sign_id());

        let mut cumulative = sha3::Sha3_256::new();
        for entry in &pending_requests {
            cumulative.update([entry.status().consensus_tag()]);
        }

        Checkpoint {
            chain,
            block_height: requests.processed_block_height.unwrap_or(0),
            pending_requests,
            cumulative_digest: cumulative.finalize().into(),
        }
    }

    /// Promotes a pending checkpoint when its digest reaches consensus, or
    /// confirms it if already promoted.
    pub(super) async fn confirm(
        &self,
        chain: Chain,
        digest: [u8; 32],
    ) -> Result<bool, CheckpointError> {
        let outcome = self
            .storage
            .promote_pending(chain, digest)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?;

        let Some(remaining_count) = outcome else {
            tracing::warn!(
                ?chain,
                ?digest,
                "pending checkpoint not found for promotion"
            );
            return Ok(false);
        };

        self.pending_counts[chain].store(remaining_count, Ordering::Release);
        self.observe(chain, remaining_count);
        tracing::info!(
            ?chain,
            ?digest,
            remaining_count,
            "consensus checkpoint confirmed"
        );
        Ok(true)
    }

    /// Hydrates the pending checkpoint count from storage into the local counter.
    pub(super) async fn hydrate(&self, chain: Chain) -> anyhow::Result<usize> {
        let count = match self.storage.pending_count(chain).await {
            Ok(count) => count,
            Err(err) => {
                tracing::warn!(
                    ?chain,
                    %err,
                    "failed to load pending count from storage; defaulting to 0"
                );
                0
            }
        };
        self.pending_counts[chain].store(count, Ordering::Release);
        self.observe(chain, count);
        Ok(count)
    }

    /// Replaces durable checkpoint state with a consensus checkpoint after regression.
    pub(super) async fn regress(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        self.storage.reset_to_latest(checkpoint).await?;
        self.pending_counts[checkpoint.chain].store(0, Ordering::Release);
        self.observe(checkpoint.chain, 0);
        Ok(())
    }

    /// Returns the newest pending checkpoint or the latest confirmed checkpoint.
    pub(super) async fn latest(&self, chain: Chain) -> Option<Checkpoint> {
        self.storage.latest(chain).await.ok().flatten()
    }

    /// Reports whether `chain` can create another pending checkpoint.
    pub(super) fn has_slot(&self, chain: Chain) -> bool {
        self.count(chain) < MAX_PENDING_CHECKPOINTS
    }

    /// Returns the number of locally pending checkpoints for `chain`.
    pub(super) fn count(&self, chain: Chain) -> usize {
        self.pending_counts[chain].load(Ordering::Acquire)
    }

    /// Finds a checkpoint by digest, searching durable latest and pending storage.
    pub(super) async fn find(&self, chain: Chain, digest: [u8; 32]) -> Option<Checkpoint> {
        self.storage.find(chain, digest).await.ok().flatten()
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
        assert_eq!(checkpoints.count(Chain::Ethereum), MAX_PENDING_CHECKPOINTS);
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

        assert_eq!(checkpoints.count(checkpoint.chain), 1);
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
        assert!(matches!(
            checkpoints.confirm(latest.chain, latest.digest()).await,
            Ok(true)
        ));
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

        assert!(matches!(
            checkpoints.confirm(second.chain, second.digest()).await,
            Ok(true)
        ));
        assert_eq!(checkpoints.count(first.chain), 1);
        assert_eq!(checkpoints.latest(first.chain).await, Some(third));
    }

    #[tokio::test]
    async fn unknown_consensus_digest_preserves_checkpoint_state() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let checkpoint = checkpoint(1);
        checkpoints.persist_pending(&checkpoint).await.unwrap();

        assert!(matches!(
            checkpoints.confirm(checkpoint.chain, [1; 32]).await,
            Ok(false)
        ));
        assert_eq!(checkpoints.count(checkpoint.chain), 1);
        assert_eq!(checkpoints.latest(checkpoint.chain).await, Some(checkpoint));
    }

    #[tokio::test]
    async fn hydrate_initializes_pending_counter_after_restart() {
        let storage = CheckpointStorage::in_memory();
        let first = checkpoint(1);
        let second = checkpoint(2);
        let checkpoints = Checkpoints::new(storage.clone());
        checkpoints.persist_pending(&first).await.unwrap();
        checkpoints.persist_pending(&second).await.unwrap();

        let restarted = Checkpoints::new(storage);
        assert_eq!(restarted.hydrate(first.chain).await.unwrap(), 2);
        assert_eq!(restarted.count(first.chain), 2);
        assert_eq!(
            restarted.find(first.chain, first.digest()).await,
            Some(first)
        );
    }

    #[tokio::test]
    async fn hydrate_loads_durable_pending_count() {
        let storage = CheckpointStorage::in_memory();
        let confirmed = checkpoint(2);
        let stale_pending = checkpoint(1);
        let fresh_pending = checkpoint(3);
        storage.persist(&confirmed).await.unwrap();
        storage.persist_pending(&stale_pending).await.unwrap();
        storage.persist_pending(&fresh_pending).await.unwrap();

        let checkpoints = Checkpoints::new(storage);
        assert_eq!(checkpoints.hydrate(confirmed.chain).await.unwrap(), 2);
        assert_eq!(checkpoints.count(confirmed.chain), 2);
        assert_eq!(
            checkpoints
                .find(stale_pending.chain, stale_pending.digest())
                .await,
            Some(stale_pending)
        );
    }

    #[tokio::test]
    async fn regression_resets_checkpoint_state() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        checkpoints.persist_pending(&checkpoint(1)).await.unwrap();
        checkpoints.persist_pending(&checkpoint(2)).await.unwrap();
        let consensus = checkpoint(0);

        checkpoints.regress(&consensus).await.unwrap();

        assert_eq!(checkpoints.count(consensus.chain), 0);
        assert_eq!(
            checkpoints
                .storage()
                .load_latest(consensus.chain)
                .await
                .unwrap(),
            Some(consensus)
        );
    }

    #[test]
    fn reset_checkpoint_digest_is_the_shared_derivation() {
        // The contract settles this digest without holding the checkpoint, so
        // the two must agree exactly or a reset would look like a divergence
        // that no peer can resolve.
        let reset = Checkpoint::reset(Chain::Solana, 42);
        assert_eq!(
            reset.digest(),
            mpc_primitives::reset_checkpoint_digest(Chain::Solana, 42)
        );
        assert!(reset.pending_requests.is_empty());
        assert_eq!(reset.block_height, 42);
    }

    #[tokio::test]
    async fn find_falls_back_to_confirmed_checkpoint() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let checkpoint = checkpoint(1);
        checkpoints.persist_pending(&checkpoint).await.unwrap();
        assert!(matches!(
            checkpoints
                .confirm(checkpoint.chain, checkpoint.digest())
                .await,
            Ok(true)
        ));

        assert_eq!(
            checkpoints
                .find(checkpoint.chain, checkpoint.digest())
                .await,
            Some(checkpoint)
        );
    }

    #[tokio::test]
    async fn confirm_reports_storage_error_when_promotion_fails() {
        let checkpoints = Checkpoints::new(CheckpointStorage::failing());
        let checkpoint = checkpoint(1);

        assert!(matches!(
            checkpoints
                .confirm(checkpoint.chain, checkpoint.digest())
                .await,
            Err(CheckpointError::Storage { .. })
        ));
    }

    #[tokio::test]
    async fn confirm_treats_already_promoted_checkpoint_as_confirmed() {
        let storage = CheckpointStorage::in_memory();
        let checkpoints = Checkpoints::new(storage.clone());
        let checkpoint = checkpoint(1);

        checkpoints.persist_pending(&checkpoint).await.unwrap();
        storage
            .promote_pending(checkpoint.chain, checkpoint.digest())
            .await
            .unwrap();

        assert!(matches!(
            checkpoints
                .confirm(checkpoint.chain, checkpoint.digest())
                .await,
            Ok(true)
        ));
        assert_eq!(checkpoints.count(checkpoint.chain), 0);
    }

    #[tokio::test]
    async fn find_finds_confirmed_and_pending_checkpoints() {
        let storage = CheckpointStorage::in_memory();
        let checkpoints = Checkpoints::new(storage.clone());
        let mut confirmed = checkpoint(1);
        confirmed.cumulative_digest = [1; 32];
        let mut pending = checkpoint(2);
        pending.cumulative_digest = [2; 32];

        storage.persist(&confirmed).await.unwrap();
        checkpoints.persist_pending(&pending).await.unwrap();

        assert_eq!(
            checkpoints.find(confirmed.chain, confirmed.digest()).await,
            Some(confirmed)
        );
        assert_eq!(
            checkpoints.find(pending.chain, pending.digest()).await,
            Some(pending)
        );
    }

    #[tokio::test]
    async fn confirm_reports_storage_error_when_lookup_fails() {
        let checkpoints = Checkpoints::new(CheckpointStorage::failing());

        // No local checkpoint and a failing storage: the lookup error must be
        // surfaced instead of being reported as "not found".
        assert!(matches!(
            checkpoints.confirm(Chain::Ethereum, [1; 32]).await,
            Err(CheckpointError::Storage { .. })
        ));
    }

    #[tokio::test]
    async fn find_serves_pending_digest_before_hydration() {
        let storage = CheckpointStorage::in_memory();
        let checkpoint = checkpoint(1);
        storage.persist_pending(&checkpoint).await.unwrap();

        // A fresh `Checkpoints` has an empty counter until `hydrate`
        // initializes it, as happens right after a restart before the mesh is active.
        // The durable pending body must still be findable.
        let checkpoints = Checkpoints::new(storage);

        assert_eq!(
            checkpoints
                .find(checkpoint.chain, checkpoint.digest())
                .await,
            Some(checkpoint)
        );
    }

    #[tokio::test]
    async fn confirm_promotes_pending_digest_before_hydration() {
        let storage = CheckpointStorage::in_memory();
        let checkpoint = checkpoint(1);
        storage.persist_pending(&checkpoint).await.unwrap();

        let checkpoints = Checkpoints::new(storage);
        assert!(matches!(
            checkpoints
                .confirm(checkpoint.chain, checkpoint.digest())
                .await,
            Ok(true)
        ));
        assert_eq!(
            checkpoints
                .storage()
                .load_latest(checkpoint.chain)
                .await
                .unwrap(),
            Some(checkpoint)
        );
    }

    #[test]
    fn test_checkpoint_debug_formatting() {
        let cp = checkpoint(3);
        let debug_str = format!("{cp:?}");
        assert!(debug_str.starts_with("Checkpoint {"));
        assert!(debug_str.contains("pending_requests: ["));
        assert!(!debug_str.contains("PendingRequest"));
        assert!(!debug_str.contains("PendingTx"));
        assert!(!debug_str.contains("IndexedSignRequest"));
        assert!(!debug_str.contains("payload"));
        for entry in &cp.pending_requests {
            assert!(debug_str.contains(&hex::encode(entry.sign_id().request_id)));
        }
    }
}
