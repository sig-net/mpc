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
    /// Present only on a body written before the digest covered source facts. Such a body
    /// hashes as it did then, over its entries' phases; the value itself is not trusted.
    #[serde(
        rename = "cumulative_digest",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes"
    )]
    pub legacy_digest: Option<[u8; 32]>,
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
            legacy_digest: None,
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        mpc_primitives::checkpoint_digest(
            self.chain,
            self.block_height,
            self.pending_requests
                .iter()
                .map(|entry| entry.sign_id().request_id),
            match self.legacy_digest {
                Some(_) => self.legacy_entries_digest(),
                None => self.entries_digest(),
            },
        )
    }

    /// The hash earlier versions took over their entries.
    fn legacy_entries_digest(&self) -> [u8; 32] {
        let mut hasher = sha3::Sha3_256::new();
        for entry in &self.pending_requests {
            hasher.update([entry.status().consensus_tag()]);
        }
        hasher.finalize().into()
    }

    /// The source facts of each entry, which every node that processed the chain holds alike
    /// (doc/checkpoints.md); a node's own progress stays out of it.
    fn entries_digest(&self) -> [u8; 32] {
        let mut hasher = sha3::Sha3_256::new();
        for entry in &self.pending_requests {
            hasher.update(entry.digest_bytes());
        }
        hasher.finalize().into()
    }

    /// This checkpoint with each entry's progress rebuilt from its source facts.
    pub(crate) fn without_progress(&self, root_pk: mpc_primitives::PublicKey) -> Self {
        Self {
            pending_requests: self
                .pending_requests
                .iter()
                .map(|entry| entry.without_progress(root_pk))
                .collect(),
            ..self.clone()
        }
    }

    pub fn len(&self) -> usize {
        self.pending_requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending_requests.is_empty()
    }
}

impl From<&Checkpoint> for mpc_primitives::CheckpointDigest {
    fn from(checkpoint: &Checkpoint) -> Self {
        Self {
            chain: checkpoint.chain,
            height: checkpoint.block_height,
            digest: checkpoint.digest(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Checkpoints {
    storage: CheckpointStorage,
    pending_counts: Arc<EnumMap<Chain, AtomicUsize>>,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("pending checkpoint cap reached for {chain}")]
    PendingCap { chain: Chain, tx_count: usize },
    #[error("failed to persist checkpoint for {chain}: {source:#}")]
    Storage {
        chain: Chain,
        #[source]
        source: anyhow::Error,
    },
}

impl Checkpoints {
    /// Creates a checkpoint tracker backed by `storage`.
    pub(crate) fn new(storage: CheckpointStorage) -> Self {
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
    pub(crate) async fn persist_pending(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<(), CheckpointError> {
        let chain = checkpoint.chain;
        if !self.has_slot(chain) {
            return Err(CheckpointError::PendingCap {
                chain,
                tx_count: checkpoint.len(),
            });
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
    pub(crate) fn snapshot(requests: &PendingRequests, chain: Chain) -> Checkpoint {
        let mut pending_requests = requests.requests.values().cloned().collect::<Vec<_>>();
        pending_requests.sort_by_key(|entry| entry.sign_id());

        Checkpoint {
            chain,
            block_height: requests.processed_block_height.unwrap_or(0),
            pending_requests,
            legacy_digest: None,
        }
    }

    /// Promotes a pending checkpoint when its digest reaches consensus, or
    /// confirms it if already promoted.
    pub async fn confirm(&self, chain: Chain, digest: [u8; 32]) -> Result<bool, CheckpointError> {
        let outcome = self
            .storage
            .promote_pending(chain, digest)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?;

        // Not a fault by itself: a node behind consensus has no such checkpoint yet.
        let Some(remaining_count) = outcome else {
            tracing::debug!(
                ?chain,
                ?digest,
                "pending checkpoint not found for promotion"
            );
            return Ok(false);
        };

        // The promotion above is authoritative; read back the height it settled
        // so serve-only orphans at or below it can be released. This is a cold
        // path (one settlement per interval), so the extra durable read is cheap.
        let settled_height = self
            .storage
            .load_latest(chain)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?
            .map(|cp| cp.block_height);
        if let Some(height) = settled_height {
            self.clear_orphan_up_to(chain, height).await?;
        }

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
    pub(crate) async fn hydrate(&self, chain: Chain) -> Result<usize, CheckpointError> {
        let count = self
            .storage
            .pending_count(chain)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?;
        self.pending_counts[chain].store(count, Ordering::Release);
        self.observe(chain, count);
        Ok(count)
    }

    /// Replaces durable checkpoint state with a consensus checkpoint after regression.
    pub(crate) async fn regress(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointError> {
        let chain = checkpoint.chain;
        self.storage
            .reset_to_latest(checkpoint)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?;
        self.pending_counts[chain].store(0, Ordering::Release);
        self.observe(chain, 0);
        Ok(())
    }

    /// Returns the newest pending checkpoint or the latest confirmed checkpoint.
    pub async fn latest(&self, chain: Chain) -> Result<Option<Checkpoint>, CheckpointError> {
        self.storage
            .latest(chain)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })
    }

    /// Returns whether a pending or confirmed checkpoint is stored for `chain`.
    pub(crate) async fn has_checkpoint(&self, chain: Chain) -> Result<bool, CheckpointError> {
        self.storage
            .has_checkpoint(chain)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })
    }

    /// Loads the durable unconfirmed checkpoints for `chain`, ordered by height.
    pub(crate) async fn load_pending(
        &self,
        chain: Chain,
    ) -> Result<Vec<Checkpoint>, CheckpointError> {
        self.storage
            .load_pending(chain)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })
    }

    /// Reports whether `chain` can create another pending checkpoint.
    pub(crate) fn has_slot(&self, chain: Chain) -> bool {
        self.count(chain) < MAX_PENDING_CHECKPOINTS
    }

    /// Returns the number of locally pending checkpoints for `chain`.
    pub(crate) fn count(&self, chain: Chain) -> usize {
        self.pending_counts[chain].load(Ordering::Acquire)
    }

    /// Finds a checkpoint by digest, searching pending, then the serve-only orphan
    /// store, then the durable latest. Used by the peer `/checkpoint` endpoint.
    pub(crate) async fn find(&self, chain: Chain, digest: [u8; 32]) -> Option<Checkpoint> {
        self.storage.find(chain, digest).await.ok().flatten()
    }

    /// Retains a checkpoint displaced from `pending` at startup, for serving only.
    pub(crate) async fn persist_orphan(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<(), CheckpointError> {
        let chain = checkpoint.chain;
        self.storage
            .persist_orphan(checkpoint)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })
    }

    /// Looks up a serve-only orphan by digest. The peer-serving path uses `find`
    /// (which includes orphans); this typed accessor is for tests and observability.
    #[allow(dead_code)]
    pub(crate) async fn find_orphan(
        &self,
        chain: Chain,
        digest: [u8; 32],
    ) -> Result<Option<Checkpoint>, CheckpointError> {
        self.storage
            .find_orphan(chain, digest)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })
    }

    /// Drops serve-only orphans at or below `height`.
    pub(crate) async fn clear_orphan_up_to(
        &self,
        chain: Chain,
        height: u64,
    ) -> Result<(), CheckpointError> {
        self.storage
            .clear_orphan_up_to(chain, height)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })
    }

    /// Atomically drops every pending checkpoint (and its digest index) for `chain`.
    /// The caller re-hydrates the counter afterwards.
    pub(crate) async fn clear_pending(&self, chain: Chain) -> Result<(), CheckpointError> {
        self.storage
            .clear_pending(chain)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })
    }

    /// Returns the backing storage.
    pub(crate) fn storage(&self) -> &CheckpointStorage {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::mock::mock_sign_request;
    use mpc_primitives::SignId;
    use tokio::sync::Barrier;

    fn checkpoint(height: u64) -> Checkpoint {
        Checkpoint::reset(Chain::Ethereum, height)
    }

    /// A checkpoint at `height` with one request so its digest differs from a reset
    /// at the same height — needed to tell "cleared by height" from "cleared by digest".
    fn checkpoint_with_entry(height: u64, id_byte: u8) -> Checkpoint {
        Checkpoint {
            chain: Chain::Ethereum,
            block_height: height,
            pending_requests: vec![BacklogEntry::new(mock_sign_request(
                SignId::new([id_byte; 32]),
                Chain::Ethereum,
            ))],
            legacy_digest: None,
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
        assert!(!checkpoints.has_slot(Chain::Ethereum));
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

        assert!(!checkpoints.has_slot(Chain::Ethereum));
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
        assert!(!checkpoints.has_slot(latest.chain));
        assert!(matches!(
            checkpoints.confirm(latest.chain, latest.digest()).await,
            Ok(true)
        ));
        assert!(checkpoints.has_slot(latest.chain));
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
        assert_eq!(checkpoints.latest(first.chain).await.unwrap(), Some(third));
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
        assert_eq!(
            checkpoints.latest(checkpoint.chain).await.unwrap(),
            Some(checkpoint)
        );
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
        let confirmed = checkpoint(1);
        let pending = checkpoint(2);

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

    // ---- orphan-store behaviour -------------------------------------------------

    #[tokio::test]
    async fn orphan_body_is_served_by_find_until_a_checkpoint_at_its_height_settles() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let chain = Chain::Ethereum;
        let discarded = checkpoint_with_entry(110, 7);
        let digest = discarded.digest();

        checkpoints.persist_orphan(&discarded).await.unwrap();
        checkpoints.clear_pending(chain).await.unwrap();
        checkpoints.hydrate(chain).await.unwrap();

        // The body is gone from pending, yet a peer asking by digest is served.
        assert_eq!(checkpoints.load_pending(chain).await.unwrap(), vec![]);
        assert_eq!(checkpoints.count(chain), 0);
        assert_eq!(
            checkpoints.find_orphan(chain, digest).await.unwrap(),
            Some(discarded.clone())
        );
        assert_eq!(checkpoints.find(chain, digest).await, Some(discarded));

        // A different checkpoint at 120 settles; the orphan at 110 is released.
        let settled = checkpoint(120);
        checkpoints.persist_pending(&settled).await.unwrap();
        assert!(checkpoints.confirm(chain, settled.digest()).await.unwrap());
        assert_eq!(checkpoints.find_orphan(chain, digest).await.unwrap(), None);
        assert_eq!(checkpoints.find(chain, digest).await, None);
    }

    #[tokio::test]
    async fn confirm_clears_orphans_at_or_below_the_confirmed_height_only() {
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        let chain = Chain::Ethereum;
        let below = checkpoint(95);
        let at = checkpoint_with_entry(100, 3);
        let above = checkpoint(105);
        for cp in [&below, &at, &above] {
            checkpoints.persist_orphan(cp).await.unwrap();
        }

        // Settle a (different) body at height 100 — the boundary is inclusive.
        let settled = checkpoint(100);
        checkpoints.persist_pending(&settled).await.unwrap();
        assert!(checkpoints.confirm(chain, settled.digest()).await.unwrap());

        assert_eq!(
            checkpoints
                .find_orphan(chain, below.digest())
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            checkpoints.find_orphan(chain, at.digest()).await.unwrap(),
            None
        );
        assert_eq!(
            checkpoints
                .find_orphan(chain, above.digest())
                .await
                .unwrap(),
            Some(above)
        );
    }

    #[tokio::test]
    async fn clear_pending_and_hydrate_reset_the_counter() {
        let storage = CheckpointStorage::in_memory();
        let checkpoints = Checkpoints::new(storage.clone());
        let chain = Chain::Ethereum;
        checkpoints.persist_pending(&checkpoint(100)).await.unwrap();
        checkpoints.persist_pending(&checkpoint(110)).await.unwrap();
        assert_eq!(checkpoints.count(chain), 2);

        checkpoints.clear_pending(chain).await.unwrap();
        assert_eq!(checkpoints.hydrate(chain).await.unwrap(), 0);
        assert_eq!(checkpoints.count(chain), 0);
    }

    #[tokio::test]
    async fn orphan_operations_map_storage_errors() {
        let checkpoints = Checkpoints::new(CheckpointStorage::failing());
        let chain = Chain::Ethereum;
        let cp = checkpoint(100);
        assert!(matches!(
            checkpoints.persist_orphan(&cp).await,
            Err(CheckpointError::Storage { .. })
        ));
        assert!(matches!(
            checkpoints.find_orphan(chain, cp.digest()).await,
            Err(CheckpointError::Storage { .. })
        ));
        assert!(matches!(
            checkpoints.clear_orphan_up_to(chain, 100).await,
            Err(CheckpointError::Storage { .. })
        ));
        assert!(matches!(
            checkpoints.clear_pending(chain).await,
            Err(CheckpointError::Storage { .. })
        ));
    }

    #[tokio::test]
    async fn mixed_rollout_threshold_settlement_clears_discarded_orphans() {
        // Deterministic two-node unit simulation with a fake contract view: there is
        // no networking and no real threshold signing. The "contract" is a local vote
        // tally we drive explicitly; both nodes observe the same settled digest.
        let chain = Chain::Ethereum;
        let base = checkpoint(100);
        let old_pending = checkpoint_with_entry(110, 9);

        // Node A upgrades first: its pending body is moved to the orphan store.
        let storage_a = CheckpointStorage::in_memory();
        storage_a.persist(&base).await.unwrap();
        storage_a.persist_pending(&old_pending).await.unwrap();
        let a = Checkpoints::new(storage_a);
        a.hydrate(chain).await.unwrap();
        a.persist_orphan(&old_pending).await.unwrap();
        a.clear_pending(chain).await.unwrap();
        a.hydrate(chain).await.unwrap();
        assert_eq!(a.count(chain), 0);
        assert!(a
            .find_orphan(chain, old_pending.digest())
            .await
            .unwrap()
            .is_some());

        // Node B has not restarted: it still holds the pending body and keeps voting
        // for it. Both nodes now build their next body on the settled base (100).
        let storage_b = CheckpointStorage::in_memory();
        storage_b.persist(&base).await.unwrap();
        storage_b.persist_pending(&old_pending).await.unwrap();
        let b = Checkpoints::new(storage_b);
        assert_eq!(
            b.load_pending(chain).await.unwrap(),
            vec![old_pending.clone()]
        );

        let next = checkpoint(120);
        a.persist_pending(&next).await.unwrap();
        b.persist_pending(&next).await.unwrap();
        assert_eq!(a.find(chain, next.digest()).await, Some(next.clone()));
        assert_eq!(b.find(chain, next.digest()).await, Some(next.clone()));

        // Fake contract: threshold = 2, both nodes vote `next` at the next boundary.
        let mut votes: std::collections::HashMap<[u8; 32], usize> = Default::default();
        *votes.entry(next.digest()).or_default() += 1; // A
        *votes.entry(next.digest()).or_default() += 1; // B
        assert_eq!(votes[&next.digest()], 2, "threshold reached");

        // Until settlement, A can still serve the discarded cohort to a peer.
        assert_eq!(
            a.find(chain, old_pending.digest()).await,
            Some(old_pending.clone())
        );

        // Both nodes confirm; A's orphan at 110 is cleared, B's stale pending at 110
        // is pruned by promotion through 120. Neither node serves the old body.
        assert!(a.confirm(chain, next.digest()).await.unwrap());
        assert!(b.confirm(chain, next.digest()).await.unwrap());
        assert_eq!(
            a.find_orphan(chain, old_pending.digest()).await.unwrap(),
            None
        );
        assert_eq!(a.find(chain, old_pending.digest()).await, None);
        assert_eq!(b.find(chain, old_pending.digest()).await, None);
        assert_eq!(
            a.storage().load_latest(chain).await.unwrap(),
            Some(next.clone())
        );
        assert_eq!(b.storage().load_latest(chain).await.unwrap(), Some(next));
    }
}
