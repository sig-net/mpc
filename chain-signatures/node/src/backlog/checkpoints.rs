use super::{BacklogEntry, PendingRequests, MAX_PENDING_CHECKPOINTS};
use crate::storage::checkpoint_storage::CheckpointStorage;
pub use crate::storage::checkpoint_storage::Confirmation;

use enum_map::EnumMap;
use mpc_primitives::{BidirectionalTxId, Chain, SignArgs, SignId, SignKind};
use sha3::Digest;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// One request as nodes send it to each other. The digest hashes every field.
/// A new field breaks the build until `digest_bytes` hashes it too.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EntryFacts {
    pub id: SignId,
    pub args: SignArgs,
    pub chain: Chain,
    pub kind: SignKind,
    pub tx_ids: Vec<BidirectionalTxId>,
    pub unviable_at: Option<u64>,
}

impl EntryFacts {
    fn digest_bytes(&self) -> Vec<u8> {
        let Self {
            id,
            args,
            chain,
            kind,
            tx_ids,
            unviable_at,
        } = self;
        let mut bytes = Vec::new();
        ciborium::into_writer(&(id, args, chain, kind, tx_ids, unviable_at), &mut bytes)
            .expect("encoding into memory cannot fail");
        bytes
    }
}

/// The checkpoint as peers exchange it; a node's own copy adds its progress.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CheckpointFacts {
    pub chain: Chain,
    pub block_height: u64,
    pub entries: Vec<EntryFacts>,
}

impl From<CheckpointFacts> for Checkpoint {
    fn from(facts: CheckpointFacts) -> Self {
        Self {
            chain: facts.chain,
            block_height: facts.block_height,
            pending_requests: facts.entries.into_iter().map(Into::into).collect(),
            legacy_digest: None,
        }
    }
}

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

/// Above this many requests a checkpoint's `Debug` shows their count instead of their ids,
/// which keeps a checkpoint log line under about 100 KB.
const MAX_DEBUG_SIGN_IDS: usize = 1000;

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

        let mut debug = f.debug_struct("Checkpoint");
        debug
            .field("chain", &self.chain)
            .field("block_height", &self.block_height);
        if self.pending_requests.len() <= MAX_DEBUG_SIGN_IDS {
            debug.field(
                "pending_requests",
                &DebugPendingRequests(&self.pending_requests),
            );
        } else {
            debug.field("pending_request_count", &self.pending_requests.len());
        }
        debug.finish()
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
            hasher.update(entry.facts().digest_bytes());
        }
        hasher.finalize().into()
    }

    /// What a peer gets of this checkpoint.
    pub(crate) fn facts(&self) -> CheckpointFacts {
        CheckpointFacts {
            chain: self.chain,
            block_height: self.block_height,
            entries: self
                .pending_requests
                .iter()
                .map(BacklogEntry::facts)
                .collect(),
        }
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
    #[error("a different pending checkpoint is stored for {chain} at height {height}")]
    Conflict { chain: Chain, height: u64 },
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

        let count = self
            .storage
            .persist_pending(checkpoint)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?
            .ok_or(CheckpointError::Conflict {
                chain,
                height: checkpoint.block_height,
            })?;

        // The count comes from storage: a write whose reply was lost is still counted.
        self.pending_counts[chain].store(count, Ordering::Release);
        self.observe(chain, count);
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

    /// Promotes a pending or orphan checkpoint when its digest reaches consensus,
    /// or confirms it if already promoted.
    pub async fn confirm(
        &self,
        chain: Chain,
        digest: [u8; 32],
    ) -> Result<Confirmation, CheckpointError> {
        let (outcome, remaining_count) = self
            .storage
            .promote(chain, digest)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?;

        if outcome == Confirmation::NotFound {
            // Not a fault by itself: a node behind consensus has no such checkpoint yet.
            tracing::debug!(?chain, ?digest, "checkpoint not found for promotion");
            return Ok(Confirmation::NotFound);
        }

        self.pending_counts[chain].store(remaining_count, Ordering::Release);
        self.observe(chain, remaining_count);
        tracing::info!(
            ?chain,
            ?digest,
            ?outcome,
            remaining_count,
            "consensus checkpoint confirmed"
        );
        Ok(outcome)
    }

    /// Zeroes the locally tracked pending count. Recovery calls this after
    /// durable pending has been cleared, so no storage read is needed.
    pub(crate) fn reset_pending_count(&self, chain: Chain) {
        self.pending_counts[chain].store(0, Ordering::Release);
        self.observe(chain, 0);
    }

    /// Moves durable pending checkpoints into the orphan set at the start of a
    /// recovery pass, then zeroes the locally tracked pending count because
    /// durable pending has been cleared. Orphans remain servable and promotable
    /// but never seed the backlog, so recovery deliberately demotes before seeding.
    pub(crate) async fn demote_pending_to_orphan(
        &self,
        chain: Chain,
    ) -> Result<usize, CheckpointError> {
        let demoted = self
            .storage
            .demote_pending_to_orphan(chain)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })?;
        self.reset_pending_count(chain);
        Ok(demoted)
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

    /// Returns the newest pending, orphan, or confirmed checkpoint by block height.
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

    /// Reports whether `chain` can create another pending checkpoint.
    pub(crate) fn has_slot(&self, chain: Chain) -> bool {
        self.count(chain) < MAX_PENDING_CHECKPOINTS
    }

    /// Returns the number of locally pending checkpoints for `chain`.
    pub(crate) fn count(&self, chain: Chain) -> usize {
        self.pending_counts[chain].load(Ordering::Acquire)
    }

    /// Finds a checkpoint by digest, searching confirmed, pending and orphan storage.
    pub(crate) async fn find(&self, chain: Chain, digest: [u8; 32]) -> Option<Checkpoint> {
        self.storage.find(chain, digest).await.ok().flatten()
    }

    /// Returns the backing storage.
    pub(crate) fn storage(&self) -> &CheckpointStorage {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Barrier;

    fn checkpoint(height: u64) -> Checkpoint {
        Checkpoint::reset(Chain::Ethereum, height)
    }

    fn checkpoint_with_requests(count: usize) -> Checkpoint {
        let mut checkpoint = checkpoint(100);
        checkpoint.pending_requests = (0..count)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                BacklogEntry::new(crate::backlog::mock::mock_sign_request(
                    mpc_primitives::SignId::new(id),
                    Chain::Ethereum,
                ))
            })
            .collect();
        checkpoint
    }

    #[test]
    fn debug_lists_sign_ids_up_to_the_limit() {
        let debug = format!("{:?}", checkpoint_with_requests(MAX_DEBUG_SIGN_IDS));
        assert_eq!(debug.matches("SignId(").count(), MAX_DEBUG_SIGN_IDS);
        assert!(debug.len() < 100_000, "{} bytes", debug.len());
    }

    #[test]
    fn debug_shows_only_the_count_above_the_limit() {
        let debug = format!("{:?}", checkpoint_with_requests(MAX_DEBUG_SIGN_IDS + 1));
        assert!(!debug.contains("SignId("), "{debug}");
        assert!(
            debug.contains(&format!(
                "pending_request_count: {}",
                MAX_DEBUG_SIGN_IDS + 1
            )),
            "{debug}"
        );
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
            Ok(Confirmation::PromotedPending)
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
            Ok(Confirmation::PromotedPending)
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
            Ok(Confirmation::NotFound)
        ));
        assert_eq!(checkpoints.count(checkpoint.chain), 1);
        assert_eq!(
            checkpoints.latest(checkpoint.chain).await.unwrap(),
            Some(checkpoint)
        );
    }

    // The checkpoint metric is process-global. These tests use a chain no other
    // test observes so the metric assertion is deterministic under parallel runs.
    fn pending_checkpoint_metric(chain: Chain) -> i64 {
        crate::metrics::requests::PENDING_CHECKPOINTS
            .with_label_values(&[chain.as_str()])
            .get()
    }

    #[tokio::test]
    async fn reset_pending_count_zeroes_counter_and_metric() {
        let chain = Chain::Tron;
        let checkpoints = Checkpoints::new(CheckpointStorage::in_memory());
        checkpoints
            .persist_pending(&Checkpoint::reset(chain, 1))
            .await
            .unwrap();
        checkpoints
            .persist_pending(&Checkpoint::reset(chain, 2))
            .await
            .unwrap();
        assert_eq!(checkpoints.count(chain), 2);

        checkpoints.reset_pending_count(chain);

        assert_eq!(checkpoints.count(chain), 0);
        assert_eq!(pending_checkpoint_metric(chain), 0);
    }

    #[tokio::test]
    async fn reset_pending_count_leaves_durable_pending_findable() {
        let chain = Chain::Tron;
        let storage = CheckpointStorage::in_memory();
        let confirmed = Checkpoint::reset(chain, 2);
        let stale_pending = Checkpoint::reset(chain, 1);
        let checkpoints = Checkpoints::new(storage.clone());
        storage.persist(&confirmed).await.unwrap();
        checkpoints.persist_pending(&stale_pending).await.unwrap();
        assert_eq!(checkpoints.count(chain), 1);

        checkpoints.reset_pending_count(chain);

        assert_eq!(checkpoints.count(chain), 0);
        assert_eq!(pending_checkpoint_metric(chain), 0);
        // The reset is purely local: durable bodies remain servable by digest.
        assert_eq!(
            checkpoints.find(chain, confirmed.digest()).await,
            Some(confirmed)
        );
        assert_eq!(
            checkpoints.find(chain, stale_pending.digest()).await,
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
            Ok(Confirmation::PromotedPending)
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
            .promote(checkpoint.chain, checkpoint.digest())
            .await
            .unwrap();

        assert!(matches!(
            checkpoints
                .confirm(checkpoint.chain, checkpoint.digest())
                .await,
            Ok(Confirmation::AlreadyConfirmed)
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

        // A fresh `Checkpoints` has an empty local counter; the durable pending
        // body must still be findable.
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
            Ok(Confirmation::PromotedPending)
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
