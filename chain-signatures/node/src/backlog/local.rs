//! This node's progress on its requests, kept in storage so a restart neither repeats nor loses
//! it (doc/checkpoints.md, Section 2).

use super::{Backlog, BacklogEntry, BacklogError, CheckpointError};
use crate::sign_bidirectional::SignStatus;
use mpc_primitives::{Chain, SignId};
use std::collections::HashMap;

/// This node's progress on a request that has to survive a restart: a signature it issued, or
/// an outcome it found.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalRecord {
    pub status: SignStatus,
    /// The source chain height processed when it was written.
    pub at: u64,
}

impl Backlog {
    /// This node's records; a failed load fails the recovery, since recovering without them
    /// would sign again what this node already signed.
    pub(super) async fn load_local(
        &self,
        chain: Chain,
    ) -> Result<HashMap<SignId, LocalRecord>, CheckpointError> {
        self.checkpoints
            .storage()
            .load_local(chain)
            .await
            .map_err(|source| CheckpointError::Storage { chain, source })
    }

    /// Store `status` as this node's progress on `id`, then take it: a status that cannot be
    /// stored is not taken, since a restart would act on the old one.
    pub(crate) async fn set_local_status(
        &self,
        chain: Chain,
        id: SignId,
        status: SignStatus,
    ) -> Result<(), BacklogError> {
        let previous = self
            .entry(chain, &id)
            .await
            .ok_or(BacklogError::NotFound { chain, id })?
            .status;
        self.replace_local_status(chain, id, &previous, status)
            .await
    }

    /// Take `status` if the entry still holds `previous`. The check and the store happen under
    /// the backlog lock, so a status that loses to a concurrent change is never stored.
    pub(super) async fn replace_local_status(
        &self,
        chain: Chain,
        id: SignId,
        previous: &SignStatus,
        status: SignStatus,
    ) -> Result<(), BacklogError> {
        let mut pending = self.pending(&chain).write().await;
        let at = pending.record_height();
        let current = pending
            .requests
            .get_mut(&id)
            .filter(|current| current.status == *previous)
            .ok_or(BacklogError::Superseded { chain, id })?;
        let mut entry = current.clone();
        entry.status = status;
        self.put_local(chain, &entry, at).await?;
        current.status = entry.status;
        Ok(())
    }

    /// Store this node's progress on `entry`, written at height `at`.
    async fn put_local(
        &self,
        chain: Chain,
        entry: &BacklogEntry,
        at: u64,
    ) -> Result<(), BacklogError> {
        let record = entry.local_record(at);
        self.checkpoints
            .storage()
            .put_local(chain, entry.sign_id(), &record)
            .await
            .map_err(|err| BacklogError::Storage {
                chain,
                id: entry.sign_id(),
                reason: format!("{err:#}"),
            })
    }

    pub(super) async fn forget_local(&self, chain: Chain, ids: &[SignId]) {
        if let Err(err) = self.checkpoints.storage().remove_local(chain, ids).await {
            tracing::error!(?chain, ?err, "failed to remove local records");
        }
    }
}

impl BacklogEntry {
    fn local_record(&self, at: u64) -> LocalRecord {
        LocalRecord {
            status: self.status.clone(),
            at,
        }
    }
}
