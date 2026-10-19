//! The intent builder's funding wallet snapshot, kept outside the child so a respawned
//! or restarted builder resumes indexing instead of replaying the chain. The snapshot is
//! opaque here and holds no secret key; losing it only costs one full wallet sync.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;

/// Where a node keeps its builder's latest wallet snapshot across restarts.
#[async_trait]
pub trait WalletSnapshotStore: Send + Sync {
    async fn load(&self) -> anyhow::Result<Option<String>>;
    async fn save(&self, snapshot: &str) -> anyhow::Result<()>;
}

/// The least time between two kept snapshots. A restored wallet replays only what came
/// after its snapshot, so a busy node replays minutes of chain; an idle one takes none and
/// replays from its last settled publish.
pub(crate) const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The latest snapshot in memory, which outlives any one child, and in the store, which
/// outlives the node process.
pub(crate) struct Snapshots {
    store: Option<Arc<dyn WalletSnapshotStore>>,
    latest: Mutex<Option<Arc<str>>>,
    kept_at: Mutex<Option<Instant>>,
}

/// Never panics on a poisoned lock: nothing inside these locks can panic.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Snapshots {
    /// Starts from the stored snapshot, or from none when the store has none or fails.
    pub(crate) async fn load(store: Option<Arc<dyn WalletSnapshotStore>>) -> Self {
        let latest = match &store {
            Some(store) => match store.load().await {
                Ok(snapshot) => snapshot.map(Arc::from),
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "midnight wallet snapshot unavailable; the builder syncs from the start"
                    );
                    None
                }
            },
            None => None,
        };
        Self {
            store,
            latest: Mutex::new(latest),
            kept_at: Mutex::new(None),
        }
    }

    pub(crate) fn latest(&self) -> Option<Arc<str>> {
        locked(&self.latest).clone()
    }

    pub(crate) fn due(&self) -> bool {
        locked(&self.kept_at).is_none_or(|kept| kept.elapsed() >= SNAPSHOT_INTERVAL)
    }

    /// Kept in memory even when the store refuses it: the next respawn still resumes.
    pub(crate) async fn keep(&self, snapshot: String) {
        *locked(&self.latest) = Some(Arc::from(snapshot.as_str()));
        *locked(&self.kept_at) = Some(Instant::now());
        if let Some(store) = &self.store {
            if let Err(error) = store.save(&snapshot).await {
                tracing::warn!(?error, "failed to store the midnight wallet snapshot");
            }
        }
    }
}
