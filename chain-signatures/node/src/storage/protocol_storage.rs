use crate::metrics::node_account_id;
use cait_sith::protocol::Participant;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, ToRedisArgs};
use std::collections::HashSet;
use std::sync::Arc;
use std::{fmt, time::Instant};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing;

use super::{owner_key, STORAGE_VERSION};

/// Trait for protocol artifacts that can be stored in Redis.
pub trait ProtocolArtifact:
    ToRedisArgs + FromRedisValue + fmt::Debug + Send + Sync + 'static
{
    const METRIC_LABEL: &'static str;
    type Id: Copy
        + Eq
        + std::hash::Hash
        + ToRedisArgs
        + FromRedisValue
        + fmt::Display
        + fmt::Debug
        + Send
        + Sync
        + tracing::Value
        + 'static;

    fn id(&self) -> Self::Id;
}

/// A pre-reserved slot for an artifact that will eventually be inserted.
pub struct ArtifactSlot<A: ProtocolArtifact> {
    id: A::Id,
    storage: ProtocolStorage<A>,
    stored: bool,
}

impl<A: ProtocolArtifact> ArtifactSlot<A> {
    pub async fn insert(&mut self, artifact: A, owner: Participant) -> bool {
        self.stored = self.storage.insert(artifact, owner).await;
        self.stored
    }

    pub fn unreserve(&self) -> Option<JoinHandle<()>> {
        if self.stored {
            return None;
        }

        let storage = self.storage.clone();
        let id = self.id;
        let task = tokio::spawn(async move {
            tracing::info!(id, "unreserving artifact");
            storage.unreserve(id).await;
        });
        Some(task)
    }
}

impl<A: ProtocolArtifact> Drop for ArtifactSlot<A> {
    fn drop(&mut self) {
        self.unreserve();
    }
}

pub struct ArtifactTaken<A: ProtocolArtifact> {
    pub artifact: A,
    storage: ArtifactTakenDropper<A>,
}

pub struct ArtifactTakenDropper<A: ProtocolArtifact> {
    pub id: A::Id,
    pub(crate) dropper: Option<ProtocolStorage<A>>,
}

impl<A: ProtocolArtifact> Drop for ArtifactTakenDropper<A> {
    fn drop(&mut self) {
        if let Some(storage) = self.dropper.take() {
            let id = self.id;
            tokio::spawn(async move {
                storage.unreserve(id).await;
            });
        }
    }
}

impl<A: ProtocolArtifact> ArtifactTaken<A> {
    pub(crate) fn new(artifact: A, storage: ProtocolStorage<A>) -> Self {
        Self {
            storage: ArtifactTakenDropper {
                id: artifact.id(),
                dropper: Some(storage),
            },
            artifact,
        }
    }

    pub fn take(self) -> (A, ArtifactTakenDropper<A>) {
        (self.artifact, self.storage)
    }
}

#[derive(Debug)]
pub struct ProtocolStorage<A: ProtocolArtifact> {
    redis_pool: Pool,
    artifact_key: String,
    used: Arc<RwLock<HashSet<A::Id>>>,
    reserved: Arc<RwLock<HashSet<A::Id>>>,
    owner_keys: String,
    account_id: AccountId,
    _phantom: std::marker::PhantomData<A>,
}

impl<A: ProtocolArtifact> Clone for ProtocolStorage<A> {
    fn clone(&self) -> Self {
        Self {
            redis_pool: self.redis_pool.clone(),
            artifact_key: self.artifact_key.clone(),
            used: self.used.clone(),
            reserved: self.reserved.clone(),
            owner_keys: self.owner_keys.clone(),
            account_id: self.account_id.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<A: ProtocolArtifact> ProtocolStorage<A> {
    pub fn new(pool: &Pool, account_id: &AccountId, base_prefix: &str) -> Self {
        let artifact_key = format!("{base_prefix}:{STORAGE_VERSION}:{account_id}");
        let used = Arc::new(RwLock::new(HashSet::new()));
        let reserved = Arc::new(RwLock::new(HashSet::new()));
        let owner_keys = format!("{base_prefix}_owners:{STORAGE_VERSION}:{account_id}");

        Self {
            redis_pool: pool.clone(),
            artifact_key,
            used,
            reserved,
            owner_keys,
            account_id: account_id.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<A: ProtocolArtifact> ProtocolStorage<A> {
    async fn connect(&self) -> Option<Connection> {
        self.redis_pool
            .get()
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to connect to redis");
            })
            .ok()
    }

    pub async fn fetch_owned(&self, me: Participant) -> Vec<A::Id> {
        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };

        // fetch owner set from redis and union with in-memory reservations
        let owned: HashSet<A::Id> = conn
            .smembers(owner_key(&self.owner_keys, me))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to fetch my owned artifacts");
            })
            .unwrap_or_default();

        owned.union(&*self.reserved.read().await).copied().collect()
    }

    pub async fn reserve(&self, id: A::Id) -> Option<ArtifactSlot<A>> {
        let used = self.used.read().await;
        if used.contains(&id) {
            return None;
        }
        if !self.reserved.write().await.insert(id) {
            return None;
        }
        drop(used);

        let start = Instant::now();
        let Some(mut conn) = self.connect().await else {
            self.reserved.write().await.remove(&id);
            return None;
        };

        // Check directly whether the artifact is already stored in Redis.
        let artifact_exists: Result<bool, _> = conn.hexists(&self.artifact_key, id).await;
        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "reserve", node_account_id()])
            .observe(elapsed.as_millis() as f64);

        match artifact_exists {
            Ok(true) => {
                // artifact already stored, reserve cannot be done, remove reservation
                self.reserved.write().await.remove(&id);
                None
            }
            // artifact does not exist, reservation successful
            Ok(false) => Some(ArtifactSlot {
                id,
                storage: self.clone(),
                stored: false,
            }),
            Err(err) => {
                self.reserved.write().await.remove(&id);
                tracing::warn!(id, ?err, ?elapsed, "failed to reserve artifact");
                None
            }
        }
    }

    async fn unreserve(&self, id: A::Id) -> bool {
        self.reserved.write().await.remove(&id)
    }

    pub async fn remove_outdated(&self, owner: Participant, owner_shares: &[A::Id]) -> Vec<A::Id> {
        const SCRIPT: &str = r#"
            local artifact_key = KEYS[1]
            local owner_key = KEYS[2]

            -- convert the list of ids to a table for easy lookup
            local owner_shares = {}
            for _, value in ipairs(ARGV) do
                owner_shares[value] = true
            end

            -- find all shares that the owner no longer tracks
            local outdated = {}
            local our_shares = redis.call("SMEMBERS", owner_key)
            for _, id in ipairs(our_shares) do
                if not owner_shares[id] then
                    table.insert(outdated, id)
                end

                -- remove the outdated shares from our node if we have too many
                -- already to be able to process them in one go.
                if #outdated >= 4096 then
                    redis.call("SREM", owner_key, unpack(outdated))
                    redis.call("HDEL", artifact_key, unpack(outdated))
                    -- clear the outdated list for the next batch
                    outdated = {}
                end
            end

            -- remove the remaining outdated shares from our node
            if #outdated > 0 then
                redis.call("SREM", owner_key, unpack(outdated))
                redis.call("HDEL", artifact_key, unpack(outdated))
            end

            return outdated
        "#;

        let start = Instant::now();
        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };
        let result: Result<Vec<A::Id>, _> = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(owner_key(&self.owner_keys, owner))
            // NOTE: this encodes each entry of owner_shares as a separate ARGV[index] entry.
            .arg(owner_shares)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "remove_outdated", node_account_id()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(outdated) => {
                if !outdated.is_empty() {
                    tracing::info!(?outdated, ?elapsed, "removed outdated artifacts");
                    // remove outdated entries from our in-memory reserved set
                    let mut reserved = self.reserved.write().await;
                    for id in outdated.iter() {
                        reserved.remove(id);
                    }
                    drop(reserved);
                    // remove outdated entries from our in-memory used set
                    let mut used = self.used.write().await;
                    for id in outdated.iter() {
                        used.remove(id);
                    }
                }
                outdated
            }
            Err(err) => {
                tracing::warn!(?err, ?elapsed, "failed to remove outdated artifacts");
                Vec::new()
            }
        }
    }

    /// Insert an artifact into the storage. If `mine` is true, the artifact will be
    /// owned by the current node. If `back` is true, the artifact will be marked as unused.
    pub async fn insert(&self, artifact: A, owner: Participant) -> bool {
        const SCRIPT: &str = r#"
            local artifact_key = KEYS[1]
            local owner_keys = KEYS[2]
            local owner_key = KEYS[3]
            local artifact_id = ARGV[1]
            local artifact = ARGV[2]

            redis.call("SADD", owner_key, artifact_id)
            redis.call("SADD", owner_keys, owner_key)
            redis.call("HSET", artifact_key, artifact_id, artifact)
        "#;

        let start = Instant::now();
        let id = artifact.id();
        let used = self.used.read().await;
        if used.contains(&id) {
            tracing::warn!(id, "artifact already marked used");
            return false;
        }

        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to insert artifact: connection failed");
            return false;
        };
        let outcome = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(&self.owner_keys)
            .key(owner_key(&self.owner_keys, owner))
            .arg(id)
            .arg(artifact)
            .invoke_async(&mut conn)
            .await;
        drop(used);

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "insert", node_account_id()])
            .observe(elapsed.as_millis() as f64);

        match outcome {
            Ok(()) => {
                self.reserved.write().await.remove(&id);
                true
            }
            Err(err) => {
                tracing::warn!(id, ?err, ?elapsed, "failed to insert artifact");
                false
            }
        }
    }

    pub async fn contains(&self, id: A::Id) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.artifact_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if artifact is stored");
                false
            }
        }
    }

    pub async fn contains_by_owner(&self, id: A::Id, owner: Participant) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.sismember(owner_key(&self.owner_keys, owner), id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(
                    id,
                    ?owner,
                    ?err,
                    "failed to check if artifact is stored by foreign owner"
                );
                false
            }
        }
    }

    pub async fn contains_used(&self, id: A::Id) -> bool {
        self.used.read().await.contains(&id)
    }

    pub async fn take(&self, id: A::Id, owner: Participant) -> Option<ArtifactTaken<A>> {
        const SCRIPT: &str = r#"
            local artifact_key = KEYS[1]
            local owner_key = KEYS[2]
            local artifact_id = ARGV[1]

            if redis.call("SREM", owner_key, artifact_id) == 0 then
                return {err = "WARN artifact " .. artifact_id .. " is not owned by this owner"}
            end

            local artifact = redis.call("HGET", artifact_key, artifact_id)
            if not artifact then
                return {err = "WARN artifact " .. artifact_id .. " not found"}
            end
            redis.call("HDEL", artifact_key, artifact_id)
            return artifact
        "#;

        let start = Instant::now();
        if !self.used.write().await.insert(id) {
            tracing::warn!(id, "taking artifact that is already used");
            return None;
        }

        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to take artifact: connection failed");
            self.used.write().await.remove(&id);
            return None;
        };
        let result: Result<A, _> = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(owner_key(&self.owner_keys, owner))
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "take", node_account_id()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(artifact) => {
                tracing::info!(id, ?elapsed, "took artifact");
                Some(ArtifactTaken::new(artifact, self.clone()))
            }
            Err(err) => {
                self.used.write().await.remove(&id);
                tracing::warn!(id, ?err, ?elapsed, "failed to take artifact");
                None
            }
        }
    }

    /// Get the number of unspent artifacts that were generated by this node.
    pub async fn len_generated(&self) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.hlen(&self.artifact_key)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of generated artifacts");
            })
            .unwrap_or(0)
    }

    /// Get the number of unspent artifacts by a specific owner.
    pub async fn len_by_owner(&self, owner: Participant) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.scard(owner_key(&self.owner_keys, owner))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of my artifacts");
            })
            .unwrap_or(0)
    }

    /// Return true when there are no generated artifacts left in storage.
    pub async fn is_empty(&self) -> bool {
        self.len_generated().await == 0
    }

    /// Clear all artifact storage, including used, reserved, and owned keys.
    /// Return true if successful, false otherwise.
    pub async fn clear(&self) -> bool {
        const SCRIPT: &str = r#"
            local owner_keys = redis.call("SMEMBERS", KEYS[1])
            local del = {}
            for _, key in ipairs(KEYS) do
                table.insert(del, key)
            end
            for _, key in ipairs(owner_keys) do
                table.insert(del, key)
            end

            redis.call("DEL", unpack(del))
        "#;

        let start = Instant::now();
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        let outcome: Option<()> = redis::Script::new(SCRIPT)
            .key(&self.owner_keys)
            .key(&self.artifact_key)
            .invoke_async(&mut conn)
            .await
            .inspect_err(|err| {
                let elapsed = start.elapsed();
                tracing::warn!(?err, ?elapsed, "failed to clear artifact storage");
            })
            .ok();

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "clear", node_account_id()])
            .observe(elapsed.as_millis() as f64);

        self.reserved.write().await.clear();
        self.used.write().await.clear();

        // if the outcome is None, it means the script failed or there was an error.
        outcome.is_some()
    }

    /// Take one artifact owned by the given participant.
    /// It is very important to NOT reuse the same artifact twice for two different
    /// protocols.
    pub async fn take_mine(&self, me: Participant) -> Option<ArtifactTaken<A>> {
        const SCRIPT: &str = r#"
            local artifact_key = KEYS[1]
            local mine_key = KEYS[2]

            if redis.call("SCARD", mine_key) < 1 then
                return nil
            end

            -- pop one artifact from the self owner set and delete it once successfully fetched
            local id = redis.call("SPOP", mine_key)
            local artifact = redis.call("HGET", artifact_key, id)
            if not artifact then
                return {err = "WARN unexpected, artifact " .. id .. " is missing"}
            end

            -- Delete the artifact from the hash map
            redis.call("HDEL", artifact_key, id)
            -- delete the artifact from our self owner set
            redis.call("SREM", mine_key, id)

            -- Return the artifact as a response
            return artifact
        "#;

        let start = Instant::now();
        let mut conn = self.connect().await?;
        let result: Result<Option<A>, _> = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(owner_key(&self.owner_keys, me))
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "take_mine", node_account_id()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(Some(artifact)) => {
                // mark reserved and used in-memory so that it won't be reserved or reused locally
                let id = artifact.id();
                self.reserved.write().await.insert(id);
                self.used.write().await.insert(id);
                let taken = ArtifactTaken::new(artifact, self.clone());
                tracing::debug!(id, ?elapsed, "took mine artifact");
                Some(taken)
            }
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(?err, ?elapsed, "failed to take mine artifact from storage");
                None
            }
        }
    }

    /// Return a taken artifact back to the available pool.
    pub async fn recycle_mine(&self, me: Participant, taken: ArtifactTaken<A>) -> bool {
        const SCRIPT: &str = r#"
            local artifact_key = KEYS[1]
            local mine_key = KEYS[2]
            local artifact_id = ARGV[1]
            local artifact = ARGV[2]

            -- Add back to artifact hash map
            redis.call("HSET", artifact_key, artifact_id, artifact)

            -- Add back to mine set
            redis.call("SADD", mine_key, artifact_id)

            return 1
        "#;

        let start = Instant::now();
        let (artifact, mut dropper) = taken.take();
        // We manually handle the return, so we don't want the dropper to unreserve it.
        dropper.dropper.take();

        let id = artifact.id();
        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to return artifact: connection failed");
            return false;
        };

        let result: Result<i32, _> = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(owner_key(&self.owner_keys, me))
            .arg(id)
            .arg(artifact)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "return_mine", node_account_id()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(_) => {
                self.reserved.write().await.remove(&id);
                self.used.write().await.remove(&id);
                tracing::info!(id, ?elapsed, "returned mine artifact");
                true
            }
            Err(err) => {
                tracing::warn!(id, ?err, ?elapsed, "failed to return mine artifact");
                false
            }
        }
    }

    /// Check if an artifact is reserved.
    pub async fn contains_reserved(&self, id: A::Id) -> bool {
        self.reserved.read().await.contains(&id)
    }

    pub fn artifact_key(&self) -> &str {
        &self.artifact_key
    }
}
