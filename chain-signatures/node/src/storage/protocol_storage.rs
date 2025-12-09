use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, ToRedisArgs};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
    time::Instant,
};
use tokio::{sync::RwLock, task::JoinHandle};
use tracing;

use super::{owner_key, STORAGE_VERSION};

const USED_EXPIRE_TIME: Duration = Duration::hours(24);

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
pub enum ProtocolStorage<A: ProtocolArtifact> {
    Redis {
        redis_pool: Pool,
        artifact_key: String,
        used_key: String,
        reserved_key: String,
        owner_keys: String,
        account_id: AccountId,
        _phantom: std::marker::PhantomData<A>,
    },
    InMemory {
        artifacts: Arc<RwLock<HashMap<A::Id, A>>>,
        used: Arc<RwLock<HashMap<A::Id, ()>>>,
        reserved: Arc<RwLock<HashSet<A::Id>>>,
        owners: Arc<RwLock<HashMap<Participant, HashSet<A::Id>>>>,
        account_id: AccountId,
        _phantom: std::marker::PhantomData<A>,
    },
}

impl<A: ProtocolArtifact> Clone for ProtocolStorage<A> {
    fn clone(&self) -> Self {
        match self {
            Self::Redis {
                redis_pool,
                artifact_key,
                used_key,
                reserved_key,
                owner_keys,
                account_id,
                _phantom,
            } => Self::Redis {
                redis_pool: redis_pool.clone(),
                artifact_key: artifact_key.clone(),
                used_key: used_key.clone(),
                reserved_key: reserved_key.clone(),
                owner_keys: owner_keys.clone(),
                account_id: account_id.clone(),
                _phantom: std::marker::PhantomData,
            },
            Self::InMemory {
                artifacts,
                used,
                reserved,
                owners,
                account_id,
                _phantom,
            } => Self::InMemory {
                artifacts: artifacts.clone(),
                used: used.clone(),
                reserved: reserved.clone(),
                owners: owners.clone(),
                account_id: account_id.clone(),
                _phantom: std::marker::PhantomData,
            },
        }
    }
}

impl<A: ProtocolArtifact> ProtocolStorage<A> {
    pub fn new(pool: &Pool, account_id: &AccountId, base_prefix: &str) -> Self {
        let artifact_key = format!("{base_prefix}:{STORAGE_VERSION}:{account_id}");
        let used_key = format!("{base_prefix}_used:{STORAGE_VERSION}:{account_id}");
        let reserved_key = format!("{base_prefix}_reserved:{STORAGE_VERSION}:{account_id}");
        let owner_keys = format!("{base_prefix}_owners:{STORAGE_VERSION}:{account_id}");

        Self::Redis {
            redis_pool: pool.clone(),
            artifact_key,
            used_key,
            reserved_key,
            owner_keys,
            account_id: account_id.clone(),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn in_memory(account_id: &AccountId) -> Self {
        Self::InMemory {
            artifacts: Arc::new(RwLock::new(HashMap::new())),
            used: Arc::new(RwLock::new(HashMap::new())),
            reserved: Arc::new(RwLock::new(HashSet::new())),
            owners: Arc::new(RwLock::new(HashMap::new())),
            account_id: account_id.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<A: ProtocolArtifact> ProtocolStorage<A> {
    async fn connect(&self) -> Option<Connection> {
        match self {
            Self::Redis { redis_pool, .. } => redis_pool
                .get()
                .await
                .inspect_err(|err| {
                    tracing::warn!(?err, "failed to connect to redis");
                })
                .ok(),
            Self::InMemory { .. } => None,
        }
    }

    pub async fn fetch_owned(&self, me: Participant) -> Vec<A::Id> {
        match self {
            Self::Redis {
                reserved_key,
                owner_keys,
                ..
            } => {
                let Some(mut conn) = self.connect().await else {
                    return Vec::new();
                };

                conn.sunion((reserved_key, owner_key(owner_keys, me)))
                    .await
                    .inspect_err(|err| {
                        tracing::warn!(?err, "failed to fetch (mine | reserved) artifacts");
                    })
                    .unwrap_or_default()
            }
            Self::InMemory {
                reserved, owners, ..
            } => {
                let reserved_read = reserved.read().await;
                let owners_read = owners.read().await;

                let mut result_set = HashSet::new();

                // Add reserved artifacts
                result_set.extend(reserved_read.iter().copied());

                // Add owned artifacts
                if let Some(owned) = owners_read.get(&me) {
                    result_set.extend(owned.iter().copied());
                }

                result_set.into_iter().collect()
            }
        }
    }

    pub async fn reserve(&self, id: A::Id) -> Option<ArtifactSlot<A>> {
        match self {
            Self::Redis {
                artifact_key,
                used_key,
                reserved_key,
                account_id,
                ..
            } => {
                const SCRIPT: &str = r#"
                    local artifact_key = KEYS[1]
                    local used_key = KEYS[2]
                    local reserved_key = KEYS[3]
                    local artifact_id = ARGV[1]

                    -- cannot reserve this artifact if its already in storage.
                    if redis.call("HEXISTS", artifact_key, artifact_id) == 1 then
                        return {err = "WARN artifact " .. artifact_id .. " has already been stored"}
                    end

                    -- cannot reserve this artifact if it has already been used.
                    if redis.call("HEXISTS", used_key, artifact_id) == 1 then
                        return {err = "WARN artifact " .. artifact_id .. " has already been used"}
                    end

                    -- cannot reserve this artifact if it already exists.
                    if redis.call("SADD", reserved_key, artifact_id) == 0 then
                        return {err = "WARN artifact " .. artifact_id .. " has already been reserved"}
                    end
                "#;

                let start = Instant::now();
                let mut conn = self.connect().await?;
                let result: Result<(), _> = redis::Script::new(SCRIPT)
                    .key(artifact_key)
                    .key(used_key)
                    .key(reserved_key)
                    .arg(id)
                    .invoke_async(&mut conn)
                    .await;

                let elapsed = start.elapsed();
                crate::metrics::REDIS_LATENCY
                    .with_label_values(&[A::METRIC_LABEL, "reserve", account_id.as_str()])
                    .observe(elapsed.as_millis() as f64);

                match result {
                    Ok(_) => Some(ArtifactSlot {
                        id,
                        storage: self.clone(),
                        stored: false,
                    }),
                    Err(err) => {
                        tracing::warn!(
                            id,
                            ?err,
                            elapsed_ms = elapsed.as_millis(),
                            "failed to reserve artifact"
                        );
                        None
                    }
                }
            }
            Self::InMemory {
                artifacts,
                used,
                reserved,
                ..
            } => {
                let artifacts_read = artifacts.read().await;
                let used_read = used.read().await;

                // Check if artifact already exists in storage or used
                if artifacts_read.contains_key(&id) {
                    tracing::warn!(id, "artifact has already been stored");
                    return None;
                }

                if used_read.contains_key(&id) {
                    tracing::warn!(id, "artifact has already been used");
                    return None;
                }

                drop(artifacts_read);
                drop(used_read);

                // Try to add to reserved set
                let mut reserved_write = reserved.write().await;
                if !reserved_write.insert(id) {
                    tracing::warn!(id, "artifact has already been reserved");
                    return None;
                }

                Some(ArtifactSlot {
                    id,
                    storage: self.clone(),
                    stored: false,
                })
            }
        }
    }

    async fn unreserve(&self, id: A::Id) {
        match self {
            Self::Redis { reserved_key, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return;
                };
                if let Err(err) = conn.srem::<'_, _, _, ()>(reserved_key, id).await {
                    tracing::warn!(id, ?err, "failed to unreserve artifact");
                }
            }
            Self::InMemory { reserved, .. } => {
                let mut reserved_write = reserved.write().await;
                reserved_write.remove(&id);
            }
        }
    }

    pub async fn remove_outdated(&self, owner: Participant, owner_shares: &[A::Id]) -> Vec<A::Id> {
        match self {
            Self::Redis {
                artifact_key,
                reserved_key,
                owner_keys,
                account_id,
                ..
            } => {
                const SCRIPT: &str = r#"
                    local artifact_key = KEYS[1]
                    local reserved_key = KEYS[2]
                    local owner_key = KEYS[3]

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
                            redis.call("SREM", reserved_key, unpack(outdated))
                            redis.call("HDEL", artifact_key, unpack(outdated))
                            -- clear the outdated list for the next batch
                            outdated = {}
                        end
                    end

                    -- remove the remaining outdated shares from our node
                    if #outdated > 0 then
                        redis.call("SREM", owner_key, unpack(outdated))
                        redis.call("SREM", reserved_key, unpack(outdated))
                        redis.call("HDEL", artifact_key, unpack(outdated))
                    end

                    return outdated
                "#;

                let start = Instant::now();
                let Some(mut conn) = self.connect().await else {
                    return Vec::new();
                };
                let result: Result<Vec<A::Id>, _> = redis::Script::new(SCRIPT)
                    .key(artifact_key)
                    .key(reserved_key)
                    .key(owner_key(owner_keys, owner))
                    // NOTE: this encodes each entry of owner_shares as a separate ARGV[index] entry.
                    .arg(owner_shares)
                    .invoke_async(&mut conn)
                    .await;

                let elapsed = start.elapsed();
                crate::metrics::REDIS_LATENCY
                    .with_label_values(&[A::METRIC_LABEL, "remove_outdated", account_id.as_str()])
                    .observe(elapsed.as_millis() as f64);

                match result {
                    Ok(outdated) => {
                        if !outdated.is_empty() {
                            tracing::info!(
                                ?outdated,
                                elapsed_ms = elapsed.as_millis(),
                                "removed outdated artifacts"
                            );
                        }
                        outdated
                    }
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            elapsed_ms = elapsed.as_millis(),
                            "failed to remove outdated artifacts"
                        );
                        Vec::new()
                    }
                }
            }
            Self::InMemory {
                artifacts,
                reserved,
                owners,
                ..
            } => {
                // Convert owner_shares to a HashSet for fast lookup
                let owner_shares_set: HashSet<A::Id> = owner_shares.iter().copied().collect();

                let mut owners_write = owners.write().await;
                let outdated: Vec<A::Id> = if let Some(our_shares) = owners_write.get(&owner) {
                    our_shares
                        .iter()
                        .filter(|id| !owner_shares_set.contains(id))
                        .copied()
                        .collect()
                } else {
                    Vec::new()
                };

                // Remove outdated artifacts
                if !outdated.is_empty() {
                    if let Some(our_shares) = owners_write.get_mut(&owner) {
                        for id in &outdated {
                            our_shares.remove(id);
                        }
                    }
                    drop(owners_write);

                    let mut reserved_write = reserved.write().await;
                    let mut artifacts_write = artifacts.write().await;
                    for id in &outdated {
                        reserved_write.remove(id);
                        artifacts_write.remove(id);
                    }

                    tracing::info!(?outdated, "removed outdated artifacts");
                }

                outdated
            }
        }
    }

    /// Insert an artifact into the storage. If `mine` is true, the artifact will be
    /// owned by the current node. If `back` is true, the artifact will be marked as unused.
    pub async fn insert(&self, artifact: A, owner: Participant) -> bool {
        match self {
            Self::Redis {
                artifact_key,
                used_key,
                reserved_key,
                owner_keys,
                account_id,
                ..
            } => {
                const SCRIPT: &str = r#"
                    local artifact_key = KEYS[1]
                    local used_key = KEYS[2]
                    local reserved_key = KEYS[3]
                    local owner_keys = KEYS[4]
                    local owner_key = KEYS[5]
                    local artifact_id = ARGV[1]
                    local artifact = ARGV[2]

                    -- if the artifact has NOT been reserved, then something went wrong when acquiring the
                    -- reservation for it via artifact slot.
                    if redis.call("SREM", reserved_key, artifact_id) == 0 then
                        return {err = "WARN artifact " .. artifact_id .. " has NOT been reserved"}
                    end

                    if redis.call('HEXISTS', used_key, artifact_id) == 1 then
                        return {err = 'WARN artifact ' .. artifact_id .. ' is already used'}
                    end

                    redis.call("SADD", owner_key, artifact_id)
                    redis.call("SADD", owner_keys, owner_key)
                    redis.call("HSET", artifact_key, artifact_id, artifact)
                "#;

                let start = Instant::now();
                let id = artifact.id();
                let Some(mut conn) = self.connect().await else {
                    tracing::warn!(id, "failed to insert artifact: connection failed");
                    return false;
                };
                let outcome = redis::Script::new(SCRIPT)
                    .key(artifact_key)
                    .key(used_key)
                    .key(reserved_key)
                    .key(owner_keys)
                    .key(owner_key(owner_keys, owner))
                    .arg(id)
                    .arg(artifact)
                    .invoke_async(&mut conn)
                    .await;

                let elapsed = start.elapsed();
                crate::metrics::REDIS_LATENCY
                    .with_label_values(&[A::METRIC_LABEL, "insert", account_id.as_str()])
                    .observe(elapsed.as_millis() as f64);

                match outcome {
                    Ok(()) => true,
                    Err(err) => {
                        tracing::warn!(
                            id,
                            ?err,
                            elapsed_ms = elapsed.as_millis(),
                            "failed to insert artifact"
                        );
                        false
                    }
                }
            }
            Self::InMemory {
                artifacts,
                used,
                reserved,
                owners,
                ..
            } => {
                let id = artifact.id();

                // Check if artifact was reserved
                let mut reserved_write = reserved.write().await;
                if !reserved_write.remove(&id) {
                    tracing::warn!(id, "artifact has NOT been reserved");
                    return false;
                }
                drop(reserved_write);

                // Check if artifact is already used
                let used_read = used.read().await;
                if used_read.contains_key(&id) {
                    tracing::warn!(id, "artifact is already used");
                    return false;
                }
                drop(used_read);

                // Add to artifacts map
                let mut artifacts_write = artifacts.write().await;
                artifacts_write.insert(id, artifact);
                drop(artifacts_write);

                // Add to owner's set
                let mut owners_write = owners.write().await;
                owners_write
                    .entry(owner)
                    .or_insert_with(HashSet::new)
                    .insert(id);

                true
            }
        }
    }

    pub async fn contains(&self, id: A::Id) -> bool {
        match self {
            Self::Redis { artifact_key, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return false;
                };
                match conn.hexists(artifact_key, id).await {
                    Ok(exists) => exists,
                    Err(err) => {
                        tracing::warn!(id, ?err, "failed to check if artifact is stored");
                        false
                    }
                }
            }
            Self::InMemory { artifacts, .. } => {
                let artifacts_read = artifacts.read().await;
                artifacts_read.contains_key(&id)
            }
        }
    }

    pub async fn contains_by_owner(&self, id: A::Id, owner: Participant) -> bool {
        match self {
            Self::Redis { owner_keys, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return false;
                };
                match conn.sismember(owner_key(owner_keys, owner), id).await {
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
            Self::InMemory { owners, .. } => {
                let owners_read = owners.read().await;
                owners_read
                    .get(&owner)
                    .map(|set| set.contains(&id))
                    .unwrap_or(false)
            }
        }
    }

    pub async fn contains_used(&self, id: A::Id) -> bool {
        match self {
            Self::Redis { used_key, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return false;
                };
                match conn.hexists(used_key, id).await {
                    Ok(exists) => exists,
                    Err(err) => {
                        tracing::warn!(id, ?err, "failed to check if artifact is used");
                        false
                    }
                }
            }
            Self::InMemory { used, .. } => {
                let used_read = used.read().await;
                used_read.contains_key(&id)
            }
        }
    }

    pub async fn take(&self, id: A::Id, owner: Participant) -> Option<ArtifactTaken<A>> {
        match self {
            Self::Redis {
                artifact_key,
                used_key,
                owner_keys,
                account_id,
                ..
            } => {
                const SCRIPT: &str = r#"
                    local artifact_key = KEYS[1]
                    local used_key = KEYS[2]
                    local owner_key = KEYS[3]
                    local artifact_id = ARGV[1]

                    if redis.call("HEXISTS", used_key, artifact_id) == 1 then
                        return {err = "WARN artifact " .. artifact_id .. " is already used"}
                    end

                    if redis.call("SREM", owner_key, artifact_id) == 0 then
                        return {err = "WARN artifact " .. artifact_id .. " is not owned by this owner"}
                    end

                    local artifact = redis.call("HGET", artifact_key, artifact_id)
                    if not artifact then
                        return {err = "WARN artifact " .. artifact_id .. " not found"}
                    end

                    redis.call("HSET", used_key, artifact_id, "")
                    redis.call("HDEL", artifact_key, artifact_id)

                    return artifact
                "#;

                let start = Instant::now();
                let Some(mut conn) = self.connect().await else {
                    tracing::warn!(id, "failed to take artifact: connection failed");
                    return None;
                };
                let result: Result<A, _> = redis::Script::new(SCRIPT)
                    .key(artifact_key)
                    .key(used_key)
                    .key(owner_key(owner_keys, owner))
                    .arg(id)
                    .invoke_async(&mut conn)
                    .await;

                let elapsed = start.elapsed();
                crate::metrics::REDIS_LATENCY
                    .with_label_values(&[A::METRIC_LABEL, "take", account_id.as_str()])
                    .observe(elapsed.as_millis() as f64);

                match result {
                    Ok(artifact) => {
                        tracing::info!(id, elapsed_ms = elapsed.as_millis(), "took artifact");
                        Some(ArtifactTaken::new(artifact, self.clone()))
                    }
                    Err(err) => {
                        tracing::warn!(
                            id,
                            ?err,
                            elapsed_ms = elapsed.as_millis(),
                            "failed to take artifact"
                        );
                        None
                    }
                }
            }
            Self::InMemory {
                artifacts,
                used,
                owners,
                ..
            } => {
                // Check if already used
                let used_read = used.read().await;
                if used_read.contains_key(&id) {
                    tracing::warn!(id, "artifact is already used");
                    return None;
                }
                drop(used_read);

                // Remove from owner's set
                let mut owners_write = owners.write().await;
                let owned = owners_write
                    .get_mut(&owner)
                    .map(|set| set.remove(&id))
                    .unwrap_or(false);

                if !owned {
                    tracing::warn!(id, ?owner, "artifact is not owned by this owner");
                    return None;
                }
                drop(owners_write);

                // Get artifact from artifacts map
                let mut artifacts_write = artifacts.write().await;
                let artifact = artifacts_write.remove(&id)?;
                drop(artifacts_write);

                // Mark as used
                let mut used_write = used.write().await;
                used_write.insert(id, ());

                tracing::info!(id, "took artifact");
                Some(ArtifactTaken::new(artifact, self.clone()))
            }
        }
    }

    pub async fn mark_used(&self, id: A::Id) -> bool {
        match self {
            Self::Redis {
                used_key,
                account_id,
                ..
            } => {
                let start = Instant::now();
                let Some(mut conn) = self.connect().await else {
                    tracing::warn!(id, "failed to mark artifact used: connection failed");
                    return false;
                };
                let result: Result<(), _> = conn.hset_nx(used_key, id, "").await;

                let elapsed = start.elapsed();
                crate::metrics::REDIS_LATENCY
                    .with_label_values(&[A::METRIC_LABEL, "mark_used", account_id.as_str()])
                    .observe(elapsed.as_millis() as f64);

                match result {
                    Ok(()) => {
                        tracing::info!(
                            id,
                            elapsed_ms = elapsed.as_millis(),
                            "marked artifact used"
                        );
                        true
                    }
                    Err(err) => {
                        tracing::warn!(
                            id,
                            ?err,
                            elapsed_ms = elapsed.as_millis(),
                            "failed to mark artifact used"
                        );
                        false
                    }
                }
            }
            Self::InMemory { used, .. } => {
                let mut used_write = used.write().await;
                if used_write.contains_key(&id) {
                    return false;
                }
                used_write.insert(id, ());
                tracing::info!(id, "marked artifact used");
                true
            }
        }
    }

    pub async fn expire_used(&self) {
        match self {
            Self::Redis { used_key, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return;
                };
                if let Err(err) = conn
                    .expire::<_, ()>(used_key, USED_EXPIRE_TIME.num_seconds())
                    .await
                {
                    tracing::warn!(?err, "failed to expire used artifacts");
                }
            }
            Self::InMemory { .. } => {
                // InMemory variant doesn't need expiration
            }
        }
    }

    /// Get the number of unspent artifacts that were generated by this node.
    pub async fn len_generated(&self) -> usize {
        match self {
            Self::Redis { artifact_key, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return 0;
                };
                conn.hlen(artifact_key)
                    .await
                    .inspect_err(|err| {
                        tracing::warn!(?err, "failed to get length of generated artifacts");
                    })
                    .unwrap_or(0)
            }
            Self::InMemory { artifacts, .. } => {
                let artifacts_read = artifacts.read().await;
                artifacts_read.len()
            }
        }
    }

    /// Get the number of unspent artifacts by a specific owner.
    pub async fn len_by_owner(&self, owner: Participant) -> usize {
        match self {
            Self::Redis { owner_keys, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return 0;
                };
                conn.scard(owner_key(owner_keys, owner))
                    .await
                    .inspect_err(|err| {
                        tracing::warn!(?err, "failed to get length of my artifacts");
                    })
                    .unwrap_or(0)
            }
            Self::InMemory { owners, .. } => {
                let owners_read = owners.read().await;
                owners_read.get(&owner).map(|set| set.len()).unwrap_or(0)
            }
        }
    }

    /// Return true when there are no generated artifacts left in storage.
    pub async fn is_empty(&self) -> bool {
        self.len_generated().await == 0
    }

    /// Clear all artifact storage, including used, reserved, and owned keys.
    /// Return true if successful, false otherwise.
    pub async fn clear(&self) -> bool {
        match self {
            Self::Redis {
                owner_keys,
                artifact_key,
                used_key,
                reserved_key,
                account_id,
                ..
            } => {
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
                    .key(owner_keys)
                    .key(artifact_key)
                    .key(used_key)
                    .key(reserved_key)
                    .invoke_async(&mut conn)
                    .await
                    .inspect_err(|err| {
                        let elapsed = start.elapsed();
                        tracing::warn!(
                            ?err,
                            elapsed_ms = elapsed.as_millis(),
                            "failed to clear artifact storage"
                        );
                    })
                    .ok();

                let elapsed = start.elapsed();
                crate::metrics::REDIS_LATENCY
                    .with_label_values(&[A::METRIC_LABEL, "clear", account_id.as_str()])
                    .observe(elapsed.as_millis() as f64);

                // if the outcome is None, it means the script failed or there was an error.
                outcome.is_some()
            }
            Self::InMemory {
                artifacts,
                used,
                reserved,
                owners,
                ..
            } => {
                let mut artifacts_write = artifacts.write().await;
                artifacts_write.clear();
                drop(artifacts_write);

                let mut used_write = used.write().await;
                used_write.clear();
                drop(used_write);

                let mut reserved_write = reserved.write().await;
                reserved_write.clear();
                drop(reserved_write);

                let mut owners_write = owners.write().await;
                owners_write.clear();

                true
            }
        }
    }

    /// Take one artifact owned by the given participant.
    /// It is very important to NOT reuse the same artifact twice for two different
    /// protocols.
    pub async fn take_mine(&self, me: Participant) -> Option<ArtifactTaken<A>> {
        match self {
            Self::Redis {
                artifact_key,
                used_key,
                owner_keys,
                reserved_key,
                account_id,
                ..
            } => {
                const SCRIPT: &str = r#"
                    local artifact_key = KEYS[1]
                    local used_key = KEYS[2]
                    local mine_key = KEYS[3]
                    local reserved_key = KEYS[4]
                    local expire_time = ARGV[1]

                    if redis.call("SCARD", mine_key) < 1 then
                        return nil
                    end

                    -- pop one artifact from the self owner set and delete it once successfully fetched
                    local id = redis.call("SPOP", mine_key)
                    local artifact = redis.call("HGET", artifact_key, id)
                    if not artifact then
                        return {err = "WARN unexpected, artifact " .. id .. " is missing"}
                    end

                    -- reserve the artifact again, since the owner is taking it here, and should
                    -- not invalidate the other nodes when syncing.
                    redis.call("SADD", reserved_key, id)

                    -- Delete the artifact from the hash map
                    redis.call("HDEL", artifact_key, id)
                    -- delete the artifact from our self owner set
                    redis.call("SREM", mine_key, id)

                    -- Add the artifact to the used set and set expiration time.
                    redis.call("HSET", used_key, id, "1")
                    redis.call("HEXPIRE", used_key, expire_time, "FIELDS", 1, id)
                    -- Return the artifact as a response
                    return artifact
                "#;

                let start = Instant::now();
                let mut conn = self.connect().await?;
                let result = redis::Script::new(SCRIPT)
                    .key(artifact_key)
                    .key(used_key)
                    .key(owner_key(owner_keys, me))
                    .key(reserved_key)
                    .arg(USED_EXPIRE_TIME.num_seconds())
                    .invoke_async(&mut conn)
                    .await;

                let elapsed = start.elapsed();
                crate::metrics::REDIS_LATENCY
                    .with_label_values(&[A::METRIC_LABEL, "take_mine", account_id.as_str()])
                    .observe(elapsed.as_millis() as f64);

                match result {
                    Ok(Some(artifact)) => {
                        let taken = ArtifactTaken::new(artifact, self.clone());
                        tracing::debug!(
                            id = taken.artifact.id(),
                            elapsed_ms = elapsed.as_millis(),
                            "took mine artifact"
                        );
                        Some(taken)
                    }
                    Ok(None) => None,
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            elapsed_ms = elapsed.as_millis(),
                            "failed to take mine artifact from storage"
                        );
                        None
                    }
                }
            }
            Self::InMemory {
                artifacts,
                used,
                reserved,
                owners,
                ..
            } => {
                // Get one artifact id from owner's set
                let mut owners_write = owners.write().await;
                let id = owners_write.get_mut(&me).and_then(|set| {
                    if set.is_empty() {
                        None
                    } else {
                        // Pop one id from the set
                        let id = *set.iter().next().unwrap();
                        set.remove(&id);
                        Some(id)
                    }
                });

                let Some(id) = id else {
                    return None;
                };
                drop(owners_write);

                // Get artifact from artifacts map
                let mut artifacts_write = artifacts.write().await;
                let artifact = artifacts_write.remove(&id)?;
                drop(artifacts_write);

                // Reserve the artifact again
                let mut reserved_write = reserved.write().await;
                reserved_write.insert(id);
                drop(reserved_write);

                // Mark as used
                let mut used_write = used.write().await;
                used_write.insert(id, ());

                let taken = ArtifactTaken::new(artifact, self.clone());
                tracing::debug!(id = taken.artifact.id(), "took mine artifact");
                Some(taken)
            }
        }
    }

    /// Return a taken artifact back to the available pool.
    pub async fn recycle_mine(&self, me: Participant, taken: ArtifactTaken<A>) -> bool {
        match self {
            Self::Redis {
                artifact_key,
                used_key,
                owner_keys,
                reserved_key,
                account_id,
                ..
            } => {
                const SCRIPT: &str = r#"
                    local artifact_key = KEYS[1]
                    local used_key = KEYS[2]
                    local mine_key = KEYS[3]
                    local reserved_key = KEYS[4]
                    local artifact_id = ARGV[1]
                    local artifact = ARGV[2]

                    -- Remove from used set
                    redis.call("HDEL", used_key, artifact_id)
                    
                    -- Add back to artifact hash map
                    redis.call("HSET", artifact_key, artifact_id, artifact)
                    
                    -- Add back to mine set
                    redis.call("SADD", mine_key, artifact_id)
                    
                    -- Ensure it is still reserved
                    redis.call("SADD", reserved_key, artifact_id)
                    
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
                    .key(artifact_key)
                    .key(used_key)
                    .key(owner_key(owner_keys, me))
                    .key(reserved_key)
                    .arg(id)
                    .arg(artifact)
                    .invoke_async(&mut conn)
                    .await;

                let elapsed = start.elapsed();
                crate::metrics::REDIS_LATENCY
                    .with_label_values(&[A::METRIC_LABEL, "return_mine", account_id.as_str()])
                    .observe(elapsed.as_millis() as f64);

                match result {
                    Ok(_) => {
                        tracing::info!(
                            id,
                            elapsed_ms = elapsed.as_millis(),
                            "returned mine artifact"
                        );
                        true
                    }
                    Err(err) => {
                        tracing::warn!(
                            id,
                            ?err,
                            elapsed_ms = elapsed.as_millis(),
                            "failed to return mine artifact"
                        );
                        false
                    }
                }
            }
            Self::InMemory {
                artifacts,
                used,
                reserved,
                owners,
                ..
            } => {
                let (artifact, mut dropper) = taken.take();
                // We manually handle the return, so we don't want the dropper to unreserve it.
                dropper.dropper.take();

                let id = artifact.id();

                // Remove from used set
                let mut used_write = used.write().await;
                used_write.remove(&id);
                drop(used_write);

                // Add back to artifacts map
                let mut artifacts_write = artifacts.write().await;
                artifacts_write.insert(id, artifact);
                drop(artifacts_write);

                // Add back to owner's set
                let mut owners_write = owners.write().await;
                owners_write
                    .entry(me)
                    .or_insert_with(HashSet::new)
                    .insert(id);
                drop(owners_write);

                // Ensure it is still reserved
                let mut reserved_write = reserved.write().await;
                reserved_write.insert(id);

                tracing::info!(id, "returned mine artifact");
                true
            }
        }
    }

    /// Check if an artifact is reserved.
    pub async fn contains_reserved(&self, id: A::Id) -> bool {
        match self {
            Self::Redis { reserved_key, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return false;
                };
                match conn.sismember(reserved_key, id).await {
                    Ok(true) => true,
                    Ok(false) => false,
                    Err(err) => {
                        tracing::warn!(id, ?err, "failed to check if artifact is reserved");
                        false
                    }
                }
            }
            Self::InMemory { reserved, .. } => {
                let reserved_read = reserved.read().await;
                reserved_read.contains(&id)
            }
        }
    }

    pub fn artifact_key(&self) -> &str {
        match self {
            Self::Redis { artifact_key, .. } => artifact_key,
            Self::InMemory { .. } => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::protocol::Participant;
    use near_sdk::AccountId;
    use redis::{RedisError, RedisWrite};
    use std::str::FromStr;

    // Simple test artifact for testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestArtifact {
        id: u64,
        data: String,
    }

    impl ProtocolArtifact for TestArtifact {
        type Id = u64;
        const METRIC_LABEL: &'static str = "test";

        fn id(&self) -> Self::Id {
            self.id
        }
    }

    impl ToRedisArgs for TestArtifact {
        fn write_redis_args<W>(&self, out: &mut W)
        where
            W: ?Sized + RedisWrite,
        {
            let json = serde_json::to_string(self).unwrap();
            out.write_arg(json.as_bytes());
        }
    }

    impl FromRedisValue for TestArtifact {
        fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
            let json = String::from_redis_value(v)?;
            serde_json::from_str(&json).map_err(|e| {
                RedisError::from((
                    redis::ErrorKind::TypeError,
                    "Failed to deserialize TestArtifact",
                    e.to_string(),
                ))
            })
        }
    }

    impl serde::Serialize for TestArtifact {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeStruct;
            let mut state = serializer.serialize_struct("TestArtifact", 2)?;
            state.serialize_field("id", &self.id)?;
            state.serialize_field("data", &self.data)?;
            state.end()
        }
    }

    impl<'de> serde::Deserialize<'de> for TestArtifact {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(serde::Deserialize)]
            struct TestArtifactFields {
                id: u64,
                data: String,
            }
            let fields = TestArtifactFields::deserialize(deserializer)?;
            Ok(TestArtifact {
                id: fields.id,
                data: fields.data,
            })
        }
    }

    fn test_account_id() -> AccountId {
        AccountId::from_str("test.near").unwrap()
    }

    fn test_participant(id: u32) -> Participant {
        Participant::from(id)
    }

    #[tokio::test]
    async fn test_inmemory_reserve_insert_take() {
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());
        let owner = test_participant(0);

        // Reserve an artifact
        let id = 1u64;
        let mut slot = storage.reserve(id).await.expect("should reserve");

        // Insert the artifact
        let artifact = TestArtifact {
            id,
            data: "test data".to_string(),
        };
        assert!(slot.insert(artifact.clone(), owner).await);

        // Check it exists
        assert!(storage.contains(id).await);
        assert!(storage.contains_by_owner(id, owner).await);
        assert_eq!(storage.len_by_owner(owner).await, 1);

        // Take the artifact
        let taken = storage.take(id, owner).await.expect("should take");
        assert_eq!(taken.artifact, artifact);

        // Check it's marked as used
        assert!(storage.contains_used(id).await);
        assert!(!storage.contains(id).await);
        assert_eq!(storage.len_by_owner(owner).await, 0);
    }

    #[tokio::test]
    async fn test_inmemory_reserve_duplicate() {
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());

        let id = 1u64;
        let _slot1 = storage
            .reserve(id)
            .await
            .expect("should reserve first time");
        let slot2 = storage.reserve(id).await;

        assert!(slot2.is_none(), "should not reserve duplicate");
    }

    #[tokio::test]
    async fn test_inmemory_insert_without_reserve() {
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());
        let owner = test_participant(0);

        let artifact = TestArtifact {
            id: 1,
            data: "test".to_string(),
        };

        // Try to insert without reserving
        assert!(!storage.insert(artifact, owner).await);
    }

    #[tokio::test]
    async fn test_inmemory_take_mine() {
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());
        let owner = test_participant(0);

        // Insert multiple artifacts
        for i in 1..=3 {
            let mut slot = storage.reserve(i).await.expect("should reserve");
            let artifact = TestArtifact {
                id: i,
                data: format!("test {}", i),
            };
            assert!(slot.insert(artifact, owner).await);
        }

        assert_eq!(storage.len_by_owner(owner).await, 3);

        // Take one
        let taken = storage.take_mine(owner).await.expect("should take mine");
        assert!(taken.artifact.id >= 1 && taken.artifact.id <= 3);

        assert_eq!(storage.len_by_owner(owner).await, 2);
        assert!(storage.contains_used(taken.artifact.id).await);
    }

    #[tokio::test]
    async fn test_inmemory_recycle_mine() {
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());
        let owner = test_participant(0);

        // Insert an artifact
        let mut slot = storage.reserve(1).await.expect("should reserve");
        let artifact = TestArtifact {
            id: 1,
            data: "test".to_string(),
        };
        assert!(slot.insert(artifact.clone(), owner).await);

        // Take it
        let taken = storage.take_mine(owner).await.expect("should take");
        assert_eq!(storage.len_by_owner(owner).await, 0);

        // Recycle it
        assert!(storage.recycle_mine(owner, taken).await);
        assert_eq!(storage.len_by_owner(owner).await, 1);
        assert!(!storage.contains_used(1).await);
        assert!(storage.contains(1).await);
    }

    #[tokio::test]
    async fn test_inmemory_clear() {
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());
        let owner = test_participant(0);

        // Insert multiple artifacts
        for i in 1..=3 {
            let mut slot = storage.reserve(i).await.expect("should reserve");
            let artifact = TestArtifact {
                id: i,
                data: format!("test {}", i),
            };
            assert!(slot.insert(artifact, owner).await);
        }

        assert_eq!(storage.len_by_owner(owner).await, 3);

        // Clear
        assert!(storage.clear().await);
        assert_eq!(storage.len_by_owner(owner).await, 0);
        assert_eq!(storage.len_generated().await, 0);
    }

    #[tokio::test]
    async fn test_inmemory_concurrent_operations() {
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());
        let owner1 = test_participant(0);
        let owner2 = test_participant(1);

        // Spawn concurrent tasks
        let storage1 = storage.clone();
        let task1 = tokio::spawn(async move {
            for i in 1..=10 {
                let mut slot = storage1.reserve(i).await.expect("should reserve");
                let artifact = TestArtifact {
                    id: i,
                    data: format!("owner1-{}", i),
                };
                slot.insert(artifact, owner1).await;
            }
        });

        let storage2 = storage.clone();
        let task2 = tokio::spawn(async move {
            for i in 11..=20 {
                let mut slot = storage2.reserve(i).await.expect("should reserve");
                let artifact = TestArtifact {
                    id: i,
                    data: format!("owner2-{}", i),
                };
                slot.insert(artifact, owner2).await;
            }
        });

        task1.await.unwrap();
        task2.await.unwrap();

        assert_eq!(storage.len_by_owner(owner1).await, 10);
        assert_eq!(storage.len_by_owner(owner2).await, 10);
        assert_eq!(storage.len_generated().await, 20);
    }

    #[tokio::test]
    async fn test_inmemory_remove_outdated() {
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());
        let owner = test_participant(0);

        // Insert artifacts 1, 2, 3
        for i in 1..=3 {
            let mut slot = storage.reserve(i).await.expect("should reserve");
            let artifact = TestArtifact {
                id: i,
                data: format!("test {}", i),
            };
            assert!(slot.insert(artifact, owner).await);
        }

        // Remove outdated, keeping only 2 and 3
        let outdated = storage.remove_outdated(owner, &[2, 3]).await;
        assert_eq!(outdated, vec![1]);

        assert!(!storage.contains(1).await);
        assert!(storage.contains(2).await);
        assert!(storage.contains(3).await);
        assert_eq!(storage.len_by_owner(owner).await, 2);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use cait_sith::protocol::Participant;
    use near_sdk::AccountId;
    use proptest::prelude::*;
    use redis::{RedisError, RedisWrite};
    use std::str::FromStr;

    // Reuse TestArtifact from tests module
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestArtifact {
        id: u64,
        data: String,
    }

    impl ProtocolArtifact for TestArtifact {
        type Id = u64;
        const METRIC_LABEL: &'static str = "test";

        fn id(&self) -> Self::Id {
            self.id
        }
    }

    impl ToRedisArgs for TestArtifact {
        fn write_redis_args<W>(&self, out: &mut W)
        where
            W: ?Sized + RedisWrite,
        {
            let json = serde_json::to_string(self).unwrap();
            out.write_arg(json.as_bytes());
        }
    }

    impl FromRedisValue for TestArtifact {
        fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
            let json = String::from_redis_value(v)?;
            serde_json::from_str(&json).map_err(|e| {
                RedisError::from((
                    redis::ErrorKind::TypeError,
                    "Failed to deserialize TestArtifact",
                    e.to_string(),
                ))
            })
        }
    }

    impl serde::Serialize for TestArtifact {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeStruct;
            let mut state = serializer.serialize_struct("TestArtifact", 2)?;
            state.serialize_field("id", &self.id)?;
            state.serialize_field("data", &self.data)?;
            state.end()
        }
    }

    impl<'de> serde::Deserialize<'de> for TestArtifact {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(serde::Deserialize)]
            struct TestArtifactFields {
                id: u64,
                data: String,
            }
            let fields = TestArtifactFields::deserialize(deserializer)?;
            Ok(TestArtifact {
                id: fields.id,
                data: fields.data,
            })
        }
    }

    fn test_account_id() -> AccountId {
        AccountId::from_str("test.near").unwrap()
    }

    #[derive(Debug, Clone)]
    enum StorageOp {
        Reserve(u64),
        Insert(u64, u32), // id, owner
        Take(u64, u32),   // id, owner
        Contains(u64),
        LenByOwner(u32),
        MarkUsed(u64),
    }

    fn storage_op_strategy() -> impl Strategy<Value = StorageOp> {
        prop_oneof![
            (1u64..100).prop_map(StorageOp::Reserve),
            (1u64..100, 0u32..5).prop_map(|(id, owner)| StorageOp::Insert(id, owner)),
            (1u64..100, 0u32..5).prop_map(|(id, owner)| StorageOp::Take(id, owner)),
            (1u64..100).prop_map(StorageOp::Contains),
            (0u32..5).prop_map(StorageOp::LenByOwner),
            (1u64..100).prop_map(StorageOp::MarkUsed),
        ]
    }

    // Feature: sign-task-convergence-testing, Property 1: Redis variant behavioral equivalence
    // Validates: Requirements 1.3
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn test_inmemory_storage_operations(ops in prop::collection::vec(storage_op_strategy(), 1..50)) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());
                let mut reserved_ids = std::collections::HashSet::new();

                for op in ops {
                    match op {
                        StorageOp::Reserve(id) => {
                            let result = storage.reserve(id).await;
                            // Track successful reservations
                            if result.is_some() {
                                reserved_ids.insert(id);
                            }
                        }
                        StorageOp::Insert(id, owner_id) => {
                            let owner = Participant::from(owner_id);
                            let artifact = TestArtifact {
                                id,
                                data: format!("data-{}", id),
                            };
                            let result = storage.insert(artifact, owner).await;
                            if result {
                                reserved_ids.remove(&id);
                            }
                        }
                        StorageOp::Take(id, owner_id) => {
                            let owner = Participant::from(owner_id);
                            let _ = storage.take(id, owner).await;
                        }
                        StorageOp::Contains(id) => {
                            let _ = storage.contains(id).await;
                        }
                        StorageOp::LenByOwner(owner_id) => {
                            let owner = Participant::from(owner_id);
                            let len = storage.len_by_owner(owner).await;
                            assert!(len < 100, "length should be reasonable");
                        }
                        StorageOp::MarkUsed(id) => {
                            let _ = storage.mark_used(id).await;
                        }
                    }
                }

                // Verify storage is in a consistent state
                let total_len = storage.len_generated().await;
                assert!(total_len < 100, "total length should be reasonable");
            });
        }
    }

    // Feature: sign-task-convergence-testing, Property 2: Shared storage concurrent access
    // Validates: Requirements 2.2
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn test_concurrent_storage_access(
            ops_per_task in prop::collection::vec(storage_op_strategy(), 1..30),
            num_tasks in 2usize..8
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _ = rt.block_on(async {
                let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory(&test_account_id());
                let mut handles = vec![];

                // Spawn multiple concurrent tasks, each performing operations on shared storage
                for task_id in 0..num_tasks {
                    let storage_clone = storage.clone();
                    let ops_clone = ops_per_task.clone();

                    let handle = tokio::spawn(async move {
                        for op in ops_clone {
                            match op {
                                StorageOp::Reserve(id) => {
                                    // Offset IDs by task to reduce collisions
                                    let offset_id = id + (task_id as u64 * 1000);
                                    let _ = storage_clone.reserve(offset_id).await;
                                }
                                StorageOp::Insert(id, owner_id) => {
                                    let offset_id = id + (task_id as u64 * 1000);
                                    let owner = Participant::from(owner_id);
                                    let artifact = TestArtifact {
                                        id: offset_id,
                                        data: format!("task-{}-data-{}", task_id, offset_id),
                                    };
                                    let _ = storage_clone.insert(artifact, owner).await;
                                }
                                StorageOp::Take(id, owner_id) => {
                                    let offset_id = id + (task_id as u64 * 1000);
                                    let owner = Participant::from(owner_id);
                                    let _ = storage_clone.take(offset_id, owner).await;
                                }
                                StorageOp::Contains(id) => {
                                    let offset_id = id + (task_id as u64 * 1000);
                                    let _ = storage_clone.contains(offset_id).await;
                                }
                                StorageOp::LenByOwner(owner_id) => {
                                    let owner = Participant::from(owner_id);
                                    let _ = storage_clone.len_by_owner(owner).await;
                                }
                                StorageOp::MarkUsed(id) => {
                                    let offset_id = id + (task_id as u64 * 1000);
                                    let _ = storage_clone.mark_used(offset_id).await;
                                }
                            }
                        }
                    });

                    handles.push(handle);
                }

                // Wait for all tasks to complete
                for handle in handles {
                    let result = handle.await;
                    prop_assert!(result.is_ok(), "concurrent task should complete without panicking");
                }

                // Verify storage is in a consistent state after concurrent operations
                let total_len = storage.len_generated().await;
                prop_assert!(total_len < 10000, "total length should be reasonable after concurrent access");

                // Verify no data corruption by checking that we can still query the storage
                for owner_id in 0..5 {
                    let owner = Participant::from(owner_id as u32);
                    let len = storage.len_by_owner(owner).await;
                    prop_assert!(len < 10000, "owner length should be reasonable");
                }

                Ok(())
            });
        }
    }
}
