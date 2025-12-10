use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, ToRedisArgs};
use std::{collections::{HashMap, HashSet}, fmt, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
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

/// In-memory state for ProtocolStorage
#[derive(Debug)]
pub(crate) struct InMemoryProtocolState<A: ProtocolArtifact> {
    artifacts: HashMap<A::Id, A>,
    used: HashSet<A::Id>,
    reserved: HashSet<A::Id>,
    owners: HashMap<Participant, HashSet<A::Id>>,
}

impl<A: ProtocolArtifact> InMemoryProtocolState<A> {
    fn new() -> Self {
        Self {
            artifacts: HashMap::new(),
            used: HashSet::new(),
            reserved: HashSet::new(),
            owners: HashMap::new(),
        }
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
        state: Arc<RwLock<InMemoryProtocolState<A>>>,
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
                _phantom: *_phantom,
            },
            Self::InMemory { state } => Self::InMemory {
                state: Arc::clone(state),
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

    pub fn in_memory() -> Self {
        Self::InMemory {
            state: Arc::new(RwLock::new(InMemoryProtocolState::new())),
        }
    }
}

impl<A: ProtocolArtifact> ProtocolStorage<A> {
    async fn connect(&self) -> Option<Connection> {
        match self {
            Self::Redis { redis_pool, .. } => {
                redis_pool
                    .get()
                    .await
                    .inspect_err(|err| {
                        tracing::warn!(?err, "failed to connect to redis");
                    })
                    .ok()
            }
            Self::InMemory { .. } => None,
        }
    }

    pub async fn fetch_owned(&self, me: Participant) -> Vec<A::Id> {
        match self {
            Self::Redis { reserved_key, owner_keys, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return Vec::new();
                };

                conn.sunion((&reserved_key, owner_key(&owner_keys, me)))
                    .await
                    .inspect_err(|err| {
                        tracing::warn!(?err, "failed to fetch (mine | reserved) artifacts");
                    })
                    .unwrap_or_default()
            }
            Self::InMemory { state } => {
                let state = state.read().await;
                let mut result = state.reserved.iter().copied().collect::<Vec<_>>();
                if let Some(owner_artifacts) = state.owners.get(&me) {
                    result.extend(owner_artifacts.iter().copied());
                }
                result
            }
        }
    }

    pub async fn reserve(&self, id: A::Id) -> Option<ArtifactSlot<A>> {
        match self {
            Self::Redis { artifact_key, used_key, reserved_key, account_id, .. } => {
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
                    .key(&artifact_key)
                    .key(&used_key)
                    .key(&reserved_key)
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
            Self::InMemory { state } => {
                let mut state = state.write().await;
                
                // cannot reserve if already in storage
                if state.artifacts.contains_key(&id) {
                    tracing::warn!(id, "artifact has already been stored");
                    return None;
                }
                
                // cannot reserve if already used
                if state.used.contains(&id) {
                    tracing::warn!(id, "artifact has already been used");
                    return None;
                }
                
                // cannot reserve if already reserved
                if !state.reserved.insert(id) {
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
                if let Err(err) = conn.srem::<'_, _, _, ()>(&reserved_key, id).await {
                    tracing::warn!(id, ?err, "failed to unreserve artifact");
                }
            }
            Self::InMemory { state } => {
                let mut state = state.write().await;
                state.reserved.remove(&id);
            }
        }
    }

    pub async fn remove_outdated(&self, owner: Participant, owner_shares: &[A::Id]) -> Vec<A::Id> {
        match self {
            Self::Redis { artifact_key, reserved_key, owner_keys, account_id, .. } => {
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
                    .key(&artifact_key)
                    .key(&reserved_key)
                    .key(owner_key(&owner_keys, owner))
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
            Self::InMemory { state } => {
                let mut state = state.write().await;
                let owner_shares_set: HashSet<_> = owner_shares.iter().copied().collect();
                
                let mut outdated = Vec::new();
                if let Some(our_shares) = state.owners.get(&owner) {
                    for id in our_shares.iter() {
                        if !owner_shares_set.contains(id) {
                            outdated.push(*id);
                        }
                    }
                }
                
                // Remove outdated artifacts
                for id in &outdated {
                    state.artifacts.remove(id);
                    state.reserved.remove(id);
                    if let Some(owner_set) = state.owners.get_mut(&owner) {
                        owner_set.remove(id);
                    }
                }
                
                outdated
            }
        }
    }

    /// Insert an artifact into the storage. If `mine` is true, the artifact will be
    /// owned by the current node. If `back` is true, the artifact will be marked as unused.
    pub async fn insert(&self, artifact: A, owner: Participant) -> bool {
        match self {
            Self::Redis { artifact_key, used_key, reserved_key, owner_keys, account_id, .. } => {
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
                    .key(&artifact_key)
                    .key(&used_key)
                    .key(&reserved_key)
                    .key(&owner_keys)
                    .key(owner_key(&owner_keys, owner))
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
            Self::InMemory { state } => {
                let mut state = state.write().await;
                let id = artifact.id();
                
                // if the artifact has NOT been reserved, fail
                if !state.reserved.remove(&id) {
                    tracing::warn!(id, "artifact has NOT been reserved");
                    return false;
                }
                
                // if already used, fail
                if state.used.contains(&id) {
                    tracing::warn!(id, "artifact is already used");
                    return false;
                }
                
                state.artifacts.insert(id, artifact);
                state.owners.entry(owner).or_insert_with(HashSet::new).insert(id);
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
                match conn.hexists(&artifact_key, id).await {
                    Ok(exists) => exists,
                    Err(err) => {
                        tracing::warn!(id, ?err, "failed to check if artifact is stored");
                        false
                    }
                }
            }
            Self::InMemory { state } => {
                state.read().await.artifacts.contains_key(&id)
            }
        }
    }

    pub async fn contains_by_owner(&self, id: A::Id, owner: Participant) -> bool {
        match self {
            Self::Redis { owner_keys, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return false;
                };
                match conn.sismember(owner_key(&owner_keys, owner), id).await {
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
            Self::InMemory { state } => {
                let state = state.read().await;
                state.owners.get(&owner).map_or(false, |set| set.contains(&id))
            }
        }
    }

    pub async fn contains_used(&self, id: A::Id) -> bool {
        match self {
            Self::Redis { used_key, .. } => {
                let Some(mut conn) = self.connect().await else {
                    return false;
                };
                match conn.hexists(&used_key, id).await {
                    Ok(exists) => exists,
                    Err(err) => {
                        tracing::warn!(id, ?err, "failed to check if artifact is used");
                        false
                    }
                }
            }
            Self::InMemory { state } => {
                state.read().await.used.contains(&id)
            }
        }
    }

    pub async fn take(&self, id: A::Id, owner: Participant) -> Option<ArtifactTaken<A>> {
        match self {
            Self::Redis { artifact_key, used_key, owner_keys, account_id, .. } => {
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
                    .key(&artifact_key)
                    .key(&used_key)
                    .key(owner_key(&owner_keys, owner))
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
            Self::InMemory { state } => {
                let mut state = state.write().await;
                
                // Check if already used
                if state.used.contains(&id) {
                    tracing::warn!(id, "artifact is already used");
                    return None;
                }
                
                // Check if owned by this owner
                if let Some(owner_set) = state.owners.get_mut(&owner) {
                    if !owner_set.remove(&id) {
                        tracing::warn!(id, "artifact is not owned by this owner");
                        return None;
                    }
                } else {
                    tracing::warn!(id, "artifact is not owned by this owner");
                    return None;
                }
                
                // Get the artifact
                if let Some(artifact) = state.artifacts.remove(&id) {
                    state.used.insert(id);
                    tracing::info!(id, "took artifact");
                    Some(ArtifactTaken::new(artifact, self.clone()))
                } else {
                    tracing::warn!(id, "artifact not found");
                    None
                }
            }
        }
    }

    pub async fn mark_used(&self, id: A::Id) -> bool {
        match self {
            Self::Redis { used_key, account_id, .. } => {
                let start = Instant::now();
                let Some(mut conn) = self.connect().await else {
                    tracing::warn!(id, "failed to mark artifact used: connection failed");
                    return false;
                };
                let result: Result<(), _> = conn.hset_nx(&used_key, id, "").await;

                let elapsed = start.elapsed();
                crate::metrics::REDIS_LATENCY
                    .with_label_values(&[A::METRIC_LABEL, "mark_used", account_id.as_str()])
                    .observe(elapsed.as_millis() as f64);

                match result {
                    Ok(()) => {
                        tracing::info!(id, elapsed_ms = elapsed.as_millis(), "marked artifact used");
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
            Self::InMemory { state } => {
                let mut state = state.write().await;
                state.used.insert(id)
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
                    .expire::<_, ()>(&used_key, USED_EXPIRE_TIME.num_seconds())
                    .await
                {
                    tracing::warn!(?err, "failed to expire used artifacts");
                }
            }
            Self::InMemory { .. } => {
                // In-memory storage doesn't need expiration
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
                conn.hlen(&artifact_key)
                    .await
                    .inspect_err(|err| {
                        tracing::warn!(?err, "failed to get length of generated artifacts");
                    })
                    .unwrap_or(0)
            }
            Self::InMemory { state } => {
                state.read().await.artifacts.len()
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
                conn.scard(owner_key(&owner_keys, owner))
                    .await
                    .inspect_err(|err| {
                        tracing::warn!(?err, "failed to get length of my artifacts");
                    })
                    .unwrap_or(0)
            }
            Self::InMemory { state } => {
                state.read().await.owners.get(&owner).map_or(0, |set| set.len())
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
            Self::Redis { owner_keys, artifact_key, used_key, reserved_key, account_id, .. } => {
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
                    .key(&owner_keys)
                    .key(&artifact_key)
                    .key(&used_key)
                    .key(&reserved_key)
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
            Self::InMemory { state } => {
                let mut state = state.write().await;
                state.artifacts.clear();
                state.used.clear();
                state.reserved.clear();
                state.owners.clear();
                true
            }
        }
    }

    /// Take one artifact owned by the given participant.
    /// It is very important to NOT reuse the same artifact twice for two different
    /// protocols.
    pub async fn take_mine(&self, me: Participant) -> Option<ArtifactTaken<A>> {
        match self {
            Self::Redis { artifact_key, used_key, owner_keys, reserved_key, account_id, .. } => {
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
                    .key(&artifact_key)
                    .key(&used_key)
                    .key(owner_key(&owner_keys, me))
                    .key(&reserved_key)
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
            Self::InMemory { state } => {
                let mut state = state.write().await;
                
                if let Some(owner_set) = state.owners.get_mut(&me) {
                    if let Some(id) = owner_set.iter().next().copied() {
                        owner_set.remove(&id);
                        
                        if let Some(artifact) = state.artifacts.remove(&id) {
                            state.reserved.insert(id);
                            state.used.insert(id);
                            tracing::debug!(id, "took mine artifact");
                            return Some(ArtifactTaken::new(artifact, self.clone()));
                        }
                    }
                }
                None
            }
        }
    }

    /// Return a taken artifact back to the available pool.
    pub async fn recycle_mine(&self, me: Participant, taken: ArtifactTaken<A>) -> bool {
        match self {
            Self::Redis { artifact_key, used_key, owner_keys, reserved_key, account_id, .. } => {
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
                    .key(&artifact_key)
                    .key(&used_key)
                    .key(owner_key(&owner_keys, me))
                    .key(&reserved_key)
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
            Self::InMemory { state } => {
                let (artifact, mut dropper) = taken.take();
                // We manually handle the return, so we don't want the dropper to unreserve it.
                dropper.dropper.take();

                let id = artifact.id();
                let mut state = state.write().await;
                
                state.used.remove(&id);
                state.artifacts.insert(id, artifact);
                state.owners.entry(me).or_insert_with(HashSet::new).insert(id);
                state.reserved.insert(id);
                
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
                match conn.sismember(&reserved_key, id).await {
                    Ok(true) => true,
                    Ok(false) => false,
                    Err(err) => {
                        tracing::warn!(id, ?err, "failed to check if artifact is reserved");
                        false
                    }
                }
            }
            Self::InMemory { state } => {
                state.read().await.reserved.contains(&id)
            }
        }
    }

    pub fn artifact_key(&self) -> &str {
        match self {
            Self::Redis { artifact_key, .. } => artifact_key,
            Self::InMemory { .. } => "in-memory",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::join_all;
    use serde::{Deserialize, Serialize};

    /// A simple test artifact for testing ProtocolStorage
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestArtifact {
        id: u64,
        data: String,
    }

    impl ProtocolArtifact for TestArtifact {
        const METRIC_LABEL: &'static str = "test";
        type Id = u64;

        fn id(&self) -> Self::Id {
            self.id
        }
    }

    impl ToRedisArgs for TestArtifact {
        fn write_redis_args<W>(&self, out: &mut W)
        where
            W: ?Sized + redis::RedisWrite,
        {
            match serde_json::to_string(self) {
                Ok(json) => out.write_arg(json.as_bytes()),
                Err(e) => {
                    tracing::error!("Failed to serialize TestArtifact: {}", e);
                    out.write_arg("failed_to_serialize".as_bytes())
                }
            }
        }
    }

    impl FromRedisValue for TestArtifact {
        fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
            let json = String::from_redis_value(v)?;
            serde_json::from_str(&json).map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "Failed to deserialize TestArtifact",
                    format!("{}", e),
                ))
            })
        }
    }

    // Property 1: Storage Implementation Equivalence
    // Validates: Requirements 2.2, 2.5
    #[tokio::test]
    async fn test_in_memory_storage_reserve_and_insert() {
        // For any artifact ID, reserving and then inserting should succeed
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory();
        let artifact = TestArtifact {
            id: 1,
            data: "test".to_string(),
        };
        let owner = Participant::from(0u32);

        // Reserve the artifact
        let slot = storage.reserve(artifact.id).await;
        assert!(slot.is_some(), "Should be able to reserve artifact");

        // Insert the artifact
        let mut slot = slot.unwrap();
        let inserted = slot.insert(artifact.clone(), owner).await;
        assert!(inserted, "Should be able to insert artifact after reservation");

        // Verify it's in storage
        assert!(storage.contains(artifact.id).await, "Artifact should be in storage");
    }

    // Property 2: Storage Consistency Under Concurrency
    // Validates: Requirements 2.4
    #[tokio::test]
    async fn test_concurrent_reserve_operations() {
        // For any set of concurrent reserve operations, only one should succeed per ID
        let storage = Arc::new(ProtocolStorage::<TestArtifact>::in_memory());
        let artifact_id = 42u64;

        let mut handles = vec![];
        for _ in 0..5 {
            let storage_clone = Arc::clone(&storage);
            let handle = tokio::spawn(async move {
                storage_clone.reserve(artifact_id).await.is_some()
            });
            handles.push(handle);
        }

        let results: Vec<_> = join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Exactly one should succeed
        let success_count = results.iter().filter(|&&r| r).count();
        assert_eq!(success_count, 1, "Only one concurrent reserve should succeed");
    }

    // Property 3: Artifact Reservation Uniqueness
    // Validates: Requirements 6.2
    #[tokio::test]
    async fn test_artifact_cannot_be_reserved_twice() {
        // For any artifact ID, attempting to reserve it twice should fail on the second attempt
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory();
        let artifact_id = 99u64;

        let first_reserve = storage.reserve(artifact_id).await;
        assert!(first_reserve.is_some(), "First reserve should succeed");

        let second_reserve = storage.reserve(artifact_id).await;
        assert!(second_reserve.is_none(), "Second reserve should fail");
    }

    // Property 4: Used Artifact Immutability
    // Validates: Requirements 6.3
    #[tokio::test]
    async fn test_used_artifact_cannot_be_taken_again() {
        // For any artifact that has been taken and marked as used,
        // subsequent attempts to take it should fail
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory();
        let artifact = TestArtifact {
            id: 77,
            data: "immutable".to_string(),
        };
        let owner = Participant::from(0u32);

        // Reserve and insert
        let slot = storage.reserve(artifact.id).await.unwrap();
        let mut slot = slot;
        slot.insert(artifact.clone(), owner).await;

        // Take the artifact
        let taken = storage.take(artifact.id, owner).await;
        assert!(taken.is_some(), "Should be able to take artifact");

        // Try to take again - should fail
        let taken_again = storage.take(artifact.id, owner).await;
        assert!(taken_again.is_none(), "Should not be able to take used artifact");
    }

    // Property 5: Storage Clear Completeness
    // Validates: Requirements 6.4
    #[tokio::test]
    async fn test_storage_clear_removes_all_data() {
        // For any storage state, after calling clear(), the storage should be empty
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory();
        let owner = Participant::from(0u32);

        // Add multiple artifacts
        for i in 0..5 {
            let artifact = TestArtifact {
                id: i,
                data: format!("artifact_{}", i),
            };
            let slot = storage.reserve(artifact.id).await.unwrap();
            let mut slot = slot;
            slot.insert(artifact, owner).await;
        }

        // Verify they're there
        assert!(storage.len_generated().await > 0, "Storage should have artifacts");

        // Clear
        let cleared = storage.clear().await;
        assert!(cleared, "Clear should succeed");

        // Verify empty
        assert_eq!(storage.len_generated().await, 0, "Storage should be empty after clear");
        assert_eq!(storage.len_by_owner(owner).await, 0, "Owner should have no artifacts");
    }

    // Property 6: Storage Operation Invariants
    // Validates: Requirements 6.1
    #[tokio::test]
    async fn test_storage_invariants_maintained() {
        // For any sequence of valid storage operations, invariants should be maintained:
        // - Reserved artifacts exist in the reserved set
        // - Used artifacts exist in the used set
        // - Owner mappings are consistent with artifact existence
        let storage: ProtocolStorage<TestArtifact> = ProtocolStorage::in_memory();
        let owner = Participant::from(0u32);

        let artifact = TestArtifact {
            id: 123,
            data: "invariant_test".to_string(),
        };

        // After reserve, artifact should be reserved
        let slot = storage.reserve(artifact.id).await.unwrap();
        assert!(
            storage.contains_reserved(artifact.id).await,
            "Reserved artifact should be in reserved set"
        );

        // After insert, artifact should be in storage and owned
        let mut slot = slot;
        slot.insert(artifact.clone(), owner).await;
        assert!(
            storage.contains(artifact.id).await,
            "Inserted artifact should be in storage"
        );
        assert!(
            storage.contains_by_owner(artifact.id, owner).await,
            "Artifact should be owned by the owner"
        );

        // After take, artifact should be marked as used
        let _taken = storage.take(artifact.id, owner).await.unwrap();
        assert!(
            storage.contains_used(artifact.id).await,
            "Taken artifact should be marked as used"
        );
        assert!(
            !storage.contains(artifact.id).await,
            "Taken artifact should not be in storage"
        );
    }
}
