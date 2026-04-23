use cait_sith::protocol::Participant;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, ToRedisArgs};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::{fmt, time::Instant};
use tokio::sync::RwLock;
use tracing;

use super::{owner_key, STORAGE_VERSION};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("failed to connect to redis")]
    ConnectionFailed,
    #[error("redis operation failed: {0}")]
    RedisFailed(String),
    #[error("ProtocolStorage::set_me() was not called")]
    NotInitialized,
}

#[derive(Debug, Clone)]
pub struct RemoveOutdatedResult<Id> {
    pub removed: Vec<Id>,
    pub not_found: Vec<Id>,
}

impl<Id> RemoveOutdatedResult<Id> {
    pub fn new(removed: Vec<Id>, not_found: Vec<Id>) -> Self {
        Self { removed, not_found }
    }
}

impl<Id> Default for RemoveOutdatedResult<Id> {
    fn default() -> Self {
        Self {
            removed: Vec::new(),
            not_found: Vec::new(),
        }
    }
}

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

    /// Original protocol participants (immutable)
    fn participants(&self) -> &[Participant];

    /// Nodes that still hold their share of the artifact
    fn holders(&self) -> Option<&[Participant]>;

    fn set_holders(&mut self, holders: Vec<Participant>);
}

/// A handle for inserting a generated artifact into storage.
/// Tracks the artifact ID in the `generating` set until insertion or drop.
pub struct ArtifactSlot<A: ProtocolArtifact> {
    id: A::Id,
    storage: ProtocolStorage<A>,
}

impl<A: ProtocolArtifact> ArtifactSlot<A> {
    pub async fn insert(&mut self, artifact: A, owner: Participant) -> bool {
        self.storage.insert(artifact, owner).await
    }
}

impl<A: ProtocolArtifact> Drop for ArtifactSlot<A> {
    fn drop(&mut self) {
        self.storage
            .remove_reserved(self.id, ReservedKind::Generating);
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
            storage.remove_reserved(self.id, ReservedKind::Using);
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

#[derive(Debug, Clone, Copy)]
enum ReservedKind {
    Generating,
    Using,
}

/// Tracks artifact IDs that are in-flight but not yet in Redis.
/// Protected by a single `RwLock` to avoid multi-lock ordering issues.
#[derive(Debug)]
struct ReservedState<Id> {
    /// IDs currently being generated. Value is `true` if this node is the owner/proposer.
    generating: HashMap<Id, bool>,
    /// IDs taken from Redis and actively consumed by a protocol.
    /// Value is `true` if this node is the owner of the artifact.
    using: HashMap<Id, bool>,
}

impl<Id: Eq + std::hash::Hash> ReservedState<Id> {
    fn new() -> Self {
        Self {
            generating: HashMap::new(),
            using: HashMap::new(),
        }
    }

    fn contains_generating(&self, id: &Id) -> bool {
        self.generating.contains_key(id)
    }

    fn contains_reserved(&self, id: &Id) -> bool {
        self.generating.contains_key(id) || self.using.contains_key(id)
    }
}

#[derive(Debug)]
pub struct ProtocolStorage<A: ProtocolArtifact> {
    redis_pool: Pool,
    artifact_key: String,
    reserved: Arc<RwLock<ReservedState<A::Id>>>,
    owner_keys: String,
    account_id: AccountId,
    me: Arc<OnceLock<Participant>>,
    _phantom: std::marker::PhantomData<A>,
}

impl<A: ProtocolArtifact> Clone for ProtocolStorage<A> {
    fn clone(&self) -> Self {
        Self {
            redis_pool: self.redis_pool.clone(),
            artifact_key: self.artifact_key.clone(),
            reserved: self.reserved.clone(),
            owner_keys: self.owner_keys.clone(),
            account_id: self.account_id.clone(),
            me: self.me.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<A: ProtocolArtifact> ProtocolStorage<A> {
    pub fn new(pool: &Pool, account_id: &AccountId, base_prefix: &str) -> Self {
        let artifact_key = format!("{base_prefix}:{STORAGE_VERSION}:{account_id}");
        let state = Arc::new(RwLock::new(ReservedState::new()));
        let owner_keys = format!("{base_prefix}_owners:{STORAGE_VERSION}:{account_id}");

        Self {
            redis_pool: pool.clone(),
            artifact_key,
            reserved: state,
            owner_keys,
            account_id: account_id.clone(),
            me: Arc::new(OnceLock::new()),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<A: ProtocolArtifact> ProtocolStorage<A> {
    /// Set this node's participant identity. Must be called before using
    /// methods that depend on ownership
    pub fn set_me(&self, me: Participant) {
        let _ = self.me.set(me);
    }

    fn me(&self) -> Result<Participant, StorageError> {
        self.me.get().copied().ok_or_else(|| {
            tracing::error!("ProtocolStorage::set_me() was not called");
            StorageError::NotInitialized
        })
    }

    /// Remove an ID from the reserved state, trying synchronous lock first.
    /// Falls back to spawning an async task if the lock is contended.
    fn remove_reserved(&self, id: A::Id, kind: ReservedKind) {
        let reserved = self.reserved.clone();
        if let Ok(mut state) = reserved.try_write() {
            match kind {
                ReservedKind::Generating => state.generating.remove(&id),
                ReservedKind::Using => state.using.remove(&id),
            };
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let mut state = reserved.write().await;
                match kind {
                    ReservedKind::Generating => state.generating.remove(&id),
                    ReservedKind::Using => state.using.remove(&id),
                };
            });
        } else {
            tracing::warn!(
                id,
                ?kind,
                "dropped with contended lock outside tokio runtime; id may remain reserved"
            );
        }
    }

    async fn connect(&self) -> Option<Connection> {
        self.redis_pool
            .get()
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to connect to redis");
            })
            .ok()
    }

    pub async fn fetch_owned(&self) -> Result<Vec<A::Id>, StorageError> {
        self.fetch_owned_by(self.me()?).await
    }

    pub async fn fetch_owned_by(&self, owner: Participant) -> Result<Vec<A::Id>, StorageError> {
        let Some(mut conn) = self.connect().await else {
            return Err(StorageError::ConnectionFailed);
        };

        let owned: HashSet<A::Id> = conn
            .smembers(owner_key(&self.owner_keys, owner))
            .await
            .map_err(|err| {
                tracing::warn!(?err, "failed to fetch my owned artifacts");
                StorageError::RedisFailed(err.to_string())
            })?;

        Ok(owned.into_iter().collect())
    }

    /// Create a slot for generating an artifact with the given ID.
    /// Tracks the ID in the `generating` set until the slot is inserted or dropped.
    /// Returns `None` if the ID is already generating, in use, or stored in Redis.
    pub async fn create_slot(&self, id: A::Id, owner: Participant) -> Option<ArtifactSlot<A>> {
        {
            let mut state = self.reserved.write().await;
            if state.using.contains_key(&id) {
                tracing::error!(id, "cannot create slot: artifact is currently in use");
                return None;
            }
            if state.contains_generating(&id) {
                tracing::error!(
                    id,
                    "cannot create slot: artifact is already being generated"
                );
                return None;
            }
            let me = self.me().ok()?;
            state.generating.insert(id, owner == me);
        }
        if self.contains(id).await {
            self.reserved.write().await.generating.remove(&id);
            tracing::error!(id, "cannot create slot: artifact already exists in storage");
            return None;
        }
        Some(ArtifactSlot {
            id,
            storage: self.clone(),
        })
    }

    /// Check if an artifact is currently being generated (mine or peer).
    pub async fn contains_generating(&self, id: A::Id) -> bool {
        self.reserved.read().await.contains_generating(&id)
    }

    pub async fn contains_reserved(&self, id: A::Id) -> bool {
        self.reserved.read().await.contains_reserved(&id)
    }

    /// Owned artifacts in Redis plus owned using and owned generating.
    /// This is the full set that should be advertised during state sync to prevent
    /// peers from pruning artifacts that are still actively in use.
    pub async fn fetch_owned_with_reserved(&self) -> Result<Vec<A::Id>, StorageError> {
        let mut ids = self.fetch_owned().await?;
        let state = self.reserved.read().await;
        ids.extend(
            state
                .generating
                .iter()
                .filter_map(|(&id, &mine)| mine.then_some(id)),
        );
        ids.extend(
            state
                .using
                .iter()
                .filter_map(|(&id, &mine)| mine.then_some(id)),
        );
        Ok(ids)
    }

    pub async fn remove_outdated(
        &self,
        owner: Participant,
        owner_shares: &[A::Id],
    ) -> Result<RemoveOutdatedResult<A::Id>, StorageError> {
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
                    -- also delete holders sets for each outdated artifact
                    for _, oid in ipairs(outdated) do
                        redis.call("DEL", artifact_key .. ':holders:' .. oid)
                    end
                    -- clear the outdated list for the next batch
                    outdated = {}
                end
            end

            -- remove the remaining outdated shares from our node
            if #outdated > 0 then
                redis.call("SREM", owner_key, unpack(outdated))
                redis.call("HDEL", artifact_key, unpack(outdated))
                -- also delete holders sets for each outdated artifact
                for _, oid in ipairs(outdated) do
                    redis.call("DEL", artifact_key .. ':holders:' .. oid)
                end
            end

            -- find shares that were shared with us but not found in our storage
            local not_found = {}
            for _, id in ipairs(ARGV) do
                if redis.call("HEXISTS", artifact_key, id) == 0 then
                    table.insert(not_found, id)
                end
            end

            -- return both outdated and not_found
            return {outdated, not_found}
        "#;

        let start = Instant::now();
        let Some(mut conn) = self.connect().await else {
            return Err(StorageError::ConnectionFailed);
        };
        type RemoveOutdatedScriptResult<T> = Result<(Vec<T>, Vec<T>), redis::RedisError>;
        let result: RemoveOutdatedScriptResult<A::Id> = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(owner_key(&self.owner_keys, owner))
            // NOTE: this encodes each entry of owner_shares as a separate ARGV[index] entry.
            .arg(owner_shares)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "remove_outdated"])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok((outdated, not_found)) => {
                // Filter out artifacts that are on this node but not in Redis:
                // - `generating`: being generated, not yet persisted
                // - `using`: taken from Redis, actively consumed by a protocol
                let state = self.reserved.read().await;
                let not_found: Vec<_> = not_found
                    .into_iter()
                    .filter(|id| !state.contains_reserved(id))
                    .collect();
                Ok(RemoveOutdatedResult::new(outdated, not_found))
            }
            Err(err) => {
                tracing::error!(?err, ?elapsed, "failed to remove outdated artifacts");
                Err(StorageError::RedisFailed(err.to_string()))
            }
        }
    }

    /// Insert an artifact into storage under `owner`'s ownership set.
    /// Holders must be set on the artifact before calling this; they are
    /// persisted as a dedicated Redis set for later holder-tracking.
    /// Private: callers must use `create_slot()` + `ArtifactSlot::insert()`.
    async fn insert(&self, artifact: A, owner: Participant) -> bool {
        const SCRIPT: &str = r#"
            local artifact_key = KEYS[1]
            local owner_keys = KEYS[2]
            local owner_key = KEYS[3]
            local artifact_id = ARGV[1]
            local artifact = ARGV[2]
            local num_holders = tonumber(ARGV[3])

            redis.call("SADD", owner_key, artifact_id)
            redis.call("SADD", owner_keys, owner_key)
            redis.call("HSET", artifact_key, artifact_id, artifact)

            -- Store holders in a dedicated Redis set
            local holders_key = artifact_key .. ':holders:' .. artifact_id
            redis.call("DEL", holders_key)
            if num_holders > 0 then
                redis.call("SADD", holders_key, unpack(ARGV, 4, 3 + num_holders))
            end
        "#;

        let start = Instant::now();
        let id = artifact.id();

        let holders: Vec<u32> = artifact
            .holders()
            .expect("holders must be set before insert")
            .iter()
            .map(|p| Into::<u32>::into(*p))
            .collect();

        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to insert artifact: connection failed");
            return false;
        };
        let outcome = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(&self.owner_keys)
            .key(owner_key(&self.owner_keys, owner))
            .arg(id)
            .arg(&artifact)
            .arg(holders.len() as i64)
            .arg(holders.as_slice())
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "insert"])
            .observe(elapsed.as_millis() as f64);

        match outcome {
            Ok(()) => true,
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

    /// Check if an artifact is currently being consumed by an active protocol.
    pub async fn contains_using(&self, id: A::Id) -> bool {
        self.reserved.read().await.using.contains_key(&id)
    }

    /// Returns the set of artifact IDs currently being consumed by active protocols.
    pub async fn using_ids(&self) -> HashSet<A::Id> {
        self.reserved.read().await.using.keys().copied().collect()
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

            -- Read and delete the holders set
            local holders_key = artifact_key .. ':holders:' .. artifact_id
            local holders = redis.call("SMEMBERS", holders_key)
            redis.call("DEL", holders_key)

            return {artifact, holders}
        "#;

        let start = Instant::now();
        let mine = owner == self.me().ok()?;
        if self.reserved.write().await.using.insert(id, mine).is_some() {
            tracing::warn!(id, "taking artifact that is already in use");
            return None;
        }

        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to take artifact: connection failed");
            self.reserved.write().await.using.remove(&id);
            return None;
        };
        let result: Result<(A, Vec<u32>), _> = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(owner_key(&self.owner_keys, owner))
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "take"])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok((mut artifact, holders)) => {
                let holders = holders.into_iter().map(Participant::from).collect();
                artifact.set_holders(holders);
                tracing::info!(id, ?elapsed, "took artifact");
                Some(ArtifactTaken::new(artifact, self.clone()))
            }
            Err(err) => {
                self.reserved.write().await.using.remove(&id);
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
            local artifact_key = KEYS[2]
            local owner_keys = redis.call("SMEMBERS", KEYS[1])
            local del = {}
            for _, key in ipairs(KEYS) do
                table.insert(del, key)
            end
            for _, key in ipairs(owner_keys) do
                table.insert(del, key)
            end

            -- Also delete all holders sets for artifacts in the hash
            local artifact_ids = redis.call("HKEYS", artifact_key)
            for _, id in ipairs(artifact_ids) do
                table.insert(del, artifact_key .. ':holders:' .. id)
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
            .with_label_values(&[A::METRIC_LABEL, "clear"])
            .observe(elapsed.as_millis() as f64);

        let mut state = self.reserved.write().await;
        state.generating.clear();
        state.using.clear();

        // if the outcome is None, it means the script failed or there was an error.
        outcome.is_some()
    }

    /// Take one artifact owned by the given participant.
    /// It is very important to NOT reuse the same artifact twice for two different
    /// protocols.
    pub async fn take_mine(&self) -> Option<ArtifactTaken<A>> {
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

            -- Read and delete the holders set
            local holders_key = artifact_key .. ':holders:' .. id
            local holders = redis.call("SMEMBERS", holders_key)
            redis.call("DEL", holders_key)

            -- Return the artifact and holders
            return {artifact, holders}
        "#;

        let start = Instant::now();
        let mut conn = self.connect().await?;
        let me = self.me().ok()?;
        let result: Result<Option<(A, Vec<u32>)>, _> = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(owner_key(&self.owner_keys, me))
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::storage::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "take_mine"])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(Some((mut artifact, holders))) => {
                let holders = holders.into_iter().map(Participant::from).collect();
                artifact.set_holders(holders);
                let id = artifact.id();
                self.reserved.write().await.using.insert(id, true);
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

    pub fn artifact_key(&self) -> &str {
        &self.artifact_key
    }

    /// Batch remove a peer from holders for a set of artifact IDs, and prune
    /// artifacts that fall below the holder threshold.
    /// Assumes the given IDs are owned by this node for ownership-set cleanup.
    /// Returns (Vec<removed>, Vec<updated>)
    pub async fn remove_holder_and_prune(
        &self,
        peer: Participant,
        threshold: usize,
        ids: &[A::Id],
    ) -> Result<(Vec<A::Id>, Vec<A::Id>), StorageError> {
        if ids.is_empty() {
            return Ok((vec![], vec![]));
        }

        // Lua script expects: KEYS[1]=artifact_key, KEYS[2]=owner_key,
        // ARGV[1]=peer, ARGV[2]=threshold, ARGV[3...]=ids
        const SCRIPT: &str = r#"
            local artifact_key = KEYS[1]
            local owner_key = KEYS[2]
            local peer = ARGV[1]
            local threshold = tonumber(ARGV[2])
            local removed = {}
            local updated = {}
            for i = 3, #ARGV do
                local id = ARGV[i]
                -- Skip if not owned by me (defense against malicious/buggy peer responses)
                if redis.call('SISMEMBER', owner_key, id) == 0 then
                    -- noop: not our artifact
                elseif redis.call('EXISTS', artifact_key .. ':holders:' .. id) == 1 then
                    local holders_key = artifact_key .. ':holders:' .. id
                    redis.call('SREM', holders_key, peer)
                    local count = redis.call('SCARD', holders_key)
                    if count < threshold then
                        redis.call('HDEL', artifact_key, id)
                        redis.call('DEL', holders_key)
                        redis.call('SREM', owner_key, id)
                        table.insert(removed, id)
                    else
                        table.insert(updated, id)
                    end
                end
            end
            return {removed, updated}
        "#;

        let Some(mut conn) = self.connect().await else {
            return Err(StorageError::ConnectionFailed);
        };
        type SyncResult<Id> = Result<(Vec<Id>, Vec<Id>), redis::RedisError>;
        let result: SyncResult<A::Id> = redis::Script::new(SCRIPT)
            .key(&self.artifact_key)
            .key(owner_key(&self.owner_keys, self.me()?))
            .arg(Into::<u32>::into(peer))
            .arg(threshold as i64)
            .arg(ids)
            .invoke_async(&mut conn)
            .await;
        match result {
            Ok((removed, updated)) => Ok((removed, updated)),
            Err(err) => Err(StorageError::RedisFailed(err.to_string())),
        }
    }

    #[cfg(feature = "test-feature")]
    pub async fn fetch_holders(&self, id: A::Id) -> Vec<Participant> {
        use deadpool_redis::redis::AsyncCommands;
        let mut conn = self.redis_pool.get().await.unwrap();
        let holders_key = format!("{}:holders:{}", self.artifact_key, id);
        let members: Vec<u32> = conn.smembers(&holders_key).await.unwrap();
        let mut holders: Vec<Participant> = members.into_iter().map(Participant::from).collect();
        holders.sort();
        holders
    }
}
