use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, ToRedisArgs};
use std::{fmt, time::Instant};
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

#[derive(Debug)]
pub struct ProtocolStorage<A> {
    redis_pool: Pool,
    artifact_key: String,
    used_key: String,
    reserved_key: String,
    owner_keys: String,
    account_id: AccountId,
    _phantom: std::marker::PhantomData<A>,
}

impl<A> Clone for ProtocolStorage<A> {
    fn clone(&self) -> Self {
        Self {
            redis_pool: self.redis_pool.clone(),
            artifact_key: self.artifact_key.clone(),
            used_key: self.used_key.clone(),
            reserved_key: self.reserved_key.clone(),
            owner_keys: self.owner_keys.clone(),
            account_id: self.account_id.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<A> ProtocolStorage<A> {
    pub fn new(pool: &Pool, account_id: &AccountId, base_prefix: &str) -> Self {
        let artifact_key = format!("{base_prefix}:{STORAGE_VERSION}:{account_id}");
        let used_key = format!("{base_prefix}_used:{STORAGE_VERSION}:{account_id}");
        let reserved_key = format!("{base_prefix}_reserved:{STORAGE_VERSION}:{account_id}");
        let owner_keys = format!("{base_prefix}_owners:{STORAGE_VERSION}:{account_id}");

        Self {
            redis_pool: pool.clone(),
            artifact_key,
            used_key,
            reserved_key,
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

        conn.sunion((&self.reserved_key, owner_key(&self.owner_keys, me)))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to fetch (mine | reserved) artifacts");
            })
            .unwrap_or_default()
    }

    pub async fn reserve(&self, id: A::Id) -> Option<ArtifactSlot<A>> {
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
            .key(&self.artifact_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "reserve", self.account_id.as_str()])
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

    async fn unreserve(&self, id: A::Id) {
        let Some(mut conn) = self.connect().await else {
            return;
        };
        if let Err(err) = conn.srem::<'_, _, _, ()>(&self.reserved_key, id).await {
            tracing::warn!(id, ?err, "failed to unreserve artifact");
        }
    }

    pub async fn remove_outdated(&self, owner: Participant, owner_shares: &[A::Id]) -> Vec<A::Id> {
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
            .key(&self.artifact_key)
            .key(&self.reserved_key)
            .key(owner_key(&self.owner_keys, owner))
            // NOTE: this encodes each entry of owner_shares as a separate ARGV[index] entry.
            .arg(owner_shares)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "remove_outdated", self.account_id.as_str()])
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

    /// Insert an artifact into the storage. If `mine` is true, the artifact will be
    /// owned by the current node. If `back` is true, the artifact will be marked as unused.
    pub async fn insert(&self, artifact: A, owner: Participant) -> bool {
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
            .key(&self.artifact_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(&self.owner_keys)
            .key(owner_key(&self.owner_keys, owner))
            .arg(id)
            .arg(artifact)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "insert", self.account_id.as_str()])
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
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.used_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if artifact is used");
                false
            }
        }
    }

    pub async fn take(&self, id: A::Id, owner: Participant) -> Option<ArtifactTaken<A>> {
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
            .key(&self.artifact_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, owner))
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "take", self.account_id.as_str()])
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

    pub async fn mark_used(&self, id: A::Id) -> bool {
        let start = Instant::now();
        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to mark artifact used: connection failed");
            return false;
        };
        let result: Result<(), _> = conn.hset_nx(&self.used_key, id, "").await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "mark_used", self.account_id.as_str()])
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

    pub async fn expire_used(&self) {
        let Some(mut conn) = self.connect().await else {
            return;
        };
        if let Err(err) = conn
            .expire::<_, ()>(&self.used_key, USED_EXPIRE_TIME.num_seconds())
            .await
        {
            tracing::warn!(?err, "failed to expire used artifacts");
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
            .key(&self.used_key)
            .key(&self.reserved_key)
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
            .with_label_values(&[A::METRIC_LABEL, "clear", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        // if the outcome is None, it means the script failed or there was an error.
        outcome.is_some()
    }

    /// Take one artifact owned by the given participant.
    /// It is very important to NOT reuse the same artifact twice for two different
    /// protocols.
    pub async fn take_mine(&self, me: Participant) -> Option<ArtifactTaken<A>> {
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
            .key(&self.artifact_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, me))
            .key(&self.reserved_key)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "take_mine", self.account_id.as_str()])
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

    /// Return a taken artifact back to the available pool.
    pub async fn recycle_mine(&self, me: Participant, taken: ArtifactTaken<A>) -> bool {
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
            .key(&self.artifact_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, me))
            .key(&self.reserved_key)
            .arg(id)
            .arg(artifact)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&[A::METRIC_LABEL, "return_mine", self.account_id.as_str()])
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

    /// Check if an artifact is reserved.
    pub async fn contains_reserved(&self, id: A::Id) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.sismember(&self.reserved_key, id).await {
            Ok(true) => true,
            Ok(false) => false,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if artifact is reserved");
                false
            }
        }
    }

    pub fn artifact_key(&self) -> &str {
        &self.artifact_key
    }
}
