use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};
use tokio::task::JoinHandle;

use crate::protocol::presignature::{Presignature, PresignatureId};

use super::{owner_key, STORAGE_VERSION};

const USED_EXPIRE_TIME: Duration = Duration::hours(24);

/// A pre-reserved slot for a presignature that will eventually be inserted.
pub struct PresignatureSlot {
    id: PresignatureId,
    storage: PresignatureStorage,
    stored: bool,
}

impl PresignatureSlot {
    // TODO: put inside a tokio task:
    pub async fn insert(&mut self, presignature: Presignature, owner: Participant) -> bool {
        self.stored = self.storage.insert(presignature, owner).await;
        self.stored
    }

    pub fn unreserve(&self) -> Option<JoinHandle<()>> {
        if self.stored {
            return None;
        }

        let storage = self.storage.clone();
        let id = self.id;
        let task = tokio::spawn(async move {
            tracing::info!(id, "unreserving presignature");
            storage.unreserve(id).await;
        });
        Some(task)
    }
}

impl Drop for PresignatureSlot {
    fn drop(&mut self) {
        self.unreserve();
    }
}

pub struct PresignatureTaken {
    pub presignature: Presignature,
    storage: PresignatureTakenDropper,
}

pub struct PresignatureTakenDropper {
    pub id: PresignatureId,
    dropper: Option<PresignatureStorage>,
}

impl Drop for PresignatureTakenDropper {
    fn drop(&mut self) {
        if let Some(storage) = self.dropper.take() {
            let id = self.id;
            tokio::spawn(async move {
                storage.unreserve(id).await;
            });
        }
    }
}

impl PresignatureTaken {
    fn owner(presignature: Presignature, storage: PresignatureStorage) -> Self {
        Self {
            storage: PresignatureTakenDropper {
                id: presignature.id,
                dropper: Some(storage),
            },
            presignature,
        }
    }

    fn foreigner(presignature: Presignature) -> Self {
        Self {
            storage: PresignatureTakenDropper {
                id: presignature.id,
                dropper: None,
            },
            presignature,
        }
    }

    pub fn take(self) -> (Presignature, PresignatureTakenDropper) {
        (self.presignature, self.storage)
    }
}

pub fn init(pool: &Pool, account_id: &AccountId) -> PresignatureStorage {
    let presig_key = format!("presignatures:{STORAGE_VERSION}:{account_id}",);
    let used_key = format!("presignatures_used:{STORAGE_VERSION}:{account_id}",);
    let reserved_key = format!("presingatures_reserved:{STORAGE_VERSION}:{account_id}",);
    let owner_keys = format!("presignatures_owners:{STORAGE_VERSION}:{account_id}",);

    PresignatureStorage {
        redis_pool: pool.clone(),
        presig_key,
        used_key,
        reserved_key,
        owner_keys,
    }
}

#[derive(Clone)]
pub struct PresignatureStorage {
    redis_pool: Pool,
    presig_key: String,
    used_key: String,
    reserved_key: String,
    owner_keys: String,
}

impl PresignatureStorage {
    async fn connect(&self) -> Option<Connection> {
        self.redis_pool
            .get()
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to connect to redis");
            })
            .ok()
    }

    pub async fn fetch_owned(&self, me: Participant) -> Vec<PresignatureId> {
        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };

        conn.sunion((&self.reserved_key, owner_key(&self.owner_keys, me)))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to fetch (mine | reserved) presignatures");
            })
            .unwrap_or_default()
    }

    pub async fn reserve(&self, id: PresignatureId) -> Option<PresignatureSlot> {
        const SCRIPT: &str = r#"
            local presig_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local presig_id = ARGV[1]

            -- cannot reserve this presignature if it already exists.
            if redis.call("SADD", reserved_key, presig_id) == 0 then
                return {err = "WARN presignature " .. presig_id .. " has already been reserved"}
            end

            -- cannot reserve this presignature if its already in storage.
            if redis.call("HEXISTS", presig_key, presig_id) == 1 then
                return {err = "WARN presignature " .. presig_id .. " has already been stored"}
            end

            -- cannot reserve this presignature if it has already been used.
            if redis.call("HEXISTS", used_key, presig_id) == 1 then
                return {err = "WARN presignature " .. presig_id .. " has already been used"}
            end
        "#;

        let mut conn = self.connect().await?;
        let result: Result<(), _> = redis::Script::new(SCRIPT)
            .key(&self.presig_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok(_) => Some(PresignatureSlot {
                id,
                storage: self.clone(),
                stored: false,
            }),
            Err(err) => {
                tracing::warn!(id, ?err, "failed to reserve presignature");
                None
            }
        }
    }

    async fn unreserve(self, id: PresignatureId) {
        let Some(mut conn) = self.connect().await else {
            return;
        };
        if let Err(err) = conn.srem::<'_, _, _, ()>(&self.reserved_key, id).await {
            tracing::warn!(id, ?err, "failed to unreserve presignature");
        }
    }

    pub async fn remove_outdated(
        &self,
        owner: Participant,
        owner_shares: &[PresignatureId],
    ) -> Vec<PresignatureId> {
        const SCRIPT: &str = r#"
            local presig_key = KEYS[1]
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
            end

            -- remove the outdated shares from our node
            if #outdated > 0 then
                redis.call("SREM", owner_key, unpack(outdated))
                redis.call("SREM", reserved_key, unpack(outdated))
                redis.call("HDEL", presig_key, unpack(outdated))
            end

            return outdated
        "#;

        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };
        let result: Result<Vec<PresignatureId>, _> = redis::Script::new(SCRIPT)
            .key(&self.presig_key)
            .key(&self.reserved_key)
            .key(owner_key(&self.owner_keys, owner))
            // NOTE: this encodes each entry of owner_shares as a separate ARGV[index] entry.
            .arg(owner_shares)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok(outdated) => {
                if !outdated.is_empty() {
                    tracing::info!(?outdated, "removed outdated presignatures");
                }
                outdated
            }
            Err(err) => {
                tracing::warn!(?err, "failed to remove outdated presignatures");
                Vec::new()
            }
        }
    }

    /// Insert a presignature into the storage. If `mine` is true, the presignature will be
    /// owned by the current node. If `back` is true, the presignature will be marked as unused.
    pub async fn insert(&self, presignature: Presignature, owner: Participant) -> bool {
        const SCRIPT: &str = r#"
            local presig_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local owner_keys = KEYS[4]
            local owner_key = KEYS[5]
            local presig_id = ARGV[1]
            local presig = ARGV[2]

            -- if the presignature has NOT been reserved, then something went wrong when acquiring the
            -- reservation for it via presignature slot.
            if redis.call("SREM", reserved_key, presig_id) == 0 then
                return {err = "WARN presignature " .. presig_id .. " has NOT been reserved"}
            end

            if redis.call('HEXISTS', used_key, presig_id) == 1 then
                return {err = 'WARN presignature ' .. presig_id .. ' is already used'}
            end

            redis.call("SADD", owner_key, presig_id)
            redis.call("SADD", owner_keys, owner_key)
            redis.call("HSET", presig_key, presig_id, presig)
        "#;

        let id = presignature.id;
        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to insert presignature: connection failed");
            return false;
        };
        let outcome = redis::Script::new(SCRIPT)
            .key(&self.presig_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(&self.owner_keys)
            .key(owner_key(&self.owner_keys, owner))
            .arg(id)
            .arg(presignature)
            .invoke_async(&mut conn)
            .await;

        match outcome {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to insert presignature");
                false
            }
        }
    }

    pub async fn contains(&self, id: PresignatureId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.presig_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if presignature is stored");
                false
            }
        }
    }

    pub async fn contains_mine(&self, id: PresignatureId, me: Participant) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.sismember(owner_key(&self.owner_keys, me), id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if presignature is owned by us");
                false
            }
        }
    }

    pub async fn contains_used(&self, id: PresignatureId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.used_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if presignature is used");
                false
            }
        }
    }

    pub async fn take(
        &self,
        id: PresignatureId,
        owner: Participant,
        me: Participant,
    ) -> Option<PresignatureTaken> {
        const SCRIPT: &str = r#"
            local presig_key = KEYS[1]
            local used_key = KEYS[2]
            local owner_key = KEYS[3]
            local mine_key = KEYS[4]
            local presig_id = ARGV[1]

            if redis.call("SISMEMBER", mine_key, presig_id) == 1 then
                return {err = 'WARN presignature ' .. presig_id ..' cannot be taken as foreign owned'}
            end
            if redis.call("SISMEMBER", owner_key, presig_id) == 0 then
                return {err = 'WARN presignature ' .. presig_id .. ' cannot be taken by incorrect owner ' .. owner_key }
            end

            local presig = redis.call("HGET", presig_key, presig_id)
            if not presig then
                return {err = "WARN presignature " .. presig_id .. " is missing"}
            end

            redis.call("SREM", owner_key, presig_id)
            redis.call("HDEL", presig_key, presig_id)
            redis.call("HSET", used_key, presig_id, "1")
            redis.call("HEXPIRE", used_key, ARGV[2], "FIELDS", "1", presig_id)

            return presig
        "#;

        let mut conn = self.connect().await?;
        match redis::Script::new(SCRIPT)
            .key(&self.presig_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, owner))
            .key(owner_key(&self.owner_keys, me))
            .arg(id)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
        {
            Ok(presignature) => Some(PresignatureTaken::foreigner(presignature)),
            Err(err) => {
                tracing::warn!(id, ?owner, ?me, ?err, "failed to take presignature");
                None
            }
        }
    }

    pub async fn take_mine(&self, me: Participant) -> Option<PresignatureTaken> {
        const SCRIPT: &str = r#"
            local presig_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local mine_key = KEYS[4]

            local presig_id = redis.call("SPOP", mine_key)
            if not presig_id then
                return nil
            end

            local presig = redis.call("HGET", presig_key, presig_id)
            if not presig then
                return {err = "WARN unexpected, presignature " .. presig_id .. " is missing"}
            end

            redis.call("SADD", reserved_key, presig_id)
            redis.call("HDEL", presig_key, presig_id)
            redis.call("HSET", used_key, presig_id, "1")
            redis.call("HEXPIRE", used_key, ARGV[1], "FIELDS", "1", presig_id)

            return presig
        "#;

        let mut conn = self.connect().await?;
        match redis::Script::new(SCRIPT)
            .key(&self.presig_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(owner_key(&self.owner_keys, me))
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
        {
            Ok(Some(presignature)) => Some(PresignatureTaken::owner(presignature, self.clone())),
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(?me, ?err, "failed to take my presignature");
                None
            }
        }
    }

    pub async fn len_generated(&self) -> Option<usize> {
        let mut conn = self.connect().await?;
        conn.hlen(&self.presig_key)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of generated presignatures");
            })
            .ok()
    }

    pub async fn len_mine(&self, me: Participant) -> Option<usize> {
        let mut conn = self.connect().await?;
        conn.scard(owner_key(&self.owner_keys, me))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of my presignatures");
            })
            .ok()
    }

    /// Clear all presignature storage, including used, reserved, and owned keys.
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

        let Some(mut conn) = self.connect().await else {
            return false;
        };
        let outcome: Option<()> = redis::Script::new(SCRIPT)
            .key(&self.owner_keys)
            .key(&self.presig_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .invoke_async(&mut conn)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to clear presignature storage");
            })
            .ok();
        outcome.is_some()
    }
}

impl ToRedisArgs for Presignature {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Presignature: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Presignature {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Presignature",
                e.to_string(),
            ))
        })
    }
}
