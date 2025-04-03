use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use crate::protocol::presignature::{Presignature, PresignatureId};
use crate::storage::error::{StoreError, StoreResult};

use super::owner_key;

// Can be used to "clear" redis storage in case of a breaking change
const PRESIGNATURE_STORAGE_VERSION: &str = "v7";
const USED_EXPIRE_TIME: Duration = Duration::hours(24);

/// A pre-reserved slot for a presignature that will eventually be inserted.
#[derive(Clone)]
pub struct PresignatureSlot {
    id: PresignatureId,
    me: Participant,
    storage: PresignatureStorage,
}

impl PresignatureSlot {
    // TODO: put inside a tokio task:
    pub async fn insert(&self, presignature: Presignature, owner: Participant) -> bool {
        if let Err(err) = self
            .storage
            .insert(presignature, owner, owner == self.me)
            .await
        {
            tracing::warn!(id = self.id, ?err, "failed to insert presignature");
            false
        } else {
            true
        }
    }

    // TODO: put inside a tokio task:
    pub async fn unreserve(&self) {
        let mut conn = match self.storage.connect().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(?err, "failed to connect to redis");
                return;
            }
        };
        let result: Result<(), _> = conn.srem(&self.storage.reserved_key, self.id).await;
        if let Err(err) = result {
            tracing::warn!(id = self.id, ?err, "failed to unreserve presignature");
        }
    }
}

pub fn init(pool: &Pool, node_account_id: &AccountId) -> PresignatureStorage {
    let presig_key = format!(
        "presignatures:{}:{}",
        PRESIGNATURE_STORAGE_VERSION, node_account_id
    );
    let mine_key = format!(
        "presignatures_mine:{}:{}",
        PRESIGNATURE_STORAGE_VERSION, node_account_id
    );
    let used_key = format!(
        "presignatures_used:{}:{}",
        PRESIGNATURE_STORAGE_VERSION, node_account_id
    );
    let reserved_key = format!(
        "presingatures_reserved:{}:{}",
        PRESIGNATURE_STORAGE_VERSION, node_account_id
    );
    let owner_keys = format!(
        "presignatures_owners:{}:{}",
        PRESIGNATURE_STORAGE_VERSION, node_account_id
    );

    PresignatureStorage {
        redis_pool: pool.clone(),
        presig_key,
        mine_key,
        used_key,
        reserved_key,
        owner_keys,
    }
}

#[derive(Clone)]
pub struct PresignatureStorage {
    redis_pool: Pool,
    presig_key: String,
    mine_key: String,
    used_key: String,
    reserved_key: String,
    owner_keys: String,
}

impl PresignatureStorage {
    async fn connect(&self) -> StoreResult<Connection> {
        self.redis_pool
            .get()
            .await
            .map_err(anyhow::Error::new)
            .map_err(StoreError::Connect)
    }

    pub async fn fetch_owned(&self, me: Participant) -> Vec<PresignatureId> {
        let mut conn = match self.connect().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(?err, "failed to connect to redis");
                return Vec::new();
            }
        };

        conn.sunion((&self.reserved_key, owner_key(&self.owner_keys, me)))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to fetch (mine | reserved) presignatures");
            })
            .unwrap_or_default()
    }

    pub async fn reserve(&self, id: PresignatureId, me: Participant) -> Option<PresignatureSlot> {
        let mut conn = match self.connect().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(?err, "failed to connect to redis");
                return None;
            }
        };
        let script = r#"
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

        let result: Result<(), _> = redis::Script::new(script)
            .key(&self.presig_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok(_) => Some(PresignatureSlot {
                id,
                me,
                storage: self.clone(),
            }),
            Err(err) => {
                tracing::warn!(?err, "failed to reserve presignature");
                None
            }
        }
    }

    pub async fn remove_outdated(
        &self,
        owner: Participant,
        owner_shares: &[PresignatureId],
    ) -> Vec<PresignatureId> {
        let mut conn = match self.connect().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(?err, "failed to connect to redis");
                return Vec::new();
            }
        };

        let script = r#"
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

        let result: Result<Vec<PresignatureId>, _> = redis::Script::new(script)
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
    pub async fn insert(
        &self,
        presignature: Presignature,
        owner: Participant,
        mine: bool,
    ) -> StoreResult<()> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local presig_key = KEYS[2]
            local used_key = KEYS[3]
            local reserved_key = KEYS[4]
            local owner_keys = KEYS[5]
            local owner_key = KEYS[6]
            local presig_id = ARGV[1]
            local presig_value = ARGV[2]
            local mine = ARGV[3]

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
            if mine == "true" then
                redis.call("SADD", mine_key, presig_id)
            end

            redis.call("HSET", presig_key, presig_id, presig_value)

            return "OK"
        "#;

        let _: String = redis::Script::new(script)
            .key(&self.mine_key)
            .key(&self.presig_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(&self.owner_keys)
            .key(owner_key(&self.owner_keys, owner))
            .arg(presignature.id)
            .arg(presignature)
            .arg(mine.to_string())
            .invoke_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn contains(&self, id: PresignatureId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(&self.presig_key, id).await?;
        Ok(result)
    }

    pub async fn contains_mine(&self, id: PresignatureId) -> StoreResult<bool> {
        let mut connection = self.connect().await?;
        let result: bool = connection.sismember(&self.mine_key, id).await?;
        Ok(result)
    }

    pub async fn contains_used(&self, id: PresignatureId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(&self.used_key, id).await?;
        Ok(result)
    }

    // TODO: need to pass in owner to delete the triple from the owner set, but we can have sync just do this
    //       for now for us.
    pub async fn take(&self, id: PresignatureId) -> StoreResult<Presignature> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local presig_key = KEYS[2]
            local used_key = KEYS[3]
            local presig_id = ARGV[1]

            if redis.call('SISMEMBER', mine_key, presig_id) == 1 then
                return {err = 'Cannot take mine presignature as foreign owned'}
            end

            local presig_value = redis.call("HGET", presig_key, presig_id)

            if not presig_value then
                return {err = "Presignature " .. presig_id .. " is missing"}
            end

            redis.call("HDEL", presig_key, presig_id)
            redis.call("HSET", used_key, presig_id, "1")
            redis.call("HEXPIRE", used_key, ARGV[2], "FIELDS", "1", presig_id)

            return presig_value
        "#;

        let result: Result<Presignature, RedisError> = redis::Script::new(script)
            .key(&self.mine_key)
            .key(&self.presig_key)
            .key(&self.used_key)
            .arg(id)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn take_mine(&self, me: Participant) -> StoreResult<Option<Presignature>> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local presig_key = KEYS[2]
            local used_key = KEYS[3]

            local presig_id = redis.call("SPOP", mine_key)
            if not presig_id then
                return nil
            end

            local presig_value = redis.call("HGET", presig_key, presig_id)
            if not presig_value then
                return {err = "Unexpected behavior. Presignature " .. presig_id .. " is missing"}
            end

            redis.call("HDEL", presig_key, presig_id)
            redis.call("HSET", used_key, presig_id, "1")
            redis.call("HEXPIRE", used_key, ARGV[1], "FIELDS", "1", presig_id)

            return presig_value
        "#;

        redis::Script::new(script)
            .key(&self.mine_key)
            .key(&self.presig_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, me))
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
            .map_err(StoreError::from)
    }

    pub async fn len_generated(&self) -> StoreResult<usize> {
        let mut conn = self.connect().await?;
        let result: usize = conn.hlen(&self.presig_key).await?;
        Ok(result)
    }

    pub async fn len_mine(&self) -> StoreResult<usize> {
        let mut conn = self.connect().await?;
        let result: usize = conn.scard(&self.mine_key).await?;
        Ok(result)
    }

    pub async fn clear(&self) -> StoreResult<()> {
        let mut conn = self.connect().await?;
        let script = r#"
            local owner_keys = redis.call("SMEMBERS", KEYS[1])
            redis.call("DEL", unpack(KEYS), unpack(owner_keys))
        "#;

        let _: () = redis::Script::new(script)
            .key(&self.owner_keys)
            .key(&self.presig_key)
            .key(&self.mine_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .invoke_async(&mut conn)
            .await
            .map_err(StoreError::from)?;

        Ok(())
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
