use crate::protocol::triple::{Triple, TripleId};
use crate::storage::error::{StoreError, StoreResult};

use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use near_account_id::AccountId;

use super::owner_key;

// Can be used to "clear" redis storage in case of a breaking change
const TRIPLE_STORAGE_VERSION: &str = "v7";
const USED_EXPIRE_TIME: Duration = Duration::hours(24);

/// A pre-reserved slot for a triple that will eventually be inserted.
#[derive(Clone)]
pub struct TripleSlot {
    id: TripleId,
    me: Participant,
    storage: TripleStorage,
}

impl TripleSlot {
    // TODO: put inside a tokio task:
    pub async fn insert(&self, triple: Triple, owner: Participant) -> bool {
        if let Err(err) = self.storage.insert(triple, owner, owner == self.me).await {
            tracing::warn!(id = self.id, ?err, "failed to insert triple");
            return false;
        }
        return true;
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
            tracing::warn!(id = self.id, ?err, "failed to unreserve triple");
        }
    }
}

pub fn init(pool: &Pool, account_id: &AccountId) -> TripleStorage {
    let triple_key = format!("triples:{}:{}", TRIPLE_STORAGE_VERSION, account_id);
    let mine_key = format!("triples_mine:{}:{}", TRIPLE_STORAGE_VERSION, account_id);
    let used_key = format!("triples_used:{}:{}", TRIPLE_STORAGE_VERSION, account_id);
    let reserved_key = format!("triples_reserved:{}:{}", TRIPLE_STORAGE_VERSION, account_id);
    let owner_keys = format!("triples_owners:{}:{}", TRIPLE_STORAGE_VERSION, account_id);

    TripleStorage {
        redis_pool: pool.clone(),
        triple_key,
        mine_key,
        used_key,
        reserved_key,
        owner_keys,
    }
}

#[derive(Clone)]
pub struct TripleStorage {
    redis_pool: Pool,
    triple_key: String,
    mine_key: String,
    used_key: String,
    reserved_key: String,
    owner_keys: String,
}

impl TripleStorage {
    async fn connect(&self) -> StoreResult<Connection> {
        self.redis_pool
            .get()
            .await
            .map_err(anyhow::Error::new)
            .map_err(StoreError::Connect)
    }

    pub async fn reserved(&self) -> Vec<TripleId> {
        let mut conn = match self.connect().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(?err, "failed to connect to redis");
                return Vec::new();
            }
        };
        conn.smembers(&self.reserved_key).await.unwrap_or_default()
    }

    // TODO: make triple reservation expire after some time if it does not get stored.
    pub async fn reserve(&self, id: TripleId, me: Participant) -> Option<TripleSlot> {
        let mut conn = match self.connect().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(?err, "failed to connect to redis");
                return None;
            }
        };
        let script = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local triple_id = ARGV[1]

            -- cannot reserve this triple if it already exists.
            if redis.call("SADD", reserved_key, triple_id) == 0 then
                return {err = "WARN triple " .. triple_id .. " has already been reserved"}
            end

            -- cannot reserve this triple if its already in storage.
            if redis.call("HEXISTS", triple_key, triple_id) == 1 then
                return {err = "WARN triple " .. triple_id .. " has already been stored"}
            end

            -- cannot reserve this triple if it has already been used.
            if redis.call("HEXISTS", used_key, triple_id) == 1 then
                return {err = "WARN triple " .. triple_id .. " has already been used"}
            end
        "#;

        let result: Result<(), _> = redis::Script::new(script)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok(_) => Some(TripleSlot {
                id,
                me,
                storage: self.clone(),
            }),
            Err(err) => {
                tracing::warn!(?err, "failed to reserve triple");
                None
            }
        }
    }

    pub async fn remove_outdated(
        &self,
        owner: Participant,
        owner_shares: &[TripleId],
    ) -> Vec<TripleId> {
        let mut conn = match self.connect().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(?err, "failed to connect to redis");
                return Vec::new();
            }
        };

        let script = r#"
            local triple_key = KEYS[1]
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
                redis.call("HDEL", triple_key, unpack(outdated))
            end

            return outdated
        "#;

        let result: Result<Vec<TripleId>, _> = redis::Script::new(script)
            .key(&self.triple_key)
            .key(&self.reserved_key)
            .key(owner_key(&self.owner_keys, owner))
            // NOTE: this encodes each entry of owner_shares as a separate ARGV[index] entry.
            .arg(owner_shares)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok(outdated) => {
                if !outdated.is_empty() {
                    tracing::info!(?outdated, "removed outdated triples");
                }
                outdated
            }
            Err(err) => {
                tracing::warn!(?err, "failed to remove outdated triples");
                Vec::new()
            }
        }
    }

    pub async fn fetch_mine(&self) -> StoreResult<Vec<TripleId>> {
        let mut conn = self.connect().await?;
        let result: Vec<TripleId> = conn.smembers(&self.mine_key).await?;
        Ok(result)
    }

    pub async fn fetch_foreign_ids(&self) -> StoreResult<Vec<TripleId>> {
        let mut conn = self.connect().await?;
        let result: Vec<TripleId> = conn.hkeys(&self.triple_key).await?;
        Ok(result)
    }

    async fn insert(&self, triple: Triple, owner: Participant, mine: bool) -> StoreResult<()> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local triple_key = KEYS[2]
            local used_key = KEYS[3]
            local reserved_key = KEYS[4]
            local owner_keys = KEYS[5]
            local owner_key = KEYS[6]
            local triple_id = ARGV[1]
            local triple_value = ARGV[2]
            local mine = ARGV[3]

            -- if the triple has not been reserved, then something went wrong when acquiring the
            -- reservation for it via triple slot.
            if redis.call("SREM", reserved_key, triple_id) == 0 then
                return {err = "WARN triple " .. triple_id .. " has NOT been reserved"}
            end

            if redis.call("HEXISTS", used_key, triple_id) == 1 then
                return {err = "WARN triple " .. triple_id .. " has already been used"}
            end

            redis.call("SADD", owner_key, triple_id)
            redis.call("SADD", owner_keys, owner_key)
            if mine == "true" then
                redis.call("SADD", mine_key, triple_id)
            end

            redis.call("HSET", triple_key, triple_id, triple_value)

            return "OK"
        "#;

        let _: String = redis::Script::new(script)
            .key(&self.mine_key)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(&self.owner_keys)
            .key(owner_key(&self.owner_keys, owner))
            .arg(triple.id)
            .arg(triple)
            .arg(mine.to_string())
            .invoke_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn contains(&self, id: TripleId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(&self.triple_key, id).await?;
        Ok(result)
    }

    pub async fn contains_mine(&self, id: TripleId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.sismember(&self.mine_key, id).await?;
        Ok(result)
    }

    pub async fn contains_used(&self, id: TripleId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(&self.used_key, id).await?;
        Ok(result)
    }

    // TODO: remove triple ids from owner set, or have eventual deletion thru sync.
    pub async fn take_two(&self, id1: TripleId, id2: TripleId) -> StoreResult<(Triple, Triple)> {
        let mut conn = self.connect().await?;

        let lua_script = r#"
            -- Check if the given IDs belong to the mine triples set
            if redis.call("SISMEMBER", KEYS[2], ARGV[1]) == 1 then
                return {err = "Triple " .. ARGV[1] .. " cannot be taken as foreign"}
            end

            if redis.call("SISMEMBER", KEYS[2], ARGV[2]) == 1 then
                return {err = "Triple " .. ARGV[2] .. " cannot be taken as foreign"}
            end

            -- Fetch the triples
            local v1 = redis.call("HGET", KEYS[1], ARGV[1])
            if not v1 then
                return {err = "Triple " .. ARGV[1] .. " is missing"}
            end

            local v2 = redis.call("HGET", KEYS[1], ARGV[2])
            if not v2 then
                return {err = "Triple " .. ARGV[2] .. " is missing"}
            end

            -- Delete the triples from the hash map and reserved slots
            redis.call("HDEL", KEYS[1], ARGV[1], ARGV[2])
            redis.call("SREM", KEYS[4], ARGV[1], ARGV[2])

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", KEYS[3], ARGV[1], "1", ARGV[2], "1")
            redis.call("HEXPIRE", KEYS[3], ARGV[3], "FIELDS", 2, ARGV[1], ARGV[2])

            -- Return the triples
            return {v1, v2}
        "#;

        let result: Result<(Triple, Triple), RedisError> = redis::Script::new(lua_script)
            .key(&self.triple_key)
            .key(&self.mine_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .arg(id1.to_string())
            .arg(id2.to_string())
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn take_two_mine(&self, me: Participant) -> StoreResult<Option<(Triple, Triple)>> {
        let mut conn = self.connect().await?;

        let lua_script = r#"
            -- Check the number of triples in the set
            local count = redis.call("SCARD", KEYS[1])

            if count < 2 then
                return nil
            end

            -- Pop two IDs atomically
            local id1 = redis.call("SPOP", KEYS[1])
            local id2 = redis.call("SPOP", KEYS[1])

            -- Retrieve the corresponding triples
            local v1 = redis.call("HGET", KEYS[2], id1)
            if not v1 then
                return {err = "Unexpected behavior. Triple " .. id1 .. " is missing"}
            end

            local v2 = redis.call("HGET", KEYS[2], id2)
            if not v2 then
                return {err = "Unexpected behavior. Triple " .. id2 .. " is missing"}
            end

            -- Delete the triples from the hash map
            redis.call("HDEL", KEYS[2], id1, id2)
            -- delete the triples from our self owner set
            redis.call("SREM", KEYS[4], id1, id2)

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", KEYS[3], id1, "1", id2, "1")
            redis.call("HEXPIRE", KEYS[3], ARGV[1], "FIELDS", 2, id1, id2)

            -- Return the triples as a response
            return {v1, v2}
        "#;

        redis::Script::new(lua_script)
            .key(&self.mine_key)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(&owner_key(&self.owner_keys, me))
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
            .map_err(StoreError::from)
    }

    pub async fn take_two_self(&self, t0: TripleId, t1: TripleId) -> StoreResult<(Triple, Triple)> {
        let mut conn = self.connect().await?;

        let lua_script = r#"
            local t0 = ARGV[1]
            local t1 = ARGV[2]
            -- remove the triples from mine set
            if not redis.call("SREM", KEYS[1], t0) then
                return {err = "WARN unable to remove mine triple " .. t0}
            end
            if not redis.call("SREM", KEYS[1], t1) then
                return {err = "WARN unable to remove mine triple " .. t1}
            end

            -- retrieve the corresponding triples
            local v1 = redis.call("HGET", KEYS[2], t0)
            if not v1 then
                return {err = "WARN unexpected, mine triple " .. t0 .. " is missing"}
            end

            local v2 = redis.call("HGET", KEYS[2], t1)
            if not v2 then
                return {err = "WARN unexpected, mine triple " .. t1 .. " is missing"}
            end

            -- delete the triples from the hash map
            redis.call("HDEL", KEYS[2], t0, t1)

            -- add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", KEYS[3], t0, "1", t1, "1")
            redis.call("HEXPIRE", KEYS[3], ARGV[3], "FIELDS", 2, t0, t1)

            return {v1, v2}
        "#;

        redis::Script::new(lua_script)
            .key(&self.mine_key)
            .key(&self.triple_key)
            .key(&self.used_key)
            .arg(t0)
            .arg(t1)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
            .map_err(StoreError::from)
    }

    pub async fn len_generated(&self) -> StoreResult<usize> {
        let mut conn = self.connect().await?;
        let result: usize = conn.hlen(&self.triple_key).await?;
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
            .key(&self.triple_key)
            .key(&self.mine_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .invoke_async(&mut conn)
            .await
            .map_err(StoreError::from)?;

        Ok(())
    }
}

impl ToRedisArgs for Triple {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Triple: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Triple {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Triple",
                e.to_string(),
            ))
        })
    }
}
