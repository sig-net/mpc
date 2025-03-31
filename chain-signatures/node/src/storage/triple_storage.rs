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
    storage: TripleStorage,
}

impl TripleSlot {
    // TODO: put inside a tokio task:
    pub async fn insert(&self, triple: Triple, owner: Participant) -> bool {
        if let Err(err) = self.storage.insert(triple, owner).await {
            tracing::warn!(id = self.id, ?err, "failed to insert triple");
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
            tracing::warn!(id = self.id, ?err, "failed to unreserve triple");
        }
    }
}

pub fn init(pool: &Pool, account_id: &AccountId) -> TripleStorage {
    let triple_key = format!("triples:{}:{}", TRIPLE_STORAGE_VERSION, account_id);
    let used_key = format!("triples_used:{}:{}", TRIPLE_STORAGE_VERSION, account_id);
    let reserved_key = format!("triples_reserved:{}:{}", TRIPLE_STORAGE_VERSION, account_id);
    let owner_keys = format!("triples_owners:{}:{}", TRIPLE_STORAGE_VERSION, account_id);

    TripleStorage {
        redis_pool: pool.clone(),
        triple_key,
        used_key,
        reserved_key,
        owner_keys,
    }
}

#[derive(Clone)]
pub struct TripleStorage {
    redis_pool: Pool,
    triple_key: String,
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
    pub async fn reserve(&self, id: TripleId) -> Option<TripleSlot> {
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

    // TODO: me can potentially be integrated into storage if we eventually can wait for our own participant info to be determined.
    pub async fn fetch_owned(&self, me: Participant) -> Vec<TripleId> {
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
                tracing::warn!(?err, "failed to fetch (mine | reserved) triples");
            })
            .unwrap_or_default()
    }

    async fn insert(&self, triple: Triple, owner: Participant) -> StoreResult<()> {
        let mut conn = self.connect().await?;

        let script = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local owner_keys = KEYS[4]
            local owner_key = KEYS[5]
            local triple_id = ARGV[1]
            local triple = ARGV[2]

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
            redis.call("HSET", triple_key, triple_id, triple)

            return "OK"
        "#;

        let _: String = redis::Script::new(script)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(&self.owner_keys)
            .key(owner_key(&self.owner_keys, owner))
            .arg(triple.id)
            .arg(triple)
            .invoke_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn contains(&self, id: TripleId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(&self.triple_key, id).await?;
        Ok(result)
    }

    pub async fn contains_mine(&self, id: TripleId, me: Participant) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.sismember(owner_key(&self.owner_keys, me), id).await?;
        Ok(result)
    }

    pub async fn contains_used(&self, id: TripleId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(&self.used_key, id).await?;
        Ok(result)
    }

    // TODO: need to pass in owner to delete the triple from the owner set, but we can have sync just do this
    //       for now for us.
    pub async fn take_two(
        &self,
        id1: TripleId,
        id2: TripleId,
        owner: Participant,
        me: Participant,
    ) -> StoreResult<(Triple, Triple)> {
        let mut conn = self.connect().await?;

        let lua_script = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local owner_key = KEYS[3]
            local mine_key = KEYS[4]
            local triple_id1 = ARGV[1]
            local triple_id2 = ARGV[2]

            -- check if the given triple id belong to us, if so then we cannot take it as foreign
            local check = redis.call("SMISMEMBER", mine_key, triple_id1, triple_id2)
            if check[1] == 1 then
                return {err = "WARN triple " .. triple_id1 .. " cannot be taken as foreign owned"}
            end
            if check[2] == 1 then
                return {err = "WARN triple " .. triple_id2 .. " cannot be taken as foreign owned"}
            end

            -- check if the given triple id belong to the owner, if so then we cannot take it as foreign
            check = redis.call("SMISMEMBER", owner_key, triple_id1, triple_id2)
            if check[1] == 0 then
                return {err = "WARN triple " .. triple_id1 .. " cannot by different owner " .. owner_key}
            end
            if check[2] == 0 then
                return {err = "WARN triple " .. triple_id2 .. " cannot by different owner " .. owner_key }
            end

            -- fetch the triples and delete them once successfully fetched
            local triples = redis.call("HMGET", triple_key, triple_id1, triple_id2)
            if not triples[1] then
                return {err = "WARN unexpected, triple " .. triple_id1 .. " is missing"}
            end
            if not triples[2] then
                return {err = "WARN unexpected, triple " .. triple_id2 .. " is missing"}
            end
            redis.call("HDEL", triple_key, triple_id1, triple_id2)
            redis.call("SREM", owner_key, triple_id1, triple_id2)

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", used_key, triple_id1, "1", triple_id2, "1")
            redis.call("HEXPIRE", used_key, ARGV[3], "FIELDS", 2, triple_id1, triple_id2)

            -- Return the triples
            return triples
        "#;

        let result: Result<(Triple, Triple), RedisError> = redis::Script::new(lua_script)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, owner))
            .key(owner_key(&self.owner_keys, me))
            .arg(id1)
            .arg(id2)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn take_two_mine(&self, me: Participant) -> StoreResult<Option<(Triple, Triple)>> {
        let mut conn = self.connect().await?;

        let lua_script = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local mine_key = KEYS[3]

            if redis.call("SCARD", mine_key) < 2 then
                return nil
            end

            -- pop two triples from the self owner set and delete them once successfully fetched
            local triple_ids = redis.call("SPOP", mine_key, 2)
            local triples = redis.call("HMGET", triple_key, unpack(triple_ids))
            if not triples[1] then
                return {err = "WARN unexpected, triple " .. triple_ids[1] .. " is missing"}
            end
            if not triples[2] then
                return {err = "WARN unexpected, triple " .. triple_ids[2] .. " is missing"}
            end
            redis.call("HDEL", triple_key, unpack(triple_ids))

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", used_key, triple_ids[1], "1", triple_ids[2], "1")
            redis.call("HEXPIRE", used_key, ARGV[1], "FIELDS", 2, unpack(triple_ids))

            -- Return the triples as a response
            return triples
        "#;

        redis::Script::new(lua_script)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, me))
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

    pub async fn len_mine(&self, me: Participant) -> StoreResult<usize> {
        let mut conn = self.connect().await?;
        let result: usize = conn.scard(owner_key(&self.owner_keys, me)).await?;
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
