use std::fmt;

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
            false
        } else {
            true
        }
    }

    // TODO: put inside a tokio task:
    pub async fn unreserve(&self) {
        self.storage.unreserve([self.id]).await;
    }
}

pub struct TriplesTaken {
    pub triple0: Triple,
    pub triple1: Triple,
    pub dropper: TriplesTakenDropper,
}

impl TriplesTaken {
    pub fn owner(triple0: Triple, triple1: Triple, storage: TripleStorage) -> Self {
        let dropper = TriplesTakenDropper {
            id0: triple0.id,
            id1: triple1.id,
            storage: Some(storage),
        };
        Self {
            triple0,
            triple1,
            dropper,
        }
    }

    pub fn foreigner(triple0: Triple, triple1: Triple) -> Self {
        let dropper = TriplesTakenDropper {
            id0: triple0.id,
            id1: triple1.id,
            storage: None,
        };
        Self {
            triple0,
            triple1,
            dropper,
        }
    }

    pub fn take(self) -> (Triple, Triple, TriplesTakenDropper) {
        (self.triple0, self.triple1, self.dropper)
    }
}

impl fmt::Debug for TriplesTaken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TriplesTaken")
            .field(&self.triple0.id)
            .field(&self.triple1.id)
            .finish()
    }
}

pub struct TriplesTakenDropper {
    pub id0: TripleId,
    pub id1: TripleId,
    storage: Option<TripleStorage>,
}

impl Drop for TriplesTakenDropper {
    fn drop(&mut self) {
        let Some(storage) = self.storage.take() else {
            return;
        };
        let id0 = self.id0;
        let id1 = self.id1;
        tokio::spawn(async move {
            tracing::info!(id0, id1, "dropping taken triples");
            storage.unreserve([id0, id1]).await;
        });
    }
}

impl fmt::Debug for TriplesTakenDropper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TriplesTakenRef")
            .field(&self.id0)
            .field(&self.id1)
            .finish()
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

    async fn unreserve<const N: usize>(&self, triples: [TripleId; N]) {
        let mut conn = match self.connect().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(?err, "failed to connect to redis");
                return;
            }
        };
        let outcome: Result<(), _> = conn.srem(&self.reserved_key, &triples).await;
        if let Err(err) = outcome {
            tracing::warn!(?triples, ?err, "failed to unreserve triples");
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

    // TODO: need to pass in owner to delete the triple from the owner set, but we can have sync just do this
    //       for now for us.
    pub async fn take_two(&self, id1: TripleId, id2: TripleId) -> StoreResult<TriplesTaken> {
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

        let (triple0, triple1): (Triple, Triple) = redis::Script::new(lua_script)
            .key(&self.triple_key)
            .key(&self.mine_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .arg(id1.to_string())
            .arg(id2.to_string())
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
            .map_err(StoreError::from)?;

        Ok(TriplesTaken::foreigner(triple0, triple1))
    }

    pub async fn take_two_mine(&self, me: Participant) -> StoreResult<Option<TriplesTaken>> {
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

            -- reserve the triples again, since the owner is taking them here, and should
            -- not invalidate the other nodes when syncing.
            redis.call("SADD", KEYS[5], id1, id2)

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

        let triples: Option<(Triple, Triple)> = redis::Script::new(lua_script)
            .key(&self.mine_key)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, me))
            .key(&self.reserved_key)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
            .map_err(StoreError::from)?;

        let Some((triple0, triple1)) = triples else {
            return Ok(None);
        };

        Ok(Some(TriplesTaken::owner(triple0, triple1, self.clone())))
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
