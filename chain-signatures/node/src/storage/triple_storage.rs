use std::fmt;

use crate::protocol::triple::{Triple, TripleId};

use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use near_account_id::AccountId;

use super::{owner_key, STORAGE_VERSION};

const USED_EXPIRE_TIME: Duration = Duration::hours(24);

/// A pre-reserved slot for a triple that will eventually be inserted.
#[derive(Clone)]
pub struct TripleSlot {
    id: TripleId,
    storage: TripleStorage,
    stored: bool,
}

impl TripleSlot {
    /// Inserts the triple into the storage, associating it with the given owner.
    /// Returns true if the insertion was successful, false otherwise.
    // TODO: put inside a tokio task:
    pub async fn insert(&mut self, triple: Triple, owner: Participant) -> bool {
        self.stored = self.storage.insert(triple, owner).await;
        self.stored
    }

    pub async fn unreserve(&self) {
        if !self.stored {
            self.storage.unreserve([self.id]).await;
        }
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
        if let Some(storage) = self.storage.take() {
            let id0 = self.id0;
            let id1 = self.id1;
            tokio::spawn(async move {
                storage.unreserve([id0, id1]).await;
            });
        }
    }
}

impl fmt::Debug for TriplesTakenDropper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TriplesTakenDropper")
            .field(&self.id0)
            .field(&self.id1)
            .finish()
    }
}

pub fn init(pool: &Pool, account_id: &AccountId) -> TripleStorage {
    let triple_key = format!("triples:{STORAGE_VERSION}:{account_id}");
    let used_key = format!("triples_used:{STORAGE_VERSION}:{account_id}");
    let reserved_key = format!("triples_reserved:{STORAGE_VERSION}:{account_id}");
    let owner_keys = format!("triples_owners:{STORAGE_VERSION}:{account_id}");

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
    async fn connect(&self) -> Option<Connection> {
        self.redis_pool
            .get()
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to connect to redis");
            })
            .ok()
    }

    pub async fn reserve(&self, id: TripleId) -> Option<TripleSlot> {
        const SCRIPT: &str = r#"
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

        let mut conn = self.connect().await?;
        let result: Result<(), _> = redis::Script::new(SCRIPT)
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
                stored: false,
            }),
            Err(err) => {
                tracing::warn!(?err, "failed to reserve triple");
                None
            }
        }
    }

    async fn unreserve<const N: usize>(&self, triples: [TripleId; N]) {
        let Some(mut conn) = self.connect().await else {
            return;
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
        const SCRIPT: &str = r#"
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

        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };
        let result: Result<Vec<TripleId>, _> = redis::Script::new(SCRIPT)
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
        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };

        conn.sunion((&self.reserved_key, owner_key(&self.owner_keys, me)))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to fetch (mine | reserved) triples");
            })
            .unwrap_or_default()
    }

    async fn insert(&self, triple: Triple, owner: Participant) -> bool {
        const SCRIPT: &str = r#"
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
        "#;

        let id = triple.id;
        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to insert triple: connection failed");
            return false;
        };
        let result: Result<(), _> = redis::Script::new(SCRIPT)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(&self.owner_keys)
            .key(owner_key(&self.owner_keys, owner))
            .arg(id)
            .arg(triple)
            .invoke_async(&mut conn)
            .await;

        if let Err(err) = result {
            tracing::warn!(id, ?err, "failed to insert triple into storage");
            false
        } else {
            true
        }
    }

    pub async fn contains(&self, id: TripleId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.triple_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if triple is stored");
                false
            }
        }
    }

    pub async fn contains_by_owner(&self, id: TripleId, owner: Participant) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };

        match conn.sismember(owner_key(&self.owner_keys, owner), id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if triple is owned by us");
                false
            }
        }
    }

    pub async fn contains_used(&self, id: TripleId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.used_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if triple in used set");
                false
            }
        }
    }

    pub async fn contains_reserved(&self, id: TripleId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.sismember(&self.reserved_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if triple in reserved set");
                false
            }
        }
    }

    /// Take two unspent triple by theirs id with no way to return it. Only takes
    /// if both of them are present.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two(
        &self,
        id1: TripleId,
        id2: TripleId,
        owner: Participant,
        me: Participant,
    ) -> Option<TriplesTaken> {
        const SCRIPT: &str = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local owner_key = KEYS[3]
            local mine_key = KEYS[4]
            local reserved_key = KEYS[5]
            local id1 = ARGV[1]
            local id2 = ARGV[2]

            local reserved = redis.call("SMISMEMBER", reserved_key, id1, id2)
            if reserved[1] == 1 or reserved[2] == 1 then
                return {err = "WARN triple " .. id1 .. " or " .. id2 .. " is generating or taken"}
            end

            -- check if the given triple id belong to us, if so then we cannot take it as foreign
            local check = redis.call("SMISMEMBER", mine_key, id1, id2)
            if check[1] == 1 or check[2] == 1 then
                return {err = "WARN triple " .. id1 .. " or " .. id2 .. " cannot be taken as foreign owned"}
            end

            -- check if the given triple id belong to the owner, if not then error out
            local check = redis.call("SMISMEMBER", owner_key, id1, id2)
            if check[1] == 0 or check[2] == 0 then
                return {err = "WARN triple " .. id1 .. " or " .. id2 .. " cannot be taken by incorrect owner " .. owner_key}
            end

            -- fetch the triples and delete them once successfully fetched
            local triples = redis.call("HMGET", triple_key, id1, id2)
            if not triples[1] then
                return {err = "WARN unexpected, triple " .. id1 .. " is missing"}
            end
            if not triples[2] then
                return {err = "WARN unexpected, triple " .. id2 .. " is missing"}
            end
            redis.call("HDEL", triple_key, id1, id2)
            redis.call("SREM", owner_key, id1, id2)

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", used_key, id1, "1", id2, "1")
            redis.call("HEXPIRE", used_key, ARGV[3], "FIELDS", 2, id1, id2)

            return triples
        "#;

        let mut conn = self.connect().await?;
        match redis::Script::new(SCRIPT)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, owner))
            .key(owner_key(&self.owner_keys, me))
            .key(&self.reserved_key)
            .arg(id1)
            .arg(id2)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
        {
            Ok((triple0, triple1)) => {
                tracing::debug!(id1, id2, "took two triples");
                Some(TriplesTaken::foreigner(triple0, triple1))
            }
            Err(err) => {
                tracing::warn!(id1, id2, ?err, "failed to take two triples from storage");
                None
            }
        }
    }

    pub async fn take_two_mine(&self, me: Participant) -> Option<TriplesTaken> {
        const SCRIPT: &str = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local mine_key = KEYS[3]
            local reserved_key = KEYS[4]
            local expire_time = ARGV[1]

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

            -- reserve the triples again, since the owner is taking them here, and should
            -- not invalidate the other nodes when syncing.
            redis.call("SADD", reserved_key, unpack(triple_ids))

            -- Delete the triples from the hash map
            redis.call("HDEL", triple_key, unpack(triple_ids))
            -- delete the triples from our self owner set
            redis.call("SREM", mine_key, unpack(triple_ids))

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", used_key, triple_ids[1], "1", triple_ids[2], "1")
            redis.call("HEXPIRE", used_key, expire_time, "FIELDS", 2, unpack(triple_ids))

            -- Return the triples as a response
            return triples
        "#;

        let mut conn = self.connect().await?;
        match redis::Script::new(SCRIPT)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, me))
            .key(&self.reserved_key)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
        {
            Ok(Some((triple0, triple1))) => {
                Some(TriplesTaken::owner(triple0, triple1, self.clone()))
            }
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(?err, "failed to take two mine triples from storage");
                None
            }
        }
    }

    /// Checks if the storage is empty.
    pub async fn is_empty(&self) -> bool {
        self.len_generated().await == 0
    }

    /// Get the number of unspent triples that were generated by this node.
    pub async fn len_generated(&self) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.hlen(&self.triple_key)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of generated triples");
            })
            .unwrap_or(0)
    }

    /// Get the number of unspent triples by a specific owner.
    pub async fn len_by_owner(&self, owner: Participant) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.scard(owner_key(&self.owner_keys, owner))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of my triples");
            })
            .unwrap_or(0)
    }

    /// Clear all triple storage, including used, reserved, and owned keys.
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
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .invoke_async(&mut conn)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to clear triple storage");
            })
            .ok();

        // if the outcome is None, it means the script failed or there was an error.
        outcome.is_some()
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
