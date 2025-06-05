use std::fmt;

use crate::protocol::triple::{Triple, TripleId};

use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::Pool;
use redis::{FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use near_account_id::AccountId;

const USED_EXPIRE_TIME: Duration = Duration::hours(24);

/// A pre-reserved slot for a triple that will eventually be inserted.
#[derive(Clone)]
pub struct TripleSlot {
    id: TripleId,
    storage: TripleStorage,
    stored: bool,
}

impl TripleSlot {
    pub fn new(id: TripleId, storage: TripleStorage) -> Self {
        Self {
            id,
            storage,
            stored: false,
        }
    }

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

pub type TripleStorage = super::ProtocolStorage<Triple>;

impl TripleStorage {
    pub fn new(redis: Pool, account_id: &AccountId) -> Self {
        Self::init("triple", redis, account_id)
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
            local participant_keys = KEYS[6]
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
            redis.call("DEL", participant_keys .. ":" .. id1, participant_keys .. ":" .. id2)

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", used_key, id1, "1", id2, "1")
            redis.call("HEXPIRE", used_key, ARGV[3], "FIELDS", 2, id1, id2)

            return triples
        "#;

        let mut conn = self.connect().await?;
        match redis::Script::new(SCRIPT)
            .key(&self.protocol_key)
            .key(&self.used_key)
            .key(self.owner_key(owner))
            .key(self.owner_key(me))
            .key(&self.reserved_key)
            .key(&self.participant_keys)
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

    /// Take two random unspent triple generated by this node. Either takes both or none.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two_mine(&self, me: Participant) -> Option<TriplesTaken> {
        const SCRIPT: &str = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local mine_key = KEYS[3]
            local reserved_key = KEYS[4]
            local participant_keys = KEYS[5]
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
            -- delete participant set associated with these triples
            redis.call("DEL", participant_keys .. ":" .. triple_ids[1], participant_keys .. ":" .. triple_ids[2])

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", used_key, triple_ids[1], "1", triple_ids[2], "1")
            redis.call("HEXPIRE", used_key, expire_time, "FIELDS", 2, unpack(triple_ids))

            -- Return the triples as a response
            return triples
        "#;

        let mut conn = self.connect().await?;
        match redis::Script::new(SCRIPT)
            .key(&self.protocol_key)
            .key(&self.used_key)
            .key(self.owner_key(me))
            .key(&self.reserved_key)
            .key(&self.participant_keys)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
        {
            Ok(Some((triple0, triple1))) => {
                let taken = TriplesTaken::owner(triple0, triple1, self.clone());
                tracing::debug!(
                    id0 = taken.triple0.id,
                    id1 = taken.triple1.id,
                    "took two mine triples"
                );
                Some(taken)
            }
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(?err, "failed to take two mine triples from storage");
                None
            }
        }
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
