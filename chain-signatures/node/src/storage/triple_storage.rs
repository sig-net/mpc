use std::fmt;
use std::time::Instant;

use crate::protocol::triple::{Triple, TripleId};

use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};
use serde::{Deserialize, Serialize};

use near_account_id::AccountId;

use super::{owner_key, STORAGE_VERSION};

const USED_EXPIRE_TIME: Duration = Duration::hours(24);

/// A pair of completed triples.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriplePair {
    pub id: TripleId,
    pub triple0: Triple,
    pub triple1: Triple,
}

impl ToRedisArgs for TriplePair {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize TriplePair: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for TriplePair {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize TriplePair",
                e.to_string(),
            ))
        })
    }
}

/// A pre-reserved slot for a triple pair that will eventually be inserted.
pub struct TriplePairSlot {
    id: TripleId,
    storage: TripleStorage,
    stored: bool,
}

impl TriplePairSlot {
    /// Inserts the triple pair into the storage, associating it with the given owner.
    /// Returns true if the insertion was successful, false otherwise.
    // TODO: put inside a tokio task:
    pub async fn insert(&mut self, pair: TriplePair, owner: Participant) -> bool {
        self.stored = self.storage.insert_pair(pair, owner).await;
        self.stored
    }

    pub async fn unreserve(&self) {
        if !self.stored {
            self.storage.unreserve_pair([self.id]).await;
        }
    }
}

impl Drop for TriplePairSlot {
    fn drop(&mut self) {
        if !self.stored {
            let storage = self.storage.clone();
            let id = self.id;
            // If the slot was not stored, we need to unreserve it.
            tokio::spawn(async move {
                storage.unreserve_pair([id]).await;
            });
        }
    }
}

pub struct TriplesTaken {
    pub pair: TriplePair,
    pub dropper: TriplesTakenDropper,
}

impl TriplesTaken {
    pub fn owner(pair: TriplePair, storage: TripleStorage) -> Self {
        let dropper = TriplesTakenDropper {
            pair_id: pair.id,
            storage: Some(storage),
        };
        Self { pair, dropper }
    }

    pub fn foreigner(pair: TriplePair) -> Self {
        let dropper = TriplesTakenDropper {
            pair_id: pair.id,
            storage: None,
        };
        Self { pair, dropper }
    }

    pub fn take(self) -> (TriplePair, TriplesTakenDropper) {
        (self.pair, self.dropper)
    }
}

impl fmt::Debug for TriplesTaken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TriplesTaken").field(&self.pair.id).finish()
    }
}

pub struct TriplesTakenDropper {
    pub pair_id: TripleId,
    storage: Option<TripleStorage>,
}

impl Drop for TriplesTakenDropper {
    fn drop(&mut self) {
        if let Some(storage) = self.storage.take() {
            let pair_id = self.pair_id;
            tokio::spawn(async move {
                storage.unreserve_pair([pair_id]).await;
            });
        }
    }
}

impl fmt::Debug for TriplesTakenDropper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TriplesTakenDropper")
            .field(&self.pair_id)
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
        account_id: account_id.clone(),
    }
}

#[derive(Clone)]
pub struct TripleStorage {
    redis_pool: Pool,
    triple_key: String,
    used_key: String,
    reserved_key: String,
    owner_keys: String,
    account_id: AccountId,
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

    pub async fn reserve(&self, id: TripleId) -> Option<TriplePairSlot> {
        let start = Instant::now();

        const SCRIPT: &str = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local pair_id = ARGV[1]

            -- cannot reserve this pair if it already exists.
            if redis.call("SADD", reserved_key, pair_id) == 0 then
                return {err = "WARN pair " .. pair_id .. " has already been reserved"}
            end

            -- cannot reserve this pair if its already in storage.
            if redis.call("HEXISTS", triple_key, pair_id) == 1 then
                return {err = "WARN pair " .. pair_id .. " has already been stored"}
            end

            -- cannot reserve this pair if it has already been used.
            if redis.call("HEXISTS", used_key, pair_id) == 1 then
                return {err = "WARN pair " .. pair_id .. " has already been used"}
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

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "reserve_pair", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(_) => Some(TriplePairSlot {
                id,
                storage: self.clone(),
                stored: false,
            }),
            Err(err) => {
                tracing::warn!(
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to reserve pair"
                );
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

    async fn unreserve_pair(&self, pairs: [TripleId; 1]) {
        self.unreserve(pairs).await;
    }

    pub async fn remove_outdated(
        &self,
        owner: Participant,
        owner_shares: &[TripleId],
    ) -> Vec<TripleId> {
        let start = Instant::now();

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

                -- remove the outdated shares from our node if we have too many
                -- already to be able to process them in one go.
                if #outdated >= 4096 then
                    redis.call("SREM", owner_key, unpack(outdated))
                    redis.call("SREM", reserved_key, unpack(outdated))
                    redis.call("HDEL", triple_key, unpack(outdated))
                    -- clear the outdated list for the next batchw
                    outdated = {}
                end
            end

            -- remove the remaining outdated shares from our node
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

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "remove_outdated", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(outdated) => {
                if !outdated.is_empty() {
                    tracing::info!(
                        ?outdated,
                        elapsed_ms = elapsed.as_millis(),
                        "removed outdated triples"
                    );
                }
                outdated
            }
            Err(err) => {
                tracing::warn!(
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to remove outdated triples"
                );
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

    async fn insert_pair(&self, pair: TriplePair, owner: Participant) -> bool {
        let start = Instant::now();

        const SCRIPT: &str = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local owner_keys = KEYS[4]
            local owner_key = KEYS[5]
            local pair_id = ARGV[1]
            local pair = ARGV[2]

            -- if the pair has not been reserved, then something went wrong when acquiring the
            -- reservation for it via triple pair slot.
            if redis.call("SREM", reserved_key, pair_id) == 0 then
                return {err = "WARN pair " .. pair_id .. " has NOT been reserved"}
            end

            if redis.call("HEXISTS", used_key, pair_id) == 1 then
                return {err = "WARN pair " .. pair_id .. " has already been used"}
            end

            redis.call("SADD", owner_key, pair_id)
            redis.call("SADD", owner_keys, owner_key)
            redis.call("HSET", triple_key, pair_id, pair)
        "#;

        let id = pair.id;
        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to insert pair: connection failed");
            return false;
        };
        let result: Result<(), _> = redis::Script::new(SCRIPT)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(&self.owner_keys)
            .key(owner_key(&self.owner_keys, owner))
            .arg(id)
            .arg(pair)
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "insert_pair", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        if let Err(err) = result {
            tracing::warn!(
                id,
                ?err,
                elapsed_ms = elapsed.as_millis(),
                "failed to insert pair into storage"
            );
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

    /// Take a triple pair by its id. Only takes if it is present.
    /// It is very important to NOT reuse the same pair twice for two different
    /// protocols.
    pub async fn take(
        &self,
        id: TripleId,
        owner: Participant,
        me: Participant,
    ) -> Option<TriplesTaken> {
        const SCRIPT: &str = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local owner_key = KEYS[3]
            local mine_key = KEYS[4]
            local reserved_key = KEYS[5]
            local pair_id = ARGV[1]

            local reserved = redis.call("SMISMEMBER", reserved_key, pair_id)
            if reserved[1] == 1 then
                return {err = "WARN pair " .. pair_id .. " is generating or taken"}
            end

            -- check if the given pair id belong to us, if so then we cannot take it as foreign
            local check = redis.call("SMISMEMBER", mine_key, pair_id)
            if check[1] == 1 then
                return {err = "WARN pair " .. pair_id .. " cannot be taken as foreign owned"}
            end

            -- check if the given pair id belong to the owner, if not then error out
            local check = redis.call("SMISMEMBER", owner_key, pair_id)
            if check[1] == 0 then
                return {err = "WARN pair " .. pair_id .. " cannot be taken by incorrect owner " .. owner_key}
            end

            -- fetch the pair and delete it once successfully fetched
            local pair = redis.call("HGET", triple_key, pair_id)
            if not pair then
                return {err = "WARN unexpected, pair " .. pair_id .. " is missing"}
            end
            redis.call("HDEL", triple_key, pair_id)
            redis.call("SREM", owner_key, pair_id)

            -- Add the pair to the used set and set expiration time.
            redis.call("HSET", used_key, pair_id, "1")
            redis.call("HEXPIRE", used_key, ARGV[2], "FIELDS", 1, pair_id)

            return pair
        "#;

        let start = Instant::now();
        let mut conn = self.connect().await?;
        let result = redis::Script::new(SCRIPT)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, owner))
            .key(owner_key(&self.owner_keys, me))
            .key(&self.reserved_key)
            .arg(id)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "take", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(pair) => {
                tracing::debug!(id, elapsed_ms = elapsed.as_millis(), "took pair");
                Some(TriplesTaken::foreigner(pair))
            }
            Err(err) => {
                tracing::warn!(
                    id,
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to take pair from storage"
                );
                None
            }
        }
    }

    /// Take a random unspent triple pair generated by this node.
    /// It is very important to NOT reuse the same pair twice for two different
    /// protocols.
    pub async fn take_mine(&self, me: Participant) -> Option<TriplesTaken> {
        const SCRIPT: &str = r#"
            local triple_key = KEYS[1]
            local used_key = KEYS[2]
            local mine_key = KEYS[3]
            local reserved_key = KEYS[4]
            local expire_time = ARGV[1]

            if redis.call("SCARD", mine_key) < 1 then
                return nil
            end

            -- pop one pair from the self owner set and delete it once successfully fetched
            local pair_ids = redis.call("SPOP", mine_key, 1)
            local pair = redis.call("HGET", triple_key, pair_ids[1])
            if not pair then
                return {err = "WARN unexpected, pair " .. pair_ids[1] .. " is missing"}
            end

            -- reserve the pair again, since the owner is taking it here, and should
            -- not invalidate the other nodes when syncing.
            redis.call("SADD", reserved_key, pair_ids[1])

            -- Delete the pair from the hash map
            redis.call("HDEL", triple_key, pair_ids[1])
            -- delete the pair from our self owner set
            redis.call("SREM", mine_key, pair_ids[1])

            -- Add the pair to the used set and set expiration time.
            redis.call("HSET", used_key, pair_ids[1], "1")
            redis.call("HEXPIRE", used_key, expire_time, "FIELDS", 1, pair_ids[1])

            -- Return the pair as a response
            return pair
        "#;

        let start = Instant::now();
        let mut conn = self.connect().await?;
        let result = redis::Script::new(SCRIPT)
            .key(&self.triple_key)
            .key(&self.used_key)
            .key(owner_key(&self.owner_keys, me))
            .key(&self.reserved_key)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "take_mine", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(Some(pair)) => {
                let taken = TriplesTaken::owner(pair, self.clone());
                tracing::debug!(
                    id = taken.pair.id,
                    elapsed_ms = elapsed.as_millis(),
                    "took mine pair"
                );
                Some(taken)
            }
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to take mine pair from storage"
                );
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

        let start = Instant::now();
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
                let elapsed = start.elapsed();
                tracing::warn!(
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to clear triple storage"
                );
            })
            .ok();

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "clear", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

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

#[cfg(feature = "test-feature")]
impl TripleStorage {
    pub fn triple_key(&self) -> &str {
        &self.triple_key
    }
}
