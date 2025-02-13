use crate::protocol::triple::{Triple, TripleId};
use crate::storage::error::{StoreError, StoreResult};

use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use near_account_id::AccountId;

// Can be used to "clear" redis storage in case of a breaking change
const TRIPLE_STORAGE_VERSION: &str = "v6";
const USED_EXPIRE_TIME: Duration = Duration::hours(24);

pub fn init(pool: &Pool, account_id: &AccountId) -> TripleStorage {
    let triple_key = format!("triples:{}:{}", TRIPLE_STORAGE_VERSION, account_id);
    let mine_key = format!("triples_mine:{}:{}", TRIPLE_STORAGE_VERSION, account_id);
    let used_key = format!("triples_used:{}:{}", TRIPLE_STORAGE_VERSION, account_id);

    TripleStorage {
        redis_pool: pool.clone(),
        triple_key,
        mine_key,
        used_key,
    }
}

#[derive(Clone)]
pub struct TripleStorage {
    redis_pool: Pool,
    triple_key: String,
    mine_key: String,
    used_key: String,
}

impl TripleStorage {
    async fn connect(&self) -> StoreResult<Connection> {
        self.redis_pool
            .get()
            .await
            .map_err(anyhow::Error::new)
            .map_err(StoreError::Connect)
    }

    pub async fn insert(&self, triple: Triple, mine: bool, back: bool) -> StoreResult<()> {
        let script = format!(
            r#"
            local triple_id = ARGV[1]
            local triple_value = ARGV[2]

            if {back} then
                redis.call("HDEL", "{used_key}", triple_id)
            elseif redis.call("HEXISTS", "{used_key}", triple_id) == 1 then
                return {{err = "warn: triple " .. triple_id .. " has already been used"}}
            end

            if {mine} then
                redis.call("SADD", "{mine_key}", triple_id)
            end

            redis.call("HSET", "{triple_key}", triple_id, triple_value)

            return "OK"
        "#,
            mine_key = self.mine_key,
            triple_key = self.triple_key,
            used_key = self.used_key,
        );

        let mut conn = self.connect().await?;
        let _: String = redis::Script::new(&script)
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

    pub async fn take_two(&self, id1: TripleId, id2: TripleId) -> StoreResult<(Triple, Triple)> {
        let script = format!(
            r#"
            -- Check if the given IDs belong to the mine triples set
            local forein_triple = redis.call("SMISMEMBER", "{mine_key}", ARGV[1], ARGV[2])
            if forein_triple[1] == 1 then
                return {{err = "warn: triple " .. ARGV[1] .. " cannot be taken as foreign"}}
            end
            if forein_triple[2] == 1 then
                return {{err = "warn: triple " .. ARGV[2] .. " cannot be taken as foreign"}}
            end

            -- Fetch the triples
            local values = redis.call("HMGET", "{triple_key}", ARGV[1], ARGV[2])
            local v1, v2 = values[1], values[2]
            if not v1 then
                return {{err = "warn: triple " .. ARGV[2] .. " is missing"}}
            end
            if not v2 then
                return {{err = "warn: triple " .. ARGV[2] .. " is missing"}}
            end

            -- Delete the triples from the hash map
            redis.call("HDEL", "{triple_key}", ARGV[1], ARGV[2])

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", "{used_key}", ARGV[1], "1", ARGV[2], "1")
            redis.call("HEXPIRE", "{used_key}", {expire_secs}, "FIELDS", 2, ARGV[1], ARGV[2])

            -- Return the triples
            return {{v1, v2}}
        "#,
            triple_key = self.triple_key,
            mine_key = self.mine_key,
            used_key = self.used_key,
            expire_secs = USED_EXPIRE_TIME.num_seconds(),
        );

        let mut conn = self.connect().await?;
        let result: Result<(Triple, Triple), RedisError> = redis::Script::new(&script)
            .arg(id1.to_string())
            .arg(id2.to_string())
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn take_two_mine(&self) -> StoreResult<Option<(Triple, Triple)>> {
        let script = format!(
            r#"
            -- Pop two IDs atomically
            local ids = redis.call("SPOP", "{mine_key}", 2)
            -- Ensure we have exactly two IDs
            if not ids or #ids < 2 then
                return nil
            end
            local id1, id2 = ids[1], ids[2]

            -- Retrieve the corresponding triples
            local values = redis.call("HMGET", "{triple_key}", id1, id2)
            local v1, v2 = values[1], values[2]
            if not v1 then
                return {{err = "warn: unexpected behavior, triple " .. id1 .. " is missing"}}
            end
            if not v2 then
                return {{err = "warn: unexpected behavior, triple " .. id2 .. " is missing"}}
            end

            -- Delete the triples from the hash map
            redis.call("HDEL", "{triple_key}", id1, id2)

            -- Add the triples to the used set and set expiration time. Note, HSET is used so
            -- we can expire on each field instead of the whole hash set.
            redis.call("HSET", "{used_key}", id1, "1", id2, "1")
            redis.call("HEXPIRE", "{used_key}", {expire_secs}, "FIELDS", 2, id1, id2)

            -- Return the triples as a response
            return {{v1, v2}}
        "#,
            mine_key = self.mine_key,
            triple_key = self.triple_key,
            used_key = self.used_key,
            expire_secs = USED_EXPIRE_TIME.num_seconds(),
        );

        let mut conn = self.connect().await?;
        redis::Script::new(&script)
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
        conn.del::<&str, ()>(&self.triple_key).await?;
        conn.del::<&str, ()>(&self.mine_key).await?;
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
