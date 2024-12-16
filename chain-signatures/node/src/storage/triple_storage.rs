use crate::protocol::triple::{Triple, TripleId};
use crate::storage::error::{StoreError, StoreResult};

use deadpool_redis::{Connection, Pool};
use redis::{AsyncCommands, FromRedisValue, RedisWrite, ToRedisArgs};

use near_account_id::AccountId;

// Can be used to "clear" redis storage in case of a breaking change
const TRIPLE_STORAGE_VERSION: &str = "v2";

pub fn init(pool: &Pool, account_id: &AccountId) -> TripleStorage {
    TripleStorage {
        redis_pool: pool.clone(),
        node_account_id: account_id.clone(),
    }
}

#[derive(Clone)]
pub struct TripleStorage {
    redis_pool: Pool,
    node_account_id: AccountId,
}

impl TripleStorage {
    async fn connect(&self) -> StoreResult<Connection> {
        self.redis_pool
            .get()
            .await
            .map_err(anyhow::Error::new)
            .map_err(StoreError::Connect)
    }

    pub async fn insert(&self, triple: Triple, mine: bool) -> StoreResult<()> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local triple_key = KEYS[2]
            local triple_id = ARGV[1]
            local triple_value = ARGV[2]
            local mine = ARGV[3]

            if mine == "true" then
                redis.call("SADD", mine_key, triple_id)
            end

            redis.call("HSET", triple_key, triple_id, triple_value)

            return "OK"
        "#;

        let _: String = redis::Script::new(script)
            .key(self.mine_key())
            .key(self.triple_key())
            .arg(triple.id)
            .arg(triple)
            .arg(mine)
            .invoke_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn contains(&self, id: TripleId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(self.triple_key(), id).await?;
        Ok(result)
    }

    pub async fn contains_mine(&self, id: TripleId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.sismember(self.mine_key(), id).await?;
        Ok(result)
    }

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
    
            -- Delete the triples from the hash map
            redis.call("HDEL", KEYS[1], ARGV[1], ARGV[2])
    
            -- Return the triples
            return {v1, v2}
        "#;

        let result: Result<(Triple, Triple), redis::RedisError> = redis::Script::new(lua_script)
            .key(self.triple_key())
            .key(self.mine_key())
            .arg(id1.to_string())
            .arg(id2.to_string())
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn take_two_mine(&self) -> StoreResult<(Triple, Triple)> {
        let mut conn = self.connect().await?;

        let lua_script = r#"
            -- Check the number of triples in the set
            local count = redis.call("SCARD", KEYS[1])
    
            if count < 2 then
                return {err = "Mine triple stockpile does not have enough triples"}
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
    
            -- Return the triples as a response
            return {v1, v2}
        "#;

        let result: Result<(Triple, Triple), redis::RedisError> = redis::Script::new(lua_script)
            .key(self.mine_key())
            .key(self.triple_key())
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn len_generated(&self) -> StoreResult<usize> {
        let mut conn = self.connect().await?;
        let result: usize = conn.hlen(self.triple_key()).await?;
        Ok(result)
    }

    pub async fn len_mine(&self) -> StoreResult<usize> {
        let mut conn = self.connect().await?;
        let result: usize = conn.scard(self.mine_key()).await?;
        Ok(result)
    }

    pub async fn clear(&self) -> StoreResult<()> {
        let mut conn = self.connect().await?;
        conn.del::<&str, ()>(&self.triple_key()).await?;
        conn.del::<&str, ()>(&self.mine_key()).await?;
        Ok(())
    }

    fn triple_key(&self) -> String {
        format!(
            "triples:{}:{}",
            TRIPLE_STORAGE_VERSION, self.node_account_id
        )
    }

    fn mine_key(&self) -> String {
        format!(
            "triples_mine:{}:{}",
            TRIPLE_STORAGE_VERSION, self.node_account_id
        )
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
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Triple",
                e.to_string(),
            ))
        })
    }
}
