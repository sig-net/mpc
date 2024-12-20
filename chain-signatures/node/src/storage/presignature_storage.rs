use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, RedisWrite, ToRedisArgs};

use crate::protocol::presignature::{Presignature, PresignatureId};
use crate::storage::error::{StoreError, StoreResult};

// Can be used to "clear" redis storage in case of a breaking change
const PRESIGNATURE_STORAGE_VERSION: &str = "v2";

pub fn init(pool: &Pool, node_account_id: &AccountId) -> PresignatureStorage {
    PresignatureStorage {
        redis_pool: pool.clone(),
        node_account_id: node_account_id.clone(),
    }
}

#[derive(Clone)]
pub struct PresignatureStorage {
    redis_pool: Pool,
    node_account_id: AccountId,
}

impl PresignatureStorage {
    async fn connect(&self) -> StoreResult<Connection> {
        self.redis_pool
            .get()
            .await
            .map_err(anyhow::Error::new)
            .map_err(StoreError::Connect)
    }

    pub async fn insert(&self, presignature: Presignature, mine: bool) -> StoreResult<()> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local presig_key = KEYS[2]
            local presig_id = ARGV[1]
            local presig_value = ARGV[2]
            local mine = ARGV[3]

            if mine == "true" then
                redis.call("SADD", mine_key, presig_id)
            end

            redis.call("HSET", presig_key, presig_id, presig_value)

            return "OK"
        "#;

        let _: String = redis::Script::new(script)
            .key(self.mine_key())
            .key(self.presig_key())
            .arg(presignature.id)
            .arg(presignature)
            .arg(mine.to_string())
            .invoke_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn contains(&self, id: &PresignatureId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(self.presig_key(), id).await?;
        Ok(result)
    }

    pub async fn contains_mine(&self, id: &PresignatureId) -> StoreResult<bool> {
        let mut connection = self.connect().await?;
        let result: bool = connection.sismember(self.mine_key(), id).await?;
        Ok(result)
    }

    pub async fn take(&self, id: &PresignatureId) -> StoreResult<Presignature> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local presig_key = KEYS[2]
            local presig_id = ARGV[1]
        
            if redis.call('SISMEMBER', mine_key, presig_id) == 1 then
                return {err = 'Cannot take mine presignature as foreign owned'}
            end
        
            local presig_value = redis.call("HGET", presig_key, presig_id)
        
            if not presig_value then
                return {err = "Presignature " .. presig_id .. " is missing"}
            end

            redis.call("HDEL", presig_key, presig_id)
            return presig_value
        "#;

        let result: Result<Presignature, redis::RedisError> = redis::Script::new(script)
            .key(self.mine_key())
            .key(self.presig_key())
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn take_mine(&self) -> StoreResult<Presignature> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local presig_key = KEYS[2]
    
            local presig_id = redis.call("SPOP", mine_key)
            if not presig_id then
                return {err = "Mine presignature stockpile does not have enough presignatures"}
            end
    
            local presig_value = redis.call("HGET", presig_key, presig_id)
            if not presig_value then
                return {err = "Unexpected behavior. Presignature " .. presig_id .. " is missing"}
            end
    
            redis.call("HDEL", presig_key, presig_id)
            return presig_value
        "#;

        let result: Result<Presignature, redis::RedisError> = redis::Script::new(script)
            .key(self.mine_key())
            .key(self.presig_key())
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn len_generated(&self) -> StoreResult<usize> {
        let mut conn = self.connect().await?;
        let result: usize = conn.hlen(self.presig_key()).await?;
        Ok(result)
    }

    pub async fn len_mine(&self) -> StoreResult<usize> {
        let mut conn = self.connect().await?;
        let result: usize = conn.scard(self.mine_key()).await?;
        Ok(result)
    }

    pub async fn clear(&self) -> StoreResult<()> {
        let mut conn = self.connect().await?;
        conn.del::<&str, ()>(&self.presig_key()).await?;
        conn.del::<&str, ()>(&self.mine_key()).await?;
        Ok(())
    }

    fn presig_key(&self) -> String {
        format!(
            "presignatures:{}:{}",
            PRESIGNATURE_STORAGE_VERSION, self.node_account_id
        )
    }

    fn mine_key(&self) -> String {
        format!(
            "presignatures_mine:{}:{}",
            PRESIGNATURE_STORAGE_VERSION, self.node_account_id
        )
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
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Presignature",
                e.to_string(),
            ))
        })
    }
}
