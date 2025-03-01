use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use crate::protocol::presignature::{Presignature, PresignatureId};
use crate::storage::error::{StoreError, StoreResult};

// Can be used to "clear" redis storage in case of a breaking change
const PRESIGNATURE_STORAGE_VERSION: &str = "v7";
const USED_EXPIRE_TIME: Duration = Duration::hours(24);

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

    PresignatureStorage {
        redis_pool: pool.clone(),
        presig_key,
        mine_key,
        used_key,
    }
}

#[derive(Clone)]
pub struct PresignatureStorage {
    redis_pool: Pool,
    presig_key: String,
    mine_key: String,
    used_key: String,
}

impl PresignatureStorage {
    async fn connect(&self) -> StoreResult<Connection> {
        self.redis_pool
            .get()
            .await
            .map_err(anyhow::Error::new)
            .map_err(StoreError::Connect)
    }

    /// Insert a presignature into the storage. If `mine` is true, the presignature will be
    /// owned by the current node. If `back` is true, the presignature will be marked as unused.
    pub async fn insert(
        &self,
        presignature: Presignature,
        mine: bool,
        back: bool,
    ) -> StoreResult<()> {
        let mut conn = self.connect().await?;

        let script = format!(
            r#"
            local presig_id = ARGV[1]
            local presig = ARGV[2]

            if {back} then
                redis.call("HDEL", "{used_key}", presig_id)
            elseif redis.call('HEXISTS', "{used_key}", presig_id) == 1 then
                return {{err = 'warn: presignature ' .. presig_id .. ' is already used'}}
            end

            if {mine} then
                redis.call("SADD", "{mine_key}", presig_id)
            end

            redis.call("HSET", "{presig_key}", presig_id, presig)

            return "OK"
        "#,
            mine_key = self.mine_key,
            presig_key = self.presig_key,
            used_key = self.used_key,
        );

        let _: String = redis::Script::new(&script)
            .arg(presignature.id)
            .arg(presignature)
            .invoke_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn contains(&self, id: &PresignatureId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(&self.presig_key, id).await?;
        Ok(result)
    }

    pub async fn contains_mine(&self, id: &PresignatureId) -> StoreResult<bool> {
        let mut connection = self.connect().await?;
        let result: bool = connection.sismember(&self.mine_key, id).await?;
        Ok(result)
    }

    pub async fn contains_used(&self, id: &PresignatureId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(&self.used_key, id).await?;
        Ok(result)
    }

    pub async fn take(&self, id: &PresignatureId) -> StoreResult<Presignature> {
        let mut conn = self.connect().await?;

        let script = format!(
            r#"
            local presig_id = ARGV[1]

            if redis.call('SISMEMBER', "{mine_key}", presig_id) == 1 then
                return {{err = 'warn: cannot take mine presignature as foreign owned'}}
            end

            local presig = redis.call("HGET", "{presig_key}", presig_id)
            if not presig then
                return {{err = "warn: presignature " .. presig_id .. " is missing"}}
            end

            redis.call("HDEL", "{presig_key}", presig_id)
            redis.call("HSET", "{used_key}", presig_id, "1")
            redis.call("HEXPIRE", "{used_key}", {expire_secs}, "FIELDS", "1", presig_id)

            return presig
        "#,
            mine_key = self.mine_key,
            presig_key = self.presig_key,
            used_key = self.used_key,
            expire_secs = USED_EXPIRE_TIME.num_seconds(),
        );

        let result: Result<Presignature, RedisError> = redis::Script::new(&script)
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn take_mine(&self) -> StoreResult<Option<Presignature>> {
        let mut conn = self.connect().await?;

        let script = format!(
            r#"
            local presig_id = redis.call("SPOP", "{mine_key}")
            if not presig_id then
                return nil
            end

            local presig = redis.call("HGET", "{presig_key}", presig_id)
            if not presig then
                return {{err = "warn: unexpected behavior, presignature " .. presig_id .. " is missing"}}
            end

            redis.call("HDEL", "{presig_key}", presig_id)
            redis.call("HSET", "{used_key}", presig_id, "1")
            redis.call("HEXPIRE", "{used_key}", {expire_secs}, "FIELDS", "1", presig_id)

            return presig
        "#,
            mine_key = self.mine_key,
            presig_key = self.presig_key,
            used_key = self.used_key,
            expire_secs = USED_EXPIRE_TIME.num_seconds(),
        );

        redis::Script::new(&script)
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
        conn.del::<&str, ()>(&self.presig_key).await?;
        conn.del::<&str, ()>(&self.mine_key).await?;
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
