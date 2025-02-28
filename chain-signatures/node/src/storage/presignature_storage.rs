use std::time::Duration;

use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use crate::protocol::presignature::{Presignature, PresignatureId};
use crate::storage::error::{StoreError, StoreResult};

// Can be used to "clear" redis storage in case of a breaking change
const PRESIGNATURE_STORAGE_VERSION: &str = "v7";

/// Expiration of 24 hours for used presignatures.
const USED_EXPIRE_TIME: Duration = Duration::from_secs(24 * 60 * 60);

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

        let script = r#"
            local mine_key = KEYS[1]
            local presig_key = KEYS[2]
            local used_key = KEYS[3]
            local presig_id = ARGV[1]
            local presig_value = ARGV[2]
            local mine = ARGV[3]
            local back = ARGV[4]

            if back == "true" then
                redis.call("HDEL", used_key, presig_id)
            elseif redis.call('HEXISTS', used_key, presig_id) == 1 then
                return {err = 'Presignature ' .. presig_id .. ' is already used'}
            end

            if mine == "true" then
                redis.call("SADD", mine_key, presig_id)
            end

            redis.call("HSET", presig_key, presig_id, presig_value)

            return "OK"
        "#;

        let _: String = redis::Script::new(script)
            .key(&self.mine_key)
            .key(&self.presig_key)
            .key(&self.used_key)
            .arg(presignature.id)
            .arg(presignature)
            .arg(mine.to_string())
            .arg(back.to_string())
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

    // TODO: make id: &PresignatureId, into id: PresignatureId
    /// Take the presginature from the storage. Expects the node to not own this presignature.
    /// If `timeout` is provided, this will block up till timeout for the presignature to be
    /// available within storage. If none is provided, then try to take the presignature
    /// immediately.
    pub async fn take(
        &self,
        id: &PresignatureId,
        timeout: Option<Duration>,
    ) -> StoreResult<Presignature> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local presig_key = KEYS[2]
            local used_key = KEYS[3]
            local presig_id = ARGV[1]

            if redis.call('SISMEMBER', mine_key, presig_id) == 1 then
                return {err = 'Cannot take mine presignature as foreign owned'}
            end

            local presig_value = redis.call("HGET", presig_key, presig_id)

            if not presig_value then
                return {err = "Presignature " .. presig_id .. " is missing"}
            end

            redis.call("HDEL", presig_key, presig_id)
            redis.call("HSET", used_key, presig_id, "1")
            redis.call("HEXPIRE", used_key, ARGV[2], "FIELDS", "1", presig_id)

            return presig_value
        "#;

        let script = redis::Script::new(script);
        if let Some(timeout) = timeout {
            if !wait_for_hexist(&mut conn, &self.presig_key, *id, timeout).await {
                return Err(StoreError::Timeout(timeout));
            }
        }

        let result: Result<Presignature, RedisError> = script
            .key(&self.mine_key)
            .key(&self.presig_key)
            .key(&self.used_key)
            .arg(id)
            .arg(USED_EXPIRE_TIME.as_secs())
            .invoke_async(&mut conn)
            .await;

        result.map_err(StoreError::from)
    }

    pub async fn take_mine(&self) -> StoreResult<Option<Presignature>> {
        let mut conn = self.connect().await?;

        let script = r#"
            local mine_key = KEYS[1]
            local presig_key = KEYS[2]
            local used_key = KEYS[3]

            local presig_id = redis.call("SPOP", mine_key)
            if not presig_id then
                return nil
            end

            local presig_value = redis.call("HGET", presig_key, presig_id)
            if not presig_value then
                return {err = "Unexpected behavior. Presignature " .. presig_id .. " is missing"}
            end

            redis.call("HDEL", presig_key, presig_id)
            redis.call("HSET", used_key, presig_id, "1")
            redis.call("HEXPIRE", used_key, ARGV[1], "FIELDS", "1", presig_id)

            return presig_value
        "#;

        redis::Script::new(script)
            .key(&self.mine_key)
            .key(&self.presig_key)
            .key(&self.used_key)
            .arg(USED_EXPIRE_TIME.as_secs())
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

async fn wait_for_hexist(
    conn: &mut Connection,
    key: &str,
    field: PresignatureId,
    timeout: Duration,
) -> bool {
    let delay = Duration::from_millis(25);
    let start = tokio::time::Instant::now();

    while start.elapsed() < timeout {
        if conn.hexists::<_, _, bool>(key, field).await.is_ok() {
            return true;
        }
        tokio::time::sleep(delay).await;
        // delay = std::cmp::min(delay * 2, Duration::from_secs(1)); // Exponential backoff
    }
    false
}
