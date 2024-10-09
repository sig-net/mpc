use std::sync::Arc;

use anyhow::Ok;
use axum::async_trait;
use redis::{Commands, Connection, FromRedisValue, RedisWrite, ToRedisArgs};
use tokio::sync::RwLock;
use url::Url;

use crate::protocol::presignature::{Presignature, PresignatureId};

// TODO: organize errors, get rid of connection with GCP
type PresignatureResult<T> = std::result::Result<T, anyhow::Error>;
pub type PresignatureStorageBox = Box<dyn PresignatureStorage + Send + Sync>;
pub type LockPresignatureStorageBox = Arc<RwLock<PresignatureStorageBox>>;

const FOREIGN_MAP_NAME: &'static str = "presignatures_foreign";
const MINE_MAP_NAME: &'static str = "presignatures_mine";

pub fn init(redis_url: Url) -> PresignatureStorageBox {
    Box::new(RedisPresignatureStorage::new(redis_url)) as PresignatureStorageBox
}

#[async_trait]
pub trait PresignatureStorage {
    async fn insert_foreign(&mut self, presignature: Presignature) -> PresignatureResult<()>;
    async fn insert_mine(&mut self, presignature: Presignature) -> PresignatureResult<()>;
    async fn contains_foreign(&mut self, id: PresignatureId) -> PresignatureResult<bool>;
    async fn contains_mine(&mut self, id: PresignatureId) -> PresignatureResult<bool>;
    async fn remove_foreign(
        &mut self,
        id: PresignatureId,
    ) -> PresignatureResult<Option<Presignature>>;
    async fn remove_mine(&mut self, id: PresignatureId)
        -> PresignatureResult<Option<Presignature>>;
    async fn count_all(&mut self) -> PresignatureResult<usize>;
    async fn count_mine(&mut self) -> PresignatureResult<usize>;
}

struct RedisPresignatureStorage {
    redis_connection: Connection,
}

impl RedisPresignatureStorage {
    fn new(redis_url: Url) -> Self {
        Self {
            redis_connection: redis::Client::open(redis_url.as_str())
                .expect("Failed to connect to Redis")
                .get_connection()
                .expect("Failed to get connection"),
        }
    }

    // This function is using a Lua script to read and remove
    // a presignature in a single atomic operation
    async fn remove_presignature(
        &mut self,
        hash_map_name: &str,
        id: PresignatureId,
    ) -> PresignatureResult<Option<Presignature>> {
        let script = redis::Script::new(
            r"
                local value = redis.call('HGET', KEYS[1], ARGV[1])
                redis.call('HDEL', KEYS[1], ARGV[1])
                return value
            ",
        );
        let presignature: Option<Presignature> = redis::pipe()
            .invoke_script(script.key(hash_map_name).arg(id))
            .query(&mut self.redis_connection)?;
        Ok(presignature) as redis::RedisResult<Self>
    }
}

#[async_trait]
impl PresignatureStorage for RedisPresignatureStorage {
    async fn insert_foreign(&mut self, presignature: Presignature) -> PresignatureResult<()> {
        self.redis_connection
            .hset(FOREIGN_MAP_NAME, presignature.id, presignature)?;
        Ok(())
    }

    async fn insert_mine(&mut self, presignature: Presignature) -> PresignatureResult<()> {
        self.redis_connection
            .hset(MINE_MAP_NAME, presignature.id, presignature)?;
        Ok(())
    }

    async fn contains_foreign(&mut self, id: PresignatureId) -> PresignatureResult<bool> {
        let result: bool = self.redis_connection.hexists(FOREIGN_MAP_NAME, id)?;
        Ok(result)
    }

    async fn contains_mine(&mut self, id: PresignatureId) -> PresignatureResult<bool> {
        let result: bool = self.redis_connection.hexists(MINE_MAP_NAME, id)?;
        Ok(result)
    }

    async fn remove_foreign(
        &mut self,
        id: PresignatureId,
    ) -> PresignatureResult<Option<Presignature>> {
        let result: Option<Presignature> = self.remove_presignature(FOREIGN_MAP_NAME, id).await?;
        Ok(result)
    }

    async fn remove_mine(
        &mut self,
        id: PresignatureId,
    ) -> PresignatureResult<Option<Presignature>> {
        let result: Option<Presignature> = self.remove_presignature(MINE_MAP_NAME, id).await?;
        Ok(result)
    }

    async fn count_all(&mut self) -> PresignatureResult<usize> {
        let count: usize = self.redis_connection.hlen(FOREIGN_MAP_NAME)?;
        Ok(count)
    }

    async fn count_mine(&mut self) -> PresignatureResult<usize> {
        let count: usize = self.redis_connection.hlen(MINE_MAP_NAME)?;
        Ok(count)
    }
}

impl ToRedisArgs for Presignature {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        let json = serde_json::to_string(self).expect("Failed to serialize Presignature");
        out.write_arg(json.as_bytes());
    }
}

impl FromRedisValue for Presignature {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json = String::from_redis_value(v)?;
        let presignature: Presignature = serde_json::from_str(&json).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize presignature",
                e.to_string(),
            ))
        })?;
        Ok(presignature)
    }
}
