use std::sync::Arc;

use anyhow::Ok;
use redis::{Commands, Connection, FromRedisValue, RedisWrite, ToRedisArgs};
use tokio::sync::RwLock;
use url::Url;

use crate::protocol::presignature::{Presignature, PresignatureId};

type PresigResult<T> = std::result::Result<T, anyhow::Error>;
pub type PresignatureStorageBox = Box<dyn PresignatureStorage + Send + Sync>;
pub type LockPresignatureStorageBox = Arc<RwLock<PresignatureStorageBox>>;

const PRESIGNATURES_MAP_NAME: &str = "presignatures";
const MINE_SET_NAME: &str = "presignatures_mine";

pub fn init(redis_url: Url) -> PresignatureStorageBox {
    Box::new(RedisPresignatureStorage::new(redis_url)) as PresignatureStorageBox
}

pub trait PresignatureStorage {
    fn insert(&mut self, presignature: Presignature) -> PresigResult<()>;
    fn insert_mine(&mut self, presignature: Presignature) -> PresigResult<()>;
    fn contains(&mut self, id: &PresignatureId) -> PresigResult<bool>;
    fn contains_mine(&mut self, id: &PresignatureId) -> PresigResult<bool>;
    fn take(&mut self, id: &PresignatureId) -> PresigResult<Option<Presignature>>;
    fn take_mine(&mut self) -> PresigResult<Option<Presignature>>;
    fn count_all(&mut self) -> PresigResult<usize>;
    fn count_mine(&mut self) -> PresigResult<usize>;
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
                .expect("Failed to get Redis connection"),
        }
    }
}

impl PresignatureStorage for RedisPresignatureStorage {
    fn insert(&mut self, presignature: Presignature) -> PresigResult<()> {
        self.redis_connection
            .hset::<&str, PresignatureId, Presignature, ()>(
                PRESIGNATURES_MAP_NAME,
                presignature.id,
                presignature,
            )?;
        Ok(())
    }

    fn insert_mine(&mut self, presignature: Presignature) -> PresigResult<()> {
        self.redis_connection
            .sadd::<&str, PresignatureId, ()>(MINE_SET_NAME, presignature.id)?;
        self.insert(presignature)?;
        Ok(())
    }

    fn contains(&mut self, id: &PresignatureId) -> PresigResult<bool> {
        let result: bool = self.redis_connection.hexists(PRESIGNATURES_MAP_NAME, id)?;
        Ok(result)
    }

    fn contains_mine(&mut self, id: &PresignatureId) -> PresigResult<bool> {
        let result: bool = self.redis_connection.sismember(MINE_SET_NAME, id)?;
        Ok(result)
    }

    fn take(&mut self, id: &PresignatureId) -> PresigResult<Option<Presignature>> {
        let result: Option<Presignature> =
            self.redis_connection.hget(PRESIGNATURES_MAP_NAME, id)?;
        match result {
            Some(presignature) => {
                self.redis_connection
                    .hdel::<&str, PresignatureId, ()>(PRESIGNATURES_MAP_NAME, *id)?;
                Ok(Some(presignature))
            }
            None => Ok(None),
        }
    }

    fn take_mine(&mut self) -> PresigResult<Option<Presignature>> {
        let id: Option<PresignatureId> = self.redis_connection.spop(MINE_SET_NAME)?;
        match id {
            Some(id) => self.take(&id),
            None => Ok(None),
        }
    }

    fn count_all(&mut self) -> PresigResult<usize> {
        let result: usize = self.redis_connection.hlen(PRESIGNATURES_MAP_NAME)?;
        Ok(result)
    }

    fn count_mine(&mut self) -> PresigResult<usize> {
        let result: usize = self.redis_connection.scard(MINE_SET_NAME)?;
        Ok(result)
    }
}

impl ToRedisArgs for Presignature {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            std::result::Result::Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Presignature: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Presignature {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json: String = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Presignature",
                e.to_string(),
            ))
        })
    }
}
