use axum::async_trait;
use redis::Connection;
use url::Url;

use crate::{
    gcp::error,
    protocol::presignature::{Presignature, PresignatureId},
};

// TODO: organize errors, get rid of connection with GCP
type PresignatureResult<T> = std::result::Result<T, error::DatastoreStorageError>;
pub type PresignatureStorageBox = Box<dyn PresignatureStorage + Send + Sync>;

pub fn init(redis_url: Url) -> PresignatureStorageBox {
    Box::new(RedisPresignatureStorage::new(redis_url)) as PresignatureStorageBox
}

#[async_trait]
pub trait PresignatureStorage {
    async fn insert(&mut self, presignature: Presignature) -> PresignatureResult<()>;
    async fn insert_mine(&mut self, presignature: Presignature) -> PresignatureResult<()>;
    async fn get(&self, id: PresignatureId) -> PresignatureResult<Option<Presignature>>;
    async fn get_mine(&self) -> PresignatureResult<Vec<Presignature>>;
    async fn delete(&mut self, id: PresignatureId) -> PresignatureResult<()>;
    async fn clear_all(&mut self) -> PresignatureResult<Vec<Presignature>>;
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
}

#[async_trait]
impl PresignatureStorage for RedisPresignatureStorage {
    async fn insert(&mut self, presignature: Presignature) -> PresignatureResult<()> {
        unimplemented!()
    }

    async fn insert_mine(&mut self, presignature: Presignature) -> PresignatureResult<()> {
        unimplemented!()
    }

    async fn get(&self, id: PresignatureId) -> PresignatureResult<Option<Presignature>> {
        unimplemented!()
    }

    async fn get_mine(&self) -> PresignatureResult<Vec<Presignature>> {
        unimplemented!()
    }

    async fn delete(&mut self, id: PresignatureId) -> PresignatureResult<()> {
        unimplemented!()
    }

    async fn clear_all(&mut self) -> PresignatureResult<Vec<Presignature>> {
        unimplemented!()
    }
}
