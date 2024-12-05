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
        if mine {
            conn.sadd::<&str, PresignatureId, ()>(&self.mine_key(), presignature.id)
                .await?;
        }
        conn.hset::<&str, PresignatureId, Presignature, ()>(
            &self.presig_key(),
            presignature.id,
            presignature,
        )
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
        let presignature: Option<Presignature> = conn.hget(self.presig_key(), id).await?;
        let presignature = presignature.ok_or_else(|| StoreError::PresignatureIsMissing(*id))?;
        conn.hdel::<&str, PresignatureId, ()>(&self.presig_key(), *id)
            .await?;
        Ok(presignature)
    }

    pub async fn take_mine(&self) -> StoreResult<Presignature> {
        let mut conn = self.connect().await?;
        let id: Option<PresignatureId> = conn.spop(self.mine_key()).await?;
        let id = id.ok_or_else(|| StoreError::Empty("mine presignature stockpile"))?;
        self.take(&id).await
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
