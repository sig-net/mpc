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
        if mine {
            conn.sadd::<&str, TripleId, ()>(&self.mine_key(), triple.id)
                .await?;
        }
        conn.hset::<&str, TripleId, Triple, ()>(&self.triple_key(), triple.id, triple)
            .await?;
        Ok(())
    }

    pub async fn contains(&self, id: &TripleId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.hexists(self.triple_key(), id).await?;
        Ok(result)
    }

    pub async fn contains_mine(&self, id: &TripleId) -> StoreResult<bool> {
        let mut conn = self.connect().await?;
        let result: bool = conn.sismember(self.mine_key(), id).await?;
        Ok(result)
    }

    pub async fn take(&self, id: &TripleId) -> StoreResult<Triple> {
        let mut conn = self.connect().await?;
        if self.contains_mine(id).await? {
            tracing::error!(?id, "cannot take mine triple as foreign owned");
            return Err(StoreError::TripleDenied(
                *id,
                "cannot take mine triple as foreign owned",
            ));
        }
        let triple: Option<Triple> = conn.hget(self.triple_key(), id).await?;
        let triple = triple.ok_or_else(|| StoreError::TripleIsMissing(*id))?;
        conn.hdel::<&str, TripleId, ()>(&self.triple_key(), *id)
            .await?;
        Ok(triple)
    }

    pub async fn take_mine(&self) -> StoreResult<Triple> {
        let mut conn = self.connect().await?;
        let id: Option<TripleId> = conn.spop(self.mine_key()).await?;
        let id = id.ok_or_else(|| StoreError::Empty("mine triple stockpile"))?;
        self.take(&id).await
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
            std::result::Result::Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Triple: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Triple {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json: String = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Triple",
                e.to_string(),
            ))
        })
    }
}
