//! The Midnight funding wallet's DUST replay checkpoint, in this node's Redis namespace.

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_chain_midnight::DustCheckpointStore;
use near_account_id::AccountId;
use redis::AsyncCommands;

use super::STORAGE_VERSION;

pub struct MidnightDustStorage {
    pool: Pool,
    key: String,
}

impl MidnightDustStorage {
    pub fn new(pool: Pool, account_id: &AccountId) -> Self {
        Self {
            pool,
            key: format!("midnight_dust_checkpoint:{STORAGE_VERSION}:{account_id}"),
        }
    }
}

#[async_trait::async_trait]
impl DustCheckpointStore for MidnightDustStorage {
    async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let mut conn = self
            .pool
            .get()
            .await
            .context("failed to get redis connection")?;
        conn.get(&self.key)
            .await
            .context("failed to load the midnight DUST checkpoint from redis")
    }

    async fn save(&self, checkpoint: &[u8]) -> anyhow::Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .context("failed to get redis connection")?;
        conn.set::<_, _, ()>(&self.key, checkpoint)
            .await
            .context("failed to save the midnight DUST checkpoint to redis")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadpool_redis::Runtime;

    #[tokio::test]
    async fn an_unreachable_redis_is_an_error() {
        // Port 1 is privileged and unused: connections are refused immediately.
        let pool = deadpool_redis::Config::from_url("redis://127.0.0.1:1/")
            .create_pool(Some(Runtime::Tokio1))
            .unwrap();
        let storage = MidnightDustStorage::new(pool, &"node.near".parse().unwrap());

        assert!(storage.load().await.is_err());
        assert!(storage.save(b"checkpoint").await.is_err());
    }
}
