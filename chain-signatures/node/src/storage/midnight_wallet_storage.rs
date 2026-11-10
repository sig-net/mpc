//! The Midnight intent builder's wallet snapshot, in this node's Redis namespace.

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_chain_midnight::WalletSnapshotStore;
use near_account_id::AccountId;
use redis::AsyncCommands;

use super::STORAGE_VERSION;

pub struct MidnightWalletStorage {
    pool: Pool,
    key: String,
}

impl MidnightWalletStorage {
    pub fn new(pool: Pool, account_id: &AccountId) -> Self {
        Self {
            pool,
            key: format!("midnight_wallet_snapshot:{STORAGE_VERSION}:{account_id}"),
        }
    }
}

#[async_trait::async_trait]
impl WalletSnapshotStore for MidnightWalletStorage {
    async fn load(&self) -> anyhow::Result<Option<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .context("failed to get redis connection")?;
        conn.get(&self.key)
            .await
            .context("failed to load the midnight wallet snapshot from redis")
    }

    async fn save(&self, snapshot: &str) -> anyhow::Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .context("failed to get redis connection")?;
        conn.set::<_, _, ()>(&self.key, snapshot)
            .await
            .context("failed to save the midnight wallet snapshot to redis")
    }

    async fn clear(&self) -> anyhow::Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .context("failed to get redis connection")?;
        conn.del::<_, ()>(&self.key)
            .await
            .context("failed to clear the midnight wallet snapshot in redis")
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
        let storage = MidnightWalletStorage::new(pool, &"node.near".parse().unwrap());

        assert!(storage.load().await.is_err());
        assert!(storage.save("{}").await.is_err());
        assert!(storage.clear().await.is_err());
    }
}
