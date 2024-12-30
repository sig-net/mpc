use anyhow::Ok;
use deadpool_redis::Pool;
use near_primitives::types::BlockHeight;
use near_sdk::AccountId;
use redis::AsyncCommands;

const APP_DATA_PREFIX: &str = "app_data";
const APP_DATA_STORAGE_VERSION: &str = "v2";

pub fn init(pool: &Pool, node_account_id: &AccountId) -> AppDataStorage {
    AppDataStorage {
        redis_pool: pool.clone(),
        node_account_id: node_account_id.clone(),
    }
}

#[derive(Clone)]
pub struct AppDataStorage {
    redis_pool: Pool,
    node_account_id: AccountId,
}

impl AppDataStorage {
    pub async fn set_last_processed_block(&self, height: BlockHeight) -> anyhow::Result<()> {
        let mut conn = self.redis_pool.get().await?;
        conn.set::<&str, BlockHeight, ()>(&self.last_block_key(), height)
            .await?;
        Ok(())
    }

    pub async fn last_processed_block(&self) -> anyhow::Result<Option<BlockHeight>> {
        let mut conn = self.redis_pool.get().await?;
        let result: Option<BlockHeight> = conn.get(self.last_block_key()).await?;
        Ok(result)
    }

    fn last_block_key(&self) -> String {
        format!(
            "{}:{}:{}:last_block",
            APP_DATA_PREFIX, APP_DATA_STORAGE_VERSION, self.node_account_id
        )
    }

    pub async fn set_last_processed_block_eth(&self, height: u64) -> anyhow::Result<()> {
        let mut conn = self.redis_pool.get().await?;
        conn.set::<&str, u64, ()>(&self.last_block_key_eth(), height)
            .await?;
        Ok(())
    }

    pub async fn last_processed_block_eth(&self) -> anyhow::Result<Option<u64>> {
        let mut conn = self.redis_pool.get().await?;
        let result: Option<u64> = conn.get(self.last_block_key_eth()).await?;
        Ok(result)
    }

    fn last_block_key_eth(&self) -> String {
        format!(
            "{}:{}:{}:last_block_eth",
            APP_DATA_PREFIX, APP_DATA_STORAGE_VERSION, self.node_account_id
        )
    }
}
