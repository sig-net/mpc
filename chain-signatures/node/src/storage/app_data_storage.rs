use anyhow::Ok;
use deadpool_redis::Pool;
use near_primitives::types::BlockHeight;
use near_sdk::AccountId;
use redis::AsyncCommands;

type AppDataResult<T> = std::result::Result<T, anyhow::Error>;

const APP_DATA_PREFIX: &str = "app_data";
const APP_DATA_STORAGE_VERSION: &str = "v1";

pub fn init(pool: &Pool, node_account_id: &AccountId) -> AppDataRedisStorage {
    AppDataRedisStorage {
        redis_pool: pool.clone(),
        node_account_id: node_account_id.clone(),
    }
}

#[derive(Clone)]
pub struct AppDataRedisStorage {
    redis_pool: Pool,
    node_account_id: AccountId,
}

impl AppDataRedisStorage {
    pub async fn set_last_processed_block(&self, height: BlockHeight) -> AppDataResult<()> {
        let mut conn = self.redis_pool.get().await?;
        conn.set::<&str, BlockHeight, ()>(&self.last_block_key(), height)
            .await?;
        Ok(())
    }

    pub async fn get_last_processed_block(&self) -> AppDataResult<Option<BlockHeight>> {
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
}
