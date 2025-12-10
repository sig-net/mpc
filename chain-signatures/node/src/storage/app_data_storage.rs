use anyhow::Ok;
use deadpool_redis::Pool;
use near_primitives::types::BlockHeight;
use near_sdk::AccountId;
use redis::AsyncCommands;
use std::sync::Arc;
use tokio::sync::RwLock;

const APP_DATA_PREFIX: &str = "app_data";
const APP_DATA_STORAGE_VERSION: &str = "v6";

pub fn init(pool: &Pool, node_account_id: &AccountId) -> AppDataStorage {
    AppDataStorage::Redis {
        redis_pool: pool.clone(),
        node_account_id: node_account_id.clone(),
    }
}

#[derive(Clone)]
pub enum AppDataStorage {
    Redis {
        redis_pool: Pool,
        node_account_id: AccountId,
    },
    InMemory {
        last_block: Arc<RwLock<Option<BlockHeight>>>,
        last_block_eth: Arc<RwLock<Option<u64>>>,
    },
}

impl AppDataStorage {
    pub fn in_memory() -> Self {
        Self::InMemory {
            last_block: Arc::new(RwLock::new(None)),
            last_block_eth: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn set_last_processed_block(&self, height: BlockHeight) -> anyhow::Result<()> {
        match self {
            AppDataStorage::Redis {
                redis_pool,
                node_account_id,
            } => {
                let mut conn = redis_pool.get().await?;
                let key = format!(
                    "{}:{}:{}:last_block",
                    APP_DATA_PREFIX, APP_DATA_STORAGE_VERSION, node_account_id
                );
                conn.set::<&str, BlockHeight, ()>(&key, height).await?;
                Ok(())
            }
            AppDataStorage::InMemory { last_block, .. } => {
                *last_block.write().await = Some(height);
                Ok(())
            }
        }
    }

    pub async fn last_processed_block(&self) -> anyhow::Result<Option<BlockHeight>> {
        match self {
            AppDataStorage::Redis {
                redis_pool,
                node_account_id,
            } => {
                let mut conn = redis_pool.get().await?;
                let key = format!(
                    "{}:{}:{}:last_block",
                    APP_DATA_PREFIX, APP_DATA_STORAGE_VERSION, node_account_id
                );
                let result: Option<BlockHeight> = conn.get(&key).await?;
                Ok(result)
            }
            AppDataStorage::InMemory { last_block, .. } => Ok(*last_block.read().await),
        }
    }

    pub async fn set_last_processed_block_eth(&self, height: u64) -> anyhow::Result<()> {
        match self {
            AppDataStorage::Redis {
                redis_pool,
                node_account_id,
            } => {
                let mut conn = redis_pool.get().await?;
                let key = format!(
                    "{}:{}:{}:last_block_eth",
                    APP_DATA_PREFIX, APP_DATA_STORAGE_VERSION, node_account_id
                );
                conn.set::<&str, u64, ()>(&key, height).await?;
                Ok(())
            }
            AppDataStorage::InMemory { last_block_eth, .. } => {
                *last_block_eth.write().await = Some(height);
                Ok(())
            }
        }
    }

    pub async fn last_processed_block_eth(&self) -> anyhow::Result<Option<u64>> {
        match self {
            AppDataStorage::Redis {
                redis_pool,
                node_account_id,
            } => {
                let mut conn = redis_pool.get().await?;
                let key = format!(
                    "{}:{}:{}:last_block_eth",
                    APP_DATA_PREFIX, APP_DATA_STORAGE_VERSION, node_account_id
                );
                let result: Option<u64> = conn.get(&key).await?;
                Ok(result)
            }
            AppDataStorage::InMemory { last_block_eth, .. } => Ok(*last_block_eth.read().await),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_storage_instantiation() {
        let storage = AppDataStorage::in_memory();
        match storage {
            AppDataStorage::InMemory { .. } => {
                // Successfully created in-memory variant
            }
            _ => panic!("Expected InMemory variant"),
        }
    }

    #[tokio::test]
    async fn test_in_memory_set_and_get_last_processed_block() {
        let storage = AppDataStorage::in_memory();

        // Initially should be None
        let result = storage.last_processed_block().await.unwrap();
        assert_eq!(result, None);

        // Set a block height
        let height: BlockHeight = 42;
        storage.set_last_processed_block(height).await.unwrap();

        // Should retrieve the same value
        let result = storage.last_processed_block().await.unwrap();
        assert_eq!(result, Some(height));

        // Update to a new height
        let new_height: BlockHeight = 100;
        storage.set_last_processed_block(new_height).await.unwrap();

        let result = storage.last_processed_block().await.unwrap();
        assert_eq!(result, Some(new_height));
    }

    #[tokio::test]
    async fn test_in_memory_set_and_get_last_processed_block_eth() {
        let storage = AppDataStorage::in_memory();

        // Initially should be None
        let result = storage.last_processed_block_eth().await.unwrap();
        assert_eq!(result, None);

        // Set an ETH block height
        let height: u64 = 12345;
        storage.set_last_processed_block_eth(height).await.unwrap();

        // Should retrieve the same value
        let result = storage.last_processed_block_eth().await.unwrap();
        assert_eq!(result, Some(height));

        // Update to a new height
        let new_height: u64 = 54321;
        storage.set_last_processed_block_eth(new_height).await.unwrap();

        let result = storage.last_processed_block_eth().await.unwrap();
        assert_eq!(result, Some(new_height));
    }

    #[tokio::test]
    async fn test_in_memory_independent_block_heights() {
        let storage = AppDataStorage::in_memory();

        // Set both block heights
        let near_height: BlockHeight = 100;
        let eth_height: u64 = 200;

        storage.set_last_processed_block(near_height).await.unwrap();
        storage.set_last_processed_block_eth(eth_height).await.unwrap();

        // Verify both are stored independently
        let near_result = storage.last_processed_block().await.unwrap();
        let eth_result = storage.last_processed_block_eth().await.unwrap();

        assert_eq!(near_result, Some(near_height));
        assert_eq!(eth_result, Some(eth_height));
    }

    #[tokio::test]
    async fn test_in_memory_storage_clone() {
        let storage1 = AppDataStorage::in_memory();
        let storage2 = storage1.clone();

        // Set value in storage1
        let height: BlockHeight = 42;
        storage1.set_last_processed_block(height).await.unwrap();

        // Should be able to read from storage2 (same underlying Arc)
        let result = storage2.last_processed_block().await.unwrap();
        assert_eq!(result, Some(height));
    }
}
