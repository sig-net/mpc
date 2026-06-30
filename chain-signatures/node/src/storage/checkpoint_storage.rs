use crate::protocol::Chain;

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_primitives::Checkpoint;
use near_account_id::AccountId;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::HashMap;
use std::sync::Arc;

const CHECKPOINT_VERSION: &str = "v12";

#[derive(Clone, Debug)]
pub enum CheckpointStorage {
    Redis(Pool, AccountId),
    InMemory {
        latest: Arc<RwLock<HashMap<Chain, Checkpoint>>>,
    },
}

impl Default for CheckpointStorage {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl CheckpointStorage {
    pub fn in_memory() -> Self {
        Self::InMemory {
            latest: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn checkpoint_key(&self, chain: Chain) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!("{account_id}:checkpoint:latest:{CHECKPOINT_VERSION}:{chain}")
            }
            CheckpointStorage::InMemory { .. } => format!("checkpoint:latest:{chain}"),
        }
    }

    /// Persist a checkpoint as the latest consensus checkpoint.
    ///
    /// Only consensus-confirmed checkpoints should be persisted.
    /// Overwrites the previous latest entry.
    pub async fn persist(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value = serde_json::to_string(checkpoint)
                    .context("failed to serialize checkpoint persistence")?;

                conn.set::<_, _, ()>(self.checkpoint_key(checkpoint.chain), &value)
                    .await
                    .context("failed to persist checkpoint to redis")?;
            }
            CheckpointStorage::InMemory { latest } => {
                latest
                    .write()
                    .await
                    .insert(checkpoint.chain, checkpoint.clone());
            }
        }
        Ok(())
    }

    pub async fn load_latest(&self, chain: Chain) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value: Option<String> = conn
                    .get(self.checkpoint_key(chain))
                    .await
                    .context("failed to get checkpoint from redis")?;
                match value {
                    Some(v) => {
                        let checkpoint: Checkpoint =
                            serde_json::from_str(&v).context("failed to deserialize checkpoint")?;
                        Ok(Some(checkpoint))
                    }
                    None => Ok(None),
                }
            }
            CheckpointStorage::InMemory { latest } => Ok(latest.read().await.get(&chain).cloned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_primitives::Chain;

    #[tokio::test]
    async fn test_in_memory_checkpoint_storage() -> anyhow::Result<()> {
        let storage = CheckpointStorage::in_memory();

        // 1. Clean storage returns None
        assert!(storage.load_latest(Chain::Solana).await?.is_none());

        // 2. Persist first checkpoint
        let cp1 = Checkpoint {
            chain: Chain::Solana,
            block_height: 10,
            pending_requests: vec![],
        };
        storage.persist(&cp1).await?;

        // 3. Verify latest
        let latest = storage.load_latest(Chain::Solana).await?.unwrap();
        assert_eq!(latest.block_height, 10);

        // 4. Persist second checkpoint at higher height
        let cp2 = Checkpoint {
            chain: Chain::Solana,
            block_height: 20,
            pending_requests: vec![],
        };
        storage.persist(&cp2).await?;

        // 5. Verify latest is updated
        let latest = storage.load_latest(Chain::Solana).await?.unwrap();
        assert_eq!(latest.block_height, 20);

        Ok(())
    }
}
