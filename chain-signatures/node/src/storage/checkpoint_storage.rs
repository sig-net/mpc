use crate::protocol::Chain;

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_primitives::Checkpoint;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum CheckpointStorage {
    Redis(Pool),
    InMemory(Arc<RwLock<HashMap<Chain, Checkpoint>>>),
}

impl Default for CheckpointStorage {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl CheckpointStorage {
    pub fn in_memory() -> Self {
        Self::InMemory(Arc::new(RwLock::new(HashMap::new())))
    }

    pub async fn persist(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let key = format!("checkpoint:{}", checkpoint.chain);
                let value =
                    serde_json::to_string(checkpoint).context("failed to serialize checkpoint")?;
                conn.set::<_, _, ()>(key, value)
                    .await
                    .context("failed to set checkpoint in redis")?;
            }
            CheckpointStorage::InMemory(storage) => {
                storage
                    .write()
                    .await
                    .insert(checkpoint.chain, checkpoint.clone());
            }
        }
        Ok(())
    }

    pub async fn load_latest(&self, chain: Chain) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let key = format!("checkpoint:{}", chain);
                let value: Option<String> = conn
                    .get(key)
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
            CheckpointStorage::InMemory(storage) => Ok(storage.read().await.get(&chain).cloned()),
        }
    }
}
