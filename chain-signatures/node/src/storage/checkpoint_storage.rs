use crate::protocol::Chain;

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_primitives::Checkpoint;
use near_account_id::AccountId;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

const CHECKPOINT_VERSION: &str = "v12";

#[derive(Clone, Debug)]
pub enum CheckpointStorage {
    Redis(Pool, AccountId),
    InMemory {
        latest: Arc<RwLock<HashMap<Chain, Checkpoint>>>,
        pending: Arc<RwLock<HashMap<Chain, BTreeMap<u64, Checkpoint>>>>,
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
            pending: Arc::new(RwLock::new(HashMap::new())),
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

    fn pending_checkpoint_key(&self, chain: Chain, height: u64) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!("{account_id}:checkpoint:pending:{CHECKPOINT_VERSION}:{chain}:{height}")
            }
            CheckpointStorage::InMemory { .. } => format!("checkpoint:pending:{chain}:{height}"),
        }
    }
    
    fn pending_checkpoints_pattern(&self, chain: Chain) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!("{account_id}:checkpoint:pending:{CHECKPOINT_VERSION}:{chain}:*")
            }
            CheckpointStorage::InMemory { .. } => format!("checkpoint:pending:{chain}:*"),
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
            CheckpointStorage::InMemory { latest, .. } => {
                latest
                    .write()
                    .await
                    .insert(checkpoint.chain, checkpoint.clone());
            }
        }
        Ok(())
    }

    /// Promote a pending checkpoint to be the latest consensus checkpoint.
    /// If the pending key does not exist (e.g. during consensus regression), it falls back to a normal persist.
    pub async fn promote_pending_to_latest(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let pending_key = self.pending_checkpoint_key(checkpoint.chain, checkpoint.block_height);
                let latest_key = self.checkpoint_key(checkpoint.chain);

                let result: redis::RedisResult<()> = redis::cmd("RENAME")
                    .arg(&pending_key)
                    .arg(&latest_key)
                    .query_async(&mut conn)
                    .await;

                if result.is_err() {
                    // Fallback if pending key is missing or RENAME fails
                    let value = serde_json::to_string(checkpoint)
                        .context("failed to serialize checkpoint persistence")?;
                    conn.set::<_, _, ()>(latest_key, &value)
                        .await
                        .context("failed to persist checkpoint to redis on fallback")?;
                }
            }
            CheckpointStorage::InMemory { latest, .. } => {
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
            CheckpointStorage::InMemory { latest, .. } => Ok(latest.read().await.get(&chain).cloned()),
        }
    }

    /// Persist a pending checkpoint to storage.
    pub async fn persist_pending(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let value = serde_json::to_string(checkpoint)
                    .context("failed to serialize checkpoint persistence")?;
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let Ok(mut conn) = pool.get().await else {
                        tracing::error!(
                            ?checkpoint,
                            "failed to get redis connection for pending checkpoint, retrying..."
                        );
                        continue;
                    };

                    let key = self.pending_checkpoint_key(checkpoint.chain, checkpoint.block_height);
                    if let Err(err) = conn.set::<_, _, ()>(key, &value).await {
                        tracing::error!(
                            ?checkpoint,
                            %err,
                            "failed to persist pending checkpoint to redis, retrying..."
                        );
                    } else {
                        break;
                    }
                }
            }
            CheckpointStorage::InMemory { pending, .. } => {
                let mut pending_map = pending.write().await;
                let chain_pending = pending_map.entry(checkpoint.chain).or_insert_with(BTreeMap::new);
                chain_pending.insert(checkpoint.block_height, checkpoint.clone());
            }
        }
        Ok(())
    }

    /// Load all pending checkpoints for a chain.
    pub async fn load_all_pending(&self, chain: Chain) -> anyhow::Result<Vec<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let pattern = self.pending_checkpoints_pattern(chain);
                let script = redis::Script::new(r#"
                    local keys = redis.call('KEYS', ARGV[1])
                    if #keys == 0 then
                        return {}
                    end
                    return redis.call('MGET', unpack(keys))
                "#);
                let values: Vec<String> = script
                    .arg(pattern)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to execute load_all_pending script")?;
                let mut checkpoints = Vec::new();
                for value in values {
                    let checkpoint: Checkpoint = serde_json::from_str(&value).context("failed to deserialize pending checkpoint")?;
                    checkpoints.push(checkpoint);
                }
                checkpoints.sort_by_key(|c| c.block_height);
                Ok(checkpoints)
            }
            CheckpointStorage::InMemory { pending, .. } => {
                let pending_map = pending.read().await;
                let checkpoints = pending_map.get(&chain).map(|c| c.values().cloned().collect()).unwrap_or_default();
                Ok(checkpoints)
            }
        }
    }

    /// Clear all pending checkpoints up to a certain height.
    pub async fn clear_pending_up_to(&self, chain: Chain, height: u64) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let pattern = self.pending_checkpoints_pattern(chain);
                let script = redis::Script::new(r#"
                    local keys = redis.call('KEYS', ARGV[1])
                    local limit = tonumber(ARGV[2])
                    for _, key in ipairs(keys) do
                        local parts = {}
                        for part in string.gmatch(key, "[^:]+") do
                            table.insert(parts, part)
                        end
                        local height = tonumber(parts[#parts])
                        if height and height <= limit then
                            redis.call('DEL', key)
                        end
                    end
                "#);
                let _: () = script
                    .arg(pattern)
                    .arg(height)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to execute clear_pending_up_to script")?;
            }
            CheckpointStorage::InMemory { pending, .. } => {
                let mut pending_map = pending.write().await;
                if let Some(chain_pending) = pending_map.get_mut(&chain) {
                    chain_pending.retain(|&h, _| h > height);
                }
            }
        }
        Ok(())
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

    #[tokio::test]
    async fn test_in_memory_checkpoint_storage_pending() -> anyhow::Result<()> {
        let storage = CheckpointStorage::in_memory();

        // 1. Clean storage returns empty pending
        assert!(storage.load_all_pending(Chain::Solana).await?.is_empty());

        // 2. Persist pending checkpoints
        let cp1 = Checkpoint {
            chain: Chain::Solana,
            block_height: 10,
            pending_requests: vec![],
        };
        storage.persist_pending(&cp1).await?;

        let cp2 = Checkpoint {
            chain: Chain::Solana,
            block_height: 20,
            pending_requests: vec![],
        };
        storage.persist_pending(&cp2).await?;

        // 3. Verify all pending loaded correctly
        let pending = storage.load_all_pending(Chain::Solana).await?;
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].block_height, 10);
        assert_eq!(pending[1].block_height, 20);

        // 4. Clear pending up to height 10
        storage.clear_pending_up_to(Chain::Solana, 15).await?;
        let pending = storage.load_all_pending(Chain::Solana).await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].block_height, 20);

        // 5. Clear remaining pending
        storage.clear_pending_up_to(Chain::Solana, 20).await?;
        assert!(storage.load_all_pending(Chain::Solana).await?.is_empty());

        Ok(())
    }
}
