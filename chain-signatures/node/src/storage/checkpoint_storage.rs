use crate::protocol::Chain;

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_primitives::Checkpoint;
use near_account_id::AccountId;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

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
                format!(
                    "{account_id}:checkpoint:latest:{}:{chain}",
                    crate::CHECKPOINT_STORAGE_VERSION
                )
            }
            CheckpointStorage::InMemory { .. } => format!("checkpoint:latest:{chain}"),
        }
    }

    fn pending_checkpoint_key(&self, chain: Chain) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!(
                    "{account_id}:checkpoint:pending:{}:{chain}",
                    crate::CHECKPOINT_STORAGE_VERSION
                )
            }
            CheckpointStorage::InMemory { .. } => format!("checkpoint:pending:{chain}"),
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

    /// Persist an unconfirmed checkpoint before its digest is submitted for consensus.
    pub async fn persist_pending(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value = serde_json::to_string(checkpoint)
                    .context("failed to serialize pending checkpoint")?;
                conn.hset::<_, _, _, ()>(
                    self.pending_checkpoint_key(checkpoint.chain),
                    checkpoint.block_height,
                    value,
                )
                .await
                .context("failed to persist pending checkpoint to redis")?;
            }
            CheckpointStorage::InMemory { pending, .. } => {
                pending
                    .write()
                    .await
                    .entry(checkpoint.chain)
                    .or_default()
                    .insert(checkpoint.block_height, checkpoint.clone());
            }
        }
        Ok(())
    }

    /// Load unconfirmed checkpoints ordered by block height.
    pub async fn load_pending(&self, chain: Chain) -> anyhow::Result<Vec<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let values: HashMap<String, String> = conn
                    .hgetall(self.pending_checkpoint_key(chain))
                    .await
                    .context("failed to load pending checkpoints from redis")?;
                let mut checkpoints = values
                    .into_values()
                    .map(|value| {
                        serde_json::from_str(&value)
                            .context("failed to deserialize pending checkpoint")
                    })
                    .collect::<anyhow::Result<Vec<Checkpoint>>>()?;
                checkpoints.sort_by_key(|checkpoint| checkpoint.block_height);
                Ok(checkpoints)
            }
            CheckpointStorage::InMemory { pending, .. } => Ok(pending
                .read()
                .await
                .get(&chain)
                .map(|checkpoints| checkpoints.values().cloned().collect())
                .unwrap_or_default()),
        }
    }

    /// Promote the durable pending checkpoint and prune all older pending checkpoints.
    pub async fn promote_pending(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        let expected = serde_json::to_string(checkpoint)
            .context("failed to serialize checkpoint persistence")?;
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                const PROMOTE: &str = r#"
                    local pending = redis.call('HGET', KEYS[2], ARGV[2])
                    if pending and pending ~= ARGV[1] then
                        return 0
                    end
                    redis.call('SET', KEYS[1], pending or ARGV[1])
                    local entries = redis.call('HGETALL', KEYS[2])
                    for i = 1, #entries, 2 do
                        if tonumber(entries[i]) <= tonumber(ARGV[2]) then
                            redis.call('HDEL', KEYS[2], entries[i])
                        end
                    end
                    return 1
                "#;
                let promoted: i32 = redis::Script::new(PROMOTE)
                    .key(self.checkpoint_key(checkpoint.chain))
                    .key(self.pending_checkpoint_key(checkpoint.chain))
                    .arg(expected)
                    .arg(checkpoint.block_height)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to promote pending checkpoint")?;
                if promoted == 0 {
                    anyhow::bail!(
                        "pending checkpoint changed before promotion at height {}",
                        checkpoint.block_height
                    );
                }
            }
            CheckpointStorage::InMemory {
                latest, pending, ..
            } => {
                let promoted = {
                    let mut pending = pending.write().await;
                    let checkpoints = pending.entry(checkpoint.chain).or_default();
                    if let Some(stored) = checkpoints.get(&checkpoint.block_height) {
                        anyhow::ensure!(
                            stored == checkpoint,
                            "pending checkpoint changed before promotion at height {}",
                            checkpoint.block_height
                        );
                    }
                    let promoted = checkpoints
                        .remove(&checkpoint.block_height)
                        .unwrap_or_else(|| checkpoint.clone());
                    checkpoints.retain(|height, _| *height > checkpoint.block_height);
                    promoted
                };
                latest.write().await.insert(checkpoint.chain, promoted);
            }
        }
        Ok(())
    }

    /// Replace the confirmed checkpoint and discard obsolete pending checkpoints.
    pub async fn reset_to_latest(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        let value = serde_json::to_string(checkpoint)
            .context("failed to serialize checkpoint persistence")?;
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                const RESET: &str = r#"
                    redis.call('SET', KEYS[1], ARGV[1])
                    redis.call('DEL', KEYS[2])
                "#;
                let _: () = redis::Script::new(RESET)
                    .key(self.checkpoint_key(checkpoint.chain))
                    .key(self.pending_checkpoint_key(checkpoint.chain))
                    .arg(value)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to reset checkpoint state")?;
            }
            CheckpointStorage::InMemory {
                latest, pending, ..
            } => {
                pending.write().await.remove(&checkpoint.chain);
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
            CheckpointStorage::InMemory { latest, .. } => {
                Ok(latest.read().await.get(&chain).cloned())
            }
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
            cumulative_digest: Checkpoint::empty_cumulative_digest(),
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
            cumulative_digest: Checkpoint::empty_cumulative_digest(),
        };
        storage.persist(&cp2).await?;

        // 5. Verify latest is updated
        let latest = storage.load_latest(Chain::Solana).await?.unwrap();
        assert_eq!(latest.block_height, 20);

        Ok(())
    }

    #[tokio::test]
    async fn pending_checkpoints_promote_and_reset() -> anyhow::Result<()> {
        let storage = CheckpointStorage::in_memory();
        let chain = Chain::Solana;
        let checkpoint = |block_height| Checkpoint {
            chain,
            block_height,
            pending_requests: vec![],
            cumulative_digest: Checkpoint::empty_cumulative_digest(),
        };

        let first = checkpoint(10);
        let second = checkpoint(20);
        storage.persist_pending(&first).await?;
        storage.persist_pending(&second).await?;
        assert_eq!(
            storage.load_pending(chain).await?,
            vec![first.clone(), second.clone()]
        );

        storage.promote_pending(&first).await?;
        assert_eq!(storage.load_latest(chain).await?, Some(first));
        assert_eq!(storage.load_pending(chain).await?, vec![second]);

        let replacement = checkpoint(5);
        storage.reset_to_latest(&replacement).await?;
        assert_eq!(storage.load_latest(chain).await?, Some(replacement));
        assert!(storage.load_pending(chain).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn promotion_rejects_stale_checkpoint() -> anyhow::Result<()> {
        let storage = CheckpointStorage::in_memory();
        let checkpoint = Checkpoint {
            chain: Chain::Solana,
            block_height: 10,
            pending_requests: vec![],
            cumulative_digest: Checkpoint::empty_cumulative_digest(),
        };
        let mut conflicting = checkpoint.clone();
        conflicting.cumulative_digest[0] = 1;

        storage.persist_pending(&checkpoint).await?;
        storage.persist_pending(&conflicting).await?;
        assert!(storage.promote_pending(&checkpoint).await.is_err());
        assert_eq!(
            storage.load_pending(Chain::Solana).await?,
            vec![conflicting]
        );
        Ok(())
    }
}
