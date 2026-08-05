use crate::protocol::Chain;

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_primitives::Checkpoint;
use near_account_id::AccountId;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::HashMap;
use std::sync::Arc;

const CHECKPOINT_VERSION: &str = "v14";

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
    /// Only consensus-confirmed checkpoints should be persisted. Persistence is
    /// monotonic by block height: a lower or equal-height checkpoint never
    /// replaces the first checkpoint already stored at that height. This keeps
    /// delayed confirmations from regressing durable recovery state.
    pub async fn persist(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        crate::backlog::validate_checkpoint_payload(checkpoint)
            .context("refusing to persist invalid checkpoint")?;

        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value = serde_json::to_string(checkpoint)
                    .context("failed to serialize checkpoint persistence")?;
                let key = self.checkpoint_key(checkpoint.chain);

                // The compare-and-set must happen on the Redis server. A
                // read-then-write sequence would allow two nodes to race and
                // let a stale checkpoint overwrite a newer one.
                const SCRIPT: &str = r#"
                    local current = redis.call('GET', KEYS[1])
                    if not current then
                        redis.call('SET', KEYS[1], ARGV[2])
                        return 1
                    end

                    local current_height = tonumber(cjson.decode(current).block_height)
                    if tonumber(ARGV[1]) > current_height then
                        redis.call('SET', KEYS[1], ARGV[2])
                        return 1
                    end
                    return 0
                "#;

                redis::Script::new(SCRIPT)
                    .key(key)
                    .arg(checkpoint.block_height)
                    .arg(value)
                    .invoke_async::<i32>(&mut conn)
                    .await
                    .context("failed to persist checkpoint to redis")?;
            }
            CheckpointStorage::InMemory { latest } => {
                let mut latest = latest.write().await;
                let should_replace = latest
                    .get(&checkpoint.chain)
                    .is_none_or(|current| checkpoint.block_height > current.block_height);
                if should_replace {
                    latest.insert(checkpoint.chain, checkpoint.clone());
                }
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
                        crate::backlog::validate_checkpoint_payload(&checkpoint)
                            .context("loaded checkpoint failed canonical validation")?;
                        Ok(Some(checkpoint))
                    }
                    None => Ok(None),
                }
            }
            CheckpointStorage::InMemory { latest } => {
                let checkpoint = latest.read().await.get(&chain).cloned();
                if let Some(checkpoint) = &checkpoint {
                    crate::backlog::validate_checkpoint_payload(checkpoint)
                        .context("loaded checkpoint failed canonical validation")?;
                }
                Ok(checkpoint)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use mpc_primitives::{Chain, IndexedSignRequest, SignArgs, SignId};

    fn checkpoint(chain: Chain, height: u64, marker: u8) -> Checkpoint {
        let mut checkpoint = Checkpoint::empty(chain);
        checkpoint.block_height = height;
        checkpoint.cumulative_digest = [marker; 32];
        checkpoint
    }

    #[tokio::test]
    async fn test_in_memory_checkpoint_storage() -> anyhow::Result<()> {
        let storage = CheckpointStorage::in_memory();

        assert!(storage.load_latest(Chain::Solana).await?.is_none());

        let cp1 = checkpoint(Chain::Solana, 10, 1);
        storage.persist(&cp1).await?;
        assert_eq!(storage.load_latest(Chain::Solana).await?, Some(cp1));

        let cp2 = checkpoint(Chain::Solana, 20, 2);
        storage.persist(&cp2).await?;
        assert_eq!(storage.load_latest(Chain::Solana).await?, Some(cp2));

        Ok(())
    }

    #[tokio::test]
    async fn test_in_memory_checkpoint_storage_ignores_stale_and_conflicting_equal_height_writes() {
        let storage = CheckpointStorage::in_memory();
        let current = checkpoint(Chain::Solana, 20, 1);
        storage.persist(&current).await.unwrap();

        storage
            .persist(&checkpoint(Chain::Solana, 10, 2))
            .await
            .unwrap();
        assert_eq!(
            storage.load_latest(Chain::Solana).await.unwrap(),
            Some(current.clone())
        );

        let competing = {
            let backlog = Backlog::new();
            backlog
                .insert(IndexedSignRequest::sign(
                    SignId::new([3; 32]),
                    SignArgs {
                        entropy: [3; 32],
                        epsilon: k256::Scalar::ONE,
                        payload: k256::Scalar::from(2u64),
                        path: "test".to_string(),
                        key_version: 0,
                    },
                    Chain::Solana,
                    0,
                ))
                .await;
            let mut checkpoint = backlog.checkpoint(Chain::Solana).await.unwrap();
            checkpoint.block_height = current.block_height;
            checkpoint
        };
        assert_ne!(competing.digest(), current.digest());

        storage.persist(&competing).await.unwrap();
        assert_eq!(
            storage.load_latest(Chain::Solana).await.unwrap(),
            Some(current)
        );
    }
}
