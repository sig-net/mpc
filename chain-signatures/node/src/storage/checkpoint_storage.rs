use crate::protocol::Chain;

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_primitives::Checkpoint;
use near_account_id::AccountId;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub const CHECKPOINT_VERSION: &str = "v8";

#[derive(Clone, Debug)]
pub enum CheckpointStorage {
    Redis(Pool, AccountId),
    InMemory {
        latest: Arc<RwLock<HashMap<Chain, Checkpoint>>>,
        history: Arc<RwLock<HashMap<Chain, BTreeMap<u64, Checkpoint>>>>,
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
            history: Arc::new(RwLock::new(HashMap::new())),
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

    fn checkpoint_history_key(&self, chain: Chain) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!("{account_id}:checkpoint:history:{CHECKPOINT_VERSION}:{chain}")
            }
            CheckpointStorage::InMemory { .. } => format!("checkpoint:history:{chain}"),
        }
    }

    pub async fn persist(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value = serde_json::to_string(checkpoint)
                    .context("failed to serialize checkpoint persistence")?;

                let timestamp = crate::util::current_unix_timestamp();
                const PERSIST_SCRIPT: &str = r#"
                    local latest_key = KEYS[1]
                    local history_key = KEYS[2]
                    local value = ARGV[1]
                    local score = tonumber(ARGV[2])

                    redis.call("SET", latest_key, value)
                    redis.call("ZADD", history_key, score, value)
                    redis.call("ZREMRANGEBYSCORE", history_key, 0, score - 1800)
                    redis.call("EXPIRE", history_key, 1800)
                "#;

                let _: () = redis::Script::new(PERSIST_SCRIPT)
                    .key(self.checkpoint_key(checkpoint.chain))
                    .key(self.checkpoint_history_key(checkpoint.chain))
                    .arg(&value)
                    .arg(timestamp)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to persist checkpoint")?;
            }
            CheckpointStorage::InMemory { latest, history } => {
                latest
                    .write()
                    .await
                    .insert(checkpoint.chain, checkpoint.clone());
                history
                    .write()
                    .await
                    .entry(checkpoint.chain)
                    .or_default()
                    .insert(checkpoint.height, checkpoint.clone());
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

    pub async fn load_history(&self, chain: Chain) -> anyhow::Result<Vec<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let timestamp = crate::util::current_unix_timestamp();

                const LOAD_HISTORY_SCRIPT: &str = r#"
                    local history_key = KEYS[1]
                    local current_time = tonumber(ARGV[1])

                    redis.call("ZREMRANGEBYSCORE", history_key, 0, current_time - 1800)
                    return redis.call("ZRANGE", history_key, 0, -1)
                "#;

                let values: Vec<String> = redis::Script::new(LOAD_HISTORY_SCRIPT)
                    .key(self.checkpoint_history_key(chain))
                    .arg(timestamp)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to load historical checkpoints")?;

                let mut checkpoints = Vec::new();
                for v in values {
                    let checkpoint: Checkpoint = serde_json::from_str(&v)
                        .context("failed to deserialize historical checkpoint")?;
                    checkpoints.push(checkpoint);
                }
                Ok(checkpoints)
            }
            CheckpointStorage::InMemory { history, .. } => {
                let guard = history.read().await;
                if let Some(map) = guard.get(&chain) {
                    Ok(map.values().cloned().collect())
                } else {
                    Ok(Vec::new())
                }
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

        // 1. Clean storage returns None / empty history
        assert!(storage.load_latest(Chain::Solana).await?.is_none());
        assert!(storage.load_history(Chain::Solana).await?.is_empty());

        // 2. Persist first checkpoint
        let cp1 = Checkpoint {
            chain: Chain::Solana,
            height: 10,
            pending_requests: vec![],
        };
        storage.persist(&cp1).await?;

        // 3. Verify latest and history
        let latest = storage.load_latest(Chain::Solana).await?.unwrap();
        assert_eq!(latest.height, 10);
        let history = storage.load_history(Chain::Solana).await?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].height, 10);

        // 4. Persist second checkpoint at higher height
        let cp2 = Checkpoint {
            chain: Chain::Solana,
            height: 20,
            pending_requests: vec![],
        };
        storage.persist(&cp2).await?;

        // 5. Verify latest is updated and history has both
        let latest = storage.load_latest(Chain::Solana).await?.unwrap();
        assert_eq!(latest.height, 20);
        let history = storage.load_history(Chain::Solana).await?;
        assert_eq!(history.len(), 2);
        let mut heights: Vec<u64> = history.iter().map(|cp| cp.height).collect();
        heights.sort();
        assert_eq!(heights, vec![10, 20]);

        Ok(())
    }
}
