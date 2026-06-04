use crate::protocol::Chain;

use anyhow::Context;
use deadpool_redis::Pool;
use mpc_primitives::Checkpoint;
use near_account_id::AccountId;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

const CHECKPOINT_VERSION: &str = "v7";

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

    fn checkpoint_history_key(&self, chain: Chain, height: u64) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!("{account_id}:checkpoint:history:{CHECKPOINT_VERSION}:{chain}:{height}")
            }
            CheckpointStorage::InMemory { .. } => format!("checkpoint:history:{chain}:{height}"),
        }
    }

    fn checkpoint_history_index_key(&self, chain: Chain) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!("{account_id}:checkpoint:history_index:{CHECKPOINT_VERSION}:{chain}")
            }
            CheckpointStorage::InMemory { .. } => format!("checkpoint:history_index:{chain}"),
        }
    }

    pub async fn persist(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value = serde_json::to_string(checkpoint)
                    .context("failed to serialize checkpoint persistence")?;

                // 1. Persist the latest checkpoint
                conn.set::<_, _, ()>(self.checkpoint_key(checkpoint.chain), &value)
                    .await
                    .context("failed to set checkpoint in redis")?;

                // 2. Persist the historical checkpoint with 30-minute (1800s) TTL
                let history_key = self.checkpoint_history_key(checkpoint.chain, checkpoint.height);
                conn.set_ex::<_, _, ()>(history_key, &value, 1800)
                    .await
                    .context("failed to set historical checkpoint in redis")?;

                // 3. Add to index set
                conn.sadd::<_, _, ()>(
                    self.checkpoint_history_index_key(checkpoint.chain),
                    checkpoint.height,
                )
                .await
                .context("failed to add height to checkpoint history index")?;
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
                let heights: Vec<u64> = conn
                    .smembers(self.checkpoint_history_index_key(chain))
                    .await
                    .context("failed to get checkpoint history heights")?;
                if heights.is_empty() {
                    return Ok(Vec::new());
                }

                let keys: Vec<String> = heights
                    .iter()
                    .map(|h| self.checkpoint_history_key(chain, *h))
                    .collect();
                let values: Vec<Option<String>> = conn
                    .mget(&keys)
                    .await
                    .context("failed to get historical checkpoints")?;

                let mut checkpoints = Vec::new();
                let mut expired_heights = Vec::new();
                for (height, value) in heights.into_iter().zip(values) {
                    if let Some(v) = value {
                        let checkpoint: Checkpoint = serde_json::from_str(&v)
                            .context("failed to deserialize historical checkpoint")?;
                        checkpoints.push(checkpoint);
                    } else {
                        expired_heights.push(height);
                    }
                }

                if !expired_heights.is_empty() {
                    let _: () = conn
                        .srem(self.checkpoint_history_index_key(chain), &expired_heights)
                        .await
                        .context("failed to remove expired heights from index")?;
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
