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

                const PERSIST_SCRIPT: &str = r#"
                    local latest_key = KEYS[1]
                    local history_key = KEYS[2]
                    local index_key = KEYS[3]
                    local value = ARGV[1]
                    local height = ARGV[2]

                    redis.call("SET", latest_key, value)
                    redis.call("SETEX", history_key, 1800, value)
                    redis.call("SADD", index_key, height)
                "#;

                let _: () = redis::Script::new(PERSIST_SCRIPT)
                    .key(self.checkpoint_key(checkpoint.chain))
                    .key(self.checkpoint_history_key(checkpoint.chain, checkpoint.height))
                    .key(self.checkpoint_history_index_key(checkpoint.chain))
                    .arg(&value)
                    .arg(checkpoint.height)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to persist checkpoint via lua script")?;
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
                let history_key_prefix = match self {
                    CheckpointStorage::Redis(_, account_id) => {
                        format!("{account_id}:checkpoint:history:{CHECKPOINT_VERSION}:{chain}:")
                    }
                    _ => unreachable!(),
                };

                const LOAD_HISTORY_SCRIPT: &str = r#"
                    local index_key = KEYS[1]
                    local history_key_prefix = ARGV[1]

                    local heights = redis.call("SMEMBERS", index_key)
                    if #heights == 0 then
                        return {}
                    end

                    local values = {}
                    local expired_heights = {}
                    for _, height in ipairs(heights) do
                        local key = history_key_prefix .. height
                        local val = redis.call("GET", key)
                        if val then
                            table.insert(values, val)
                        else
                            table.insert(expired_heights, height)
                        end
                    end

                    if #expired_heights > 0 then
                        redis.call("SREM", index_key, unpack(expired_heights))
                    end

                    return values
                "#;

                let values: Vec<String> = redis::Script::new(LOAD_HISTORY_SCRIPT)
                    .key(self.checkpoint_history_index_key(chain))
                    .arg(&history_key_prefix)
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
