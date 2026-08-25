use crate::protocol::Chain;

use crate::backlog::Checkpoint;
use crate::util::ChainMap;
use anyhow::Context;
use deadpool_redis::Pool;
use near_account_id::AccountId;
use redis::AsyncCommands;

use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug)]
pub enum CheckpointStorage {
    Redis(Pool, AccountId),
    InMemory {
        latest: ChainMap<Option<Checkpoint>>,
        pending: ChainMap<BTreeMap<u64, Checkpoint>>,
    },
    /// A storage that fails every operation, used to exercise error paths in tests.
    #[cfg(test)]
    Failing,
}

impl Default for CheckpointStorage {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl CheckpointStorage {
    pub fn in_memory() -> Self {
        Self::InMemory {
            latest: ChainMap::default(),
            pending: ChainMap::default(),
        }
    }

    #[cfg(test)]
    pub fn failing() -> Self {
        Self::Failing
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
            #[cfg(test)]
            CheckpointStorage::Failing => format!("checkpoint:latest:{chain}"),
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
            #[cfg(test)]
            CheckpointStorage::Failing => format!("checkpoint:pending:{chain}"),
        }
    }

    fn pending_digest_key(&self, chain: Chain) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!(
                    "{account_id}:checkpoint:pending_digest:{}:{chain}",
                    crate::CHECKPOINT_STORAGE_VERSION
                )
            }
            CheckpointStorage::InMemory { .. } => format!("checkpoint:pending_digest:{chain}"),
            #[cfg(test)]
            CheckpointStorage::Failing => format!("checkpoint:pending_digest:{chain}"),
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
                let value = encode_checkpoint(checkpoint)
                    .context("failed to serialize checkpoint persistence")?;

                conn.set::<_, _, ()>(self.checkpoint_key(checkpoint.chain), value)
                    .await
                    .context("failed to persist checkpoint to redis")?;
            }
            CheckpointStorage::InMemory { latest, .. } => {
                latest
                    .write(checkpoint.chain, |slot| *slot = Some(checkpoint.clone()))
                    .await;
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
        Ok(())
    }

    /// Persist an unconfirmed checkpoint before its digest is submitted for consensus.
    pub async fn persist_pending(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value = encode_checkpoint(checkpoint)
                    .context("failed to serialize pending checkpoint")?;
                let digest = hex::encode(checkpoint.digest());
                const PERSIST: &str = r#"
                    local existing = redis.call('HGET', KEYS[1], ARGV[1])
                    if existing and existing ~= ARGV[2] then
                        return 0
                    end
                    redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
                    redis.call('HSET', KEYS[2], ARGV[3], ARGV[1])
                    return 1
                "#;
                let persisted: i32 = redis::Script::new(PERSIST)
                    .key(self.pending_checkpoint_key(checkpoint.chain))
                    .key(self.pending_digest_key(checkpoint.chain))
                    .arg(checkpoint.block_height)
                    .arg(value)
                    .arg(digest)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to persist pending checkpoint to redis")?;
                if persisted == 0 {
                    anyhow::bail!(
                        "conflicting pending checkpoint at height {}",
                        checkpoint.block_height
                    );
                }
            }
            CheckpointStorage::InMemory { pending, .. } => {
                pending
                    .write(checkpoint.chain, |checkpoints| {
                        if let Some(existing) = checkpoints.get(&checkpoint.block_height) {
                            anyhow::ensure!(
                                existing == checkpoint,
                                "conflicting pending checkpoint at height {}",
                                checkpoint.block_height
                            );
                        }
                        checkpoints.insert(checkpoint.block_height, checkpoint.clone());
                        Ok(())
                    })
                    .await?;
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
        Ok(())
    }

    /// Load unconfirmed checkpoints ordered by block height.
    pub async fn load_pending(&self, chain: Chain) -> anyhow::Result<Vec<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let values: HashMap<String, Vec<u8>> = conn
                    .hgetall(self.pending_checkpoint_key(chain))
                    .await
                    .context("failed to load pending checkpoints from redis")?;
                let mut checkpoints = values
                    .into_values()
                    .map(|value| {
                        decode_checkpoint(&value)
                            .context("failed to deserialize pending checkpoint")
                    })
                    .collect::<anyhow::Result<Vec<Checkpoint>>>()?;
                checkpoints.sort_by_key(|checkpoint| checkpoint.block_height);
                Ok(checkpoints)
            }
            CheckpointStorage::InMemory { pending, .. } => Ok(pending
                .read(chain, |checkpoints| checkpoints.values().cloned().collect())
                .await),
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }

    /// Find a pending checkpoint by digest without loading the full pending set.
    ///
    /// Redis resolves the digest through a dedicated `digest -> height` index in
    /// a single script and fetches only the matching body, so a lookup never
    /// pulls other (possibly very large) pending checkpoints into memory.
    pub async fn find_pending(
        &self,
        chain: Chain,
        digest: [u8; 32],
    ) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                const FIND: &str = r#"
                    local height = redis.call('HGET', KEYS[1], ARGV[1])
                    if not height then
                        return false
                    end
                    return redis.call('HGET', KEYS[2], height)
                "#;
                let body: Option<Vec<u8>> = redis::Script::new(FIND)
                    .key(self.pending_digest_key(chain))
                    .key(self.pending_checkpoint_key(chain))
                    .arg(hex::encode(digest))
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to find pending checkpoint")?;
                match body {
                    Some(body) => {
                        let checkpoint: Checkpoint = decode_checkpoint(&body)
                            .context("failed to deserialize pending checkpoint")?;
                        Ok(Some(checkpoint))
                    }
                    None => Ok(None),
                }
            }
            CheckpointStorage::InMemory { pending, .. } => Ok(pending
                .read(chain, |checkpoints| {
                    checkpoints
                        .values()
                        .find(|checkpoint| checkpoint.digest() == digest)
                        .cloned()
                })
                .await),
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }

    /// Promote the durable pending checkpoint identified by its height.
    /// Returns false when the checkpoint is no longer pending.
    pub async fn promote_pending(&self, chain: Chain, height: u64) -> anyhow::Result<bool> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                const PROMOTE: &str = r#"
                    local pending = redis.call('HGET', KEYS[2], ARGV[1])
                    if not pending then
                        return 0
                    end
                    redis.call('SET', KEYS[1], pending)
                    local height = tonumber(ARGV[1])
                    local entries = redis.call('HGETALL', KEYS[2])
                    for i = 1, #entries, 2 do
                        local field_height = tonumber(entries[i])
                        if field_height <= height then
                            redis.call('HDEL', KEYS[2], entries[i])
                        end
                    end
                    local index = redis.call('HGETALL', KEYS[3])
                    for i = 1, #index, 2 do
                        local field_height = tonumber(index[i+1])
                        if field_height <= height then
                            redis.call('HDEL', KEYS[3], index[i])
                        end
                    end
                    return 1
                "#;
                let promoted: i32 = redis::Script::new(PROMOTE)
                    .key(self.checkpoint_key(chain))
                    .key(self.pending_checkpoint_key(chain))
                    .key(self.pending_digest_key(chain))
                    .arg(height)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to promote pending checkpoint")?;
                Ok(promoted == 1)
            }
            CheckpointStorage::InMemory {
                latest, pending, ..
            } => {
                let promoted = pending
                    .write(chain, |checkpoints| {
                        let promoted = checkpoints.remove(&height)?;
                        checkpoints.retain(|height, _| *height > promoted.block_height);
                        Some(promoted)
                    })
                    .await;
                let Some(promoted) = promoted else {
                    return Ok(false);
                };
                latest.write(chain, |slot| *slot = Some(promoted)).await;
                Ok(true)
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }

    /// Replace the confirmed checkpoint and discard obsolete pending checkpoints.
    pub async fn reset_to_latest(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        let value =
            encode_checkpoint(checkpoint).context("failed to serialize checkpoint persistence")?;
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                const RESET: &str = r#"
                    redis.call('SET', KEYS[1], ARGV[1])
                    redis.call('DEL', KEYS[2])
                    redis.call('DEL', KEYS[3])
                "#;
                let _: () = redis::Script::new(RESET)
                    .key(self.checkpoint_key(checkpoint.chain))
                    .key(self.pending_checkpoint_key(checkpoint.chain))
                    .key(self.pending_digest_key(checkpoint.chain))
                    .arg(value)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to reset checkpoint state")?;
            }
            CheckpointStorage::InMemory {
                latest, pending, ..
            } => {
                pending
                    .write(checkpoint.chain, |checkpoints| checkpoints.clear())
                    .await;
                latest
                    .write(checkpoint.chain, |slot| *slot = Some(checkpoint.clone()))
                    .await;
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
        Ok(())
    }

    pub async fn load_latest(&self, chain: Chain) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value: Option<Vec<u8>> = conn
                    .get(self.checkpoint_key(chain))
                    .await
                    .context("failed to get checkpoint from redis")?;
                match value {
                    Some(v) => {
                        let checkpoint: Checkpoint =
                            decode_checkpoint(&v).context("failed to deserialize checkpoint")?;
                        Ok(Some(checkpoint))
                    }
                    None => Ok(None),
                }
            }
            CheckpointStorage::InMemory { latest, .. } => {
                Ok(latest.read(chain, |slot| slot.clone()).await)
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }
}

fn encode_checkpoint(checkpoint: &Checkpoint) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(checkpoint, &mut bytes).context("failed to encode checkpoint CBOR")?;
    Ok(bytes)
}

fn decode_checkpoint(bytes: &[u8]) -> anyhow::Result<Checkpoint> {
    ciborium::from_reader(bytes).context("failed to decode checkpoint CBOR")
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

        assert!(storage.promote_pending(chain, first.block_height).await?);
        assert_eq!(storage.load_latest(chain).await?, Some(first));
        assert_eq!(storage.load_pending(chain).await?, vec![second]);

        let replacement = checkpoint(5);
        storage.reset_to_latest(&replacement).await?;
        assert_eq!(storage.load_latest(chain).await?, Some(replacement));
        assert!(storage.load_pending(chain).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn pending_checkpoint_rejects_conflicting_height() -> anyhow::Result<()> {
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
        storage.persist_pending(&checkpoint).await?;
        assert!(storage.persist_pending(&conflicting).await.is_err());
        assert!(
            !storage
                .promote_pending(Chain::Solana, checkpoint.block_height + 1)
                .await?
        );
        assert_eq!(storage.load_pending(Chain::Solana).await?, vec![checkpoint]);
        Ok(())
    }

    #[test]
    fn test_checkpoint_cbor_encoding_roundtrip() {
        let checkpoint = Checkpoint {
            chain: Chain::Ethereum,
            block_height: 100,
            pending_requests: vec![],
            cumulative_digest: [42u8; 32],
        };
        let encoded = encode_checkpoint(&checkpoint).unwrap();
        let decoded = decode_checkpoint(&encoded).unwrap();
        assert_eq!(checkpoint, decoded);
    }
}
