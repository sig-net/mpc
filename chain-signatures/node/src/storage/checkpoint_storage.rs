use crate::protocol::Chain;

use crate::backlog::Checkpoint;
use anyhow::Context;
use deadpool_redis::Pool;
use near_account_id::AccountId;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailKind {
    All,
    Promotion,
}

#[derive(Clone, Debug)]
pub enum CheckpointStorage {
    Redis(Pool, AccountId),
    InMemory {
        latest: Arc<RwLock<HashMap<Chain, Checkpoint>>>,
        pending: Arc<RwLock<HashMap<Chain, BTreeMap<u64, Checkpoint>>>>,
    },
    /// A storage configured to fail operations, used to exercise error paths in tests.
    #[cfg(test)]
    Failing(FailKind),
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

    #[cfg(test)]
    pub fn failing() -> Self {
        Self::Failing(FailKind::All)
    }

    #[cfg(test)]
    pub fn failing_promotion() -> Self {
        Self::Failing(FailKind::Promotion)
    }

    fn key(&self, kind: &str, chain: Chain) -> String {
        match self {
            CheckpointStorage::Redis(_, account_id) => {
                format!(
                    "{account_id}:checkpoint:{kind}:{}:{chain}",
                    crate::CHECKPOINT_STORAGE_VERSION
                )
            }
            _ => format!("checkpoint:{kind}:{chain}"),
        }
    }

    fn checkpoint_key(&self, chain: Chain) -> String {
        self.key("latest", chain)
    }

    fn pending_checkpoint_key(&self, chain: Chain) -> String {
        self.key("pending", chain)
    }

    fn pending_digest_key(&self, chain: Chain) -> String {
        self.key("pending_digest", chain)
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
                    .write()
                    .await
                    .insert(checkpoint.chain, checkpoint.clone());
            }
            #[cfg(test)]
            CheckpointStorage::Failing(_) => {
                anyhow::bail!("failing storage")
            }
        }
        Ok(())
    }

    /// Persist an unconfirmed checkpoint before its digest is submitted for consensus.
    /// Returns true if newly persisted, or false if already persisted.
    pub async fn persist_pending(&self, checkpoint: &Checkpoint) -> anyhow::Result<bool> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value = encode_checkpoint(checkpoint)
                    .context("failed to serialize pending checkpoint")?;
                let digest = hex::encode(checkpoint.digest());
                // Atomically inserts a pending checkpoint and its reverse digest index
                // while checking for height collisions:
                // - If an entry already exists at `block_height`:
                //   - If the serialized payload is different, return -1 (conflicting checkpoint).
                //   - If identical, return 0 (idempotent no-op).
                // - If new, write `height -> body` to pending and `digest -> height` to index,
                //   and return 1 (successfully inserted).
                const PERSIST: &str = r#"
                    local existing = redis.call('HGET', KEYS[1], ARGV[1])
                    if existing then
                        if existing ~= ARGV[2] then
                            return -1
                        end
                        return 0
                    end
                    redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
                    redis.call('HSET', KEYS[2], ARGV[3], ARGV[1])
                    return 1
                "#;
                let status: i32 = redis::Script::new(PERSIST)
                    .key(self.pending_checkpoint_key(checkpoint.chain))
                    .key(self.pending_digest_key(checkpoint.chain))
                    .arg(checkpoint.block_height)
                    .arg(value)
                    .arg(digest)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to persist pending checkpoint to redis")?;
                if status < 0 {
                    anyhow::bail!(
                        "conflicting pending checkpoint at height {}",
                        checkpoint.block_height
                    );
                }
                Ok(status == 1)
            }
            CheckpointStorage::InMemory { pending, .. } => {
                let mut pending = pending.write().await;
                let checkpoints = pending.entry(checkpoint.chain).or_default();
                if let Some(existing) = checkpoints.get(&checkpoint.block_height) {
                    anyhow::ensure!(
                        existing == checkpoint,
                        "conflicting pending checkpoint at height {}",
                        checkpoint.block_height
                    );
                    return Ok(false);
                }
                checkpoints.insert(checkpoint.block_height, checkpoint.clone());
                Ok(true)
            }
            #[cfg(test)]
            CheckpointStorage::Failing(_) => {
                anyhow::bail!("failing storage")
            }
        }
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
                .read()
                .await
                .get(&chain)
                .map(|checkpoints| checkpoints.values().cloned().collect())
                .unwrap_or_default()),
            #[cfg(test)]
            CheckpointStorage::Failing(_) => {
                anyhow::bail!("failing storage")
            }
        }
    }

    /// Promote the durable pending checkpoint identified by its digest, or confirm
    /// it if already the latest checkpoint.
    /// Returns `Some(remaining_pending_count)` if confirmed, or `None` if not found.
    pub async fn promote_pending(
        &self,
        chain: Chain,
        digest: [u8; 32],
    ) -> anyhow::Result<Option<usize>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                // Atomically promotes a pending checkpoint to canonical latest and trims
                // obsolete pending entries, or falls back to checking the existing latest:
                // 1. Looks up `height` from the digest index (`KEYS[2]`) and fetches the `pending` body.
                // 2. If present in pending:
                //    - Overwrites canonical latest (`KEYS[3]`).
                //    - Scans `KEYS[2]` and trims all entries with `height <= num` from both
                //      the pending hash (`KEYS[1]`) and the index hash (`KEYS[2]`).
                //    - Returns `{ true, remaining_count, false }`.
                // 3. If absent from pending:
                //    - Returns `{ false, remaining_count, latest_body }` so caller can verify
                //      if the checkpoint was already promoted.
                const PROMOTE: &str = r#"
                    local height = redis.call('HGET', KEYS[2], ARGV[1])
                    local pending = height and redis.call('HGET', KEYS[1], height)
                    if pending then
                        redis.call('SET', KEYS[3], pending)
                        local num = tonumber(height)
                        local index = redis.call('HGETALL', KEYS[2])
                        for i = 1, #index, 2 do
                            if tonumber(index[i+1]) <= num then
                                redis.call('HDEL', KEYS[1], index[i+1])
                                redis.call('HDEL', KEYS[2], index[i])
                            end
                        end
                        return { true, redis.call('HLEN', KEYS[1]), false }
                    end
                    return { false, redis.call('HLEN', KEYS[1]), redis.call('GET', KEYS[3]) }
                "#;
                let (promoted, remaining, maybe_latest): (bool, usize, Option<Vec<u8>>) =
                    redis::Script::new(PROMOTE)
                        .key(self.pending_checkpoint_key(chain))
                        .key(self.pending_digest_key(chain))
                        .key(self.checkpoint_key(chain))
                        .arg(hex::encode(digest))
                        .invoke_async(&mut conn)
                        .await
                        .context("failed to promote pending checkpoint")?;

                if promoted {
                    return Ok(Some(remaining));
                }

                let is_confirmed = maybe_latest
                    .map(|bytes| decode_checkpoint(&bytes))
                    .transpose()
                    .context("failed to deserialize latest checkpoint")?
                    .is_some_and(|cp| cp.digest() == digest);

                Ok(is_confirmed.then_some(remaining))
            }
            CheckpointStorage::InMemory {
                latest, pending, ..
            } => {
                let mut pending = pending.write().await;
                let checkpoints = pending.entry(chain).or_default();

                if let Some((&height, _)) = checkpoints.iter().find(|(_, cp)| cp.digest() == digest)
                {
                    let promoted = checkpoints.remove(&height).unwrap();
                    checkpoints.retain(|h, _| *h > height);
                    let remaining = checkpoints.len();
                    drop(pending);

                    latest.write().await.insert(chain, promoted);
                    return Ok(Some(remaining));
                }

                let remaining = checkpoints.len();
                drop(pending);

                let is_confirmed = latest
                    .read()
                    .await
                    .get(&chain)
                    .is_some_and(|cp| cp.digest() == digest);

                Ok(is_confirmed.then_some(remaining))
            }
            #[cfg(test)]
            CheckpointStorage::Failing(_) => anyhow::bail!("failing storage"),
        }
    }

    /// Replace the confirmed checkpoint and discard obsolete pending checkpoints.
    pub async fn reset_to_latest(&self, checkpoint: &Checkpoint) -> anyhow::Result<()> {
        let value =
            encode_checkpoint(checkpoint).context("failed to serialize checkpoint persistence")?;
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                // Atomically replaces the canonical latest checkpoint with the consensus
                // checkpoint and wipes both pending storage hashes, clearing diverged history.
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
                pending.write().await.remove(&checkpoint.chain);
                latest
                    .write()
                    .await
                    .insert(checkpoint.chain, checkpoint.clone());
            }
            #[cfg(test)]
            CheckpointStorage::Failing(_) => anyhow::bail!("failing storage"),
        }
        Ok(())
    }

    /// Returns the number of pending checkpoints for `chain`.
    pub async fn pending_count(&self, chain: Chain) -> anyhow::Result<usize> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let count: usize = conn
                    .hlen(self.pending_checkpoint_key(chain))
                    .await
                    .context("failed to get pending checkpoint count from redis")?;
                Ok(count)
            }
            CheckpointStorage::InMemory { pending, .. } => Ok(pending
                .read()
                .await
                .get(&chain)
                .map(|p| p.len())
                .unwrap_or(0)),
            #[cfg(test)]
            CheckpointStorage::Failing(FailKind::All) => anyhow::bail!("failing storage"),
            #[cfg(test)]
            CheckpointStorage::Failing(FailKind::Promotion) => Ok(0),
        }
    }

    /// Returns the newest pending checkpoint or the latest confirmed checkpoint.
    pub async fn latest(&self, chain: Chain) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                // Redis Hashes (`HSET`) store unordered key-value pairs (block_height -> checkpoint body).
                // Redis does not support ordering or range queries on hash keys.
                // Because the pending checkpoint set is strictly bounded by MAX_PENDING_CHECKPOINTS,
                // walking the entire list of pending entries in Lua via `HGETALL` is effectively O(1).
                // This linear scan is instantaneous (< 1 microsecond) and avoids the operational complexity
                // and dual-write maintenance of an auxiliary Redis Sorted Set (ZSET).
                const LATEST: &str = r#"
                    local entries = redis.call('HGETALL', KEYS[1])
                    local max_height = -1
                    local newest_body = nil
                    for i = 1, #entries, 2 do
                        local height = tonumber(entries[i])
                        if height and height > max_height then
                            max_height = height
                            newest_body = entries[i+1]
                        end
                    end
                    if newest_body then
                        return newest_body
                    end
                    return redis.call('GET', KEYS[2])
                "#;
                let body: Option<Vec<u8>> = redis::Script::new(LATEST)
                    .key(self.pending_checkpoint_key(chain))
                    .key(self.checkpoint_key(chain))
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to load latest or newest pending checkpoint from redis")?;
                let Some(body) = body else {
                    return Ok(None);
                };
                let checkpoint =
                    decode_checkpoint(&body).context("failed to deserialize checkpoint")?;
                Ok(Some(checkpoint))
            }
            CheckpointStorage::InMemory {
                latest, pending, ..
            } => {
                let newest_pending = pending
                    .read()
                    .await
                    .get(&chain)
                    .and_then(|checkpoints| checkpoints.values().next_back().cloned());
                let confirmed = latest.read().await.get(&chain).cloned();
                Ok(match (newest_pending, confirmed) {
                    (Some(p), Some(c)) => Some(if p.block_height >= c.block_height {
                        p
                    } else {
                        c
                    }),
                    (p, c) => p.or(c),
                })
            }
            #[cfg(test)]
            CheckpointStorage::Failing(FailKind::All) => anyhow::bail!("failing storage"),
            #[cfg(test)]
            CheckpointStorage::Failing(FailKind::Promotion) => Ok(None),
        }
    }

    /// Finds a checkpoint by digest, searching durable latest and pending storage.
    pub async fn find(&self, chain: Chain, digest: [u8; 32]) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                // Resolves a checkpoint by digest across pending and latest storage:
                // - Checks the digest index (`KEYS[2]`); if present in pending, returns `{ true, pending_body }`.
                // - Otherwise returns `{ false, latest_body }` for latest checkpoint comparison.
                const FIND: &str = r#"
                    local height = redis.call('HGET', KEYS[2], ARGV[1])
                    local pending = height and redis.call('HGET', KEYS[1], height)
                    if pending then
                        return { true, pending }
                    end
                    return { false, redis.call('GET', KEYS[3]) }
                "#;
                let (is_pending, maybe_body): (bool, Option<Vec<u8>>) = redis::Script::new(FIND)
                    .key(self.pending_checkpoint_key(chain))
                    .key(self.pending_digest_key(chain))
                    .key(self.checkpoint_key(chain))
                    .arg(hex::encode(digest))
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to find checkpoint by digest")?;
                let Some(body) = maybe_body else {
                    return Ok(None);
                };
                let checkpoint =
                    decode_checkpoint(&body).context("failed to deserialize checkpoint")?;
                if is_pending || checkpoint.digest() == digest {
                    Ok(Some(checkpoint))
                } else {
                    Ok(None)
                }
            }
            CheckpointStorage::InMemory {
                latest, pending, ..
            } => {
                if let Some(cp) = pending.read().await.get(&chain).and_then(|checkpoints| {
                    checkpoints
                        .values()
                        .find(|cp| cp.digest() == digest)
                        .cloned()
                }) {
                    return Ok(Some(cp));
                }
                let confirmed = latest.read().await.get(&chain).cloned();
                Ok(confirmed.filter(|cp| cp.digest() == digest))
            }
            #[cfg(test)]
            CheckpointStorage::Failing(FailKind::All) => anyhow::bail!("failing storage"),
            #[cfg(test)]
            CheckpointStorage::Failing(FailKind::Promotion) => Ok(None),
        }
    }

    pub async fn load_latest(&self, chain: Chain) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value: Option<Vec<u8>> = conn
                    .get(self.checkpoint_key(chain))
                    .await
                    .context("failed to get checkpoint from redis")?;
                let Some(v) = value else {
                    return Ok(None);
                };
                let checkpoint: Checkpoint =
                    decode_checkpoint(&v).context("failed to deserialize checkpoint")?;
                Ok(Some(checkpoint))
            }
            CheckpointStorage::InMemory { latest, .. } => {
                Ok(latest.read().await.get(&chain).cloned())
            }
            #[cfg(test)]
            CheckpointStorage::Failing(FailKind::All) => anyhow::bail!("failing storage"),
            #[cfg(test)]
            CheckpointStorage::Failing(FailKind::Promotion) => Ok(None),
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

        assert_eq!(
            storage.promote_pending(chain, first.digest()).await?,
            Some(1)
        );
        assert_eq!(storage.load_latest(chain).await?, Some(first.clone()));
        assert_eq!(storage.load_pending(chain).await?, vec![second.clone()]);
        assert_eq!(storage.latest(chain).await?, Some(second));
        assert_eq!(storage.find(chain, first.digest()).await?, Some(first));

        let replacement = checkpoint(5);
        storage.reset_to_latest(&replacement).await?;
        assert_eq!(storage.load_latest(chain).await?, Some(replacement.clone()));
        assert_eq!(storage.latest(chain).await?, Some(replacement.clone()));
        assert_eq!(
            storage.find(chain, replacement.digest()).await?,
            Some(replacement)
        );
        assert!(storage.load_pending(chain).await?.is_empty());
        assert_eq!(storage.pending_count(chain).await?, 0);
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

        assert!(storage.persist_pending(&checkpoint).await?);
        assert!(!storage.persist_pending(&checkpoint).await?);
        assert!(storage.persist_pending(&conflicting).await.is_err());
        assert!(storage
            .promote_pending(Chain::Solana, [99; 32])
            .await?
            .is_none());
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
