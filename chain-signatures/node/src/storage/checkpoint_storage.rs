use crate::protocol::Chain;

use crate::backlog::Checkpoint;
use crate::sign_bidirectional::{BidirectionalProgress, SignStatus};
use anyhow::Context;
use deadpool_redis::Pool;
use mpc_primitives::SignId;
use near_account_id::AccountId;
use redis::AsyncCommands;
use tokio::sync::RwLock;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Per-chain digest-to-height index mirroring the Redis `orphan_digest` hash.
type ChainDigestHeights = RwLock<HashMap<Chain, HashMap<[u8; 32], u64>>>;

#[derive(Clone, Debug)]
pub enum CheckpointStorage {
    Redis(Pool, AccountId),
    InMemory {
        latest: Arc<RwLock<HashMap<Chain, Checkpoint>>>,
        pending: Arc<RwLock<HashMap<Chain, BTreeMap<u64, Checkpoint>>>>,
        orphan: Arc<RwLock<HashMap<Chain, BTreeMap<u64, Checkpoint>>>>,
        orphan_digest: Arc<ChainDigestHeights>,
        local: Arc<RwLock<HashMap<Chain, LocalRecords>>>,
        /// Upcoming calls to fail, for tests of transient errors.
        #[cfg(test)]
        injected_failures: Arc<InjectedFailures>,
    },
    /// A storage configured to fail operations, used to exercise error paths in tests.
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
            latest: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(RwLock::new(HashMap::new())),
            orphan: Arc::new(RwLock::new(HashMap::new())),
            orphan_digest: Arc::new(RwLock::new(HashMap::new())),
            local: Arc::default(),
            #[cfg(test)]
            injected_failures: Arc::default(),
        }
    }

    #[cfg(test)]
    pub fn failing() -> Self {
        Self::Failing
    }

    /// Makes the next `times` calls to `load_pending` fail; in-memory storage only.
    #[cfg(test)]
    pub fn fail_next_load_pending(&self, times: usize) {
        if let Self::InMemory {
            injected_failures, ..
        } = self
        {
            injected_failures
                .load_pending
                .store(times, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Makes the next `times` calls to `persist_pending` fail after the write,
    /// as when the reply is lost; in-memory storage only.
    #[cfg(test)]
    pub fn fail_next_persist_pending(&self, times: usize) {
        if let Self::InMemory {
            injected_failures, ..
        } = self
        {
            injected_failures
                .persist_pending
                .store(times, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[cfg(test)]
    fn take_injected_load_pending_failure(&self) -> bool {
        matches!(self, Self::InMemory { injected_failures, .. }
            if take_injected_failure(&injected_failures.load_pending))
    }

    #[cfg(test)]
    fn take_injected_persist_pending_failure(&self) -> bool {
        matches!(self, Self::InMemory { injected_failures, .. }
            if take_injected_failure(&injected_failures.persist_pending))
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

    fn orphan_checkpoint_key(&self, chain: Chain) -> String {
        self.key("orphan", chain)
    }

    fn orphan_digest_key(&self, chain: Chain) -> String {
        self.key("orphan_digest", chain)
    }

    fn local_key(&self, chain: Chain) -> String {
        self.key("local", chain)
    }

    /// Store what this node signed for one leg of a request, before it is published.
    pub async fn put_local(
        &self,
        chain: Chain,
        id: SignId,
        status: &SignStatus,
    ) -> anyhow::Result<()> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let bytes = encode_local(status)?;
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                conn.hset::<_, _, _, ()>(
                    self.local_key(chain),
                    local_field(id, leg(status)),
                    bytes,
                )
                .await
                .context("failed to store local record")?;
            }
            CheckpointStorage::InMemory { local, .. } => {
                local
                    .write()
                    .await
                    .entry(chain)
                    .or_default()
                    .insert((id, leg(status)), status.clone());
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
        Ok(())
    }

    /// This node's records for `chain`, up to one per leg of a request. One that cannot be read
    /// is skipped, which costs only signing that leg again.
    pub async fn load_local(&self, chain: Chain) -> anyhow::Result<Vec<(SignId, SignStatus)>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let stored: HashMap<Vec<u8>, Vec<u8>> = conn
                    .hgetall(self.local_key(chain))
                    .await
                    .context("failed to load local records")?;
                let decode = |(field, bytes): (Vec<u8>, Vec<u8>)| {
                    let id = SignId::new(field.get(..32)?.try_into().ok()?);
                    decode_local(&bytes)
                        .inspect_err(|err| {
                            tracing::warn!(?chain, ?id, ?err, "skipping unreadable local record");
                        })
                        .ok()
                        .map(|status| (id, status))
                };
                Ok(stored.into_iter().filter_map(decode).collect())
            }
            CheckpointStorage::InMemory { local, .. } => {
                let local = local.read().await;
                let records = local.get(&chain).into_iter().flatten();
                Ok(records
                    .map(|((id, _), status)| (*id, status.clone()))
                    .collect())
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }

    /// Delete this node's records of both legs of `ids`.
    pub async fn remove_local(&self, chain: Chain, ids: &[SignId]) -> anyhow::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let fields: Vec<Vec<u8>> = ids
                    .iter()
                    .flat_map(|id| LEGS.map(|leg| local_field(*id, leg)))
                    .collect();
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                conn.hdel::<_, _, ()>(self.local_key(chain), fields)
                    .await
                    .context("failed to remove local records")?;
            }
            CheckpointStorage::InMemory { local, .. } => {
                if let Some(records) = local.write().await.get_mut(&chain) {
                    records.retain(|(id, _), _| !ids.contains(id));
                }
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
        Ok(())
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
            CheckpointStorage::Failing => {
                anyhow::bail!("failing storage")
            }
        }
        Ok(())
    }

    /// Persist an unconfirmed checkpoint before its digest is submitted for consensus.
    /// Returns the number of pending checkpoints afterwards, or `None` if a
    /// different checkpoint is already stored at that height.
    pub async fn persist_pending(&self, checkpoint: &Checkpoint) -> anyhow::Result<Option<usize>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                let value = encode_checkpoint(checkpoint)
                    .context("failed to serialize pending checkpoint")?;
                let digest = hex::encode(checkpoint.digest());
                // Atomically inserts a pending checkpoint and its reverse digest index
                // while checking for height collisions:
                // - If an entry already exists at `block_height`:
                //   - If its digest is different, return -1 (a body can differ in this node's
                //     progress alone; conflicting checkpoint).
                //   - If identical, it is an idempotent no-op.
                // - If new, write `height -> body` to pending and `digest -> height` to index.
                // Returns the pending count unless conflicting.
                const PERSIST: &str = r#"
                    local existing = redis.call('HGET', KEYS[1], ARGV[1])
                    if existing then
                        if redis.call('HGET', KEYS[2], ARGV[3]) ~= ARGV[1] then
                            return -1
                        end
                    else
                        redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
                        redis.call('HSET', KEYS[2], ARGV[3], ARGV[1])
                    end
                    return redis.call('HLEN', KEYS[1])
                "#;
                let count: i64 = redis::Script::new(PERSIST)
                    .key(self.pending_checkpoint_key(checkpoint.chain))
                    .key(self.pending_digest_key(checkpoint.chain))
                    .arg(checkpoint.block_height)
                    .arg(value)
                    .arg(digest)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to persist pending checkpoint to redis")?;
                Ok(usize::try_from(count).ok())
            }
            CheckpointStorage::InMemory { pending, .. } => {
                let mut pending = pending.write().await;
                let checkpoints = pending.entry(checkpoint.chain).or_default();
                match checkpoints.get(&checkpoint.block_height) {
                    Some(existing) if existing.digest() != checkpoint.digest() => return Ok(None),
                    Some(_) => {}
                    None => {
                        checkpoints.insert(checkpoint.block_height, checkpoint.clone());
                    }
                }
                #[cfg(test)]
                if self.take_injected_persist_pending_failure() {
                    anyhow::bail!("injected persist_pending failure");
                }
                Ok(Some(checkpoints.len()))
            }
            #[cfg(test)]
            CheckpointStorage::Failing => {
                anyhow::bail!("failing storage")
            }
        }
    }

    /// Load unconfirmed checkpoints ordered by block height.
    pub async fn load_pending(&self, chain: Chain) -> anyhow::Result<Vec<Checkpoint>> {
        #[cfg(test)]
        if self.take_injected_load_pending_failure() {
            anyhow::bail!("injected load_pending failure");
        }
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
            CheckpointStorage::Failing => {
                anyhow::bail!("failing storage")
            }
        }
    }

    /// Move every durable pending checkpoint into the orphan set, keyed by height
    /// and indexed by digest. Orphans stay durable, servable by digest, and
    /// promotable, but are never a recovery seed or re-voted. Returns the number
    /// of bodies moved. Idempotent when pending is empty.
    pub async fn demote_pending_to_orphan(&self, chain: Chain) -> anyhow::Result<usize> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                // Reuse the pending index rather than recomputing any digest. Each
                // hash is read in a single pass up front (Redis is single-threaded,
                // so per-entry HGETALL would block other clients): the pending
                // bodies keyed by height, the pending (digest -> height) index that
                // drives the loop, and a reverse (height -> digests) map of the
                // orphan index. For each index entry, copy the body at that height
                // into the orphan hash and its reverse index, then drop both
                // pending keys. Empty pending is a no-op returning zero.
                const DEMOTE: &str = r#"
                    local count = 0
                    -- Single-pass reads: bodies[height] = body.
                    local bodies = {}
                    local pending = redis.call('HGETALL', KEYS[1])
                    for i = 1, #pending, 2 do
                        bodies[pending[i]] = pending[i+1]
                    end
                    -- The pending digest index is the loop source.
                    local index = redis.call('HGETALL', KEYS[2])
                    -- Reverse orphan index: digests_at_height[height] = { digest, ... }.
                    local digests_at_height = {}
                    local reverse = redis.call('HGETALL', KEYS[4])
                    for i = 1, #reverse, 2 do
                        local height = reverse[i+1]
                        if not digests_at_height[height] then
                            digests_at_height[height] = {}
                        end
                        table.insert(digests_at_height[height], reverse[i])
                    end
                    for i = 1, #index, 2 do
                        local height = index[i+1]
                        local digest = index[i]
                        local body = bodies[height]
                        if body then
                            -- A prior demotion may have indexed a different body at this
                            -- height. Purge every digest pointing here (from the
                            -- pre-read snapshot) before writing the incoming one so no
                            -- stale digest can resolve to this body.
                            local at_height = digests_at_height[height]
                            if at_height then
                                for j = 1, #at_height do
                                    redis.call('HDEL', KEYS[4], at_height[j])
                                end
                            end
                            redis.call('HSET', KEYS[3], height, body)
                            redis.call('HSET', KEYS[4], digest, height)
                            count = count + 1
                        end
                    end
                    redis.call('DEL', KEYS[1])
                    redis.call('DEL', KEYS[2])
                    return count
                "#;
                let count: usize = redis::Script::new(DEMOTE)
                    .key(self.pending_checkpoint_key(chain))
                    .key(self.pending_digest_key(chain))
                    .key(self.orphan_checkpoint_key(chain))
                    .key(self.orphan_digest_key(chain))
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to demote pending checkpoints to orphans")?;
                Ok(count)
            }
            CheckpointStorage::InMemory {
                pending,
                orphan,
                orphan_digest,
                ..
            } => {
                let Some(moved) = pending.write().await.remove(&chain) else {
                    return Ok(0);
                };
                let count = moved.len();
                let mut orphans = orphan.write().await;
                let chain_orphans = orphans.entry(chain).or_default();
                let mut index = orphan_digest.write().await;
                let chain_index = index.entry(chain).or_default();
                for (height, checkpoint) in moved {
                    let digest = checkpoint.digest();
                    // A prior demotion may have indexed a different body at this
                    // height. Drop every digest pointing here except the incoming
                    // one so no stale digest can resolve to this body.
                    chain_index.retain(|indexed_digest, indexed_height| {
                        *indexed_height != height || *indexed_digest == digest
                    });
                    chain_index.insert(digest, height);
                    chain_orphans.insert(height, checkpoint);
                }
                Ok(count)
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }

    /// Promote the durable checkpoint identified by its digest from either the
    /// pending or the orphan store, or confirm it if already the canonical base.
    /// Returns `Some(remaining_pending_count)` if confirmed, or `None` if not found.
    pub async fn promote(&self, chain: Chain, digest: [u8; 32]) -> anyhow::Result<Option<usize>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                // Atomically promotes a pending or orphan checkpoint to canonical latest
                // and trims obsolete entries, or falls back to checking the existing latest.
                // Promotion matches by the stored digest index: DEMOTE's purge keeps each
                // indexed digest pointing at the body it indexes, so no re-verification is
                // needed here.
                // 1. Looks up `height` from the pending index (`KEYS[2]`), else the orphan
                //    index (`KEYS[5]`), and fetches the matching body.
                // 2. If found:
                //    - Overwrites canonical latest (`KEYS[3]`).
                //    - Trims every entry with `height <= num` from both stores and both
                //      indexes; the matched body's height is `num`, so this retires it
                //      too (no separate retire step is needed).
                //    - Returns `{ true, remaining_pending_count, false }` — orphans never
                //      count toward the pending cap.
                // 3. If absent from both:
                //    - Returns `{ false, remaining_pending_count, latest_body }` so the
                //      caller can verify whether the checkpoint was already promoted.
                const PROMOTE: &str = r#"
                    local height = redis.call('HGET', KEYS[2], ARGV[1])
                    local body = height and redis.call('HGET', KEYS[1], height)
                    if not body then
                        height = redis.call('HGET', KEYS[5], ARGV[1])
                        body = height and redis.call('HGET', KEYS[4], height)
                    end
                    if body then
                        redis.call('SET', KEYS[3], body)
                        local num = tonumber(height)
                        local index = redis.call('HGETALL', KEYS[2])
                        for i = 1, #index, 2 do
                            if tonumber(index[i+1]) <= num then
                                redis.call('HDEL', KEYS[1], index[i+1])
                                redis.call('HDEL', KEYS[2], index[i])
                            end
                        end
                        index = redis.call('HGETALL', KEYS[5])
                        for i = 1, #index, 2 do
                            if tonumber(index[i+1]) <= num then
                                redis.call('HDEL', KEYS[4], index[i+1])
                                redis.call('HDEL', KEYS[5], index[i])
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
                        .key(self.orphan_checkpoint_key(chain))
                        .key(self.orphan_digest_key(chain))
                        .arg(hex::encode(digest))
                        .invoke_async(&mut conn)
                        .await
                        .context("failed to promote checkpoint")?;

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
                latest,
                pending,
                orphan,
                orphan_digest,
                ..
            } => {
                // Pending has no in-memory digest index, so scan it; orphans are
                // indexed by digest, so resolve the height directly.
                let mut found = {
                    let pending = pending.read().await;
                    pending.get(&chain).and_then(|checkpoints| {
                        checkpoints
                            .iter()
                            .find(|(_, cp)| cp.digest() == digest)
                            .map(|(&height, cp)| (height, cp.clone()))
                    })
                };
                if found.is_none() {
                    let height = orphan_digest
                        .read()
                        .await
                        .get(&chain)
                        .and_then(|index| index.get(&digest))
                        .copied();
                    if let Some(height) = height {
                        let orphan = orphan.read().await;
                        if let Some(cp) = orphan.get(&chain).and_then(|m| m.get(&height)) {
                            if cp.digest() == digest {
                                found = Some((height, cp.clone()));
                            }
                        }
                    }
                }

                if let Some((height, promoted)) = found {
                    // Retire the matched body and every other entry at or below
                    // its height from both stores and the orphan index.
                    let mut pending = pending.write().await;
                    if let Some(checkpoints) = pending.get_mut(&chain) {
                        checkpoints.retain(|h, _| *h > height);
                    }
                    let remaining = pending
                        .get(&chain)
                        .map_or(0, |checkpoints| checkpoints.len());
                    drop(pending);

                    let mut orphan = orphan.write().await;
                    if let Some(checkpoints) = orphan.get_mut(&chain) {
                        checkpoints.retain(|h, _| *h > height);
                    }
                    drop(orphan);
                    let mut index = orphan_digest.write().await;
                    if let Some(index) = index.get_mut(&chain) {
                        index.retain(|_, h| *h > height);
                    }
                    drop(index);

                    latest.write().await.insert(chain, promoted);
                    return Ok(Some(remaining));
                }

                let remaining = pending.read().await.get(&chain).map_or(0, |m| m.len());
                let is_confirmed = latest
                    .read()
                    .await
                    .get(&chain)
                    .is_some_and(|cp| cp.digest() == digest);

                Ok(is_confirmed.then_some(remaining))
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
                // Atomically replaces the canonical latest checkpoint with the consensus
                // checkpoint and wipes both pending and both orphan hashes, clearing
                // diverged history.
                const RESET: &str = r#"
                    redis.call('SET', KEYS[1], ARGV[1])
                    redis.call('DEL', KEYS[2])
                    redis.call('DEL', KEYS[3])
                    redis.call('DEL', KEYS[4])
                    redis.call('DEL', KEYS[5])
                "#;
                let _: () = redis::Script::new(RESET)
                    .key(self.checkpoint_key(checkpoint.chain))
                    .key(self.pending_checkpoint_key(checkpoint.chain))
                    .key(self.pending_digest_key(checkpoint.chain))
                    .key(self.orphan_checkpoint_key(checkpoint.chain))
                    .key(self.orphan_digest_key(checkpoint.chain))
                    .arg(value)
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to reset checkpoint state")?;
            }
            CheckpointStorage::InMemory {
                latest,
                pending,
                orphan,
                orphan_digest,
                ..
            } => {
                pending.write().await.remove(&checkpoint.chain);
                orphan.write().await.remove(&checkpoint.chain);
                orphan_digest.write().await.remove(&checkpoint.chain);
                latest
                    .write()
                    .await
                    .insert(checkpoint.chain, checkpoint.clone());
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
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
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }

    /// Returns the newest pending, orphan, or confirmed checkpoint by block height.
    pub async fn latest(&self, chain: Chain) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                // One atomic pass returns the best pending/orphan candidate together with
                // the raw canonical base body (`KEYS[2]`), so no separate GET is needed.
                // Lua cannot decode the base's CBOR to read its height, so the final
                // comparison (base wins height ties) happens in Rust once both bodies
                // are decoded.
                // Redis Hashes (`HSET`) store unordered key-value pairs (block_height -> checkpoint body).
                // Redis does not support ordering or range queries on hash keys.
                // Pending is capped at MAX_PENDING_CHECKPOINTS. Orphans hold at most one body
                // per boundary height in the window above the confirmed base: a demotion
                // overwrites the body at a height (purging stale index entries) rather than
                // adding a second one, `promote` deletes every orphan at or below the promoted
                // height, and `reset` wipes them. So the scan stays small and does not grow with
                // restart frequency, only with new heights above the base, which the cap bounds.
                // This linear scan avoids the operational complexity and dual-write maintenance
                // of a ZSET.
                const LATEST: &str = r#"
                    local function scan(key)
                        local entries = redis.call('HGETALL', key)
                        local best_height = -1
                        local best_body = false
                        for i = 1, #entries, 2 do
                            local h = tonumber(entries[i])
                            if h and h > best_height then
                                best_height = h
                                best_body = entries[i+1]
                            end
                        end
                        return best_height, best_body
                    end
                    local ph, pb = scan(KEYS[1])   -- pending
                    local oh, ob = scan(KEYS[3])   -- orphan
                    local best_h, best_b = ph, pb
                    if oh > best_h then best_h, best_b = oh, ob end
                    local base_b = redis.call('GET', KEYS[2])   -- confirmed base
                    return { best_h, best_b, base_b }
                "#;
                let (_, candidate_body, base_body): (i64, Option<Vec<u8>>, Option<Vec<u8>>) =
                    redis::Script::new(LATEST)
                        .key(self.pending_checkpoint_key(chain))
                        .key(self.checkpoint_key(chain))
                        .key(self.orphan_checkpoint_key(chain))
                        .invoke_async(&mut conn)
                        .await
                        .context("failed to load latest checkpoint from redis")?;

                // Decode both bodies in Rust: Lua cannot read the base's CBOR height.
                let base = base_body
                    .map(|bytes| decode_checkpoint(&bytes))
                    .transpose()
                    .context("failed to deserialize confirmed checkpoint")?;
                let candidate = candidate_body
                    .map(|bytes| decode_checkpoint(&bytes))
                    .transpose()
                    .context("failed to deserialize checkpoint")?;

                // The confirmed base wins height ties; a pending/orphan candidate is
                // chosen only when strictly newer.
                Ok(match (base, candidate) {
                    (Some(base), Some(candidate)) if candidate.block_height > base.block_height => {
                        Some(candidate)
                    }
                    (Some(base), _) => Some(base),
                    (None, candidate) => candidate,
                })
            }
            CheckpointStorage::InMemory {
                latest,
                pending,
                orphan,
                ..
            } => {
                let newest_pending = pending
                    .read()
                    .await
                    .get(&chain)
                    .and_then(|checkpoints| checkpoints.values().next_back().cloned());
                let newest_orphan = orphan
                    .read()
                    .await
                    .get(&chain)
                    .and_then(|checkpoints| checkpoints.values().next_back().cloned());
                let confirmed = latest.read().await.get(&chain).cloned();
                // The confirmed base wins height ties: it starts as the candidate and is
                // replaced only by a strictly newer pending or orphan body, matching the
                // Redis arm where the base height seeds the max comparison.
                let mut best = confirmed;
                for candidate in [newest_pending, newest_orphan].into_iter().flatten() {
                    if best
                        .as_ref()
                        .is_none_or(|current| candidate.block_height > current.block_height)
                    {
                        best = Some(candidate);
                    }
                }
                Ok(best)
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }

    /// Returns whether a pending or confirmed checkpoint exists for `chain`,
    /// without reading its body. Mirrors [`Self::latest`]'s key selection, so it
    /// answers `true` whenever `latest` would return a body, and may also answer
    /// `true` for stored state `latest` cannot read back.
    pub async fn has_checkpoint(&self, chain: Chain) -> anyhow::Result<bool> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                // An empty hash does not exist in Redis, so these keys cover
                // exactly the pending/orphan/confirmed states `latest` looks at.
                let found: usize = conn
                    .exists((
                        self.pending_checkpoint_key(chain),
                        self.checkpoint_key(chain),
                        self.orphan_checkpoint_key(chain),
                    ))
                    .await
                    .context("failed to check for a stored checkpoint in redis")?;
                Ok(found > 0)
            }
            CheckpointStorage::InMemory {
                latest,
                pending,
                orphan,
                ..
            } => {
                let has_pending = pending
                    .read()
                    .await
                    .get(&chain)
                    .is_some_and(|checkpoints| !checkpoints.is_empty());
                let has_orphan = orphan
                    .read()
                    .await
                    .get(&chain)
                    .is_some_and(|checkpoints| !checkpoints.is_empty());
                Ok(has_pending || has_orphan || latest.read().await.contains_key(&chain))
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }

    /// Finds a checkpoint by digest, searching durable latest, pending and orphan storage.
    pub async fn find(&self, chain: Chain, digest: [u8; 32]) -> anyhow::Result<Option<Checkpoint>> {
        match self {
            CheckpointStorage::Redis(pool, _) => {
                let mut conn = pool.get().await.context("failed to get redis connection")?;
                // Resolves a checkpoint by digest across pending, orphan and latest storage:
                // checks the pending digest index (`KEYS[2]`), then the orphan digest index
                // (`KEYS[5]`), then the confirmed base (`KEYS[3]`), and returns the body.
                // The body's digest is always verified in Rust against the requested one;
                // a stale orphan index must never make a different body look like a hit.
                const FIND: &str = r#"
                    local height = redis.call('HGET', KEYS[2], ARGV[1])
                    local pending = height and redis.call('HGET', KEYS[1], height)
                    if pending then
                        return pending
                    end
                    local orphan_height = redis.call('HGET', KEYS[5], ARGV[1])
                    local orphan = orphan_height and redis.call('HGET', KEYS[4], orphan_height)
                    if orphan then
                        return orphan
                    end
                    return redis.call('GET', KEYS[3])
                "#;
                let body: Option<Vec<u8>> = redis::Script::new(FIND)
                    .key(self.pending_checkpoint_key(chain))
                    .key(self.pending_digest_key(chain))
                    .key(self.checkpoint_key(chain))
                    .key(self.orphan_checkpoint_key(chain))
                    .key(self.orphan_digest_key(chain))
                    .arg(hex::encode(digest))
                    .invoke_async(&mut conn)
                    .await
                    .context("failed to find checkpoint by digest")?;
                let Some(body) = body else {
                    return Ok(None);
                };
                let checkpoint =
                    decode_checkpoint(&body).context("failed to deserialize checkpoint")?;
                Ok((checkpoint.digest() == digest).then_some(checkpoint))
            }
            CheckpointStorage::InMemory {
                latest,
                pending,
                orphan,
                orphan_digest,
                ..
            } => {
                if let Some(cp) = pending.read().await.get(&chain).and_then(|checkpoints| {
                    checkpoints
                        .values()
                        .find(|cp| cp.digest() == digest)
                        .cloned()
                }) {
                    return Ok(Some(cp));
                }
                let orphan_cp = {
                    let height = orphan_digest
                        .read()
                        .await
                        .get(&chain)
                        .and_then(|index| index.get(&digest))
                        .copied();
                    match height {
                        Some(height) => orphan
                            .read()
                            .await
                            .get(&chain)
                            .and_then(|m| m.get(&height))
                            .cloned(),
                        None => None,
                    }
                };
                if let Some(cp) = orphan_cp.filter(|cp| cp.digest() == digest) {
                    return Ok(Some(cp));
                }
                let confirmed = latest.read().await.get(&chain).cloned();
                Ok(confirmed.filter(|cp| cp.digest() == digest))
            }
            #[cfg(test)]
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
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
            CheckpointStorage::Failing => anyhow::bail!("failing storage"),
        }
    }
}

/// In-memory records, by request and leg.
type LocalRecords = HashMap<(SignId, Leg), SignStatus>;

/// The byte after the request id in a record's field, so the values are part of the format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Leg {
    First = 0,
    Attestation = 1,
}

const LEGS: [Leg; 2] = [Leg::First, Leg::Attestation];

/// The leg a record belongs to, so an attestation never replaces the first leg's signature.
fn leg(status: &SignStatus) -> Leg {
    match status {
        SignStatus::Bidirectional(BidirectionalProgress::Final { .. }) => Leg::Attestation,
        _ => Leg::First,
    }
}

fn local_field(id: SignId, leg: Leg) -> Vec<u8> {
    [id.request_id.as_slice(), &[leg as u8]].concat()
}

fn encode_local(status: &SignStatus) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(status, &mut bytes).context("failed to encode local record")?;
    Ok(bytes)
}

fn decode_local(bytes: &[u8]) -> anyhow::Result<SignStatus> {
    ciborium::from_reader(bytes).context("failed to decode local record")
}

fn encode_checkpoint(checkpoint: &Checkpoint) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(checkpoint, &mut bytes).context("failed to encode checkpoint CBOR")?;
    Ok(bytes)
}

fn decode_checkpoint(bytes: &[u8]) -> anyhow::Result<Checkpoint> {
    ciborium::from_reader(bytes).context("failed to decode checkpoint CBOR")
}

/// Per-operation counts of upcoming calls to fail.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct InjectedFailures {
    load_pending: std::sync::atomic::AtomicUsize,
    persist_pending: std::sync::atomic::AtomicUsize,
}

/// Consumes one injected failure from `remaining`, if any is left.
#[cfg(test)]
fn take_injected_failure(remaining: &std::sync::atomic::AtomicUsize) -> bool {
    remaining
        .fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |remaining| remaining.checked_sub(1),
        )
        .is_ok()
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
            legacy_digest: None,
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
            legacy_digest: None,
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
            legacy_digest: None,
        };

        let first = checkpoint(10);
        let second = checkpoint(20);
        storage.persist_pending(&first).await?;
        storage.persist_pending(&second).await?;
        assert_eq!(
            storage.load_pending(chain).await?,
            vec![first.clone(), second.clone()]
        );

        assert_eq!(storage.promote(chain, first.digest()).await?, Some(1));
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
            legacy_digest: None,
        };
        let mut conflicting = checkpoint.clone();
        conflicting
            .pending_requests
            .push(crate::backlog::BacklogEntry::new(
                crate::backlog::mock::mock_sign_request(
                    mpc_primitives::SignId::new([1; 32]),
                    conflicting.chain,
                ),
            ));

        assert_eq!(storage.persist_pending(&checkpoint).await?, Some(1));
        assert_eq!(storage.persist_pending(&checkpoint).await?, Some(1));
        assert_eq!(storage.persist_pending(&conflicting).await?, None);
        assert!(storage.promote(Chain::Solana, [99; 32]).await?.is_none());
        assert_eq!(storage.load_pending(Chain::Solana).await?, vec![checkpoint]);
        Ok(())
    }

    #[test]
    fn test_checkpoint_cbor_encoding_roundtrip() {
        let checkpoint = Checkpoint {
            chain: Chain::Ethereum,
            block_height: 100,
            pending_requests: vec![],
            legacy_digest: None,
        };
        let encoded = encode_checkpoint(&checkpoint).unwrap();
        let decoded = decode_checkpoint(&encoded).unwrap();
        assert_eq!(checkpoint, decoded);
    }

    /// `promote` leaves an empty map behind for a chain that has no
    /// checkpoints, so "pending is present" must not be read as "non-empty".
    /// The Redis arm is covered in integration-tests/tests/cases/store.rs.
    #[tokio::test]
    async fn has_checkpoint_ignores_an_empty_pending_map() -> anyhow::Result<()> {
        let chain = Chain::Solana;
        let storage = CheckpointStorage::in_memory();
        storage.promote(chain, [0u8; 32]).await?;

        assert!(!storage.has_checkpoint(chain).await?);
        assert!(storage.latest(chain).await?.is_none());
        Ok(())
    }

    fn checkpoint(chain: Chain, block_height: u64) -> Checkpoint {
        Checkpoint {
            chain,
            block_height,
            pending_requests: vec![],
            legacy_digest: None,
        }
    }

    /// A checkpoint at `block_height` with one distinct request, so different ids
    /// produce different digests at the same height.
    fn checkpoint_with_id(chain: Chain, block_height: u64, id: u8) -> Checkpoint {
        let mut cp = checkpoint(chain, block_height);
        cp.pending_requests.push(crate::backlog::BacklogEntry::new(
            crate::backlog::mock::mock_sign_request(mpc_primitives::SignId::new([id; 32]), chain),
        ));
        cp
    }

    #[tokio::test]
    async fn demote_moves_pending_to_orphan_and_is_idempotent() -> anyhow::Result<()> {
        let chain = Chain::Solana;
        let storage = CheckpointStorage::in_memory();
        let first = checkpoint(chain, 10);
        let second = checkpoint(chain, 20);
        storage.persist_pending(&first).await?;
        storage.persist_pending(&second).await?;

        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 2);
        // Orphans are servable by digest but are no longer pending.
        assert!(storage.load_pending(chain).await?.is_empty());
        assert_eq!(
            storage.find(chain, first.digest()).await?,
            Some(first.clone())
        );
        assert_eq!(
            storage.find(chain, second.digest()).await?,
            Some(second.clone())
        );
        assert!(storage.has_checkpoint(chain).await?);

        // A second pass over empty pending is a no-op and keeps the orphans.
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 0);
        assert_eq!(storage.find(chain, first.digest()).await?, Some(first));
        Ok(())
    }

    #[tokio::test]
    async fn promote_works_from_orphan_by_digest() -> anyhow::Result<()> {
        let chain = Chain::Solana;
        let storage = CheckpointStorage::in_memory();
        let first = checkpoint(chain, 10);
        let second = checkpoint(chain, 20);
        storage.persist_pending(&first).await?;
        storage.persist_pending(&second).await?;
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 2);
        assert!(storage.load_pending(chain).await?.is_empty());

        assert_eq!(storage.promote(chain, second.digest()).await?, Some(0));
        assert_eq!(storage.load_latest(chain).await?, Some(second.clone()));
        // Both orphans were at or below the promoted height and were retired.
        assert!(storage.find(chain, first.digest()).await?.is_none());
        assert_eq!(storage.latest(chain).await?, Some(second));
        Ok(())
    }

    #[tokio::test]
    async fn reset_clears_orphans() -> anyhow::Result<()> {
        let chain = Chain::Solana;
        let storage = CheckpointStorage::in_memory();
        let orphan = checkpoint(chain, 10);
        storage.persist_pending(&orphan).await?;
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 1);

        let replacement = checkpoint(chain, 5);
        storage.reset_to_latest(&replacement).await?;

        assert_eq!(storage.load_latest(chain).await?, Some(replacement.clone()));
        assert!(storage.find(chain, orphan.digest()).await?.is_none());
        assert!(storage.load_pending(chain).await?.is_empty());
        assert_eq!(storage.latest(chain).await?, Some(replacement));
        Ok(())
    }

    #[tokio::test]
    async fn latest_picks_higher_of_orphan_and_base() -> anyhow::Result<()> {
        let chain = Chain::Solana;
        let storage = CheckpointStorage::in_memory();
        let base = checkpoint(chain, 30);
        storage.persist(&base).await?;

        let older = checkpoint(chain, 10);
        storage.persist_pending(&older).await?;
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 1);
        assert_eq!(storage.latest(chain).await?, Some(base.clone()));

        let newer = checkpoint(chain, 40);
        storage.persist_pending(&newer).await?;
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 1);
        assert_eq!(storage.latest(chain).await?, Some(newer));
        Ok(())
    }

    /// A stale digest index left by the first demotion must not resolve to a
    /// different body persisted and demoted at the same height after a restart.
    #[tokio::test]
    async fn demote_overwrite_drops_stale_digest_body() -> anyhow::Result<()> {
        let chain = Chain::Solana;
        let storage = CheckpointStorage::in_memory();
        let old = checkpoint_with_id(chain, 10, 1);
        let new = checkpoint_with_id(chain, 10, 2);
        assert_ne!(old.digest(), new.digest());

        // First pass: demote the body with digest `old` at height 10.
        storage.persist_pending(&old).await?;
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 1);

        // Restart: re-index and persist a different body at the same height,
        // then demote again. This overwrites orphan[10] with `new`.
        storage.persist_pending(&new).await?;
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 1);

        // The settled but stale digest must not return the new body, and must
        // not promote it as the confirmed base.
        let found = storage.find(chain, old.digest()).await?;
        assert!(
            found.as_ref().is_none_or(|cp| cp.digest() == old.digest()),
            "find returned a body that does not match the requested digest"
        );
        assert!(storage.promote(chain, old.digest()).await?.is_none());
        assert!(
            storage
                .load_latest(chain)
                .await?
                .is_none_or(|cp| cp.digest() != new.digest()),
            "the stale digest promoted the new body as base"
        );

        // The current body is still servable and promotable.
        assert_eq!(storage.find(chain, new.digest()).await?, Some(new.clone()));
        assert_eq!(storage.promote(chain, new.digest()).await?, Some(0));
        assert_eq!(storage.load_latest(chain).await?, Some(new));
        Ok(())
    }

    /// Orphans are bounded by height, not by how often a node restarts:
    /// re-demoting a different body at the same heights must overwrite, not
    /// accumulate, so a restart cycle cannot grow the orphan set.
    #[tokio::test]
    async fn demote_twice_with_different_digests_does_not_grow_orphans() -> anyhow::Result<()> {
        let chain = Chain::Solana;
        let storage = CheckpointStorage::in_memory();

        // First pass: three boundary heights, one body each.
        let old = [
            checkpoint_with_id(chain, 10, 1),
            checkpoint_with_id(chain, 20, 2),
            checkpoint_with_id(chain, 30, 3),
        ];
        for cp in &old {
            storage.persist_pending(cp).await?;
        }
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 3);
        assert_eq!(
            match &storage {
                CheckpointStorage::InMemory { orphan, .. } =>
                    orphan.read().await.get(&chain).map_or(0, |m| m.len()),
                _ => unreachable!("in-memory storage"),
            },
            3
        );

        // A restart re-indexes fresh bodies at the SAME heights with different
        // digests. Each demotion must overwrite the orphan at that height.
        let new = [
            checkpoint_with_id(chain, 10, 4),
            checkpoint_with_id(chain, 20, 5),
            checkpoint_with_id(chain, 30, 6),
        ];
        for (old_cp, new_cp) in old.iter().zip(&new) {
            assert_ne!(old_cp.digest(), new_cp.digest());
        }
        for cp in &new {
            storage.persist_pending(cp).await?;
        }
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 3);
        // Still exactly one orphan per height - overwritten, not accumulated.
        assert_eq!(
            match &storage {
                CheckpointStorage::InMemory { orphan, .. } =>
                    orphan.read().await.get(&chain).map_or(0, |m| m.len()),
                _ => unreachable!("in-memory storage"),
            },
            3
        );

        // The stale digests are gone from the index: they must not resolve to a
        // different body (the stale-index regression), while the new ones do.
        for old_cp in &old {
            let found = storage.find(chain, old_cp.digest()).await?;
            assert!(
                found
                    .as_ref()
                    .is_none_or(|cp| cp.digest() == old_cp.digest()),
                "find returned a body that does not match the requested stale digest"
            );
        }
        for new_cp in &new {
            assert_eq!(
                storage.find(chain, new_cp.digest()).await?,
                Some(new_cp.clone())
            );
        }

        // Promoting the middle height retires every orphan at or below it.
        let promoted = &new[1];
        assert_eq!(storage.promote(chain, promoted.digest()).await?, Some(0));
        assert_eq!(storage.load_latest(chain).await?, Some(promoted.clone()));
        assert_eq!(
            match &storage {
                CheckpointStorage::InMemory { orphan, .. } =>
                    orphan.read().await.get(&chain).map_or(0, |m| m.len()),
                _ => unreachable!("in-memory storage"),
            },
            1
        );
        assert!(storage.find(chain, new[0].digest()).await?.is_none());
        assert!(storage.find(chain, old[0].digest()).await?.is_none());
        assert_eq!(
            storage.find(chain, new[2].digest()).await?,
            Some(new[2].clone())
        );
        Ok(())
    }

    /// Even with a corrupt/stale index entry, orphan lookups verify the body's
    /// digest before returning or promoting it.
    #[tokio::test]
    async fn orphan_lookup_verifies_body_digest() -> anyhow::Result<()> {
        let chain = Chain::Solana;
        let storage = CheckpointStorage::in_memory();
        let stale = checkpoint_with_id(chain, 10, 1);
        let real = checkpoint_with_id(chain, 10, 2);
        assert_ne!(stale.digest(), real.digest());

        storage.persist_pending(&real).await?;
        assert_eq!(storage.demote_pending_to_orphan(chain).await?, 1);
        // Simulate pre-fix persisted state: a stale digest also points at height 10,
        // whose only body is `real`.
        if let CheckpointStorage::InMemory { orphan_digest, .. } = &storage {
            orphan_digest
                .write()
                .await
                .entry(chain)
                .or_default()
                .insert(stale.digest(), 10);
        } else {
            unreachable!("in-memory storage");
        }

        assert!(
            storage
                .find(chain, stale.digest())
                .await?
                .is_none_or(|cp| cp.digest() == stale.digest()),
            "find returned the wrong body for a stale orphan digest"
        );
        assert!(storage.promote(chain, stale.digest()).await?.is_none());
        assert!(
            storage
                .load_latest(chain)
                .await?
                .is_none_or(|cp| cp.digest() != real.digest()),
            "promote wrote the wrong orphan body as base"
        );
        assert_eq!(
            storage.find(chain, real.digest()).await?,
            Some(real.clone())
        );
        Ok(())
    }

    #[tokio::test]
    async fn latest_base_wins_height_ties() -> anyhow::Result<()> {
        let chain = Chain::Solana;
        let base = checkpoint(chain, 10);

        // Pending tie: the confirmed base wins over a pending body at the same height.
        let pending_storage = CheckpointStorage::in_memory();
        pending_storage.persist(&base).await?;
        pending_storage
            .persist_pending(&checkpoint_with_id(chain, 10, 9))
            .await?;
        assert_eq!(pending_storage.latest(chain).await?, Some(base.clone()));

        // Orphan tie: the confirmed base wins over an orphan body at the same height.
        let orphan_storage = CheckpointStorage::in_memory();
        orphan_storage.persist(&base).await?;
        orphan_storage
            .persist_pending(&checkpoint_with_id(chain, 10, 8))
            .await?;
        assert_eq!(orphan_storage.demote_pending_to_orphan(chain).await?, 1);
        assert_eq!(orphan_storage.latest(chain).await?, Some(base));
        Ok(())
    }
}
