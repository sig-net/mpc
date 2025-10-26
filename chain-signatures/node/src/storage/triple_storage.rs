use std::fmt;
use std::time::Instant;

use crate::protocol::triple::{Triple, TripleId};

use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};
use serde_json;

use near_account_id::AccountId;

use super::{owner_key, STORAGE_VERSION};

const USED_EXPIRE_TIME: Duration = Duration::hours(24);

/// A pre-reserved slot for a triple that will eventually be inserted.
pub struct TripleSlot {
    id: TripleId,
    storage: TripleStorage,
    stored: bool,
}

impl TripleSlot {
    /// Inserts the triple into the storage, associating it with the given owner.
    /// Returns true if the insertion was successful, false otherwise.
    // TODO: put inside a tokio task:
    pub async fn insert(&mut self, triple: Triple, owner: Participant) -> bool {
        self.stored = self.storage.insert(triple, owner).await;
        self.stored
    }

    pub async fn unreserve(&self) {
        if !self.stored {
            self.storage.unreserve([self.id]).await;
        }
    }
}

impl Drop for TripleSlot {
    fn drop(&mut self) {
        if !self.stored {
            let storage = self.storage.clone();
            let id = self.id;
            // If the slot was not stored, we need to unreserve it.
            tokio::spawn(async move {
                storage.unreserve([id]).await;
            });
        }
    }
}

pub struct TriplesTaken {
    pub triple0: Triple,
    pub triple1: Triple,
    pub dropper: TriplesTakenDropper,
}

impl TriplesTaken {
    pub fn owner(triple0: Triple, triple1: Triple, storage: TripleStorage) -> Self {
        let dropper = TriplesTakenDropper {
            id0: triple0.id,
            id1: triple1.id,
            storage: Some(storage),
        };
        Self {
            triple0,
            triple1,
            dropper,
        }
    }

    pub fn foreigner(triple0: Triple, triple1: Triple) -> Self {
        let dropper = TriplesTakenDropper {
            id0: triple0.id,
            id1: triple1.id,
            storage: None,
        };
        Self {
            triple0,
            triple1,
            dropper,
        }
    }

    pub fn take(self) -> (Triple, Triple, TriplesTakenDropper) {
        (self.triple0, self.triple1, self.dropper)
    }
}

impl fmt::Debug for TriplesTaken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TriplesTaken")
            .field(&self.triple0.id)
            .field(&self.triple1.id)
            .finish()
    }
}

pub struct TriplesTakenDropper {
    pub id0: TripleId,
    pub id1: TripleId,
    storage: Option<TripleStorage>,
}

impl Drop for TriplesTakenDropper {
    fn drop(&mut self) {
        if let Some(storage) = self.storage.take() {
            let id0 = self.id0;
            let id1 = self.id1;
            tokio::spawn(async move {
                storage.unreserve([id0, id1]).await;
            });
        }
    }
}

impl fmt::Debug for TriplesTakenDropper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TriplesTakenDropper")
            .field(&self.id0)
            .field(&self.id1)
            .finish()
    }
}

pub fn init(pool: &Pool, account_id: &AccountId) -> TripleStorage {
    let triple_key = format!("triples:{STORAGE_VERSION}:{account_id}");
    let used_key = format!("triples_used:{STORAGE_VERSION}:{account_id}");
    let reserved_key = format!("triples_reserved:{STORAGE_VERSION}:{account_id}");
    let owner_keys = format!("triples_owners:{STORAGE_VERSION}:{account_id}");

    TripleStorage {
        redis_pool: pool.clone(),
        triple_key,
        used_key,
        reserved_key,
        owner_keys,
        account_id: account_id.clone(),
    }
}

#[derive(Clone)]
pub struct TripleStorage {
    redis_pool: Pool,
    triple_key: String,
    used_key: String,
    reserved_key: String,
    owner_keys: String,
    account_id: AccountId,
}

impl TripleStorage {
    async fn connect(&self) -> Option<Connection> {
        self.redis_pool
            .get()
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to connect to redis");
            })
            .ok()
    }

    pub async fn reserve(&self, id: TripleId) -> Option<TripleSlot> {
        let start = Instant::now();

        let mut conn = self.connect().await?;
        let result: Result<String, _> = redis::cmd("TRIPLES.RESERVE")
            .arg(self.account_id.to_string())
            .arg(id)
            .query_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "reserve", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        if result.is_ok() {
            Some(TripleSlot {
                id,
                storage: self.clone(),
                stored: false,
            })
        } else {
            tracing::warn!(?result, "failed to reserve triple");
            None
        }
    }

    async fn unreserve<const N: usize>(&self, triples: [TripleId; N]) {
        let Some(mut conn) = self.connect().await else {
            return;
        };
        let mut cmd = redis::cmd("TRIPLES.UNRESERVE");
        cmd.arg(self.account_id.to_string());
        for triple in triples {
            cmd.arg(triple);
        }
        let outcome: Result<(), _> = cmd.query_async(&mut conn).await;
        if let Err(err) = outcome {
            tracing::warn!(?triples, ?err, "failed to unreserve triples");
        }
    }

    pub async fn remove_outdated(
        &self,
        owner: Participant,
        owner_shares: &[TripleId],
    ) -> Vec<TripleId> {
        let start = Instant::now();

        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };
        let mut cmd = redis::cmd("TRIPLES.REMOVE_OUTDATED");
        cmd.arg(self.account_id.to_string())
            .arg(Into::<u32>::into(owner));
        for share in owner_shares {
            cmd.arg(share);
        }
        let result: Result<Vec<TripleId>, _> = cmd.query_async(&mut conn).await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "remove_outdated", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(outdated) => {
                if !outdated.is_empty() {
                    tracing::info!(
                        ?outdated,
                        elapsed_ms = elapsed.as_millis(),
                        "removed outdated triples"
                    );
                }
                outdated
            }
            Err(err) => {
                tracing::warn!(
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to remove outdated triples"
                );
                Vec::new()
            }
        }
    }

    // TODO: me can potentially be integrated into storage if we eventually can wait for our own participant info to be determined.
    pub async fn fetch_owned(&self, me: Participant) -> Vec<TripleId> {
        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };

        conn.sunion((&self.reserved_key, owner_key(&self.owner_keys, me)))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to fetch (mine | reserved) triples");
            })
            .unwrap_or_default()
    }

    async fn insert(&self, triple: Triple, owner: Participant) -> bool {
        let start = Instant::now();

        let id = triple.id;
        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to insert triple: connection failed");
            return false;
        };
        let result: Result<String, _> = redis::cmd("TRIPLES.INSERT")
            .arg(self.account_id.to_string())
            .arg(id)
            .arg(serde_json::to_string(&triple).unwrap())
            .arg(Into::<u32>::into(owner))
            .query_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "insert", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        if let Err(err) = result {
            tracing::warn!(
                id,
                ?err,
                elapsed_ms = elapsed.as_millis(),
                "failed to insert triple into storage"
            );
            false
        } else {
            true
        }
    }

    pub async fn contains(&self, id: TripleId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.triple_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if triple is stored");
                false
            }
        }
    }

    pub async fn contains_by_owner(&self, id: TripleId, owner: Participant) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };

        match conn.sismember(owner_key(&self.owner_keys, owner), id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if triple is owned by us");
                false
            }
        }
    }

    pub async fn contains_used(&self, id: TripleId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.used_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if triple in used set");
                false
            }
        }
    }

    pub async fn contains_reserved(&self, id: TripleId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.sismember(&self.reserved_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if triple in reserved set");
                false
            }
        }
    }

    /// Take two unspent triple by theirs id with no way to return it. Only takes
    /// if both of them are present.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two(
        &self,
        id1: TripleId,
        id2: TripleId,
        owner: Participant,
        me: Participant,
    ) -> Option<TriplesTaken> {
        let start = Instant::now();
        let mut conn = self.connect().await?;
        let result: Result<(Triple, Triple), _> = redis::cmd("TRIPLES.TAKE_TWO")
            .arg(self.account_id.to_string())
            .arg(id1)
            .arg(id2)
            .arg(Into::<u32>::into(owner))
            .arg(Into::<u32>::into(me))
            .query_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "take_two", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok((triple0, triple1)) => {
                tracing::debug!(
                    id1,
                    id2,
                    elapsed_ms = elapsed.as_millis(),
                    "took two triples"
                );
                Some(TriplesTaken::foreigner(triple0, triple1))
            }
            Err(err) => {
                tracing::warn!(
                    id1,
                    id2,
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to take two triples from storage"
                );
                None
            }
        }
    }

    /// Take two random unspent triple generated by this node. Either takes both or none.
    /// It is very important to NOT reuse the same triple twice for two different
    /// protocols.
    pub async fn take_two_mine(&self, me: Participant) -> Option<TriplesTaken> {
        let start = Instant::now();
        let mut conn = self.connect().await?;
        let result: Result<Option<(Triple, Triple)>, _> = redis::cmd("TRIPLES.TAKE_TWO_MINE")
            .arg(self.account_id.to_string())
            .arg(Into::<u32>::into(me))
            .query_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "take_two_mine", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(Some((triple0, triple1))) => {
                let taken = TriplesTaken::owner(triple0, triple1, self.clone());
                tracing::debug!(
                    id0 = taken.triple0.id,
                    id1 = taken.triple1.id,
                    elapsed_ms = elapsed.as_millis(),
                    "took two mine triples"
                );
                Some(taken)
            }
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to take two mine triples from storage"
                );
                None
            }
        }
    }

    /// Checks if the storage is empty.
    pub async fn is_empty(&self) -> bool {
        self.len_generated().await == 0
    }

    /// Get the number of unspent triples that were generated by this node.
    pub async fn len_generated(&self) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.hlen(&self.triple_key)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of generated triples");
            })
            .unwrap_or(0)
    }

    /// Get the number of unspent triples by a specific owner.
    pub async fn len_by_owner(&self, owner: Participant) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.scard(owner_key(&self.owner_keys, owner))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of my triples");
            })
            .unwrap_or(0)
    }

    /// Clear all triple storage, including used, reserved, and owned keys.
    /// Return true if successful, false otherwise.
    pub async fn clear(&self) -> bool {
        let start = Instant::now();
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        let outcome: Result<(), _> = redis::cmd("TRIPLES.CLEAR")
            .arg(self.account_id.to_string())
            .query_async(&mut conn)
            .await
            .inspect_err(|err| {
                let elapsed = start.elapsed();
                tracing::warn!(
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to clear triple storage"
                );
            });

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["triple", "clear", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        outcome.is_ok()
    }
}

impl ToRedisArgs for Triple {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Triple: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Triple {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Triple",
                e.to_string(),
            ))
        })
    }
}

#[cfg(feature = "test-feature")]
impl TripleStorage {
    pub fn triple_key(&self) -> &str {
        &self.triple_key
    }
}
