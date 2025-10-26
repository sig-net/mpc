use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};
use serde_json;
use std::time::Instant;
use tokio::task::JoinHandle;

use crate::protocol::presignature::{Presignature, PresignatureId};

use super::{owner_key, STORAGE_VERSION};

const USED_EXPIRE_TIME: Duration = Duration::hours(24);

/// A pre-reserved slot for a presignature that will eventually be inserted.
pub struct PresignatureSlot {
    id: PresignatureId,
    storage: PresignatureStorage,
    stored: bool,
}

impl PresignatureSlot {
    pub async fn insert(&mut self, presignature: Presignature, owner: Participant) -> bool {
        self.stored = self.storage.insert(presignature, owner).await;
        self.stored
    }

    pub fn unreserve(&self) -> Option<JoinHandle<()>> {
        if self.stored {
            return None;
        }

        let storage = self.storage.clone();
        let id = self.id;
        let task = tokio::spawn(async move {
            tracing::info!(id, "unreserving presignature");
            storage.unreserve(id).await;
        });
        Some(task)
    }
}

impl Drop for PresignatureSlot {
    fn drop(&mut self) {
        self.unreserve();
    }
}

pub struct PresignatureTaken {
    pub presignature: Presignature,
    storage: PresignatureTakenDropper,
}

pub struct PresignatureTakenDropper {
    pub id: PresignatureId,
    dropper: Option<PresignatureStorage>,
}

impl Drop for PresignatureTakenDropper {
    fn drop(&mut self) {
        if let Some(storage) = self.dropper.take() {
            let id = self.id;
            tokio::spawn(async move {
                storage.unreserve(id).await;
            });
        }
    }
}

impl PresignatureTaken {
    fn owner(presignature: Presignature, storage: PresignatureStorage) -> Self {
        Self {
            storage: PresignatureTakenDropper {
                id: presignature.id,
                dropper: Some(storage),
            },
            presignature,
        }
    }

    fn foreigner(presignature: Presignature) -> Self {
        Self {
            storage: PresignatureTakenDropper {
                id: presignature.id,
                dropper: None,
            },
            presignature,
        }
    }

    pub fn take(self) -> (Presignature, PresignatureTakenDropper) {
        (self.presignature, self.storage)
    }
}

pub fn init(pool: &Pool, account_id: &AccountId) -> PresignatureStorage {
    let presig_key = format!("presignatures:{STORAGE_VERSION}:{account_id}",);
    let used_key = format!("presignatures_used:{STORAGE_VERSION}:{account_id}",);
    let reserved_key = format!("presingatures_reserved:{STORAGE_VERSION}:{account_id}",);
    let owner_keys = format!("presignatures_owners:{STORAGE_VERSION}:{account_id}",);

    PresignatureStorage {
        redis_pool: pool.clone(),
        presig_key,
        used_key,
        reserved_key,
        owner_keys,
        account_id: account_id.clone(),
    }
}

#[derive(Clone)]
pub struct PresignatureStorage {
    redis_pool: Pool,
    presig_key: String,
    used_key: String,
    reserved_key: String,
    owner_keys: String,
    account_id: AccountId,
}

impl PresignatureStorage {
    async fn connect(&self) -> Option<Connection> {
        self.redis_pool
            .get()
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to connect to redis");
            })
            .ok()
    }

    pub async fn fetch_owned(&self, me: Participant) -> Vec<PresignatureId> {
        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };

        conn.sunion((&self.reserved_key, owner_key(&self.owner_keys, me)))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to fetch (mine | reserved) presignatures");
            })
            .unwrap_or_default()
    }

    pub async fn reserve(&self, id: PresignatureId) -> Option<PresignatureSlot> {
        let start = Instant::now();
        let mut conn = self.connect().await?;
        let result: Result<String, _> = redis::cmd("PRESIG.RESERVE")
            .arg(self.account_id.to_string())
            .arg(id)
            .query_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["presignature", "reserve", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(_) => Some(PresignatureSlot {
                id,
                storage: self.clone(),
                stored: false,
            }),
            Err(err) => {
                tracing::warn!(
                    id,
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to reserve presignature"
                );
                None
            }
        }
    }

    async fn unreserve(self, id: PresignatureId) {
        let Some(mut conn) = self.connect().await else {
            return;
        };
        let outcome: Result<(), _> = redis::cmd("PRESIG.UNRESERVE")
            .arg(self.account_id.to_string())
            .arg(id)
            .query_async(&mut conn)
            .await;
        if let Err(err) = outcome {
            tracing::warn!(id, ?err, "failed to unreserve presignature");
        }
    }

    pub async fn remove_outdated(
        &self,
        owner: Participant,
        owner_shares: &[PresignatureId],
    ) -> Vec<PresignatureId> {
        let start = Instant::now();
        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };
        let mut cmd = redis::cmd("PRESIG.REMOVE_OUTDATED");
        cmd.arg(self.account_id.to_string())
            .arg(Into::<u32>::into(owner));
        for share in owner_shares {
            cmd.arg(share);
        }
        let result: Result<Vec<PresignatureId>, _> = cmd.query_async(&mut conn).await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["presignature", "remove_outdated", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(outdated) => {
                if !outdated.is_empty() {
                    tracing::info!(
                        ?outdated,
                        elapsed_ms = elapsed.as_millis(),
                        "removed outdated presignatures"
                    );
                }
                outdated
            }
            Err(err) => {
                tracing::warn!(
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to remove outdated presignatures"
                );
                Vec::new()
            }
        }
    }

    /// Insert a presignature into the storage. If `mine` is true, the presignature will be
    /// owned by the current node. If `back` is true, the presignature will be marked as unused.
    pub async fn insert(&self, presignature: Presignature, owner: Participant) -> bool {
        let start = Instant::now();
        let id = presignature.id;
        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to insert presignature: connection failed");
            return false;
        };
        let outcome: Result<(), _> = redis::cmd("PRESIG.INSERT")
            .arg(self.account_id.to_string())
            .arg(id)
            .arg(serde_json::to_string(&presignature).unwrap())
            .arg(Into::<u32>::into(owner))
            .query_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["presignature", "insert", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match outcome {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(
                    id,
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to insert presignature"
                );
                false
            }
        }
    }

    pub async fn contains(&self, id: PresignatureId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.presig_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if presignature is stored");
                false
            }
        }
    }

    pub async fn contains_by_owner(&self, id: PresignatureId, owner: Participant) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.sismember(owner_key(&self.owner_keys, owner), id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(
                    id,
                    ?owner,
                    ?err,
                    "failed to check if presignature is stored by foreign owner"
                );
                false
            }
        }
    }

    pub async fn contains_used(&self, id: PresignatureId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.used_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if presignature is used");
                false
            }
        }
    }

    pub async fn take(
        &self,
        id: PresignatureId,
        owner: Participant,
        me: Participant,
    ) -> Option<PresignatureTaken> {
        let start = Instant::now();
        let mut conn = self.connect().await?;
        let result: Result<Presignature, _> = redis::cmd("PRESIG.TAKE")
            .arg(self.account_id.to_string())
            .arg(id)
            .arg(Into::<u32>::into(owner))
            .arg(Into::<u32>::into(me))
            .query_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["presignature", "take", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(presignature) => Some(PresignatureTaken::foreigner(presignature)),
            Err(err) => {
                tracing::warn!(
                    id,
                    ?owner,
                    ?me,
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to take presignature"
                );
                None
            }
        }
    }

    pub async fn take_mine(&self, me: Participant) -> Option<PresignatureTaken> {
        let start = Instant::now();
        let mut conn = self.connect().await?;
        let result: Result<Option<Presignature>, _> = redis::cmd("PRESIG.TAKE_MINE")
            .arg(self.account_id.to_string())
            .arg(Into::<u32>::into(me))
            .query_async(&mut conn)
            .await;

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["presignature", "take_mine", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        match result {
            Ok(Some(presignature)) => Some(PresignatureTaken::owner(presignature, self.clone())),
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(
                    ?me,
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to take my presignature"
                );
                None
            }
        }
    }

    pub async fn len_generated(&self) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.hlen(&self.presig_key)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of generated presignatures");
            })
            .unwrap_or(0)
    }

    pub async fn len_by_owner(&self, me: Participant) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.scard(owner_key(&self.owner_keys, me))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of my presignatures");
            })
            .unwrap_or(0)
    }

    /// Returns if there are unspent presignatures available in the manager.
    pub async fn is_empty(&self) -> bool {
        self.len_generated().await == 0
    }

    /// Clear all presignature storage, including used, reserved, and owned keys.
    /// Return true if successful, false otherwise.
    pub async fn clear(&self) -> bool {
        let start = Instant::now();
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        let outcome: Result<(), _> = redis::cmd("PRESIG.CLEAR")
            .arg(self.account_id.to_string())
            .query_async(&mut conn)
            .await
            .inspect_err(|err| {
                let elapsed = start.elapsed();
                tracing::warn!(
                    ?err,
                    elapsed_ms = elapsed.as_millis(),
                    "failed to clear presignature storage"
                );
            });

        let elapsed = start.elapsed();
        crate::metrics::REDIS_LATENCY
            .with_label_values(&["presignature", "clear", self.account_id.as_str()])
            .observe(elapsed.as_millis() as f64);

        outcome.is_ok()
    }
}

impl ToRedisArgs for Presignature {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Presignature: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Presignature {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Presignature",
                e.to_string(),
            ))
        })
    }
}

#[cfg(feature = "test-feature")]
impl PresignatureStorage {
    pub fn presignature_key(&self) -> &str {
        &self.presig_key
    }
}
