use cait_sith::protocol::Participant;
use chrono::Duration;
use deadpool_redis::Pool;
use near_sdk::AccountId;
use redis::{FromRedisValue, RedisError, RedisWrite, ToRedisArgs};
use tokio::task::JoinHandle;

use crate::protocol::presignature::{Presignature, PresignatureId};

const USED_EXPIRE_TIME: Duration = Duration::hours(24);

/// A pre-reserved slot for a presignature that will eventually be inserted.
pub struct PresignatureSlot {
    id: PresignatureId,
    storage: PresignatureStorage,
    stored: bool,
}

impl PresignatureSlot {
    pub fn new(id: PresignatureId, storage: PresignatureStorage) -> Self {
        Self {
            id,
            storage,
            stored: false,
        }
    }

    // TODO: put inside a tokio task:
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
            storage.unreserve([id]).await;
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
                storage.unreserve([id]).await;
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

pub type PresignatureStorage = super::ProtocolStorage<Presignature>;

impl PresignatureStorage {
    pub fn new(redis: Pool, account_id: &AccountId) -> Self {
        Self::init("presignature", redis, account_id)
    }

    pub async fn take(
        &self,
        id: PresignatureId,
        owner: Participant,
        me: Participant,
    ) -> Option<PresignatureTaken> {
        const SCRIPT: &str = r#"
            local presig_key = KEYS[1]
            local used_key = KEYS[2]
            local owner_key = KEYS[3]
            local mine_key = KEYS[4]
            local reserved_key = KEYS[5]
            local participant_keys = KEYS[6]
            local presig_id = ARGV[1]

            if redis.call("SMISMEMBER", reserved_key, presig_id) == 1 then
                return {err = 'WARN presignature ' .. presig_id .. ' is generating or taken'}
            end

            if redis.call("SISMEMBER", mine_key, presig_id) == 1 then
                return {err = 'WARN presignature ' .. presig_id ..' cannot be taken as foreign owned'}
            end
            if redis.call("SISMEMBER", owner_key, presig_id) == 0 then
                return {err = 'WARN presignature ' .. presig_id .. ' cannot be taken by incorrect owner ' .. owner_key }
            end

            local presig = redis.call("HGET", presig_key, presig_id)
            if not presig then
                return {err = "WARN presignature " .. presig_id .. " is missing"}
            end

            redis.call("HDEL", presig_key, presig_id)
            redis.call("SREM", owner_key, presig_id)
            redis.call("DEL", participant_keys .. ":" .. presig_id)
            redis.call("HSET", used_key, presig_id, "1")
            redis.call("HEXPIRE", used_key, ARGV[2], "FIELDS", "1", presig_id)

            return presig
        "#;

        let mut conn = self.connect().await?;
        match redis::Script::new(SCRIPT)
            .key(&self.protocol_key)
            .key(&self.used_key)
            .key(self.owner_key(owner))
            .key(self.owner_key(me))
            .key(&self.reserved_key)
            .key(&self.participant_keys)
            .arg(id)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
        {
            Ok(presignature) => Some(PresignatureTaken::foreigner(presignature)),
            Err(err) => {
                tracing::warn!(id, ?owner, ?me, ?err, "failed to take presignature");
                None
            }
        }
    }

    pub async fn take_mine(&self, me: Participant) -> Option<PresignatureTaken> {
        const SCRIPT: &str = r#"
            local presig_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local mine_key = KEYS[4]
            local participant_keys = KEYS[5]

            local presig_id = redis.call("SPOP", mine_key)
            if not presig_id then
                return nil
            end

            local presig = redis.call("HGET", presig_key, presig_id)
            if not presig then
                return {err = "WARN unexpected, presignature " .. presig_id .. " is missing"}
            end

            redis.call("DEL", participant_keys .. ":" .. presig_id)
            redis.call("SADD", reserved_key, presig_id)
            redis.call("HDEL", presig_key, presig_id)
            redis.call("HSET", used_key, presig_id, "1")
            redis.call("HEXPIRE", used_key, ARGV[1], "FIELDS", "1", presig_id)

            return presig
        "#;

        let mut conn = self.connect().await?;
        match redis::Script::new(SCRIPT)
            .key(&self.protocol_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(self.owner_key(me))
            .key(&self.participant_keys)
            .arg(USED_EXPIRE_TIME.num_seconds())
            .invoke_async(&mut conn)
            .await
        {
            Ok(Some(presignature)) => Some(PresignatureTaken::owner(presignature, self.clone())),
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(?me, ?err, "failed to take my presignature");
                None
            }
        }
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
