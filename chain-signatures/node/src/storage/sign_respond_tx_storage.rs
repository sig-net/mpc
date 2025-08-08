use crate::sign_respond_tx::{SignRespondTx, SignRespondTxId};
use crate::storage::STORAGE_VERSION;
use deadpool_redis::{Connection, Pool};
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use deadpool_redis::{Connection, Pool};
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use crate::sign_respond_tx::{SignRespondTx, SignRespondTxId};
use crate::storage::STORAGE_VERSION;
use near_account_id::AccountId;

pub fn init(pool: &Pool, account_id: &AccountId) -> SignRespondTxStorage {
    let tx_key = format!("sign_respond_tx:{STORAGE_VERSION}:{account_id}");
    let pending_key = format!("sign_respond_tx_pending:{STORAGE_VERSION}:{account_id}");
    let success_key = format!("sign_respond_tx_success:{STORAGE_VERSION}:{account_id}");
    let failed_key = format!("sign_respond_tx_failed:{STORAGE_VERSION}:{account_id}");

    SignRespondTxStorage {
        redis_pool: pool.clone(),
        tx_key,
        pending_key,
        success_key,
        failed_key,
    }
}

#[derive(Clone)]
pub struct SignRespondTxStorage {
    redis_pool: Pool,
    tx_key: String,
    pending_key: String,
    success_key: String,
    failed_key: String,
}

impl SignRespondTxStorage {
    async fn connect(&self) -> Option<Connection> {
        self.redis_pool
            .get()
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to connect to redis");
            })
            .ok()
    }

    pub async fn fetch_pending(&self) -> Vec<SignRespondTx> {
        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };

        let pending_ids: Vec<SignRespondTxId> = conn
            .sdiff((&self.pending_key, &self.success_key, &self.failed_key))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to fetch pending tx ids");
            })
            .unwrap_or_default();

        if pending_ids.is_empty() {
            return Vec::new();
        }

        // Then, fetch values from the hash

        match conn.hget(&self.tx_key, pending_ids).await {
            Ok(pending_txs) => pending_txs,

            Err(err) => {
                tracing::warn!(?err, "failed to fetch pending tx data");
                Vec::new()
            }
        }
    }

    pub async fn insert(&self, id: SignRespondTxId, tx: SignRespondTx) -> bool {
        const SCRIPT: &str = r#"
            local tx_key = KEYS[1]
            local tx_id = ARGV[1]
            local tx = ARGV[2]

            if redis.call("HEXISTS", tx_key, tx_id) == 1 then
                return {err = "WARN tx " .. tx_id .. " has already been inserted}
            end

            redis.call("SADD", tx_key, tx_id)
            redis.call("HSET", tx_key, tx_id, tx)
        "#;

        let Some(mut conn) = self.connect().await else {
            tracing::warn!(?id, "failed to insert tx: connection failed");
            return false;
        };

        let result: Result<(), _> = redis::Script::new(SCRIPT)
            .key(&self.tx_key)
            .arg(id)
            .arg(tx)
            .invoke_async(&mut conn)
            .await;

        if let Err(err) = result {
            tracing::warn!(?id, ?err, "failed to insert tx into storage");
            false
        } else {
            true
        }
    }

    pub async fn mark_tx_success(&self, id: SignRespondTxId) -> bool {
        const SCRIPT: &str = r#"
            local success_key = KEYS[1]   
            local pending_key = KEYS[2]
            local tx_id = ARGV[1]

            redis.call("SADD", success_key, tx_id)
            redis.call("SREM", pending_key, tx_id)
        "#;

        let Some(mut conn) = self.connect().await else {
            tracing::warn!(?id, "failed to complete tx: connection failed");
            return false;
        };

        let outcome: Option<()> = redis::Script::new(SCRIPT)
            .key(&self.success_key)
            .key(&self.pending_key)
            .arg(id)
            .invoke_async(&mut conn)
            .await
            .inspect_err(|err| {
                tracing::warn!(?id, ?err, "failed to complete tx");
            })
            .ok();

        outcome.is_some()
    }

    pub async fn mark_tx_failed(&self, id: SignRespondTxId) -> bool {
        const SCRIPT: &str = r#"
            local failed_key = KEYS[1]   
            local pending_key = KEYS[2]
            local tx_id = ARGV[1]

            redis.call("SADD", failed_key, tx_id)
            redis.call("SREM", pending_key, tx_id)
        "#;

        let Some(mut conn) = self.connect().await else {
            tracing::warn!(?id, "failed to remove tx: connection failed");

            return false;
        };

        let outcome: Option<()> = redis::Script::new(SCRIPT)
            .key(&self.failed_key)
            .key(&self.pending_key)
            .arg(id)
            .invoke_async(&mut conn)
            .await
            .inspect_err(|err| {
                tracing::warn!(?id, ?err, "failed to remove tx");
            })
            .ok();

        outcome.is_some()
    }

    pub async fn mark_success_responded(&self, id: SignRespondTxId) -> bool {
        const SCRIPT: &str = r#"
            local tx_key = KEYS[1]
            local pending_key = KEYS[2]
            local success_key = KEYS[3]
            local tx_id = ARGV[1]

            redis.call("SREM", pending_key, tx_id)
            redis.call("SADD", success_key, tx_id)
            redis.call("HDEL", tx_key, tx_id)
        "#;

        let Some(mut conn) = self.connect().await else {
            tracing::warn!(?id, "failed to remove tx: connection failed");

            return false;
        };

        let outcome: Option<()> = redis::Script::new(SCRIPT)
            .key(&self.tx_key)
            .key(&self.pending_key)
            .key(&self.success_key)
            .arg(id)
            .invoke_async(&mut conn)
            .await
            .inspect_err(|err| {
                tracing::warn!(?id, ?err, "failed to remove tx");
            })
            .ok();

        outcome.is_some()
    }

    pub async fn mark_failed_responded(&self, id: SignRespondTxId) -> bool {
        const SCRIPT: &str = r#"
            local tx_key = KEYS[1]
            local pending_key = KEYS[2]
            local failed_key = KEYS[3]
            local tx_id = ARGV[1]

            redis.call("SREM", pending_key, tx_id)
            redis.call("SADD", failed_key, tx_id)
            redis.call("HDEL", tx_key, tx_id)
        "#;

        let Some(mut conn) = self.connect().await else {
            tracing::warn!(?id, "failed to remove tx: connection failed");

            return false;
        };

        let outcome: Option<()> = redis::Script::new(SCRIPT)
            .key(&self.tx_key)
            .key(&self.pending_key)
            .key(&self.failed_key)
            .arg(id)
            .invoke_async(&mut conn)
            .await
            .inspect_err(|err| {
                tracing::warn!(?id, ?err, "failed to remove tx");
            })
            .ok();

        outcome.is_some()
    }

    pub async fn contains(&self, id: SignRespondTxId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };

        match conn.hexists(&self.tx_key, id).await {
            Ok(exists) => exists,

            Err(err) => {
                tracing::warn!(?id, ?err, "failed to check if the tx id is stored");

                false
            }
        }
    }

    pub async fn contains_success(&self, id: SignRespondTxId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };

        match conn.sismember(&self.success_key, id).await {
            Ok(exists) => exists,

            Err(err) => {
                tracing::warn!(?id, ?err, "failed to check if tx in completed set");

                false
            }
        }
    }

    pub async fn contains_failed(&self, id: SignRespondTxId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };

        match conn.sismember(&self.failed_key, id).await {
            Ok(exists) => exists,

            Err(err) => {
                tracing::warn!(?id, ?err, "failed to check if tx in completed set");

                false
            }
        }
    }

    pub async fn contains_pending(&self, id: SignRespondTxId) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };

        match conn.sismember(&self.pending_key, id).await {
            Ok(exists) => exists,

            Err(err) => {
                tracing::warn!(?id, ?err, "failed to check if tx in completed set");

                false
            }
        }
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    pub async fn len(&self) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.hlen(&self.tx_key)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get number of txs");
            })
            .unwrap_or(0)
    }

    pub async fn clear(&self) -> bool {
        const SCRIPT: &str = r#"
            local owner_keys = redis.call("SMEMBERS", KEYS[1])
            local del = {}
            for _, key in ipairs(KEYS) do
                table.insert(del, key)
            end
            for _, key in ipairs(owner_keys) do
                table.insert(del, key)
            end

            redis.call("DEL", unpack(del))
        "#;

        let Some(mut conn) = self.connect().await else {
            return false;
        };
        let outcome: Option<()> = redis::Script::new(SCRIPT)
            .key(&self.tx_key)
            .key(&self.pending_key)
            .key(&self.success_key)
            .key(&self.failed_key)
            .invoke_async(&mut conn)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to clear sign respond tx storage");
            })
            .ok();

        // if the outcome is None, it means the script failed or there was an error.
        outcome.is_some()
    }
}

impl ToRedisArgs for SignRespondTxId {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(&self.0) {
            Ok(json) => out.write_arg(json.as_bytes()),

            Err(e) => {
                tracing::error!("Failed to serialize SignRespondTxId: {}", e);

                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl ToRedisArgs for SignRespondTx {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(&self.id) {
            Ok(json) => out.write_arg(json.as_bytes()),

            Err(e) => {
                tracing::error!("Failed to serialize SignRespondTx: {}", e);

                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for SignRespondTxId {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json = String::from_redis_value(v)?;
        serde_json::from_str(&json).map_err(|e| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize SignRespondTxId",
                e.to_string(),
            ))
        })
    }
}

impl FromRedisValue for SignRespondTx {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json = String::from_redis_value(v)?;
        serde_json::from_str(&json).map_err(|e| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize SignRespondTx",
                e.to_string(),
            ))
        })
    }
}
