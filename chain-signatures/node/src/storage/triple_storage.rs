use deadpool_redis::Pool;
use near_sdk::AccountId;
use redis::{FromRedisValue, RedisError, RedisWrite, ToRedisArgs};
use serde::{Deserialize, Serialize};

use crate::protocol::triple::{Triple, TripleId};

use super::protocol_storage::{
    ArtifactSlot, ArtifactTaken, ArtifactTakenDropper, ProtocolArtifact, ProtocolStorage,
};

pub type TripleStorage = ProtocolStorage<TriplePair>;
pub type TriplePairSlot = ArtifactSlot<TriplePair>;
pub type TriplesTaken = ArtifactTaken<TriplePair>;
pub type TriplesTakenDropper = ArtifactTakenDropper<TriplePair>;

/// A pair of completed triples.
#[derive(Debug, Serialize, Deserialize)]
pub struct TriplePair {
    pub id: TripleId,
    pub triple0: Triple,
    pub triple1: Triple,
}

impl TriplePair {
    pub fn storage(pool: &Pool, account_id: &AccountId) -> TripleStorage {
        ProtocolStorage::new(pool, account_id, "triples")
    }
}

impl ProtocolArtifact for TriplePair {
    const METRIC_LABEL: &'static str = "triple";
    type Id = TripleId;

    fn id(&self) -> Self::Id {
        self.id
    }
}

impl ToRedisArgs for TriplePair {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize TriplePair: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for TriplePair {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize TriplePair",
                e.to_string(),
            ))
        })
    }
}

#[cfg(feature = "test-feature")]
impl ProtocolStorage<TriplePair> {
    pub fn triple_key(&self) -> &str {
        self.artifact_key()
    }
}
