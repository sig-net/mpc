use deadpool_redis::Pool;
use near_sdk::AccountId;
use redis::{FromRedisValue, RedisError, RedisWrite, ToRedisArgs};

use cait_sith::protocol::Participant;

use super::protocol_storage::{
    ArtifactReservation, ArtifactSlot, ArtifactTaken, ArtifactTakenDropper, ProtocolStorage,
};
use crate::protocol::presignature::{Presignature, PresignatureId};
use crate::storage::protocol_storage::ProtocolArtifact;

pub type PresignatureStorage = ProtocolStorage<Presignature>;
pub type PresignatureSlot = ArtifactSlot<Presignature>;
pub type PresignatureTaken = ArtifactTaken<Presignature>;
pub type PresignatureTakenDropper = ArtifactTakenDropper<Presignature>;
pub type PresignatureReservation = ArtifactReservation<Presignature>;

impl Presignature {
    pub fn storage(pool: &Pool, account_id: &AccountId) -> PresignatureStorage {
        ProtocolStorage::new(pool, account_id, "presignatures")
    }
}

impl ProtocolArtifact for Presignature {
    type Id = PresignatureId;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn participants(&self) -> &[Participant] {
        &self.participants
    }

    fn holders(&self) -> Option<&[Participant]> {
        self.holders.as_deref()
    }

    fn set_holders(&mut self, holders: Vec<Participant>) {
        self.holders = Some(holders);
    }

    const METRIC_LABEL: &'static str = "presignature";
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
impl ProtocolStorage<Presignature> {
    pub fn presignature_key(&self) -> &str {
        self.artifact_key()
    }
}
