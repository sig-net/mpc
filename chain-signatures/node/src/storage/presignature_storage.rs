use deadpool_redis::Pool;
use near_sdk::AccountId;
use redis::{FromRedisValue, RedisWrite, ToRedisArgs};

use cait_sith::protocol::Participant;
use cait_sith::PresignOutput;

use super::cbor::{
    read_cbor_or_json, write_cbor_redis_arg, CborPoint, CborPointRef, CborScalar, CborScalarRef,
};
use super::protocol_storage::{
    ArtifactReservation, ArtifactSlot, ArtifactTaken, ArtifactTakenDropper, Initializing,
    ProtocolStorage, Ready,
};
pub use crate::protocol::presignature::Presignature;
use crate::protocol::presignature::PresignatureId;
use crate::storage::protocol_storage::ProtocolArtifact;

pub type PresignatureStorage<Phase = Ready> = ProtocolStorage<Presignature, Phase>;
pub type PresignatureSlot = ArtifactSlot<Presignature>;
pub type PresignatureTaken = ArtifactTaken<Presignature>;
pub type PresignatureTakenDropper = ArtifactTakenDropper<Presignature>;
pub type PresignatureReservation = ArtifactReservation<Presignature>;

impl Presignature {
    pub fn storage(pool: &Pool, account_id: &AccountId) -> PresignatureStorage<Initializing> {
        ProtocolStorage::new(pool, account_id, "presignatures")
    }

    pub fn ready_storage(
        pool: &Pool,
        account_id: &AccountId,
        me: Participant,
    ) -> PresignatureStorage {
        ProtocolStorage::ready(pool, account_id, "presignatures", me)
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

#[derive(serde::Serialize)]
struct CborPresignatureRef<'a>(
    PresignatureId,
    CborPointRef<'a>,
    CborScalarRef<'a>,
    CborScalarRef<'a>,
    &'a [Participant],
);

#[derive(serde::Deserialize)]
struct CborPresignature(
    PresignatureId,
    CborPoint,
    CborScalar,
    CborScalar,
    Vec<Participant>,
);

impl ToRedisArgs for Presignature {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        let cbor_presig = CborPresignatureRef(
            self.id,
            CborPointRef(&self.output.big_r),
            CborScalarRef(&self.output.k),
            CborScalarRef(&self.output.sigma),
            &self.participants,
        );
        write_cbor_redis_arg(&cbor_presig, out, 256, "Presignature");
    }
}

impl FromRedisValue for Presignature {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        read_cbor_or_json::<CborPresignature, Self>(v, "Presignature", |c| Self {
            id: c.0,
            output: PresignOutput {
                big_r: c.1 .0,
                k: c.2 .0,
                sigma: c.3 .0,
            },
            participants: c.4,
            holders: None,
        })
    }
}

#[cfg(feature = "test-feature")]
impl<Phase> ProtocolStorage<Presignature, Phase> {
    pub fn presignature_key(&self) -> &str {
        self.artifact_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{AffinePoint, Scalar};

    fn test_presignature(id: u64) -> Presignature {
        let participants: Vec<Participant> = (0..12u32).map(Participant::from).collect();
        let k = Scalar::from(0x1234_5678_9abc_def0u64);
        let sigma = Scalar::from(0xfedc_ba98_7654_3210u64);
        Presignature {
            id,
            output: PresignOutput {
                big_r: (AffinePoint::GENERATOR * k).to_affine(),
                k,
                sigma,
            },
            participants: participants.clone(),
            holders: Some(participants),
        }
    }

    #[test]
    fn test_presignature_cbor_roundtrip() {
        let original = test_presignature(42);

        let mut out = Vec::new();
        original.write_redis_args(&mut out);
        assert_eq!(out.len(), 1);

        let redis_val = redis::Value::BulkString(out[0].clone());
        let deserialized = Presignature::from_redis_value(&redis_val).unwrap();

        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.participants, original.participants);
        assert_eq!(deserialized.output.big_r, original.output.big_r);
        assert_eq!(deserialized.output.k, original.output.k);
        assert_eq!(deserialized.output.sigma, original.output.sigma);
    }

    #[test]
    fn test_presignature_json_backwards_compatible() {
        let original = test_presignature(99);

        let json_str = serde_json::to_string(&original).unwrap();
        let redis_val = redis::Value::BulkString(json_str.into_bytes());

        let deserialized = Presignature::from_redis_value(&redis_val).unwrap();
        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.participants, original.participants);
        assert_eq!(deserialized.output.big_r, original.output.big_r);
        assert_eq!(deserialized.output.k, original.output.k);
        assert_eq!(deserialized.output.sigma, original.output.sigma);
    }

    #[test]
    fn test_presignature_cbor_size_reduction() {
        let presig = test_presignature(1);
        let json_bytes = serde_json::to_vec(&presig).unwrap();

        let mut out = Vec::new();
        presig.write_redis_args(&mut out);
        let cbor_bytes = &out[0];

        println!(
            "Presignature JSON size: {} bytes, CBOR size: {} bytes ({:.1}% reduction)",
            json_bytes.len(),
            cbor_bytes.len(),
            (1.0 - cbor_bytes.len() as f64 / json_bytes.len() as f64) * 100.0
        );
        assert!(cbor_bytes.len() < json_bytes.len() / 2);
    }
}
