use deadpool_redis::Pool;
use near_sdk::AccountId;
use redis::{FromRedisValue, RedisWrite, ToRedisArgs};
use serde::{Deserialize, Serialize};

use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};

use crate::protocol::triple::{Triple, TripleId};

use super::cbor::{
    read_cbor_or_json, write_cbor_redis_arg, CborPoint, CborPointRef, CborScalar, CborScalarRef,
};
use super::protocol_storage::{
    ArtifactReservation, ArtifactSlot, ArtifactTaken, ArtifactTakenDropper, Initializing,
    ProtocolArtifact, ProtocolStorage, Ready,
};

pub type TripleStorage<Phase = Ready> = ProtocolStorage<TriplePair, Phase>;
pub type TriplePairSlot = ArtifactSlot<TriplePair>;
pub type TriplesTaken = ArtifactTaken<TriplePair>;
pub type TriplesTakenDropper = ArtifactTakenDropper<TriplePair>;
pub type TriplesReserved = ArtifactReservation<TriplePair>;

/// A pair of completed triples.
#[derive(Debug, Serialize, Deserialize)]
pub struct TriplePair {
    pub id: TripleId,
    pub triple0: Triple,
    pub triple1: Triple,
    /// Nodes still holding this artifact
    #[serde(skip, default)]
    pub holders: Option<Vec<Participant>>,
}

impl TriplePair {
    pub fn storage(pool: &Pool, account_id: &AccountId) -> TripleStorage<Initializing> {
        ProtocolStorage::new(pool, account_id, "triples")
    }

    pub fn ready_storage(pool: &Pool, account_id: &AccountId, me: Participant) -> TripleStorage {
        ProtocolStorage::ready(pool, account_id, "triples", me)
    }
}

impl ProtocolArtifact for TriplePair {
    const METRIC_LABEL: &'static str = "triple";
    type Id = TripleId;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn participants(&self) -> &[Participant] {
        &self.triple0.public.participants
    }

    fn holders(&self) -> Option<&[Participant]> {
        self.holders.as_deref()
    }

    fn set_holders(&mut self, holders: Vec<Participant>) {
        self.holders = Some(holders);
    }
}

#[derive(Serialize)]
struct CborTripleRef<'a>(
    CborScalarRef<'a>,
    CborScalarRef<'a>,
    CborScalarRef<'a>,
    CborPointRef<'a>,
    CborPointRef<'a>,
    CborPointRef<'a>,
    &'a [Participant],
    usize,
);

impl<'a> From<&'a Triple> for CborTripleRef<'a> {
    fn from(t: &'a Triple) -> Self {
        Self(
            CborScalarRef(&t.share.a),
            CborScalarRef(&t.share.b),
            CborScalarRef(&t.share.c),
            CborPointRef(&t.public.big_a),
            CborPointRef(&t.public.big_b),
            CborPointRef(&t.public.big_c),
            &t.public.participants,
            t.public.threshold,
        )
    }
}

#[derive(Serialize)]
struct CborTriplePairRef<'a>(TripleId, CborTripleRef<'a>, CborTripleRef<'a>);

#[derive(Deserialize)]
struct CborTriple(
    CborScalar,
    CborScalar,
    CborScalar,
    CborPoint,
    CborPoint,
    CborPoint,
    Vec<Participant>,
    usize,
);

impl From<CborTriple> for Triple {
    fn from(c: CborTriple) -> Self {
        Self {
            share: TripleShare {
                a: c.0 .0,
                b: c.1 .0,
                c: c.2 .0,
            },
            public: TriplePub {
                big_a: c.3 .0,
                big_b: c.4 .0,
                big_c: c.5 .0,
                participants: c.6,
                threshold: c.7,
            },
        }
    }
}

#[derive(Deserialize)]
struct CborTriplePair(TripleId, CborTriple, CborTriple);

impl ToRedisArgs for TriplePair {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        let cbor_pair = CborTriplePairRef(
            self.id,
            CborTripleRef::from(&self.triple0),
            CborTripleRef::from(&self.triple1),
        );
        write_cbor_redis_arg(&cbor_pair, out, 512, "TriplePair");
    }
}

impl FromRedisValue for TriplePair {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        read_cbor_or_json::<CborTriplePair, Self>(v, "TriplePair", |c| Self {
            id: c.0,
            triple0: c.1.into(),
            triple1: c.2.into(),
            holders: None,
        })
    }
}

#[cfg(feature = "test-feature")]
impl<Phase> ProtocolStorage<TriplePair, Phase> {
    pub fn triple_key(&self) -> &str {
        self.artifact_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{AffinePoint, Scalar};

    fn test_triple_pair(id: u64) -> TriplePair {
        let participants: Vec<Participant> = (0..12u32).map(Participant::from).collect();
        let s1 = Scalar::from(0x1234_5678_9abc_def0u64);
        let s2 = Scalar::from(0xfedc_ba98_7654_3210u64);
        let p_gen = AffinePoint::GENERATOR;
        let triple = Triple {
            share: TripleShare {
                a: s1,
                b: s2,
                c: s1 + s2,
            },
            public: TriplePub {
                big_a: p_gen,
                big_b: (p_gen * s1).to_affine(),
                big_c: (p_gen * s2).to_affine(),
                participants: participants.clone(),
                threshold: 8,
            },
        };
        TriplePair {
            id,
            triple0: triple.clone(),
            triple1: triple,
            holders: Some(participants),
        }
    }

    #[test]
    fn test_triple_pair_cbor_roundtrip() {
        let original = test_triple_pair(42);

        let mut out = Vec::new();
        original.write_redis_args(&mut out);
        assert_eq!(out.len(), 1);

        let redis_val = redis::Value::BulkString(out[0].clone());
        let deserialized = TriplePair::from_redis_value(&redis_val).unwrap();

        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.triple0.share.a, original.triple0.share.a);
        assert_eq!(deserialized.triple0.share.b, original.triple0.share.b);
        assert_eq!(deserialized.triple0.share.c, original.triple0.share.c);
        assert_eq!(
            deserialized.triple0.public.big_a,
            original.triple0.public.big_a
        );
        assert_eq!(
            deserialized.triple0.public.big_b,
            original.triple0.public.big_b
        );
        assert_eq!(
            deserialized.triple0.public.big_c,
            original.triple0.public.big_c
        );
        assert_eq!(
            deserialized.triple0.public.participants,
            original.triple0.public.participants
        );
        assert_eq!(
            deserialized.triple0.public.threshold,
            original.triple0.public.threshold
        );
    }

    #[test]
    fn test_triple_pair_json_backwards_compatible() {
        let original = test_triple_pair(99);

        let json_str = serde_json::to_string(&original).unwrap();
        let redis_val = redis::Value::BulkString(json_str.into_bytes());

        let deserialized = TriplePair::from_redis_value(&redis_val).unwrap();
        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.triple0.share.a, original.triple0.share.a);
        assert_eq!(
            deserialized.triple0.public.big_b,
            original.triple0.public.big_b
        );
        assert_eq!(
            deserialized.triple0.public.participants,
            original.triple0.public.participants
        );
    }

    #[test]
    fn test_triple_pair_cbor_size_reduction() {
        let pair = test_triple_pair(1);
        let json_bytes = serde_json::to_vec(&pair).unwrap();

        let mut out = Vec::new();
        pair.write_redis_args(&mut out);
        let cbor_bytes = &out[0];

        println!(
            "TriplePair JSON size: {} bytes, CBOR size: {} bytes ({:.1}% reduction)",
            json_bytes.len(),
            cbor_bytes.len(),
            (1.0 - cbor_bytes.len() as f64 / json_bytes.len() as f64) * 100.0
        );
        assert!(cbor_bytes.len() < json_bytes.len() / 2);
    }
}
