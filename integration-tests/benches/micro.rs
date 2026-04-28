use std::io::Cursor;

use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::protocol::Participant;
use cait_sith::{PresignOutput, triples::{TriplePub, TripleShare}};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main, black_box};
use elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke;
use serde::{Serialize, de::DeserializeOwned};

use mpc_node::protocol::{presignature::Presignature, triple::Triple};
use mpc_node::storage::triple_storage::TriplePair;

fn dummy_triple() -> Triple {
    Triple {
        share: TripleShare {
            a: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            b: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
            c: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
        },
        public: TriplePub {
            big_a: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_b: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_c: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            participants: vec![Participant::from(1), Participant::from(2)],
            threshold: 5,
        },
    }
}

fn dummy_triple_pair(id: u64) -> TriplePair {
    TriplePair {
        id,
        triple0: dummy_triple(),
        triple1: dummy_triple(),
        holders: Some(vec![Participant::from(1), Participant::from(2)]),
    }
}

fn dummy_presignature(id: u64) -> Presignature {
    Presignature {
        id,
        output: PresignOutput {
            big_r: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            k: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            sigma: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
        },
        participants: vec![Participant::from(1), Participant::from(2)],
        holders: Some(vec![Participant::from(1), Participant::from(2)]),
    }
}

fn dummy_protocol_config() -> ProtocolConfig {
    ProtocolConfig::default()
}

fn json_roundtrip_bench<T>(c: &mut Criterion, group: &str, name: &str, value: &T)
where
    T: Serialize + DeserializeOwned,
{
    let encoded = serde_json::to_vec(value).unwrap();
    let mut group = c.benchmark_group(group);

    group.bench_function(BenchmarkId::new("json_encode", name), |b| {
        b.iter(|| {
            black_box(serde_json::to_vec(black_box(value)).unwrap())
        })
    });

    group.bench_function(BenchmarkId::new("json_decode", name), |b| {
        b.iter(|| {
            let decoded: T = serde_json::from_slice(black_box(encoded.as_slice())).unwrap();
            black_box(decoded)
        })
    });

    group.bench_function(BenchmarkId::new("json_roundtrip", name), |b| {
        b.iter(|| {
            let bytes = serde_json::to_vec(black_box(value)).unwrap();
            let decoded: T = serde_json::from_slice(black_box(bytes.as_slice())).unwrap();
            black_box(decoded)
        })
    });

    group.finish();
}

fn borsh_roundtrip_bench<T>(c: &mut Criterion, group: &str, name: &str, value: &T)
where
    T: BorshSerialize + BorshDeserialize,
{
    let encoded = {
        let mut buf = Vec::new();
        value.serialize(&mut buf).unwrap();
        buf
    };

    let mut group = c.benchmark_group(group);

    group.bench_function(BenchmarkId::new("borsh_encode", name), |b| {
        b.iter(|| {
            let mut buf = Vec::new();
            black_box(value).serialize(&mut buf).unwrap();
            black_box(buf)
        })
    });

    group.bench_function(BenchmarkId::new("borsh_decode", name), |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(encoded.as_slice()));
            let decoded = T::deserialize_reader(&mut cursor).unwrap();
            black_box(decoded)
        })
    });

    group.bench_function(BenchmarkId::new("borsh_roundtrip", name), |b| {
        b.iter(|| {
            let mut buf = Vec::new();
            black_box(value).serialize(&mut buf).unwrap();
            let mut cursor = Cursor::new(buf.as_slice());
            let decoded = T::deserialize_reader(&mut cursor).unwrap();
            black_box(decoded)
        })
    });

    group.finish();
}

fn bench_micro(c: &mut Criterion) {
    let triple_pair = dummy_triple_pair(1);
    let presignature = dummy_presignature(7);
    let protocol_config = dummy_protocol_config();
    let (_, public_key) = hpke::generate();

    json_roundtrip_bench(c, "serialization", "triple_pair", &triple_pair);
    json_roundtrip_bench(c, "serialization", "presignature", &presignature);
    json_roundtrip_bench(c, "serialization", "protocol_config", &protocol_config);
    json_roundtrip_bench(c, "crypto", "public_key", &public_key);
}

criterion_group!(micro_benches, bench_micro);
criterion_main!(micro_benches);