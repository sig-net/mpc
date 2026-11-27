use k256::elliptic_curve::sec1::{FromEncodedPoint as _, ToEncodedPoint as _};
use k256::elliptic_curve::PrimeField as _;
use k256::{AffinePoint, EncodedPoint, Scalar};
use redis::{RedisError, RedisResult, RedisWrite, Value};
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serializes `value` as CBOR into a pre-sized buffer and writes it as a Redis argument.
pub(crate) fn write_cbor_redis_arg<T: Serialize, W: ?Sized + RedisWrite>(
    value: &T,
    out: &mut W,
    capacity: usize,
    type_name: &str,
) {
    let mut bytes = Vec::with_capacity(capacity);
    match ciborium::into_writer(value, &mut bytes) {
        Ok(()) => out.write_arg(&bytes),
        Err(e) => {
            tracing::error!("Failed to serialize {type_name}: {e}");
            out.write_arg(b"failed_to_serialize");
        }
    }
}

/// Deserializes a Redis value by trying compact CBOR (`C`) first, then falling back to legacy JSON (`T`).
pub(crate) fn read_cbor_or_json<C, T>(
    v: &Value,
    type_name: &str,
    from_cbor: impl FnOnce(C) -> T,
) -> RedisResult<T>
where
    C: DeserializeOwned,
    T: DeserializeOwned,
{
    let mut curr = v;
    while let Value::Attribute { data, .. } = curr {
        curr = data.as_ref();
    }
    let bytes = match curr {
        Value::BulkString(bytes) => bytes.as_slice(),
        Value::SimpleString(s) => s.as_bytes(),
        Value::VerbatimString { text, .. } => text.as_bytes(),
        _ => {
            return Err(RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize artifact: response type not byte compatible",
                type_name.to_string(),
            )));
        }
    };

    match ciborium::from_reader::<C, _>(bytes) {
        Ok(cbor_val) => Ok(from_cbor(cbor_val)),
        Err(cbor_err) => serde_json::from_slice(bytes).map_err(|json_err| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize artifact (tried CBOR and JSON)",
                format!("{type_name}: cbor error: {cbor_err}; json error: {json_err}"),
            ))
        }),
    }
}

/// CBOR serializer for `k256::Scalar` using a CBOR byte string (major type 2).
pub(crate) struct CborScalarRef<'a>(pub &'a Scalar);

impl Serialize for CborScalarRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(self.0.to_bytes().as_slice()).serialize(serializer)
    }
}

/// CBOR deserializer for `k256::Scalar` from a 32-byte CBOR byte string.
pub(crate) struct CborScalar(pub Scalar);

impl<'de> Deserialize<'de> for CborScalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let arr: [u8; 32] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| de::Error::custom("expected 32 bytes for Scalar"))?;
        Option::from(Scalar::from_repr(arr.into()))
            .map(CborScalar)
            .ok_or_else(|| de::Error::custom("invalid non-canonical Scalar bytes"))
    }
}

/// CBOR serializer for `k256::AffinePoint` using compressed SEC1 bytes.
pub(crate) struct CborPointRef<'a>(pub &'a AffinePoint);

impl Serialize for CborPointRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = self.0.to_encoded_point(true);
        serde_bytes::Bytes::new(encoded.as_bytes()).serialize(serializer)
    }
}

/// CBOR deserializer for `k256::AffinePoint` from compressed SEC1 bytes.
pub(crate) struct CborPoint(pub AffinePoint);

impl<'de> Deserialize<'de> for CborPoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let encoded = EncodedPoint::from_bytes(bytes.as_ref())
            .map_err(|e| de::Error::custom(format!("invalid SEC1 EncodedPoint: {e}")))?;
        Option::from(AffinePoint::from_encoded_point(&encoded))
            .map(CborPoint)
            .ok_or_else(|| de::Error::custom("point not on curve"))
    }
}
