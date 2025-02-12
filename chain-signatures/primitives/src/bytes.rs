/// Scalar module for any scalars to be sent through messaging other nodes.
/// There's an issue with serializing with ciborium when it comes to
/// forward and backward compatibility, so we need to implement our own
/// custom serialization here.
pub mod cbor_scalar {
    use k256::elliptic_curve::bigint::Encoding as _;
    use k256::elliptic_curve::scalar::FromUintUnchecked as _;
    use k256::Scalar;
    use serde::{de, Deserialize as _, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(scalar: &Scalar, ser: S) -> Result<S::Ok, S::Error> {
        let num = k256::U256::from(scalar);
        let bytes = num.to_le_bytes();
        serde_bytes::Bytes::new(&bytes).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Scalar, D::Error> {
        let bytes = match ciborium::Value::deserialize(deserializer)? {
            ciborium::Value::Bytes(bytes) if bytes.len() != 32 => {
                return Err(de::Error::custom("expected 32 bytes for Scalar"))
            }
            ciborium::Value::Bytes(bytes) => bytes,
            _ => return Err(de::Error::custom("expected ciborium::Value::Bytes")),
        };

        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes[0..32]);

        let num = k256::U256::from_le_bytes(buf);
        let scalar = k256::Scalar::from_uint_unchecked(num);
        Ok(scalar)
    }
}
