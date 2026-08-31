use k256::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignArgs {
    #[serde(with = "serde_bytes")]
    pub entropy: [u8; 32],
    #[serde(with = "cbor_scalar")]
    pub epsilon: Scalar,
    #[serde(with = "cbor_scalar")]
    pub payload: Scalar,
    pub path: String,
    pub key_version: u32,
}

impl std::fmt::Debug for SignArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignArgs")
            .field("entropy", &hex::encode(&self.entropy[..4])) // not a secret atm, but better truncate for readability and logging safety in the future (if it becomes one)
            .field("epsilon", &self.epsilon)
            .field("payload", &self.payload)
            .field("path", &self.path)
            .field("key_version", &self.key_version)
            .finish()
    }
}

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
            ciborium::Value::Bytes(bytes) => {
                if bytes.len() != 32 {
                    return Err(de::Error::custom("expected 32 bytes for Scalar"));
                }
                bytes
            }
            ciborium::Value::Array(items) => {
                if items.len() != 32 {
                    return Err(de::Error::custom("expected 32 bytes for Scalar"));
                }
                let mut bytes = Vec::with_capacity(32);
                for item in items {
                    match item {
                        ciborium::Value::Integer(i) => {
                            let b: u8 = i.try_into().map_err(de::Error::custom)?;
                            bytes.push(b);
                        }
                        _ => return Err(de::Error::custom("expected integer in byte array")),
                    }
                }
                bytes
            }
            _ => return Err(de::Error::custom("expected bytes for Scalar")),
        };

        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes[0..32]);

        let num = k256::U256::from_le_bytes(buf);
        let scalar = k256::Scalar::from_uint_unchecked(num);
        Ok(scalar)
    }
}
