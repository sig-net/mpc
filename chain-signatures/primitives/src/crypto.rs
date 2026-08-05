use k256::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
    use k256::elliptic_curve::{
        bigint::{ArrayEncoding as _, Encoding as _},
        PrimeField,
    };
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
        k256::Scalar::from_repr(num.to_be_byte_array())
            .into_option()
            .ok_or_else(|| de::Error::custom("scalar value out of range"))
    }
}

#[cfg(test)]
mod tests {
    use super::cbor_scalar;
    use k256::{elliptic_curve::PrimeField, Scalar};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    struct WithScalar(#[serde(with = "cbor_scalar")] Scalar);

    fn deserialize_scalar(
        bytes: [u8; 32],
    ) -> Result<WithScalar, ciborium::de::Error<std::io::Error>> {
        let mut encoded = Vec::new();
        ciborium::into_writer(&ciborium::Value::Bytes(bytes.to_vec()), &mut encoded).unwrap();
        ciborium::from_reader(encoded.as_slice())
    }

    fn scalar_order_le() -> [u8; 32] {
        let mut order: [u8; 32] =
            hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
                .unwrap()
                .try_into()
                .unwrap();
        order.reverse();
        order
    }

    #[test]
    fn cbor_scalar_rejects_out_of_range_value() {
        // The secp256k1 order, encoded little-endian as required by cbor_scalar.
        let error = deserialize_scalar(scalar_order_le()).unwrap_err();
        assert!(error.to_string().contains("scalar value out of range"));
        assert!(deserialize_scalar([0xff; 32]).is_err());
    }

    #[test]
    fn cbor_scalar_accepts_value_below_order() {
        let mut order_minus_one = scalar_order_le();
        order_minus_one[0] -= 1;
        let value = deserialize_scalar(order_minus_one).unwrap();

        let mut expected_bytes = scalar_order_le();
        expected_bytes.reverse();
        expected_bytes[31] -= 1;
        let expected = Scalar::from_repr(expected_bytes.into()).unwrap();
        assert_eq!(value.0, expected);
    }

    #[test]
    fn cbor_scalar_accepts_valid_value() {
        let mut one = [0; 32];
        one[0] = 1;
        let value = deserialize_scalar(one).unwrap();
        assert_eq!(value.0, Scalar::ONE);
    }
}
