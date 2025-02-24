/// Scalar module for any scalars to be sent through messaging other nodes.
/// There's an issue with serializing with ciborium when it comes to
/// forward and backward compatibility, so we need to implement our own
/// custom serialization here.
pub mod cbor_scalar {
    use k256::Scalar;
    use k256::elliptic_curve::bigint::Encoding as _;
    use k256::elliptic_curve::scalar::FromUintUnchecked as _;
    use serde::{Deserialize as _, Deserializer, Serialize, Serializer, de};

    pub fn serialize<S: Serializer>(scalar: &Scalar, ser: S) -> Result<S::Ok, S::Error> {
        let num = k256::U256::from(scalar);
        let bytes = num.to_le_bytes();
        serde_bytes::Bytes::new(&bytes).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Scalar, D::Error> {
        let bytes = match ciborium::Value::deserialize(deserializer)? {
            ciborium::Value::Bytes(bytes) if bytes.len() != 32 => {
                return Err(de::Error::custom("expected 32 bytes for Scalar"));
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

pub mod borsh_scalar {
    use k256::Scalar;
    use mpc_crypto::ScalarExt as _;
    use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
    use std::io;

    pub fn serialize<W: io::prelude::Write>(scalar: &Scalar, writer: &mut W) -> io::Result<()> {
        let to_ser: [u8; 32] = scalar.to_bytes().into();
        BorshSerialize::serialize(&to_ser, writer)
    }

    pub fn deserialize_reader<R: io::prelude::Read>(reader: &mut R) -> io::Result<Scalar> {
        let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
        let scalar = Scalar::from_bytes(from_ser).ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Scalar bytes are not in the k256 field",
        ))?;
        Ok(scalar)
    }
}

pub mod borsh_affine_point {
    use k256::AffinePoint;
    use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
    use near_sdk::serde_json;
    use std::io;
    use std::io::prelude::{Read, Write};

    pub fn serialize<W: Write>(affine_point: &AffinePoint, writer: &mut W) -> io::Result<()> {
        let to_ser: Vec<u8> = serde_json::to_vec(affine_point)?;
        BorshSerialize::serialize(&to_ser, writer)
    }

    pub fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<AffinePoint> {
        let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        Ok(serde_json::from_slice(&from_ser)?)
    }
}

#[cfg(test)]
mod tests {
    use borsh::{BorshDeserialize, BorshSerialize};
    use k256::{Scalar, elliptic_curve::PrimeField};
    use mpc_crypto::ScalarExt as _;
    use serde::{Deserialize, Serialize};

    #[test]
    fn serializeable_scalar_roundtrip() {
        let test_vec = vec![
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::from_u128(u128::MAX),
            Scalar::from_bytes([3; 32]).unwrap(),
        ];

        #[derive(Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq)]
        struct WithScalar {
            #[borsh(
                serialize_with = "super::borsh_scalar::serialize",
                deserialize_with = "super::borsh_scalar::deserialize_reader"
            )]
            scalar: Scalar,
        }

        for scalar in test_vec.into_iter() {
            let input = WithScalar { scalar };
            // Test borsh
            {
                let serialized = borsh::to_vec(&input).unwrap();
                let output: WithScalar = borsh::from_slice(&serialized).unwrap();
                assert_eq!(input, output, "Failed on {:?}", scalar);
            }

            // Test Serde via JSON
            {
                let serialized = serde_json::to_vec(&input).unwrap();
                let output: WithScalar = serde_json::from_slice(&serialized).unwrap();
                assert_eq!(input, output, "Failed on {:?}", scalar);
            }
        }
    }
}
