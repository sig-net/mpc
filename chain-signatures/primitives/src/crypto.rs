use borsh::{BorshDeserialize, BorshSerialize};
use k256::elliptic_curve::{
    bigint::ArrayEncoding, sec1::ToEncodedPoint, CurveArithmetic, PrimeField,
};
use k256::{AffinePoint, Scalar, Secp256k1, U256};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::sync::LazyLock;

pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn from_non_biased(bytes: [u8; 32]) -> Self;
}

impl ScalarExt for Scalar {
    /// Returns nothing if the bytes are greater than or equal to the secp256k1 scalar field order
    /// (n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let bytes = U256::from_be_slice(bytes.as_slice());
        Scalar::from_repr(bytes.to_be_byte_array()).into_option()
    }

    /// When the user can't directly select the value, this will always work
    /// Use cases are things that we know have been hashed
    fn from_non_biased(hash: [u8; 32]) -> Self {
        // This should never happen.
        // The space of inputs is 2^256, the group order is ~2^256 - 2^128.
        // This means that you'd have to run ~2^128 hashes to find a value that causes this to fail.
        Scalar::from_bytes(hash).expect("Derived epsilon value falls outside of the field")
    }
}

/// The maximum valid scalar for the secp256k1 curve (group order minus one).
pub static MAX_SECP256K1_SCALAR: LazyLock<Scalar> = LazyLock::new(|| {
    Scalar::from_bytes(
        hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
});

#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SignId {
    #[serde(with = "serde_bytes")]
    pub request_id: [u8; 32],
}

impl std::fmt::Debug for SignId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SignId")
            .field(&hex::encode(self.request_id))
            .finish()
    }
}

impl SignId {
    pub fn new(request_id: [u8; 32]) -> Self {
        Self { request_id }
    }

    pub fn from_parts(id: &str, payload: &[u8; 32], path: &str, key_version: u32) -> Self {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(id.as_bytes());
        hasher.update(payload);
        hasher.update(path.as_bytes());
        hasher.update(key_version.to_le_bytes());
        let request_id: [u8; 32] = hasher.finalize().into();
        Self { request_id }
    }
}

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

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Signature {
    #[borsh(
        serialize_with = "borsh_affine_point::serialize",
        deserialize_with = "borsh_affine_point::deserialize_reader"
    )]
    pub big_r: AffinePoint,
    #[borsh(
        serialize_with = "borsh_scalar::serialize",
        deserialize_with = "borsh_scalar::deserialize_reader"
    )]
    pub s: Scalar,
    pub recovery_id: u8,
}

impl Signature {
    pub fn new(big_r: AffinePoint, s: Scalar, recovery_id: u8) -> Self {
        Signature {
            big_r,
            s,
            recovery_id,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let encoded_point = self.big_r.to_encoded_point(false);
        let mut bytes = Vec::with_capacity(encoded_point.len() + 32 + 1);
        bytes.extend_from_slice(encoded_point.as_bytes());
        bytes.extend_from_slice(self.s.to_bytes().as_slice());
        bytes.push(self.recovery_id);
        bytes
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

pub mod borsh_scalar {
    use crate::crypto::ScalarExt as _;
    use borsh::{BorshDeserialize, BorshSerialize};
    use k256::Scalar;
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
    use borsh::{BorshDeserialize, BorshSerialize};
    use k256::AffinePoint;
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
    use super::*;
    use borsh::{BorshDeserialize, BorshSerialize};
    use k256::{elliptic_curve::PrimeField, AffinePoint, Scalar};
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
                assert_eq!(input, output, "Failed on {scalar:?}");
            }

            // Test Serde via JSON
            {
                let serialized = serde_json::to_vec(&input).unwrap();
                let output: WithScalar = serde_json::from_slice(&serialized).unwrap();
                assert_eq!(input, output, "Failed on {scalar:?}");
            }
        }
    }

    #[test]
    fn signature_to_bytes_is_stable() {
        let signature = Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 7);

        let bytes = signature.to_bytes();

        assert_eq!(bytes.len(), 98);
        assert_eq!(bytes[0], 0x04);
        assert_eq!(&bytes[65..97], Scalar::ONE.to_bytes().as_slice());
        assert_eq!(bytes[97], 7);
    }

    #[test]
    fn scalar_fails_as_expected() {
        let too_high = [0xFF; 32];
        assert!(Scalar::from_bytes(too_high).is_none());

        let mut not_too_high = [0xFF; 32];
        // Order of k256 is FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        //                                                  [15]
        not_too_high[15] = 0xFD;
        assert!(Scalar::from_bytes(not_too_high).is_some());
    }
}
