use borsh::{BorshDeserialize, BorshSerialize};
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, CurveArithmetic, PrimeField},
    AffinePoint, Scalar, Secp256k1, U256,
};
use serde::{Deserialize, Serialize};

pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn from_non_biased(bytes: [u8; 32]) -> Self;
}

impl ScalarExt for Scalar {
    /// Returns nothing if the bytes are greater than the field size of Secp256k1.
    /// This will be very rare with random bytes as the field size is 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let bytes = U256::from_be_slice(bytes.as_slice());
        Scalar::from_repr(bytes.to_be_byte_array()).into_option()
    }

    /// When the user can't directly select the value, this will always work
    /// Use cases are things that we know have been hashed
    fn from_non_biased(hash: [u8; 32]) -> Self {
        // This should never happen.
        // The space of inputs is 2^256, the space of the field is ~2^256 - 2^129.
        // This mean that you'd have to run 2^127 hashes to find a value that causes this to fail.
        Scalar::from_bytes(hash).expect("Derived epsilon value falls outside of the field")
    }
}

#[test]
fn scalar_fails_as_expected() {
    let too_high = [0xFF; 32];
    assert!(Scalar::from_bytes(too_high).is_none());

    let mut not_too_high = [0xFF; 32];
    // Order is of k256 is FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    //                                                  [15]
    not_too_high[15] = 0xFD;
    assert!(Scalar::from_bytes(not_too_high).is_some());
}

pub mod borsh_scalar {
    use super::ScalarExt as _;
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

#[test]
fn serializeable_scalar_roundtrip() {
    use k256::elliptic_curve::PrimeField;
    let test_vec = vec![
        Scalar::ZERO,
        Scalar::ONE,
        Scalar::from_u128(u128::MAX),
        Scalar::from_bytes([3; 32]).unwrap(),
    ];

    #[derive(Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq)]
    struct WithScalar {
        #[borsh(
            serialize_with = "borsh_scalar::serialize",
            deserialize_with = "borsh_scalar::deserialize_reader"
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

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignatureResponse {
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

impl SignatureResponse {
    pub fn new(big_r: AffinePoint, s: Scalar, recovery_id: u8) -> Self {
        SignatureResponse {
            big_r,
            s,
            recovery_id,
        }
    }
}
