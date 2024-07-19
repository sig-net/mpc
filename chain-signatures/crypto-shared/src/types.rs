use borsh::{BorshDeserialize, BorshSerialize};
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, CurveArithmetic, PrimeField},
    AffinePoint, Scalar, Secp256k1, U256,
};
use serde::{Deserialize, Serialize};

pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

pub trait ScalarExt {
    fn from_bytes(bytes: &[u8]) -> Self;
}

// TODO prevent bad scalars from beind sent
impl ScalarExt for Scalar {
    fn from_bytes(bytes: &[u8]) -> Self {
        let bytes = U256::from_be_slice(bytes);
        Scalar::from_repr(bytes.to_be_byte_array()).expect("Byte conversion to scalar failed")
    }
}

// Is there a better way to force a borsh serialization?
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub struct SerializableScalar {
    pub scalar: Scalar,
}

impl BorshSerialize for SerializableScalar {
    fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let to_ser: [u8; 32] = self.scalar.to_bytes().into();
        BorshSerialize::serialize(&to_ser, writer)
    }
}

impl BorshDeserialize for SerializableScalar {
    fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
        let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
        let scalar = Scalar::from_bytes(&from_ser[..]);
        Ok(SerializableScalar { scalar })
    }
}

// Is there a better way to force a borsh serialization?
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub struct SerializableAffinePoint {
    pub affine_point: AffinePoint,
}

impl BorshSerialize for SerializableAffinePoint {
    fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let to_ser: Vec<u8> = serde_json::to_vec(&self.affine_point)?;
        BorshSerialize::serialize(&to_ser, writer)
    }
}

impl BorshDeserialize for SerializableAffinePoint {
    fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
        let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let affine_point = serde_json::from_slice(&from_ser)?;
        Ok(SerializableAffinePoint { affine_point })
    }
}

#[test]
fn serializeable_scalar_roundtrip() {
    use k256::elliptic_curve::PrimeField;
    let test_vec = vec![
        Scalar::ZERO,
        Scalar::ONE,
        Scalar::from_u128(u128::MAX),
        Scalar::from_bytes(&[3; 32]),
    ];

    for scalar in test_vec.into_iter() {
        let input = SerializableScalar { scalar };
        // Test borsh
        {
            let serialized = borsh::to_vec(&input).unwrap();
            let output: SerializableScalar = borsh::from_slice(&serialized).unwrap();
            assert_eq!(input, output, "Failed on {:?}", scalar);
        }

        // Test Serde via JSON
        {
            let serialized = serde_json::to_vec(&input).unwrap();
            let output: SerializableScalar = serde_json::from_slice(&serialized).unwrap();
            assert_eq!(input, output, "Failed on {:?}", scalar);
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignatureResponse {
    pub big_r: SerializableAffinePoint,
    pub s: SerializableScalar,
    pub recovery_id: u8,
}

impl SignatureResponse {
    pub fn new(big_r: AffinePoint, s: Scalar, recovery_id: u8) -> Self {
        SignatureResponse {
            big_r: SerializableAffinePoint {
                affine_point: big_r,
            },
            s: SerializableScalar { scalar: s },
            recovery_id,
        }
    }
}
