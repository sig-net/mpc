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

/// Identifier of a signature request. This is the one id type used by the NEAR
/// contract, every chain indexer and publisher, the node's protocol layer, and
/// the backlog.
///
/// The 32 bytes are derived from the on-chain request, and **every chain derives
/// them differently**: each derivation reproduces whatever that chain's contract
/// or client SDK computes, so the bytes match what the chain later echoes back in
/// its responded event. Each derivation is a named constructor. The ones that
/// need chain-specific dependencies live in the crate that owns those
/// dependencies, as extension traits implemented on `RequestId`. The full registry:
///
/// | Request | Constructor | Scheme |
/// |---|---|---|
/// | NEAR `sign` | [`RequestId::from_near_request`] | SHA3-256 over raw concatenation |
/// | Solana / Hydration `sign` | `EvmRequestId::from_evm_sign_request` (`mpc-chain-integration-core`) | keccak256 over ABI encoding, string sender |
/// | Solana / Hydration `sign_bidirectional` | `EvmRequestId::from_evm_bidirectional_request` (`mpc-chain-integration-core`) | keccak256 over packed ABI encoding |
/// | Ethereum `sign` | `EthereumRequestId::from_ethereum_sign_request` (`mpc-chain-ethereum`) | keccak256 over ABI encoding, address sender |
/// | Canton `sign_bidirectional` | `CantonRequestId::from_canton_bidirectional_request` (`mpc-chain-canton`) | keccak256 over EIP-712 data words |
/// | Midnight `sign_bidirectional` | `MidnightRequestId::from_midnight_record` (`mpc-chain-midnight`) | Compact transient hash of the record cell |
///
/// Ids are unique only within a chain; key by `(Chain, RequestId)` when mixing
/// chains. When an id arrives on the wire (a responded event, a contract call),
/// wrap it with [`RequestId::new`] or `From<[u8; 32]>` instead of re-deriving it.
///
/// The serde layout is `{"request_id": <bytes>}`. That is the NEAR contract's
/// JSON ABI, so it must not change; use [`request_id_as_array`] on fields whose
/// persisted layout is the bare 32-byte array.
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
pub struct RequestId {
    /// Named `request_id` on the wire: that is the NEAR contract's JSON ABI.
    #[serde(rename = "request_id", with = "serde_bytes")]
    pub bytes: [u8; 32],
}

impl std::fmt::Debug for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RequestId")
            .field(&hex::encode(self.bytes))
            .finish()
    }
}

impl RequestId {
    /// Wraps an id that was already derived, typically one read back off the wire.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// NEAR `sign`: `sha3_256(predecessor || payload || path || key_version.to_le_bytes())`,
    /// exactly as the NEAR contract computes it when it accepts a request.
    pub fn from_near_request(
        predecessor: &str,
        payload: &[u8; 32],
        path: &str,
        key_version: u32,
    ) -> Self {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(predecessor.as_bytes());
        hasher.update(payload);
        hasher.update(path.as_bytes());
        hasher.update(key_version.to_le_bytes());
        Self::new(hasher.finalize().into())
    }

    /// Former name of [`RequestId::from_near_request`], kept so external clients
    /// compiled against this crate keep building.
    #[deprecated(note = "renamed to `RequestId::from_near_request`")]
    pub fn from_parts(id: &str, payload: &[u8; 32], path: &str, key_version: u32) -> Self {
        Self::from_near_request(id, payload, path, key_version)
    }

    /// Test helper: an id made of one byte repeated 32 times.
    pub const fn from_u8(byte: u8) -> Self {
        Self::new([byte; 32])
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl From<[u8; 32]> for RequestId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

/// Serde adapter that (de)serializes a [`RequestId`] as a bare `[u8; 32]` array.
/// For fields whose persisted layout predates their switch to `RequestId`.
pub mod request_id_as_array {
    use super::RequestId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(id: &RequestId, serializer: S) -> Result<S::Ok, S::Error> {
        id.bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<RequestId, D::Error> {
        <[u8; 32]>::deserialize(deserializer).map(RequestId::new)
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

#[cfg(test)]
mod request_id_tests {
    use super::RequestId;

    /// The NEAR contract's `respond` takes this JSON shape; node-to-node messages
    /// carry it too. Renaming the Rust field must not change it.
    #[test]
    fn request_id_json_layout_is_contract_abi() {
        let id = RequestId::from_u8(7);
        let json = serde_json::to_value(id).unwrap();
        assert_eq!(json, serde_json::json!({ "request_id": vec![7u8; 32] }));
        assert_eq!(serde_json::from_value::<RequestId>(json).unwrap(), id);
    }
}
