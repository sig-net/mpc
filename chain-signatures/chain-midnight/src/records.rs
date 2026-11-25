//! Mirrors of the Midnight Signet contract's on-chain record types.

use crate::types::MidnightAddress;
use mpc_primitives::TxParams;

/// `MPCSignatureAlgorithm`, one byte on the wire: ecdsa = 0, reserved = 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MpcSignatureAlgorithm {
    Ecdsa = 0,
    Reserved = 1,
}

/// `MPCDestination`, one byte on the wire: unused = 0, reserved = 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MpcDestination {
    Unused = 0,
    Reserved = 1,
}

/// A one-byte record discriminant outside the variants the contract defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDiscriminantError {
    Algo(u8),
    Destination(u8),
}

impl std::fmt::Display for RecordDiscriminantError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Algo(value) => write!(
                formatter,
                "unsupported algo {value}: ecdsa (0) is the only real variant, 1 is reserved"
            ),
            Self::Destination(value) => write!(
                formatter,
                "unsupported signature_dest {value}: unused (0) is the only real variant, 1 is \
                 reserved"
            ),
        }
    }
}

impl std::error::Error for RecordDiscriminantError {}

impl TryFrom<u8> for MpcSignatureAlgorithm {
    type Error = RecordDiscriminantError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ecdsa),
            1 => Ok(Self::Reserved),
            other => Err(RecordDiscriminantError::Algo(other)),
        }
    }
}

impl TryFrom<u8> for MpcDestination {
    type Error = RecordDiscriminantError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unused),
            1 => Ok(Self::Reserved),
            other => Err(RecordDiscriminantError::Destination(other)),
        }
    }
}

/// One signing request, the contract's `SignBidirectionalEventV1` record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignBidirectionalRecord {
    /// `Uint<8>`: the first field of the record and request-id preimage.
    pub key_version: u8,
    /// `ContractAddress { bytes: Bytes<32> }`, a single-field wrapper.
    pub sender: MidnightAddress,
    pub path: [u8; 32],
    pub algo: MpcSignatureAlgorithm,
    /// `txParamType` with `txParams` (§7.1): the discriminant names the payload's
    /// structure, so they are one field here, never two that can disagree.
    pub tx_params: TxParams,
    /// ASCII `Bytes<64>`, trailing-zero-trimmed on the wire and re-padded to 64 bytes
    /// in the preimage
    pub execution_dest: [u8; 64],
    /// This and the remaining protocol fields are outside request identity.
    pub signature_dest: MpcDestination,
    pub params: [u8; 64],
    /// `Bytes<LenOut>`, runtime width chosen per integrator
    pub output_deserialization_schema: Vec<u8>,
    /// `Bytes<LenResp>`, runtime width chosen per integrator
    pub respond_serialization_schema: Vec<u8>,
}

/// Notification recovered from the central singleton's emitted event payload.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalEventNotification {
    pub version: u8,
    pub request_id: [u8; 32],
    pub payload: [u8; 128],
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the wire bytes as identity, not just admission: `compute_request_id`
    /// folds the discriminants with `as u8`, and a field reverted to raw `u8` would
    /// slip through `one_byte_enum` via identity `TryFrom`.
    #[test]
    fn try_from_u8_partitions_the_whole_byte_domain() {
        for byte in 0..=u8::MAX {
            assert_eq!(
                MpcSignatureAlgorithm::try_from(byte),
                match byte {
                    0 => Ok(MpcSignatureAlgorithm::Ecdsa),
                    1 => Ok(MpcSignatureAlgorithm::Reserved),
                    other => Err(RecordDiscriminantError::Algo(other)),
                },
                "algo byte {byte}"
            );
            assert_eq!(
                MpcDestination::try_from(byte),
                match byte {
                    0 => Ok(MpcDestination::Unused),
                    1 => Ok(MpcDestination::Reserved),
                    other => Err(RecordDiscriminantError::Destination(other)),
                },
                "signature_dest byte {byte}"
            );
        }
        for (algo, byte) in [
            (MpcSignatureAlgorithm::Ecdsa, 0),
            (MpcSignatureAlgorithm::Reserved, 1),
        ] {
            assert_eq!(algo as u8, byte);
            assert_eq!(MpcSignatureAlgorithm::try_from(algo as u8), Ok(algo));
        }
        for (dest, byte) in [(MpcDestination::Unused, 0), (MpcDestination::Reserved, 1)] {
            assert_eq!(dest as u8, byte);
            assert_eq!(MpcDestination::try_from(dest as u8), Ok(dest));
        }
    }
}
