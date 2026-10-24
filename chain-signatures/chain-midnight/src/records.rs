//! Mirrors of the Midnight Signet contract's on-chain record types.

use mpc_primitives::TxParams;

/// One signing request, the contract's `SignBidirectionalEventV1` record.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalRecord {
    /// `Uint<8>`: the first field of the record and request-id preimage.
    pub key_version: u8,
    /// `ContractAddress { bytes: Bytes<32> }`, a single-field wrapper.
    pub sender: [u8; 32],
    pub path: [u8; 32],
    /// `MPCSignatureAlgorithm` enum, one byte: ecdsa = 0, reserved = 1
    pub algo: u8,
    /// `txParamType` with `txParams` (§7.1): the discriminant names the payload's
    /// structure, so they are one field here, never two that can disagree.
    pub tx_params: TxParams,
    /// ASCII `Bytes<64>`, trailing-zero-trimmed on the wire and re-padded to 64 bytes
    /// in the preimage
    pub execution_dest: [u8; 64],
    /// `MPCDestination` enum, one byte: unused = 0, reserved = 1.
    /// This and the remaining protocol fields are outside request identity.
    pub signature_dest: u8,
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
