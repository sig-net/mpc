//! Mirrors of the Midnight Signet contract's on-chain record types.
//!
//! Plain data only. The request id is keccak256 over the contract's
//! `toBinaryRepr`, but `request_id::binary_repr` writes each field by name in an
//! explicit sequence, so the preimage follows that function rather than this
//! file's declaration order. Fields are kept in contract order for readability;
//! `tests/rid_vectors.json` is what pins the layout.
//!
//! Every `Uint` here is little-endian zero-padded to its declared width, in the
//! preimage and on the wire, so nothing may assume Rust's memory layout.

/// One signing request, the contract's `SignBidirectionalEvent` record.
///
/// Named `Record` because `mpc-primitives` already exports a chain-agnostic
/// `SignBidirectionalEvent` and both are in scope in the conversion layer.
///
/// The 12 fields are in keccak preimage order; `tx_params` expands in place.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalRecord {
    /// `ContractAddress { bytes: Bytes<32> }`, a single-field wrapper that
    /// contributes exactly 32 preimage bytes
    pub sender: [u8; 32],
    pub request_nonce: u64,
    /// `Uint<8>`: one byte in the preimage, not four
    pub key_version: u8,
    pub path: [u8; 32],
    /// `MPCSignatureAlgorithm` enum, one byte: ecdsa = 0, reserved = 1
    pub algo: u8,
    /// `MPCDestination` enum, one byte: unused = 0, reserved = 1
    pub dest: u8,
    pub params: [u8; 64],
    /// `TxParamType` enum, one byte: evmType2 = 0, reserved = 1
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams,
    /// ASCII `Bytes<32>`, trailing-zero-trimmed on the wire and re-padded to
    /// 32 bytes in the preimage
    pub caip2_id: [u8; 32],
    /// `Bytes<LenOut>`, runtime width chosen per integrator
    pub output_deserialization_schema: Vec<u8>,
    /// `Bytes<LenResp>`, runtime width chosen per integrator
    pub respond_serialization_schema: Vec<u8>,
}

/// EIP-1559 parameters in the contract's payload order, which is the hash
/// order and reads backwards against EVM habit: the priority fee precedes the
/// fee cap, `to` sits sixth, and `calldata` precedes the access-list pair.
/// Each count field sits directly before the vector it bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct EvmType2TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    /// Before `max_fee_per_gas`, backwards against EVM habit
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    /// Before the access-list pair, backwards against EVM habit
    pub calldata: CompactMaybe<EvmCalldata>,
    pub access_list_entry_count: u8,
    /// `Vector<maxAccessListEntries, _>`: always at capacity, unused slots
    /// zero-filled and still hashed
    pub access_list: Vec<EvmAccessListEntry>,
}

/// Compact's `Maybe<T>`, which is not `Option<T>`: `value` carries a full
/// default-valued `T` even when `is_some` is false, so vector capacities stay
/// inferable from the record. Serializers emit the flag byte then `T` at full
/// width regardless of the flag; an `Option` would emit a short preimage and a
/// wrong request id for every request without calldata.
#[derive(Debug, Clone, PartialEq)]
pub struct CompactMaybe<T> {
    pub is_some: bool,
    pub value: T,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmCalldata {
    pub selector: [u8; 4],
    /// `Uint<16>`: two bytes in the preimage, not one
    pub no_words: u16,
    /// `Vector<maxCalldataWords, Bytes<32>>`: always at capacity, unused
    /// slots zero-filled and still hashed
    pub words: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmAccessListEntry {
    pub address: [u8; 20],
    pub storage_key_count: u8,
    /// `Vector<maxStorageKeysPerEntry, Bytes<32>>`: always at capacity
    pub storage_keys: Vec<[u8; 32]>,
}

/// Entry of the central singleton's notification map.
///
/// The V1 payload is `caller_address(32) || requests_index_field(1) ||
/// zeros(95)` and names no decode selector, so decoders must fail closed on an
/// unrecognised `version` rather than reinterpret bytes under V1 offsets.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalEventNotification {
    pub version: u8,
    pub payload: [u8; 128],
}
