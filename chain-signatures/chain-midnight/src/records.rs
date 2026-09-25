//! Mirrors of the Midnight Signet contract's on-chain record types.

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
    /// `TxParamType` enum, one byte: evmType2 = 0, reserved = 1
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams,
    /// ASCII `Bytes<32>`, trailing-zero-trimmed on the wire and re-padded to 32 bytes
    /// in the preimage
    pub execution_dest: [u8; 32],
    /// `MPCDestination` enum, one byte: unused = 0, reserved = 1.
    /// This and the remaining protocol fields are outside request identity.
    pub signature_dest: u8,
    pub params: [u8; 64],
    /// `Bytes<LenOut>`, runtime width chosen per integrator
    pub output_deserialization_schema: Vec<u8>,
    /// `Bytes<LenResp>`, runtime width chosen per integrator
    pub respond_serialization_schema: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmType2TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub calldata: CompactMaybe<EvmCalldata>,
    pub access_list_entry_count: u8,
    /// `Vector<maxAccessListEntries, _>`: stored at capacity; only used entries
    /// participate in the transaction digest.
    pub access_list: Vec<EvmAccessListEntry>,
}

/// Compact's `Maybe<T>`, which is not `Option<T>`: `value` carries a full `T` even
/// when `is_some` is false, so vector capacities stay inferable from the record.
#[derive(Debug, Clone, PartialEq)]
pub struct CompactMaybe<T> {
    pub is_some: bool,
    pub value: T,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmCalldata {
    pub selector: [u8; 4],
    /// `Uint<16>`: number of used words when calldata is present.
    pub no_words: u16,
    /// `Vector<maxCalldataWords, Bytes<32>>`: stored at capacity; unused slots
    /// do not participate in the transaction digest.
    pub words: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmAccessListEntry {
    pub address: [u8; 20],
    pub storage_key_count: u8,
    /// `Vector<maxStorageKeysPerEntry, Bytes<32>>`: always at capacity
    pub storage_keys: Vec<[u8; 32]>,
}

/// Notification recovered from the central singleton's emitted event payload.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalEventNotification {
    pub version: u8,
    pub request_id: [u8; 32],
    pub payload: [u8; 128],
}
