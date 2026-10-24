//! The `txParams` structures of `SignBidirectionalEventV1` (bidirectional-calls
//! §7.3, §7.4): source-chain neutral protocol types, the transaction a request
//! names. Each source chain decodes them from its own record container and binds
//! its own `H`/`E` when hashing the digest; each target chain assembles its wire
//! transaction from them.

/// `TxParamType` discriminant (§7.1): evmType2 = 0.
pub const TX_PARAM_TYPE_EVM_TYPE2: u8 = 0;
/// `TxParamType` discriminant (§7.1): tron = 1.
pub const TX_PARAM_TYPE_TRON: u8 = 1;

/// `txParamType` with `txParams` (§7.1)
#[derive(Debug, Clone, PartialEq)]
pub enum TxParams {
    EvmType2(EvmType2TxParams),
    Tron(TronTxParams),
}

impl TxParams {
    /// The `txParamType` byte this variant is filed under.
    pub fn discriminant(&self) -> u8 {
        match self {
            TxParams::EvmType2(_) => TX_PARAM_TYPE_EVM_TYPE2,
            TxParams::Tron(_) => TX_PARAM_TYPE_TRON,
        }
    }
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

/// `txParams` for `txParamType = tron` (§7.4), a `TriggerSmartContract` call.
/// `owner_address` is derived from the request's key and the contract type is
/// fixed, so neither is a record field.
#[derive(Debug, Clone, PartialEq)]
pub struct TronTxParams {
    /// the reference block height's low two bytes, big-endian
    pub ref_block_bytes: [u8; 2],
    /// the reference block id's bytes 8..16
    pub ref_block_hash: [u8; 8],
    /// milliseconds
    pub timestamp: u64,
    /// milliseconds
    pub expiration: u64,
    /// sun
    pub fee_limit: u64,
    /// `0x41` followed by the target contract's 20-byte address
    pub contract_address: [u8; 21],
    /// sun
    pub call_value: u64,
    pub calldata: CompactMaybe<EvmCalldata>,
}
