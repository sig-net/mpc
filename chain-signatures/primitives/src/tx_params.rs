//! The `txParams` structures of `SignBidirectionalEventV1` (bidirectional-calls
//! §7.3, §7.4): source-chain neutral protocol types, the transaction a request
//! names. Each source chain decodes them from its own record container and binds
//! its own `H`/`E` when hashing the digest; each target chain assembles its wire
//! transaction from them.

/// `txParamType` (§7.1): the discriminant a record's `txParams` is filed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TxParamType {
    EvmType2 = 0,
    Tron = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxParamTypeError {
    Unsupported(u8),
}

impl std::fmt::Display for TxParamTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(value) => write!(
                f,
                "unsupported tx_param_type {value}: the defined types are evmType2 (0) and tron (1)"
            ),
        }
    }
}

impl std::error::Error for TxParamTypeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalldataError {
    NoWordsOverrun { no_words: u16, capacity: usize },
}

impl std::fmt::Display for CalldataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoWordsOverrun { no_words, capacity } => write!(
                f,
                "calldata no_words {no_words} overruns the record's {capacity} stored word slots"
            ),
        }
    }
}

impl std::error::Error for CalldataError {}

impl TryFrom<u8> for TxParamType {
    type Error = TxParamTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::EvmType2),
            1 => Ok(Self::Tron),
            other => Err(TxParamTypeError::Unsupported(other)),
        }
    }
}

/// `txParamType` with `txParams` (§7.1)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TxParams {
    EvmType2(EvmType2TxParams),
    Tron(TronTxParams),
}

impl TxParams {
    /// The `txParamType` this variant is filed under.
    pub fn ty(&self) -> TxParamType {
        match self {
            TxParams::EvmType2(_) => TxParamType::EvmType2,
            TxParams::Tron(_) => TxParamType::Tron,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvmType2TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub calldata: CompactMaybe<Calldata>,
    pub access_list_entry_count: u8,
    /// `Vector<maxAccessListEntries, _>`: stored at capacity; only used entries
    /// participate in the transaction digest.
    pub access_list: Vec<EvmAccessListEntry>,
}

/// Compact's `Maybe<T>`, which is not `Option<T>`: `value` carries a full `T` even
/// when `is_some` is false, so vector capacities stay inferable from the record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompactMaybe<T> {
    pub is_some: bool,
    pub value: T,
}

/// Calldata as both targets define it (§7.3, §7.4): a 4-byte selector plus its
/// canonical ABI word arguments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Calldata {
    pub selector: [u8; 4],
    /// `Uint<16>`: number of used words when calldata is present.
    pub no_words: u16,
    /// `Vector<maxCalldataWords, Bytes<32>>`: stored at capacity; unused slots
    /// do not participate in the transaction digest.
    pub words: Vec<[u8; 32]>,
}

impl Calldata {
    /// The used word prefix `words[..no_words]`.
    pub fn used_words(&self) -> Result<&[[u8; 32]], CalldataError> {
        let no_words = usize::from(self.no_words);
        if no_words > self.words.len() {
            return Err(CalldataError::NoWordsOverrun {
                no_words: self.no_words,
                capacity: self.words.len(),
            });
        }
        Ok(&self.words[..no_words])
    }

    /// `data = selector ‖ used_words`.
    pub fn data(&self) -> Result<Vec<u8>, CalldataError> {
        let words = self.used_words()?;
        let mut data = Vec::with_capacity(4 + 32 * words.len());
        data.extend_from_slice(&self.selector);
        data.extend(words.iter().flatten());
        Ok(data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvmAccessListEntry {
    pub address: [u8; 20],
    pub storage_key_count: u8,
    /// `Vector<maxStorageKeysPerEntry, Bytes<32>>`: always at capacity
    pub storage_keys: Vec<[u8; 32]>,
}

/// `txParams` for `txParamType = tron` (§7.4), a `TriggerSmartContract` call.
/// `owner_address` is derived from the request's key and the contract type is
/// fixed, so neither is a record field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    pub calldata: CompactMaybe<Calldata>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calldata(no_words: u16, capacity: usize) -> Calldata {
        Calldata {
            selector: [0x0a; 4],
            no_words,
            words: vec![[0x11; 32]; capacity],
        }
    }

    #[test]
    fn used_words_pins_the_used_prefix() {
        assert_eq!(calldata(0, 2).used_words(), Ok(&[][..]));
        assert_eq!(calldata(2, 3).used_words(), Ok(&calldata(2, 2).words[..]));
        let err = calldata(2, 1).used_words().unwrap_err();
        assert_eq!(
            err,
            CalldataError::NoWordsOverrun {
                no_words: 2,
                capacity: 1
            }
        );
        assert!(err.to_string().contains("calldata no_words 2"));
    }

    #[test]
    fn data_concatenates_the_selector_and_used_words() {
        let mut expected = vec![0x0a; 4];
        expected.extend_from_slice(&[0x11; 32]);
        assert_eq!(calldata(1, 2).data(), Ok(expected));
        assert_eq!(
            calldata(2, 1).data().unwrap_err(),
            CalldataError::NoWordsOverrun {
                no_words: 2,
                capacity: 1
            }
        );
    }

    #[test]
    fn tx_param_type_decodes_exactly_its_closed_set() {
        assert_eq!(TxParamType::EvmType2 as u8, 0);
        assert_eq!(TxParamType::Tron as u8, 1);
        for byte in 0..=u8::MAX {
            assert_eq!(TxParamType::try_from(byte).is_ok(), byte <= 1);
        }
        let err = TxParamType::try_from(2).unwrap_err().to_string();
        assert!(err.contains("tx_param_type 2"), "{err}");
    }
}
