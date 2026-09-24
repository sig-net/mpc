//! Shared respond-output codec for bidirectional requests whose source chain
//! is Midnight.
//!
//! An execution target decodes its chain's return value into the
//! producer-neutral [`DecodedOutput`] boundary and hands it to [`fab::serialize`],
//! which validates and coerces it against Midnight's respond schema (carrying
//! the `maxBytes`/`maxItems` capacities ABI schemas lack) and packs it in the
//! Compact layout Midnight contracts read.

pub mod fab;

pub use signet_midnight_serde::U256;

/// A decoded execution-target return value, neutral to the target chain.
///
/// The mapping from a target's native values is lossy by design: producers
/// render everything the FAB codec can consume, and the coercions the codec
/// performs (BigInt-grammar text to integer, `0x`-prefixed text to bytes) are
/// TypeScript-oracle semantics, not producer semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedValue {
    Bool(bool),
    Uint(U256),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<DecodedValue>),
}

/// Decoded named return fields of an execution, plus whether they came from a
/// real contract call. Non-contract-call outputs (plain transfers) serialize
/// per-schema defaults instead of decoded data.
#[derive(Clone, Debug, Default)]
pub struct DecodedOutput {
    fields: Vec<(String, DecodedValue)>,
    from_contract_call: bool,
}

impl DecodedOutput {
    pub fn contract_call(fields: Vec<(String, DecodedValue)>) -> Self {
        Self {
            fields,
            from_contract_call: true,
        }
    }

    pub fn non_contract_call() -> Self {
        Self {
            fields: Vec::new(),
            from_contract_call: false,
        }
    }

    pub fn is_contract_call(&self) -> bool {
        self.from_contract_call
    }

    /// Last occurrence of a duplicated name wins, mirroring the map-based
    /// decoded outputs this boundary replaced.
    pub(crate) fn field(&self, name: &str) -> Option<&DecodedValue> {
        self.fields
            .iter()
            .rev()
            .find(|(field_name, _)| field_name == name)
            .map(|(_, value)| value)
    }
}
