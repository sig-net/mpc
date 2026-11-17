//! Hash newtypes for the seams between the node RPC and its consumers: bytes
//! in transit, canonical `0x` hex in text.

use std::fmt;

/// A 32-byte Midnight block hash. Canonical text is the `0x`-prefixed lowercase
/// hex every pinned read is addressed by; parse and format happen only at the
/// RPC edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct BlockHash([u8; 32]);

/// Why a `0x`-prefixed block-hash string did not parse.
///
/// Only tests parse hash text: every production boundary receives hashes typed
/// from the node's own replies, so this stays out of non-test builds.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockHashError {
    Not0xPrefixed,
    NotHex,
    Not32Bytes(usize),
}

#[cfg(test)]
impl fmt::Display for BlockHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Not0xPrefixed => write!(formatter, "block hash is not 0x-prefixed"),
            Self::NotHex => write!(formatter, "block hash is not hex"),
            Self::Not32Bytes(len) => write!(formatter, "block hash is {len} bytes, not 32"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for BlockHashError {}

impl BlockHash {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses the `0x`-prefixed 32-byte hex form; test fixtures and stubs only.
    #[cfg(test)]
    pub(crate) fn from_0x_hex(value: &str) -> Result<Self, BlockHashError> {
        let bare = value
            .strip_prefix("0x")
            .ok_or(BlockHashError::Not0xPrefixed)?;
        let bytes: [u8; 32] = hex::decode(bare)
            .map_err(|_| BlockHashError::NotHex)?
            .try_into()
            .map_err(|decoded: Vec<u8>| BlockHashError::Not32Bytes(decoded.len()))?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{}", hex::encode(self.0))
    }
}

/// A 32-byte Midnight ledger transaction hash, distinct from [`BlockHash`] so the
/// two cannot be swapped where a seam carries both. Canonical text is bare
/// lowercase hex, the form receipts and telemetry print.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LedgerTxHash([u8; 32]);

impl LedgerTxHash {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for LedgerTxHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", hex::encode(self.0))
    }
}
