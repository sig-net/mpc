//! Hash newtypes for the seams between the node RPC and its consumers: bytes
//! in transit, canonical `0x` hex in text.

use std::fmt;

/// A 32-byte Midnight block hash. Canonical text is the `0x`-prefixed lowercase
/// hex every pinned read is addressed by; parse and format happen only at the
/// RPC edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct BlockHash([u8; 32]);

/// Why a `0x`-prefixed block-hash string did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockHashError {
    Not0xPrefixed,
    NotHex,
    Not32Bytes(usize),
}

impl fmt::Display for BlockHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Not0xPrefixed => write!(formatter, "block hash is not 0x-prefixed"),
            Self::NotHex => write!(formatter, "block hash is not hex"),
            Self::Not32Bytes(len) => write!(formatter, "block hash is {len} bytes, not 32"),
        }
    }
}

impl std::error::Error for BlockHashError {}

impl BlockHash {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

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
