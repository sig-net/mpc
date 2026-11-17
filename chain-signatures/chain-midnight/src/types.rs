//! Boundary primitives for the seams between the node RPC and its consumers:
//! the contract address, the block and transaction hashes, the network id —
//! bytes in transit, canonical text at the edges.

use std::fmt;

/// A Midnight contract address in its native 32-byte representation.
///
/// Text input is normalized to 64 lowercase hex characters without a `0x` prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MidnightAddress([u8; 32]);

impl MidnightAddress {
    pub fn from_hex(value: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes)?;
        Ok(Self(bytes))
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for MidnightAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// The Midnight networks the publisher builds transactions for. [`Self::as_str`] is
/// the wire name, used at the SDK and storage edges that take text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkId {
    Undeployed,
    Stagenet,
    Preview,
    Preprod,
    Mainnet,
}

impl NetworkId {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Undeployed => "undeployed",
            Self::Stagenet => "stagenet",
            Self::Preview => "preview",
            Self::Preprod => "preprod",
            Self::Mainnet => "mainnet",
        }
    }

    /// Every supported network, the closed family this type admits.
    pub const ALL: [Self; 5] = [
        Self::Undeployed,
        Self::Stagenet,
        Self::Preview,
        Self::Preprod,
        Self::Mainnet,
    ];
}

impl fmt::Display for NetworkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The network id a node reported, which the publisher does not support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedNetwork(pub String);

impl fmt::Display for UnsupportedNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let supported = NetworkId::ALL
            .iter()
            .map(|network| network.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            formatter,
            "unsupported midnight network id '{}': the publisher builds for {supported}",
            self.0
        )
    }
}

impl std::error::Error for UnsupportedNetwork {}

impl TryFrom<&str> for NetworkId {
    type Error = UnsupportedNetwork;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "undeployed" => Self::Undeployed,
            "stagenet" => Self::Stagenet,
            "preview" => Self::Preview,
            "preprod" => Self::Preprod,
            "mainnet" => Self::Mainnet,
            other => return Err(UnsupportedNetwork(other.to_owned())),
        })
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midnight_address_round_trips_bytes_and_canonical_hex() {
        let bytes = [
            0x00, 0x0f, 0x10, 0xab, 0xcd, 0xef, 0x80, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x09, 0x08,
            0x07, 0x06, 0x05, 0x04,
        ];
        let expected = "000f10abcdef80ff0123456789aabbccddeefedcba9876543210090807060504";

        let address = MidnightAddress::from_bytes(bytes);

        assert_eq!(address.as_bytes(), &bytes);
        assert_eq!(address.to_hex(), expected);
        assert_eq!(MidnightAddress::from_hex(expected).unwrap(), address);
        assert_eq!(
            MidnightAddress::from_hex(&expected.to_ascii_uppercase()).unwrap(),
            address
        );
    }

    #[test]
    fn midnight_address_rejects_invalid_hex() {
        for input in [
            "ab".repeat(31),
            "ab".repeat(33),
            format!("0x{}", "ab".repeat(31)),
            "zz".repeat(32),
        ] {
            assert!(
                MidnightAddress::from_hex(&input).is_err(),
                "unexpectedly accepted {input}"
            );
        }
    }

    #[test]
    fn network_ids_round_trip_the_whole_family_and_refuse_the_unknown() {
        for network in NetworkId::ALL {
            assert_eq!(NetworkId::try_from(network.as_str()), Ok(network));
        }
        let err = NetworkId::try_from("devnet").unwrap_err();
        assert_eq!(err.0, "devnet");
        let refusal = err.to_string();
        assert!(refusal.contains("'devnet'"), "{refusal}");
        // Derived from ALL, the refusal cannot omit a member.
        for network in NetworkId::ALL {
            assert!(refusal.contains(network.as_str()), "{refusal}");
        }
    }

    #[test]
    fn block_hash_parses_canonical_hex_and_refuses_other_shapes() {
        let hash = BlockHash::from_bytes([0xab; 32]);
        assert_eq!(BlockHash::from_0x_hex(&hash.to_string()), Ok(hash));
        for malformed in [
            "ab".repeat(32),
            format!("0x{}", "ab".repeat(31)),
            format!("0x{}", "ab".repeat(33)),
            format!("0x{}", "zz".repeat(32)),
        ] {
            assert!(BlockHash::from_0x_hex(&malformed).is_err(), "{malformed}");
        }
        assert_eq!(
            BlockHash::from_0x_hex("0xzz").unwrap_err(),
            BlockHashError::NotHex
        );
        assert_eq!(
            BlockHash::from_0x_hex(&format!("0x{}", "ab".repeat(31))).unwrap_err(),
            BlockHashError::Not32Bytes(31)
        );
        assert_eq!(
            BlockHash::from_0x_hex("deadbeef").unwrap_err(),
            BlockHashError::Not0xPrefixed
        );
    }
}
