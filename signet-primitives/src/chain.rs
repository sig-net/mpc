use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Supported blockchain networks.
#[repr(u8)]
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    enum_map::Enum,
)]
pub enum Chain {
    NEAR,
    Ethereum,
    Solana,
    Bitcoin,
    Hydration,
    Canton,
    Midnight,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum ChainFromError {
    #[error("unknown CAIP-2 chain ID: {0}")]
    UnknownCaip2Id(String),
    #[error("unknown deprecated chain ID: {0}")]
    UnknownDeprecatedId(String),
}

impl Chain {
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    pub const fn to_bytes(self) -> [u8; 1] {
        [self.to_byte()]
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Chain::NEAR => "NEAR",
            Chain::Ethereum => "Ethereum",
            Chain::Solana => "Solana",
            Chain::Bitcoin => "Bitcoin",
            Chain::Hydration => "Hydration",
            Chain::Canton => "Canton",
            Chain::Midnight => "Midnight",
        }
    }

    pub const fn iter() -> [Chain; 7] {
        [
            Chain::NEAR,
            Chain::Ethereum,
            Chain::Solana,
            Chain::Bitcoin,
            Chain::Hydration,
            Chain::Canton,
            Chain::Midnight,
        ]
    }

    pub fn deprecated_chain_id(&self) -> &'static str {
        match self {
            Chain::NEAR => "0x18d",
            Chain::Ethereum => "0x1",
            Chain::Solana => "0x800001f5",
            Chain::Bitcoin => "bip122:000000000019d6689c085ae165831e93",
            Chain::Hydration => "polkadot:2034",
            Chain::Canton => "canton:global",
            Chain::Midnight => "midnight:testnet",
        }
    }

    pub fn caip2_chain_id(&self) -> &'static str {
        match self {
            Chain::NEAR => "near:mainnet",
            Chain::Ethereum => "eip155:1",
            Chain::Solana => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            Chain::Bitcoin => "bip122:000000000019d6689c085ae165831e93",
            Chain::Hydration => "polkadot:2034",
            // Synthetic — Canton has no registered CAIP-2 namespace in
            // ChainAgnostic/namespaces. "canton:global" follows the
            // namespace:reference format as a project-local identifier.
            Chain::Canton => "canton:global",
            Chain::Midnight => "midnight:testnet",
        }
    }

    pub fn from_caip2_chain_id(chain_id: &str) -> Result<Self, ChainFromError> {
        Self::iter()
            .into_iter()
            .find(|chain| chain.caip2_chain_id() == chain_id)
            .ok_or_else(|| ChainFromError::UnknownCaip2Id(chain_id.to_string()))
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "near" => Ok(Chain::NEAR),
            "ethereum" | "eth" => Ok(Chain::Ethereum),
            "solana" | "sol" => Ok(Chain::Solana),
            "bitcoin" | "btc" => Ok(Chain::Bitcoin),
            "hydration" | "hyd" => Ok(Chain::Hydration),
            "canton" | "ctn" => Ok(Chain::Canton),
            "midnight" => Ok(Chain::Midnight),
            other => Err(format!("unknown or unsupported chain {other}")),
        }
    }
}
