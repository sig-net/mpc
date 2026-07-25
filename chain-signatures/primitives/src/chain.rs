use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SerDeserFormat {
    Borsh,
    Abi,
}

/// Supported blockchain networks for checkpoints.
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
            // Synthetic: Midnight has no registered CAIP-2 namespace in
            // ChainAgnostic/namespaces. Must stay byte-identical to
            // MIDNIGHT_TESTNET_CHAIN_ID in @sig-net/midnight's
            // epsilon-derivation.ts, the string integrators derive keys with.
            Chain::Midnight => "midnight:testnet",
        }
    }

    pub fn checkpoint_interval(&self) -> Option<u64> {
        let (key, default) = match self {
            Chain::NEAR | Chain::Bitcoin => return None,
            Chain::Ethereum => ("CHECKPOINT_INTERVAL_ETHEREUM", 20),
            Chain::Solana => ("CHECKPOINT_INTERVAL_SOLANA", 120),
            Chain::Hydration => ("CHECKPOINT_INTERVAL_HYDRATION", 240),
            Chain::Canton => ("CHECKPOINT_INTERVAL_CANTON", 50),
            Chain::Midnight => ("CHECKPOINT_INTERVAL_MIDNIGHT", 120),
        };

        let interval = std::env::var(key)
            .map(|param| param.parse::<u64>().unwrap_or(default))
            .unwrap_or(default);

        Some(interval)
    }

    pub fn checkpoint_env_vars() -> Vec<(&'static str, &'static str)> {
        vec![
            ("CHECKPOINT_INTERVAL_ETHEREUM", "2"),
            ("CHECKPOINT_INTERVAL_SOLANA", "5"),
            ("CHECKPOINT_INTERVAL_HYDRATION", "5"),
            ("CHECKPOINT_INTERVAL_CANTON", "5"),
            ("CHECKPOINT_INTERVAL_MIDNIGHT", "120"),
        ]
    }

    pub fn expected_finality_time_secs(&self) -> u64 {
        match self {
            Chain::NEAR => 3,
            Chain::Ethereum => 30 * 60,
            Chain::Solana => 3,
            Chain::Bitcoin => 60 * 60 + 20 * 60, // 6 confirmations at 10 minutes each, plus some buffer
            Chain::Hydration => 12,
            Chain::Canton => 15,
            Chain::Midnight => 15,
        }
    }

    pub fn expected_response_time_secs(&self) -> u64 {
        // finality time * 2 = finality time of sign/sign_bidirectional event + finality time of respond event
        self.expected_finality_time_secs() * 2 + 5 // + Buffer time
    }

    pub fn respond_serialization_format(&self) -> SerDeserFormat {
        match self {
            Chain::Canton => SerDeserFormat::Abi,
            Chain::Midnight => SerDeserFormat::Abi,
            // Solana and Hydration use Borsh for bidirectional responses.
            _ => SerDeserFormat::Borsh,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midnight_enum_arms() {
        assert_eq!(Chain::Midnight as u8, 6);
        assert_eq!(Chain::Midnight.as_str(), "Midnight");
        assert_eq!(Chain::Midnight.caip2_chain_id(), "midnight:testnet");
        assert_eq!(Chain::Midnight.expected_finality_time_secs(), 15);
        assert_eq!(
            Chain::Midnight.respond_serialization_format(),
            SerDeserFormat::Abi
        );
        assert_eq!("midnight".parse::<Chain>().unwrap(), Chain::Midnight);
        assert!(Chain::iter().contains(&Chain::Midnight));
    }
}
