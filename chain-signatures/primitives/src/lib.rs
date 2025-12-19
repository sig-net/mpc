pub mod bytes;

use k256::{AffinePoint, Scalar};
use near_account_id::AccountId;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use sha3::Digest;
use std::{fmt, str::FromStr};

use crate::bytes::cbor_scalar;

pub const LATEST_MPC_KEY_VERSION: u32 = 1;
pub const LEGACY_MPC_KEY_VERSION_0: u32 = 0;

#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[borsh(crate = "near_sdk::borsh")]
pub struct SignId {
    #[serde(with = "serde_bytes")]
    pub request_id: [u8; 32],
}

impl std::fmt::Debug for SignId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SignId")
            .field(&hex::encode(self.request_id))
            .finish()
    }
}

impl SignId {
    pub fn new(request_id: [u8; 32]) -> Self {
        Self { request_id }
    }

    pub fn from_parts(id: &AccountId, payload: &[u8; 32], path: &str, key_version: u32) -> Self {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(id.as_bytes());
        hasher.update(payload);
        hasher.update(path.as_bytes());
        hasher.update(key_version.to_le_bytes());
        let request_id: [u8; 32] = hasher.finalize().into();
        Self { request_id }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SignArgs {
    #[serde(with = "serde_bytes")]
    pub entropy: [u8; 32],
    #[serde(with = "cbor_scalar")]
    pub epsilon: Scalar,
    #[serde(with = "cbor_scalar")]
    pub payload: Scalar,
    pub path: String,
    pub key_version: u32,
}

impl std::fmt::Debug for SignArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignArgs")
            .field("entropy", &hex::encode(self.entropy))
            .field("epsilon", &self.epsilon)
            .field("payload", &self.payload)
            .field("path", &self.path)
            .field("key_version", &self.key_version)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Signature {
    #[borsh(
        serialize_with = "bytes::borsh_affine_point::serialize",
        deserialize_with = "bytes::borsh_affine_point::deserialize_reader"
    )]
    pub big_r: AffinePoint,
    #[borsh(
        serialize_with = "bytes::borsh_scalar::serialize",
        deserialize_with = "bytes::borsh_scalar::deserialize_reader"
    )]
    pub s: Scalar,
    pub recovery_id: u8,
}

impl Signature {
    pub fn new(big_r: AffinePoint, s: Scalar, recovery_id: u8) -> Self {
        Signature {
            big_r,
            s,
            recovery_id,
        }
    }
}

/// Supported blockchain networks for checkpoints.
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
)]
#[borsh(crate = "near_sdk::borsh")]
pub enum Chain {
    NEAR,
    Ethereum,
    Solana,
    Hydration,
}

impl Chain {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Chain::NEAR => "NEAR",
            Chain::Ethereum => "Ethereum",
            Chain::Solana => "Solana",
            Chain::Hydration => "Hydration",
        }
    }

    pub const fn iter() -> [Chain; 4] {
        [
            Chain::NEAR,
            Chain::Ethereum,
            Chain::Solana,
            Chain::Hydration,
        ]
    }

    pub fn checkpoint_interval(&self) -> Option<u64> {
        let (key, default) = match self {
            Chain::NEAR => return None,
            Chain::Ethereum => ("CHECKPOINT_INTERVAL_ETHEREUM", 20),
            Chain::Solana => ("CHECKPOINT_INTERVAL_SOLANA", 120),
            Chain::Hydration => ("CHECKPOINT_INTERVAL_HYDRATION", 240),
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
        ]
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
            "hydration" | "hyd" => Ok(Chain::Hydration),
            other => Err(format!("unknown or unsupported chain {other}")),
        }
    }
}

/// Transaction information tracked across checkpoints.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[borsh(crate = "near_sdk::borsh")]
pub struct PendingTx {
    pub sign_id: SignId,
    #[serde(with = "serde_bytes")]
    pub transaction: Vec<u8>,
}

impl fmt::Debug for PendingTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTx")
            .field("sign_id", &self.sign_id)
            .finish()
    }
}

/// A checkpoint represents the backlog state at a specific block height.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Checkpoint {
    pub chain: Chain,
    pub block_height: u64,
    pub pending_requests: Vec<PendingTx>,
}

impl Checkpoint {
    pub fn empty(chain: Chain) -> Self {
        Self {
            chain,
            block_height: 0,
            pending_requests: Vec::new(),
        }
    }
}
