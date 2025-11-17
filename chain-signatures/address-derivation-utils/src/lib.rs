pub mod types;

use crate::types::ScalarExt;
use alloy_primitives::Address;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::AffinePoint;
use k256::Scalar;
use sha3::{Digest, Keccak256};

pub type PublicKey = <k256::Secp256k1 as k256::elliptic_curve::CurveArithmetic>::AffinePoint;

// Constant prefix that ensures epsilon derivation values are used specifically for
// Sig.Network with key derivation protocol vX.Y.Z.
const EPSILON_DERIVATION_PREFIX_V1: &str = "sig.network v1.0.0 epsilon derivation";
const EPSILON_DERIVATION_PREFIX_V2: &str = "sig.network v2.0.0 epsilon derivation";

#[derive(Debug, Clone, Copy)]
pub enum Chain {
    Near,
    Ethereum,
    Solana,
    Bitcoin,
}

impl Chain {
    pub fn deprecated_chain_id(&self) -> &str {
        match self {
            Chain::Near => "0x18d",
            Chain::Ethereum => "0x1",
            Chain::Solana => "0x800001f5",
            Chain::Bitcoin => "bip122:000000000019d6689c085ae165831e93",
        }
    }

    pub fn caip2_chain_id(&self) -> &str {
        match self {
            Chain::Near => "near:mainnet",
            Chain::Ethereum => "eip155:1",
            Chain::Solana => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            Chain::Bitcoin => "bip122:000000000019d6689c085ae165831e93",
        }
    }
}

/// Creates a derivation path string using the legacy format
fn deprecated_derivation_path(chain: Chain, sender: &str, path: &str) -> String {
    let chain_id = chain.deprecated_chain_id();
    format!("{EPSILON_DERIVATION_PREFIX_V1},{chain_id},{sender},{path}")
}

/// Creates a derivation path string using the extended with prefix CAIP-2 format
fn caip2_derivation_path(chain: Chain, sender: &str, derivation_path: &str) -> String {
    let chain_id = chain.caip2_chain_id();
    format!("{EPSILON_DERIVATION_PREFIX_V2}:{chain_id}:{sender}:{derivation_path}")
}

fn derivation_path(key_version: u32, chain: Chain, sender: &str, derivation_path: &str) -> String {
    match key_version {
        0 => deprecated_derivation_path(chain, sender, derivation_path),
        // Note: if the user provides a key_version that is higher than supported, we fall back to the latest supported one
        _ => caip2_derivation_path(chain, sender, derivation_path),
    }
}

fn keccak(derivation_path: impl AsRef<[u8]>) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_non_biased(hash)
}

pub fn derive_epsilon_sol(key_version: u32, sender: &str, path: &str) -> Scalar {
    let derivation_path = derivation_path(key_version, Chain::Solana, sender, path);
    keccak(derivation_path.as_bytes())
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<k256::Secp256k1 as k256::elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR
        * epsilon
        + public_key)
        .to_affine()
}

fn public_key_to_address_from_affine(user_pk: &AffinePoint) -> Address {
    // false => uncompressed (65 bytes, 0x04 || X || Y)
    let enc = user_pk.to_encoded_point(false);
    let bytes = enc.as_bytes();
    debug_assert!(!enc.is_compressed());
    debug_assert_eq!(bytes[0], 0x04);

    // keccak256 over X||Y (skip the 0x04)
    let hash: [u8; 32] = *alloy_primitives::keccak256(&bytes[1..]);
    Address::from_slice(&hash[12..]) // last 20 bytes
}

pub fn derive_user_address(mpc_pk: PublicKey, derivation_epsilon: Scalar) -> Address {
    let user_pk: AffinePoint = derive_key(mpc_pk, derivation_epsilon);
    public_key_to_address_from_affine(&user_pk)
}
