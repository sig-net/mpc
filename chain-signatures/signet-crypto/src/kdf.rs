use crate::{Address, KeyVersion, Path, Purpose};
use k256::{elliptic_curve::CurveArithmetic, Scalar, Secp256k1};
use signet_primitives::{Chain, PublicKey, ScalarExt};
use sha3::{Digest, Keccak256, Sha3_256};

// Constant prefix that ensures epsilon derivation values are used specifically for
// Sig.Network with key derivation protocol vX.Y.Z.
pub const EPSILON_DERIVATION_PREFIX_V1: &str = "sig.network v1.0.0 epsilon derivation";
pub const EPSILON_DERIVATION_PREFIX_V2: &str = "sig.network v2.0.0 epsilon derivation";

const CHECKPOINT_SENDER: &str = "checkpoint|sender";

pub enum DerivationParams {
    /// Account owned by a user on a specific chain.
    UserAccount(KeyVersion, Chain, Address, Path),
    /// Account owned by MPC system on a specific chain.
    SystemAccount(KeyVersion, Chain, Path),
    /// Key used for system purposes.
    SystemKey(Purpose),
    /// Checkpoint for consensus of a given chain and block height.
    ConsensusCheckpoint(Chain, u64),
}

impl DerivationParams {
    pub fn derivation_path(&self) -> String {
        match self {
            DerivationParams::UserAccount(key_version, chain, owner, path) => match key_version {
                0 => deprecated_derivation_path(*chain, owner, path),
                _ => caip2_derivation_path(*chain, owner, path),
            },
            DerivationParams::SystemAccount(key_version, chain, path) => {
                let sender = "%admin#";
                match key_version {
                    0 => deprecated_derivation_path(*chain, sender, path),
                    _ => caip2_derivation_path(*chain, sender, path),
                }
            }
            DerivationParams::SystemKey(purpose) => {
                // key version and other parameters are not relevant for system keys
                format!("{EPSILON_DERIVATION_PREFIX_V2}:system_key:{purpose}")
            }
            DerivationParams::ConsensusCheckpoint(chain, height) => {
                caip2_derivation_path(*chain, CHECKPOINT_SENDER, &height.to_string())
            }
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

fn sha3(derivation_path: impl AsRef<[u8]>) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_non_biased(hash)
}

fn keccak(derivation_path: impl AsRef<[u8]>) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_non_biased(hash)
}

pub fn derive_epsilon(params: &DerivationParams) -> Scalar {
    let derivation_path = params.derivation_path();
    match params {
        DerivationParams::UserAccount(_, Chain::NEAR, _, _)
        | DerivationParams::SystemAccount(_, Chain::NEAR, _)
        | DerivationParams::ConsensusCheckpoint(_, _) => sha3(derivation_path),
        _ => keccak(derivation_path),
    }
}

pub fn derive_epsilon_eth(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Ethereum,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_epsilon_sol(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Solana,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_epsilon_canton(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Canton,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_epsilon_hydration(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Hydration,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_epsilon_bitcoin(key_version: KeyVersion, address: &str, path: &str) -> Scalar {
    derive_epsilon(&DerivationParams::UserAccount(
        key_version,
        Chain::Bitcoin,
        address.to_string(),
        path.to_string(),
    ))
}

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * epsilon + public_key).to_affine()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation_path_stays_the_same() {
        assert_eq!(
            DerivationParams::UserAccount(
                0,
                Chain::Ethereum,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,0x1,sender,path"
        );
        assert_eq!(
            DerivationParams::UserAccount(
                1,
                Chain::Ethereum,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:eip155:1:sender:path"
        );

        assert_eq!(
            DerivationParams::UserAccount(
                0,
                Chain::Solana,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,0x800001f5,sender,path"
        );
        assert_eq!(
            DerivationParams::UserAccount(1, Chain::Solana, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:sender:path"
        );

        assert_eq!(
            DerivationParams::UserAccount(0, Chain::NEAR, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,0x18d,sender,path"
        );

        assert_eq!(
            DerivationParams::UserAccount(1, Chain::NEAR, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:near:mainnet:sender:path"
        );

        assert_eq!(
            DerivationParams::UserAccount(0, Chain::Bitcoin, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,bip122:000000000019d6689c085ae165831e93,sender,path"
        );
        assert_eq!(
            DerivationParams::UserAccount(1, Chain::Bitcoin, "sender".to_string(), "path".to_string())
                .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:bip122:000000000019d6689c085ae165831e93:sender:path"
        );

        assert_eq!(
            DerivationParams::UserAccount(
                0,
                Chain::Canton,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v1.0.0 epsilon derivation,canton:global,sender,path"
        );
        assert_eq!(
            DerivationParams::UserAccount(
                1,
                Chain::Canton,
                "sender".to_string(),
                "path".to_string()
            )
            .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:canton:global:sender:path"
        );

        assert_eq!(
            DerivationParams::SystemAccount(1, Chain::Ethereum, "path".to_string())
                .derivation_path(),
            "sig.network v2.0.0 epsilon derivation:eip155:1:%admin#:path"
        );
    }

    #[test]
    fn test_derive_epsilon_stays_the_same() {
        // Expected scalar values for Ethereum epsilon derivation
        let expected_eth_v0 = Scalar::from_bytes([
            0x8F, 0x2A, 0x2D, 0xCC, 0x32, 0xB3, 0x35, 0xE1, 0x21, 0x40, 0x4D, 0xE8, 0x43, 0x6E,
            0xD8, 0x95, 0x83, 0xD5, 0xA6, 0x39, 0x70, 0xA6, 0x1A, 0x23, 0xD9, 0x78, 0xAC, 0x12,
            0x5B, 0xF2, 0x00, 0x69,
        ])
        .unwrap();

        let expected_eth_v1 = Scalar::from_bytes([
            0x51, 0x8D, 0x99, 0xF3, 0x4A, 0x18, 0x27, 0xA5, 0x9E, 0xD2, 0xA8, 0xC6, 0xB7, 0x00,
            0x3C, 0xF4, 0x24, 0x6C, 0x6E, 0xCA, 0x82, 0xE8, 0x4B, 0xFB, 0x40, 0xC4, 0x7D, 0xD8,
            0xD1, 0xA1, 0xD4, 0x2F,
        ])
        .unwrap();

        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                0,
                Chain::Ethereum,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_eth_v0
        );
        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                1,
                Chain::Ethereum,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_eth_v1
        );

        // Expected scalar values for Solana epsilon derivation
        let expected_sol_v0 = Scalar::from_bytes([
            0x61, 0xDD, 0xCA, 0xFF, 0x12, 0xF1, 0x29, 0xBB, 0x47, 0x3C, 0xFB, 0x26, 0x8A, 0x01,
            0x9C, 0x7D, 0x2F, 0xDD, 0xF2, 0x65, 0xF1, 0xD9, 0x5A, 0xC5, 0xAD, 0x65, 0x4E, 0x27,
            0x9B, 0xA3, 0x39, 0x92,
        ])
        .unwrap();

        let expected_sol_v1 = Scalar::from_bytes([
            0xF1, 0x83, 0x50, 0x69, 0xD5, 0x52, 0x22, 0xD0, 0x08, 0xB3, 0x07, 0x39, 0x81, 0x98,
            0x85, 0x00, 0xAB, 0x7C, 0xE2, 0x96, 0x88, 0x43, 0xE7, 0x1A, 0xD9, 0x38, 0x8B, 0xF8,
            0xFA, 0x93, 0xFF, 0x9E,
        ])
        .unwrap();

        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                0,
                Chain::Solana,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_sol_v0
        );
        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                1,
                Chain::Solana,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_sol_v1
        );

        // Expected scalar values for NEAR epsilon derivation
        let expected_near_v0 = Scalar::from_bytes([
            0x0E, 0x32, 0x6D, 0x79, 0x76, 0x3A, 0xEE, 0xC1, 0x9F, 0x16, 0x6A, 0xE1, 0xC4, 0x6B,
            0x08, 0x65, 0x29, 0xC9, 0x40, 0x21, 0xC3, 0x6E, 0xD6, 0xFF, 0x4C, 0xF2, 0x2C, 0xD7,
            0xF4, 0xE6, 0x5A, 0x97,
        ])
        .unwrap();

        let expected_near_v1 = Scalar::from_bytes([
            0xFD, 0xFD, 0xB2, 0x01, 0x7F, 0x43, 0xB6, 0x8B, 0x2C, 0xC9, 0x8F, 0x6B, 0x4F, 0x87,
            0x55, 0x4C, 0xE3, 0x2C, 0xC7, 0x13, 0xE5, 0xC3, 0xFF, 0x33, 0x70, 0x34, 0x93, 0x94,
            0xD9, 0xF7, 0x1E, 0x4B,
        ])
        .unwrap();

        // Test NEAR epsilon derivation
        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                0,
                Chain::NEAR,
                "sender.near".to_string(),
                "path".to_string()
            )),
            expected_near_v0
        );
        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                1,
                Chain::NEAR,
                "sender.near".to_string(),
                "path".to_string()
            )),
            expected_near_v1
        );
    }

    #[test]
    fn test_derive_epsilon_canton_stays_the_same() {
        let expected_canton_v0 = Scalar::from_bytes([
            0xA4, 0xCF, 0xD1, 0x98, 0x07, 0xD1, 0x96, 0x8D, 0xAA, 0xDA, 0x88, 0xB5, 0xB8, 0x12,
            0xAD, 0x61, 0xC6, 0x24, 0x08, 0xB4, 0x84, 0xB5, 0x51, 0xFC, 0x37, 0x30, 0x34, 0x51,
            0x03, 0x14, 0x61, 0x4C,
        ])
        .unwrap();

        let expected_canton_v1 = Scalar::from_bytes([
            0x49, 0x05, 0x93, 0xA1, 0x00, 0xEA, 0xE1, 0x26, 0x98, 0x8F, 0x3B, 0xA4, 0xEC, 0x3A,
            0xBD, 0x75, 0x4C, 0xD2, 0x4C, 0xD9, 0xA6, 0x6B, 0x14, 0x71, 0x27, 0x6A, 0x1B, 0xC3,
            0xE3, 0x10, 0xCA, 0xBD,
        ])
        .unwrap();

        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                0,
                Chain::Canton,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_canton_v0
        );
        assert_eq!(
            derive_epsilon(&DerivationParams::UserAccount(
                1,
                Chain::Canton,
                "sender".to_string(),
                "path".to_string()
            )),
            expected_canton_v1
        );
    }

    #[test]
    fn test_derive_epsilon_checkpoint() {
        let p = DerivationParams::SystemKey("checkpoint".to_string()).derivation_path();
        assert_eq!(
            p,
            "sig.network v2.0.0 epsilon derivation:system_key:checkpoint"
        );
    }
}
