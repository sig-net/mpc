//! The funding wallet's keys: BIP-32 derivation and seed parsing.
//!
//! The master key is derived by hand over HMAC-SHA512 rather than with
//! `bip32::XPrv::new`, which only accepts 16, 32 or 64 byte seeds, so every seed
//! length `crate::config::validate_funding_seed` allows derives like the wallet
//! SDK's.

use anyhow::Context as _;
use midnight_ledger_v9::dust::{DustPublicKey, DustSecretKey};
use sha2::Digest as _;

/// The DUST key of account 0 at index 0, derived the way the Midnight wallet SDK
/// derives it from the same seed: BIP-32 `m/44'/2400'/0'/2/0`, then the ledger's
/// `DustSecretKey::derive_secret_key` over that private key.
pub(crate) fn dust_secret_key(seed: &[u8]) -> anyhow::Result<DustSecretKey> {
    let path: bip32::DerivationPath = "m/44'/2400'/0'/2/0"
        .parse()
        .expect("the DUST role path is a valid derivation path");
    let role = path
        .iter()
        .try_fold(master_key(seed)?, |key, child| key.derive_child(child))
        .map_err(|error| anyhow::anyhow!("deriving the funding wallet's DUST role key: {error}"))?;
    Ok(DustSecretKey::derive_secret_key(&role.to_bytes()))
}

/// The BIP-32 master key. `bip32::XPrv::new` takes only 16, 32 or 64 byte seeds, but
/// BIP-32 itself, the wallet SDK and `crate::config::validate_funding_seed` allow any
/// length from 16 to 64.
fn master_key(seed: &[u8]) -> anyhow::Result<bip32::XPrv> {
    use hmac::Mac as _;
    let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(b"Bitcoin seed")
        .expect("HMAC takes a key of any length");
    mac.update(seed);
    let digest = mac.finalize().into_bytes();
    let (key, chain_code) = digest.split_at(32);
    let mut key_bytes = [0u8; 33];
    key_bytes[1..].copy_from_slice(key);
    bip32::XPrv::try_from(bip32::ExtendedKey {
        prefix: bip32::Prefix::XPRV,
        attrs: bip32::ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: bip32::ChildNumber::default(),
            chain_code: chain_code.try_into().expect("HMAC-SHA512 is 64 bytes"),
        },
        key_bytes,
    })
    .map_err(|error| anyhow::anyhow!("deriving the funding wallet's master key: {error}"))
}

/// Hex seed bytes, with or without `0x`, of any length — the length check is
/// `crate::config::validate_funding_seed`'s.
pub(crate) fn parse_seed(seed: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = seed.trim();
    let bare = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    hex::decode(bare).context("the funding seed is not hex")
}

/// Which funding key a checkpoint belongs to: the hash of the key's public key,
/// matching `Checkpoint::owner` in `super::checkpoint`.
pub(crate) fn owner_of(key: &DustSecretKey) -> [u8; 32] {
    let public = DustPublicKey::from(key.clone());
    let mut bytes = Vec::new();
    midnight_serialize::tagged_serialize(&public, &mut bytes)
        .expect("serializing into a Vec cannot fail");
    sha2::Sha256::digest(&bytes).into()
}
