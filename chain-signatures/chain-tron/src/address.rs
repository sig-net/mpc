//! Address forms at the Tron boundary: 21-byte `0x41 ‖ eth20` base58check
//! (`T…`) at the wallet/RPC boundary, plain 20-byte EVM inside the TVM.

use std::fmt;
use std::str::FromStr;

use alloy::primitives::Address;
use anyhow::{anyhow, Context};
use sha2::{Digest, Sha256};

/// Byte prepended to the 20-byte EVM form on Tron mainnet.
pub const TRON_ADDRESS_PREFIX: u8 = 0x41;

/// A Tron address: 21 bytes, `0x41 ‖ eth20`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TronAddress([u8; 21]);

impl TronAddress {
    pub fn from_evm(address: Address) -> Self {
        let mut bytes = [0u8; 21];
        bytes[0] = TRON_ADDRESS_PREFIX;
        bytes[1..].copy_from_slice(address.as_slice());
        Self(bytes)
    }

    pub fn to_evm(self) -> Address {
        Address::from_slice(&self.0[1..])
    }

    pub fn as_bytes(&self) -> &[u8; 21] {
        &self.0
    }
}

impl From<Address> for TronAddress {
    fn from(address: Address) -> Self {
        Self::from_evm(address)
    }
}

impl From<TronAddress> for Address {
    fn from(address: TronAddress) -> Self {
        address.to_evm()
    }
}

impl fmt::Display for TronAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base58check())
    }
}

impl fmt::Debug for TronAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TronAddress({})", self.base58check())
    }
}

impl FromStr for TronAddress {
    type Err = ParseTronAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(ParseTronAddressError::Base58)?;
        if decoded.len() != 25 {
            return Err(ParseTronAddressError::Length(decoded.len()));
        }
        let (payload, checksum) = decoded.split_at(21);
        if checksum != base58check_checksum(payload) {
            return Err(ParseTronAddressError::Checksum);
        }
        let mut bytes = [0u8; 21];
        bytes.copy_from_slice(payload);
        if bytes[0] != TRON_ADDRESS_PREFIX {
            return Err(ParseTronAddressError::Prefix(bytes[0]));
        }
        Ok(Self(bytes))
    }
}

/// Tron address parsing errors.
#[derive(Debug, thiserror::Error)]
pub enum ParseTronAddressError {
    #[error("invalid base58: {0}")]
    Base58(#[from] bs58::decode::Error),
    #[error("expected 25 bytes (21 payload + 4 checksum), got {0}")]
    Length(usize),
    #[error("base58check checksum mismatch")]
    Checksum,
    #[error("expected 0x41 address prefix, got {0:#04x}")]
    Prefix(u8),
}

/// Parses a hex address as emitted in Tron JSON: either the plain 20-byte
/// EVM form or the 21-byte `0x41`-prefixed wallet form.
pub fn parse_hex(s: &str) -> anyhow::Result<Address> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s))
    .with_context(|| format!("decoding hex address {s}"))?;
match bytes.len() {
    20 => Ok(Address::from_slice(&bytes)),
    21 if bytes[0] == TRON_ADDRESS_PREFIX => Ok(Address::from_slice(&bytes[1..])),
    _ => Err(anyhow!(
        "hex address must be 20 bytes or 0x41-prefixed 21 bytes, got {} bytes",
        bytes.len()
    )),
}
}

/// Computes the base58check checksum for a given payload.
fn base58check_checksum(payload: &[u8]) -> [u8; 4] {
    let h = Sha256::digest(Sha256::digest(payload));
    [h[0], h[1], h[2], h[3]]
}

impl TronAddress {
    /// Returns the base58check-encoded representation of the Tron address.
    fn base58check(&self) -> String {
        let checksum = base58check_checksum(&self.0);
        let mut buf = [0u8; 25];
        buf[..21].copy_from_slice(&self.0);
        buf[21..].copy_from_slice(&checksum);
        bs58::encode(buf).into_string()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// Live mainnet vectors: the USDT TRC-20 contract and the all-zero
    /// burn ("blackhole") address.
    #[test]
    fn known_vectors() {
        let usdt: TronAddress = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".parse().unwrap();
        assert_eq!(
            hex::encode(usdt.as_bytes()),
            "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
        );
        assert_eq!(
            usdt.to_evm(),
            Address::from_slice(&hex::decode("a614f803b6fd780986a42c78ec9c7f77e6ded13c").unwrap())
        );
        assert_eq!(usdt.to_string(), "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");

        let blackhole: TronAddress = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb".parse().unwrap();
        assert_eq!(&blackhole.as_bytes()[1..], &[0u8; 20]);
        assert_eq!(blackhole.to_string(), "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb");
    }

    #[test]
    fn round_trips() {
        let mut seen = HashSet::new();
        for seed in 1u8..=5 {
            let mut raw = [0u8; 20];
            raw[..4].copy_from_slice(&u32::from(seed).to_be_bytes());
            raw[19] = seed;
            let evm = Address::from(raw);
            let tron = TronAddress::from_evm(evm);
            assert_eq!(tron.as_bytes()[0], TRON_ADDRESS_PREFIX);
            assert_eq!(tron.to_evm(), evm);
            assert_eq!(Address::from(tron), evm);

            let s = tron.to_string();
            seen.insert(s.clone());
            assert_eq!(s.parse::<TronAddress>().unwrap(), tron);
        }
        assert_eq!(seen.len(), 5, "distinct addresses must encode distinctly");
    }

    #[test]
    fn rejects_corrupted_input() {
        // String-level mutation: the embedded checksum no longer matches.
        let err = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u"
            .parse::<TronAddress>()
            .unwrap_err();
        assert!(matches!(err, ParseTronAddressError::Checksum));

        // Not a Tron address: version byte 0x00 (bitcoin p2pkh shape).
        let btc = {
            let mut buf = [0u8; 25];
            buf[0] = 0x00;
            let checksum = base58check_checksum(&buf[..21]);
            buf[21..].copy_from_slice(&checksum);
            bs58::encode(buf).into_string()
        };
        let err = btc.parse::<TronAddress>().unwrap_err();
        assert!(matches!(err, ParseTronAddressError::Prefix(0x00)));

        let err = "".parse::<TronAddress>().unwrap_err();
        assert!(matches!(err, ParseTronAddressError::Length(0)));

        // 0, O, I, l are excluded from the base58 alphabet.
        let err = "0OIl".parse::<TronAddress>().unwrap_err();
        assert!(matches!(err, ParseTronAddressError::Base58(_)));
    }

    #[test]
    fn hex_forms_normalize_to_evm() {
        let usdt = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
            .parse::<TronAddress>()
            .unwrap();
        let evm = usdt.to_evm();
        assert_eq!(
            parse_hex("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").unwrap(),
            evm
        );
        assert_eq!(
            parse_hex("a614f803b6fd780986a42c78ec9c7f77e6ded13c").unwrap(),
            evm
        );
        assert_eq!(
            parse_hex("0xa614f803b6fd780986a42c78ec9c7f77e6ded13c").unwrap(),
            evm
        );
        assert!(parse_hex("a614f803b6fd78098").is_err());
    }
}
