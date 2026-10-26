//! Shared hex-encoding conventions for Tron wire data.

use anyhow::Context as _;

/// Tron hex strings tolerate a `0x` prefix.
pub fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// Decodes a Tron hex string (`0x` optional).
pub fn decode_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    hex::decode(strip_0x(s)).with_context(|| format!("decoding hex bytes {s}"))
}
