#!/usr/bin/env bash
set -euo pipefail

# Search the repo for potentially unsafe ed25519 calls (Keypair serialization, from_bytes, raw sign)
echo "Searching for ed25519-dalek Keypair/Signing usage..."
rg "(Keypair::from_bytes|to_bytes\(|raw_sign|from_bytes_unchecked|ExpandedSecretKey|hazmat|SigningKey::|VerifyingKey::)" --hidden --glob '!target' || true

echo "Search complete. Review results for unsafe APIs or 64-byte Keypair serializations."
