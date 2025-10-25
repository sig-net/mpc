# Threshold Signatures Integration: Compatibility Analysis

## Overview
This document analyzes the compatibility between the current `cait-sith` library (ECDSA-only) and the proposed `near/threshold-signatures` library (ECDSA + EdDSA support) for gradual replacement.

## Current State (cait-sith)
- **Algorithm**: Threshold ECDSA only
- **Curve**: Secp256k1
- **Key Types**:
  - Public: `PublicKey` (compressed secp256k1 point)
  - Private Shares: `SecretKeyShare` (scalar)
- **Signature Types**:
  - `FullSignature<Secp256k1>`: { r, s, v (recovery id) }
- **Presignature Types**:
  - `PresignOutput<Secp256k1>`: { big_r (point), k (scalar), sigma (scalar) }
- **Triple Types**:
  - `TriplePub`: commitments to triples
  - `TripleShare`: shares of triples
- **Protocols**:
  - Keygen, Reshare, Triple Gen, Presign, Sign
- **Storage**: Redis-backed, serializes above types as JSON/Bincode
- **Network**: P2P messaging via `MessageData`, participant-based

## Target State (near/threshold-signatures)
- **Algorithms**: Threshold ECDSA + Threshold EdDSA
- **Curves**: Secp256k1 (ECDSA), Curve25519 (EdDSA)
- **Key Types** (ECDSA):
  - Compatible with cait-sith (same curve, similar formats)
- **Key Types** (EdDSA):
  - Public: Ed25519 public key (32 bytes)
  - Private Shares: Distributed via DKG
- **Signature Types** (ECDSA):
  - Compatible: { r, s, recovery_id }
- **Signature Types** (EdDSA):
  - Ed25519: { R (point), s (scalar) }
- **Presignature Types** (ECDSA):
  - Compatible: Similar structure (big_r, k, sigma)
- **Presignature Types** (EdDSA):
  - None (no offline presigning phase)
- **Triple Types** (ECDSA):
  - Compatible: Beaver triples for multiplication
- **Triple Types** (EdDSA):
  - None (not needed)
- **Protocols**:
  - DKG/Reshare: Unified for both curves
  - Triple Gen/Presign: ECDSA only
  - Sign: Both, but EdDSA is online-only
- **Storage**: Likely similar serialization, but EdDSA keys/signatures different format
- **Network**: Similar participant-based P2P

## Compatibility Matrix

| Aspect | ECDSA Compatibility | EdDSA Compatibility | Notes |
|--------|---------------------|---------------------|-------|
| Curves | ✅ Full | ❌ N/A | EdDSA uses Curve25519 |
| Key Formats | ✅ Full | ❌ Different | EdDSA keys are 32-byte vs secp256k1 points |
| Signature Formats | ✅ Full | ❌ Different | EdDSA is (R,s) vs ECDSA (r,s,v) |
| Presignature Formats | ✅ Full | ❌ None | EdDSA doesn't use presignatures |
| Triple Formats | ✅ Full | ❌ None | EdDSA doesn't use triples |
| Protocols (Keygen/Reshare) | ✅ Full | ✅ Full | Unified DKG |
| Protocols (Sign) | ✅ Full | ✅ Full | But EdDSA online-only |
| Storage Serialization | ✅ Full (ECDSA) | ❌ Partial | Need new storage for EdDSA keys/sigs |
| Network Messages | ✅ Full | ✅ Full | Same participant framework |
| API Surface | ✅ Similar | ❌ Extended | New EdDSA APIs |

## Breaking Changes Anticipated
- **Storage**: EdDSA keys/signatures require new Redis keys/tables or format versioning
- **Presignature Logic**: EdDSA signing bypasses presignature phase entirely
- **Triple Logic**: EdDSA doesn't generate/use triples
- **Verification**: EdDSA signatures verified differently (no recovery id)
- **Chain Support**: EdDSA only usable on chains supporting Ed25519 (e.g., NEAR, Solana)

## Recommended Adapter Interfaces
- **Signing Trait**: `ThresholdSigner` with methods for keygen, sign, verify, supporting both curves
- **Storage Abstraction**: `KeyStorage`, `SignatureStorage` with curve-agnostic APIs but curve-specific impls
- **Protocol Runner**: Unified runner that dispatches to ECDSA or EdDSA backends based on key type
- **Migration Path**: Feature flag per-key to choose backend, with conversion scripts for storage

## Next Steps
1. Design the `ThresholdSigner` trait in `chain-signatures/node`
2. Prototype wrapper crate for `near/threshold-signatures`
3. Implement adapter layer mimicking cait-sith API
4. Add component tests comparing outputs
5. Plan storage migration for EdDSA</content>
<parameter name="filePath">/home/ubuntu/space/mpc14/doc/threshold_signatures_compatibility.md