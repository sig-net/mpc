# Threshold Signatures Integration: Implementation Status

## Overview
This document describes the current implementation status of the EdDSA support migration, which enables the MPC system to support both ECDSA (via `cait-sith`) and EdDSA (via `near/threshold-signatures`) threshold signatures.

## Implementation Status

### ✅ Completed
- **Protocol Factory Pattern**: Redesigned `ThresholdSigner` trait as a protocol factory with `keygen_protocol()`, `presign_protocol()`, and `sign_protocol()` methods
- **Backend Adapters**: Implemented `CaitSithAdapter` and `NearThresholdSigner` using the unified protocol interface
- **Protocol Abstraction**: Created `ThresholdProtocol` trait and `CaitSithProtocolWrapper` for cross-backend compatibility
- **Feature Flags**: Added `near-threshold-signatures` feature flag for gradual migration
- **CI/CD Updates**: Updated GitHub Actions to test both backend configurations
- **Migration Infrastructure**: Feature flag-based backend selection with backward compatibility

### 🔄 Current State
- **ECDSA Support**: Fully functional via `CaitSithAdapter` (default)
- **EdDSA Support**: Protocol factory implemented, but presign/sign protocols not yet fully integrated
- **Storage**: Compatible for ECDSA, EdDSA storage format needs implementation
- **Testing**: Unit tests pass for both backends, integration tests temporarily disabled pending protocol updates

## Architecture

### Protocol Factory Pattern
The new architecture uses a protocol factory pattern where backends implement:

```rust
#[async_trait]
pub trait ThresholdSigner {
    fn keygen_protocol(&self, participants: &[Participant], me: Participant, threshold: usize) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError>;
    fn presign_protocol(&self, participants: &[Participant], me: Participant, keygen_output: &[u8]) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError>;
    fn sign_protocol(&self, participants: &[Participant], me: Participant, keygen_output: &[u8], presign_output: &[u8], message: &[u8]) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError>;
}
```

### Backend Implementations
- **CaitSithAdapter**: Wraps `cait-sith` for ECDSA-only support
- **NearThresholdSigner**: Wraps `near/threshold-signatures` for ECDSA + EdDSA support
- **Protocol Wrapper**: `CaitSithProtocolWrapper` adapts cait-sith protocols to the unified interface

### Feature Flags
```toml
[features]
default = []
near-threshold-signatures = ["threshold-ts"]
```

## Compatibility Matrix

| Aspect | ECDSA (cait-sith) | EdDSA (near/threshold-signatures) | Status |
|--------|------------------|----------------------------------|--------|
| Curves | Secp256k1 ✅ | Curve25519 ✅ | Implemented |
| Key Formats | Compressed points ✅ | 32-byte keys ✅ | Implemented |
| Signature Formats | {r, s, recovery_id} ✅ | {R, s} ✅ | Implemented |
| Presignature Formats | {big_r, k, sigma} ✅ | None ❌ | TODO |
| Triple Formats | Beaver triples ✅ | None ❌ | TODO |
| Keygen Protocol | ✅ Full | ✅ Full | Implemented |
| Presign Protocol | ✅ Full | ❌ N/A | TODO |
| Sign Protocol | ✅ Full | ✅ Online-only | TODO |
| Storage | JSON/Bincode ✅ | Needs format ✅ | TODO |
| Network | P2P messaging ✅ | P2P messaging ✅ | Implemented |
| API | Protocol factory ✅ | Protocol factory ✅ | Implemented |

## Migration Strategy

### Phase 1: Infrastructure (✅ Completed)
- Protocol factory pattern implemented
- Backend adapters created
- Feature flags added
- CI/CD updated for dual testing

### Phase 2: EdDSA Protocol Integration (🔄 In Progress)
- Implement presign protocol for EdDSA (not needed - online only)
- Implement sign protocol for EdDSA
- Update storage layer for EdDSA keys/signatures
- Add EdDSA-specific tests

### Phase 3: Production Migration (📋 Planned)
- Enable feature flag in production
- Monitor performance and stability
- Gradual rollout with rollback capability
- Deprecate old direct cait-sith usage

## Usage

### Building with EdDSA Support
```bash
cargo build --features near-threshold-signatures
```

### Configuration
The backend is selected via feature flags at compile time. The `near-threshold-signatures` feature enables the new backend with both ECDSA and EdDSA support.

### API Changes
The old `ThresholdSigner` trait with `generate_key()`, `sign()`, `verify()` methods has been replaced with the protocol factory pattern. Users should migrate to using the protocol methods for new implementations.

## Security Considerations
- **Backward Compatibility**: Existing ECDSA functionality unchanged
- **Key Security**: Both backends use audited cryptographic libraries
- **Network Security**: Same P2P messaging framework used
- **Storage Security**: EdDSA keys require secure storage implementation

## Next Steps
1. Complete EdDSA protocol integration (presign/sign)
2. Implement EdDSA storage format
3. Add comprehensive EdDSA tests
4. Update integration tests for new API
5. Performance benchmarking
6. Production deployment plan</content>
<parameter name="filePath">/home/ubuntu/space/mpc14/doc/threshold_signatures_compatibility.md