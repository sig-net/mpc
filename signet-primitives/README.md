# signet-primitives

Interface types for the SigNet network. Signing types, signatures, supported chains, etc.

These are the exact types the on-chain contracts deserialize, so clients
compiling against this crate are wire-correct by construction.

```rust
use signet_primitives::{Chain, SignId, Signature, LATEST_MPC_KEY_VERSION};

let sign_id = SignId::from_parts(requester, &payload, path, LATEST_MPC_KEY_VERSION);
```
