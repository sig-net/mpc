# signet-crypto

Key-derivation primitives for the SigNet network: epsilon derivation,
derived-key computation, and signature reconstruction from secp256k1
components (`reconstruct_signature`, `x_coordinate`).

These are the exact algorithms the MPC network uses, so a client compiling
against this crate derives keys and request identifiers that match the network
by construction.

```rust
use signet_crypto::{derive_epsilon_eth, derive_key, RequestPurpose};
use signet_primitives::LATEST_MPC_KEY_VERSION;

// The purpose is the signing API the request is made on. Fails for a key
// version the network does not know.
let epsilon = derive_epsilon_eth(LATEST_MPC_KEY_VERSION, RequestPurpose::Plain, "0xabc…", "my/path")?;
let user_key = derive_key(root_public_key, epsilon);
```
