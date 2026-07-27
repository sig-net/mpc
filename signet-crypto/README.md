# signet-crypto

Key-derivation primitives for the SigNet network: epsilon derivation and
derived-key computation.

These are the exact algorithms the MPC network uses, so a client compiling
against this crate derives keys and request identifiers that match the network
by construction.

```rust
use signet_crypto::{derive_epsilon_eth, derive_key};
use signet_primitives::LATEST_MPC_KEY_VERSION;

let epsilon = derive_epsilon_eth(LATEST_MPC_KEY_VERSION, "0xabc…", "my/path");
let user_key = derive_key(root_public_key, epsilon);
```
