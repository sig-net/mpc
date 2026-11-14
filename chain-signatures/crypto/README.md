# mpc-crypto

Internal, node-side cryptography for the MPC network. **Not published.**

If you are building a client against the network, you almost certainly want
[`signet-crypto`](../../signet-crypto) instead — that is the small, published crate
of key-derivation and signature-reconstruction primitives (epsilon derivation,
derived-key computation, reconstruction of a signature from its components)
that produce keys and request identifiers matching the network.

The derivation helpers are re-exported from `signet-crypto`; signature
reconstruction lives there too and callers use it from `signet-crypto`
directly. On top, this crate adds node-only cryptography: signature
verification and recovery (including the wasm NEAR ecrecover path), secret-key
derivation, and checkpoint and delta derivation.
