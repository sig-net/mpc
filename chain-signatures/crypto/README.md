# mpc-crypto

Internal, node-side cryptography for the MPC network. **Not published.**

If you are building a client against the network, you almost certainly want
[`signet-crypto`](../signet-crypto) instead — that is the small, published crate
of key-derivation primitives (epsilon derivation and derived-key computation)
that produce keys and request identifiers matching the network.

This crate re-exports `signet-crypto` and adds node-only cryptography on top:
signature verification and recovery, secret-key derivation, and checkpoint and
delta derivation.
