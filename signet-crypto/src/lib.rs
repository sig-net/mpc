//! Key-derivation and signature-reconstruction primitives shared between the
//! MPC network and its clients.
//!
//! Everything here is a pure function of its inputs — the epsilon derivation
//! scheme, derived-key computation, and reconstruction of a signature from its
//! secp256k1 components. Clients compiling against this crate stay
//! wire-correct by construction. Node-only helpers (secret-key derivation, NEAR
//! account-id wrappers, checkpoint derivation, recovery on wasm) live in
//! `mpc-crypto`.

mod kdf;

pub use kdf::{
    derive_epsilon, derive_key, reconstruct_signature, x_coordinate, DeriveError, KeyPurpose,
};
pub use signet_primitives::{KeyVersion, PublicKey, ScalarExt};
