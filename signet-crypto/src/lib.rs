//! Key-derivation primitives shared between the MPC network and its clients.
//!
//! Everything here is a pure function of its inputs — the epsilon derivation
//! scheme and derived-key computation the network uses. Clients compiling
//! against this crate stay wire-correct by construction. Node-only helpers
//! (secret-key derivation, NEAR account-id wrappers, checkpoint derivation,
//! signature recovery on wasm) live in `mpc-crypto`.

mod kdf;

pub use kdf::{
    derive_epsilon, derive_epsilon_bitcoin, derive_epsilon_canton, derive_epsilon_eth,
    derive_epsilon_hydration, derive_epsilon_midnight, derive_epsilon_sol, derive_key,
    DerivationParams, EPSILON_DERIVATION_PREFIX_V1, EPSILON_DERIVATION_PREFIX_V2,
};
pub use signet_primitives::{PublicKey, ScalarExt};

pub type KeyVersion = u32;
pub type Address = String;
pub type Path = String;
pub type Purpose = String;
