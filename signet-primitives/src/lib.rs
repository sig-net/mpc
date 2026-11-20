//! Public interface types shared between the MPC contracts and their clients.
//!
//! Everything in this crate is part of the on-chain interface: the contracts
//! deserialize these exact types, so clients compiling against this crate are
//! wire-correct by construction. Node-internal types live in `mpc-primitives`.

mod bidirectional;
mod chain;
mod crypto;
mod requests;

pub use bidirectional::{BidirectionalTxId, RespondBidirectionalSerializedOutput};
pub use chain::{Chain, ChainFromError};
pub use crypto::{borsh_scalar, PublicKey, ScalarExt, SignId, Signature, MAX_SECP256K1_SCALAR};
pub use requests::SignRequest;

/// The highest key version the network signs for; it refuses requests above it.
pub const MAX_SUPPORTED_MPC_KEY_VERSION: u32 = 1;
/// The key version clients use unless they pick one. It reaches a new version only
/// after `MAX_SUPPORTED_MPC_KEY_VERSION` does, so clients can opt in first.
pub const LATEST_MPC_KEY_VERSION: u32 = 1;
const _: () = assert!(LATEST_MPC_KEY_VERSION <= MAX_SUPPORTED_MPC_KEY_VERSION);
/// The first key version.
pub const LEGACY_MPC_KEY_VERSION_0: u32 = 0;
