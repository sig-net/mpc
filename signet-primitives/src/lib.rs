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

/// An MPC key version: which root key and derivation path format a key comes from.
pub type KeyVersion = u32;

/// The first key version.
pub const LEGACY_MPC_KEY_VERSION_0: KeyVersion = 0;
/// The second key version. Its derivation path names no purpose.
pub const LEGACY_MPC_KEY_VERSION_1: KeyVersion = 1;
/// The first key version whose derivation path names the key's purpose.
pub const MPC_KEY_VERSION_2: KeyVersion = 2;
/// The highest key version the network signs; it refuses requests above it.
pub const LATEST_MPC_KEY_VERSION: KeyVersion = MPC_KEY_VERSION_2;
