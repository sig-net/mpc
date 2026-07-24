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

pub const LATEST_MPC_KEY_VERSION: u32 = 1;
pub const LEGACY_MPC_KEY_VERSION_0: u32 = 0;
