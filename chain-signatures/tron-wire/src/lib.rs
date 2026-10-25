//! The Tron transaction wire format: the protobuf-binary messages, their
//! canonical parse and signing derivations, address forms, and the reference
//! block's field derivation — pure, with no RPC client. The chain integration
//! (`mpc-chain-tron`) and the bidirectional signing path both build on it.

pub mod pb;

mod address;
pub mod encoding;
mod tx;
mod types;

pub use address::{parse_hex, ParseTronAddressError, TronAddress, TRON_ADDRESS_PREFIX};
pub use pb::Message;
pub use types::NowBlock;
