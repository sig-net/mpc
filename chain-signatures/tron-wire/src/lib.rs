//! The Tron transaction wire format: the protobuf-binary messages, their
//! canonical parse and signing derivations, address forms, and the reference
//! block's field derivation — pure, with no RPC client. The chain integration
//! (`mpc-chain-tron`) and the bidirectional signing path both build on it.

pub mod pb;

mod address;
pub mod encoding;
mod tx;
mod types;

pub use address::{ParseTronAddressError, TRON_ADDRESS_PREFIX, TronAddress, parse_hex};
pub use pb::Message;
pub use tx::{MAX_EXPIRATION_SPAN_MS, to_unsigned_tron_tx};
pub use types::NowBlock;
